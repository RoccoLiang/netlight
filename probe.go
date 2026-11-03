package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	totalBudget    = 8 * time.Second
	gatewayTimeout = 1200 * time.Millisecond
	directTimeout  = 2 * time.Second
	dnsTimeout     = 2500 * time.Millisecond
	siteTimeout    = 5 * time.Second
	captiveTimeout = 3 * time.Second
)

// runWithEvents 各組探測完成時 emit 的 stage 字串
const (
	stageDirect    = "direct"
	stagePublicDNS = "public_dns"
	stageDNS       = "dns"
	stageLocal     = "local"
	stageGateway   = "gateway"
	stageSites     = "sites"
	stageCaptive   = "captive"
)

// 撥號逾時：自建 Transport 的 DialContext 上限，避免撥號在背景無限等待
var dialTimeout = 3 * time.Second

var errICMPUnavailable = errors.New("此系統不允許一般權限 ICMP")

var (
	directTargets = []string{"1.1.1.1:443", "8.8.8.8:443"}
	publicDNS     = []string{"8.8.8.8:53", "1.1.1.1:53"}
	captiveURLs   = []captiveURL{
		{"http://connectivitycheck.gstatic.com/generate_204", 204, ""},
		{"http://captive.apple.com/hotspot-detect.html", 200, "Success"},
	}
)

// classify：把各平台的錯誤歸成少數幾類，供判斷使用
func classify(err error) ErrClass {
	if err == nil {
		return ErrNone
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "proxyconnect" {
		return ErrProxy
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return ErrNotFound
		}
		if dnsErr.IsTimeout {
			return ErrTimeout
		}
		return ErrDNS
	}
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalid x509.CertificateInvalidError
	switch {
	case errors.As(err, &unknownCA):
		return ErrCertUnknown
	case errors.As(err, &hostErr):
		return ErrCertHostname
	case errors.As(err, &invalid):
		if invalid.Reason == x509.Expired {
			return ErrCertExpired
		}
		return ErrCertUnknown
	}
	if c := platformErrClass(err); c != ErrNone {
		return c
	}
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return ErrTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return ErrRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.EOF):
		return ErrReset
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return ErrUnreachable
	}
	return ErrOther
}

func done(p Probe, start time.Time, err error) Probe {
	p.Ms = time.Since(start).Milliseconds()
	p.OK = err == nil
	p.Err = classify(err)
	return p
}

func tcpProbe(ctx context.Context, addr string, timeout time.Duration) Probe {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err == nil {
		c.Close()
	}
	return done(Probe{Target: addr}, start, err)
}

func dnsProbe(ctx context.Context, r *net.Resolver, host string, timeout time.Duration) Probe {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	addrs, err := r.LookupHost(ctx, host)
	p := done(Probe{Target: host}, start, err)
	if err == nil {
		p.Note = strings.Join(addrs[:min(len(addrs), 2)], ", ")
	}
	return p
}

// publicDNSProbe：直接對指定 DNS 伺服器送 UDP 查詢，不經過系統設定
func publicDNSProbe(ctx context.Context, server, name string, timeout time.Duration) Probe {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	target := server
	if host, _, err := net.SplitHostPort(server); err == nil {
		target = host
	}
	p := Probe{Target: target}
	start := time.Now()
	q := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: uint16(start.UnixNano()), RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	msg, _ := q.Pack()
	c, err := (&net.Dialer{}).DialContext(ctx, "udp", server)
	if err != nil {
		return done(p, start, err)
	}
	defer c.Close()
	// ctx 取消時立即關閉連線中斷讀取，不等到 socket 期限
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	dl, _ := ctx.Deadline()
	c.SetDeadline(dl)
	if _, err := c.Write(msg); err != nil {
		return done(p, start, err)
	}
	buf := make([]byte, 1500)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return done(p, start, err)
		}
		var m dnsmessage.Message
		if m.Unpack(buf[:n]) != nil || !m.Header.Response || m.Header.ID != q.Header.ID ||
			len(m.Questions) != 1 || m.Questions[0] != q.Questions[0] {
			continue // 不是這次查詢的回應
		}
		p = done(p, start, nil)
		if m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) == 0 {
			p.OK, p.Err = false, ErrDNS
			if m.Header.Truncated {
				p.Note = "回應被截斷"
			}
		}
		return p
	}
}

func proxyFunc(px Proxy) func(*http.Request) (*url.URL, error) {
	switch px.Mode {
	case ProxyEnv:
		// http.ProxyFromEnvironment 會快取環境變數，自行讀取以反映測試中的變更
		return func(req *http.Request) (*url.URL, error) {
			// localhost 與 loopback 一律直連，與 Go 標準行為一致
			host := req.URL.Hostname()
			if host == "localhost" || net.ParseIP(host).IsLoopback() {
				return nil, nil
			}
			rules := px.Bypass
			if rules == nil {
				rules = splitCSV(cmp.Or(os.Getenv("NO_PROXY"), os.Getenv("no_proxy")))
			}
			if bypassed(host, rules) {
				return nil, nil
			}
			// 依請求 scheme 選擇環境變數，與 curl／Go 慣例一致
			var raw string
			if req.URL.Scheme == "https" {
				raw = cmp.Or(os.Getenv("HTTPS_PROXY"), os.Getenv("https_proxy"))
			} else {
				raw = cmp.Or(os.Getenv("HTTP_PROXY"), os.Getenv("http_proxy"))
			}
			if raw == "" {
				return nil, nil
			}
			if !strings.Contains(raw, "://") {
				raw = "http://" + raw
			}
			return url.Parse(raw)
		}
	case ProxyExplicit:
		return func(req *http.Request) (*url.URL, error) {
			if bypassed(req.URL.Hostname(), px.Bypass) {
				return nil, nil
			}
			return url.Parse("http://" + px.Addr)
		}
	}
	return nil // 無代理或 PAC（無法執行 PAC 腳本）→ 直連
}

func newClient(px Proxy, roots *x509.CertPool, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: proxyFunc(px),
			// 明確的撥號逾時，避免 Go 1.27 之後 Transport 撥號用 WithoutCancel 在背景拖延
			DialContext:         (&net.Dialer{Timeout: min(timeout, dialTimeout)}).DialContext,
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 3 * time.Second,
			TLSClientConfig:     &tls.Config{RootCAs: roots},
		},
		// 不跟隨重新導向：任何回應都代表連得到，且 captive 檢查需要看到 3xx
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func siteProbe(ctx context.Context, cl *http.Client, t Target) Site {
	s := Site{Name: t.Name, Probe: Probe{Target: t.URL}}
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, t.URL, nil)
	req.Header.Set("User-Agent", "netlight/"+version)
	resp, err := cl.Do(req)
	s.Probe = done(s.Probe, start, err)
	if err == nil {
		s.Status = resp.StatusCode
		resp.Body.Close()
	}
	return s
}

// traceProbe：對目標送 Cloudflare trace 請求取得對外 IP 與位置（逾時 3 秒）
func traceProbe(ctx context.Context, cl *http.Client, t Target) (TraceResult, bool) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	u, err := url.Parse(t.URL)
	if err != nil {
		return TraceResult{}, false
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+u.Host+"/cdn-cgi/trace", nil)
	req.Header.Set("User-Agent", "netlight/"+version)
	resp, err := cl.Do(req)
	if err != nil {
		return TraceResult{}, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if err != nil || resp.StatusCode != 200 {
		return TraceResult{}, false
	}
	ip, loc, ok := parseCFTrace(string(body))
	if !ok {
		return TraceResult{}, false
	}
	return TraceResult{Name: t.Name, Host: u.Hostname(), IP: ip, Loc: loc}, true
}

type captiveURL struct {
	URL    string
	Status int
	Body   string // 非空時，回應內容必須包含此字串
}

type captiveResult struct {
	ok      bool // 收到回應且讀完 body
	portal  bool
	note    string
	skew    time.Duration
	hasDate bool
}

func captiveCheck(ctx context.Context, cl *http.Client, checks []captiveURL) Captive {
	c := Captive{Checked: true}
	results := make([]captiveResult, len(checks))
	var wg sync.WaitGroup
	for i, chk := range checks {
		wg.Go(func() {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, chk.URL, nil)
			req.Header.Set("Cache-Control", "no-cache")
			req.Header.Set("Pragma", "no-cache")
			resp, err := cl.Do(req)
			if err != nil {
				return // 連不上不代表是登入頁
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if err != nil {
				return // 讀不完 body 不算拿到回應
			}
			r := &results[i]
			r.ok = true
			switch {
			case resp.StatusCode >= 300 && resp.StatusCode < 400:
				r.portal = true
				r.note = "HTTP " + resp.Status
				if loc := resp.Header.Get("Location"); loc != "" {
					r.note += " → " + loc
				}
			case resp.StatusCode >= 200 && resp.StatusCode < 300 &&
				(resp.StatusCode != chk.Status || (chk.Body != "" && !strings.Contains(string(body), chk.Body))):
				r.portal = true
				r.note = "HTTP " + resp.Status
			default:
				// 4xx／5xx：不是登入頁，但記下檢查點的異常回應
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					r.note = "檢查點回應 HTTP " + resp.Status
				}
			}
			// 只採用真正檢查伺服器的 Date，登入頁或代理的時鐘不可信
			if !r.portal && resp.StatusCode >= 200 && resp.StatusCode < 300 {
				if d, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
					r.skew, r.hasDate = time.Since(d), true
				}
			}
		})
	}
	wg.Wait()

	anyOKResult := false
	for _, r := range results {
		if !r.ok {
			continue
		}
		anyOKResult = true
		if r.portal && !c.Portal {
			c.Portal, c.Note = true, r.note
		}
	}
	if !anyOKResult {
		c.Note = "無法完成檢查"
	} else if c.Note == "" {
		for _, r := range results {
			if r.note != "" {
				c.Note = r.note
				break
			}
		}
	}
	// 時間：所有 Date 兩兩差距都在 1 小時內才可信
	var skews []time.Duration
	for _, r := range results {
		if r.hasDate {
			skews = append(skews, r.skew)
		}
	}
	if len(skews) > 0 {
		minS, maxS := skews[0], skews[0]
		for _, s := range skews[1:] {
			minS = min(minS, s)
			maxS = max(maxS, s)
		}
		c.Skew, c.SkewKnown = skews[0], maxS-minS <= time.Hour
	}
	return c
}

// gatewayProbe：ICMP、TCP、ARP 任一有證據即視為可達；都沒有只代表「無法確認」
func gatewayProbe(ctx context.Context, gw string) GatewayResult {
	ctx, cancel := context.WithTimeout(ctx, gatewayTimeout)
	defer cancel()
	arp := arpProbeFn // 快取，避免測試替換全域變數時的競態
	res := make(chan GatewayResult, 5)
	go func() {
		err := icmpPing(ctx, gw)
		switch {
		case err == nil:
			res <- GatewayResult{Alive: true, Via: "ICMP"}
		case errors.Is(err, errICMPUnavailable):
			res <- GatewayResult{Note: "此系統不允許一般權限 ping"}
		default:
			res <- GatewayResult{}
		}
	}()
	for _, port := range []string{"80", "443", "53"} {
		go func() {
			p := tcpProbe(ctx, net.JoinHostPort(gw, port), gatewayTimeout)
			if p.OK || p.Err == ErrRefused { // 收到 RST 也代表對方活著
				res <- GatewayResult{Alive: true, Via: "TCP " + port}
				return
			}
			res <- GatewayResult{}
		}()
	}
	go func() {
		if arp(ctx, gw) {
			res <- GatewayResult{Alive: true, Via: "ARP"}
			return
		}
		res <- GatewayResult{}
	}()
	note := ""
	for range 5 {
		r := <-res
		if r.Alive {
			return r
		}
		if r.Note != "" {
			note = r.Note
		}
	}
	return GatewayResult{Note: note}
}

// arpProbeFn：測試可替換的 ARP 探測
var arpProbeFn = arpProbe

func isAPIPA(ip net.IP) bool { return ip.IsLinkLocalUnicast() && ip.To4() != nil }

var vpnPrefixes = []string{"utun", "tun", "tap", "wg", "ppp", "ipsec", "tailscale", "zt"}

func isVPNName(name string) bool {
	return slices.ContainsFunc(vpnPrefixes, func(p string) bool { return strings.HasPrefix(name, p) })
}

// egress：問核心「往外連會用哪個來源 IP」，不會真的送出封包
func egress() (net.IP, bool) {
	for _, t := range []struct{ net, addr string }{{"udp4", "1.1.1.1:53"}, {"udp6", "[2606:4700:4700::1111]:53"}} {
		if c, err := net.Dial(t.net, t.addr); err == nil {
			ip := c.LocalAddr().(*net.UDPAddr).IP
			c.Close()
			return ip, true
		}
	}
	return nil, false
}

// chooseCandidate：有對外路由時找擁有該 IP 的位址；沒有時先找 IPv4（含 169.254），再找全域 IPv6；都沒有回 -1
func chooseCandidate(egressIP net.IP, haveEgress bool, ips []net.IP) int {
	if haveEgress {
		for i := len(ips) - 1; i >= 0; i-- { // 多個相同 IP 時取最後一個（後者覆蓋）
			if ips[i].Equal(egressIP) {
				return i
			}
		}
		return -1
	}
	for i, ip := range ips {
		if ip.To4() != nil {
			return i
		}
	}
	for i, ip := range ips {
		if ip.To4() == nil && ip.IsGlobalUnicast() {
			return i
		}
	}
	return -1
}

// collectLocal：本機 IP、介面、閘道、DNS、代理、VPN
// 沒有可用介面時回傳的 Local.IP 為空字串
func collectLocal(ctx context.Context) Local {
	lo := Local{OS: osName()}
	ip, ok := egress()
	ifaces, _ := net.Interfaces()
	var ifaces2 []*net.Interface
	var ips []net.IP
	for i := range ifaces {
		it := &ifaces[i]
		if it.Flags&net.FlagUp == 0 || it.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := it.Addrs()
		for _, a := range addrs {
			if n, ok2 := a.(*net.IPNet); ok2 {
				ifaces2 = append(ifaces2, it)
				ips = append(ips, n.IP)
			}
		}
	}
	idx := chooseCandidate(ip, ok, ips)
	if idx < 0 {
		return lo
	}
	iface, ip := ifaces2[idx], ips[idx]
	lo.Iface, lo.IP, lo.APIPA = iface.Name, ip.String(), isAPIPA(ip)
	if isVPNName(iface.Name) || iface.Flags&net.FlagPointToPoint != 0 {
		lo.VPN = iface.Name
	}
	if !ok {
		lo.Notes = append(lo.Notes, "沒有對外路由")
	}
	platformLocal(ctx, &lo)
	// 平台只回報硬體類型；經由 VPN 時一律顯示 VPN
	if lo.VPN != "" {
		lo.Kind = "VPN"
	} else if lo.Kind == "" {
		lo.Kind = "網路"
	}
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v := os.Getenv(k); v != "" {
			lo.Proxy = Proxy{Mode: ProxyEnv, Addr: v}
			lo.Proxy.Bypass = splitCSV(cmp.Or(os.Getenv("NO_PROXY"), os.Getenv("no_proxy")))
			break
		}
	}
	if bypassAll(lo.Proxy.Bypass) {
		lo.Proxy = Proxy{}
	}
	return lo
}

// run：所有探測平行執行，整體不超過 totalBudget
func run(ctx context.Context, cfg Config) Facts { return runWithEvents(ctx, cfg, nil) }

// runWithEvents：所有探測平行執行，整體不超過 totalBudget；每組探測完成時呼叫 emit（可為 nil）
func runWithEvents(ctx context.Context, cfg Config, emit func(stage string)) Facts {
	ctx, cancel := context.WithTimeout(ctx, totalBudget)
	defer cancel()

	var mu sync.Mutex // 序列化 emit，同一時間只有一個呼叫
	fire := func(stage string) {
		if emit == nil {
			return
		}
		mu.Lock()
		emit(stage)
		mu.Unlock()
	}

	targets := cfg.targets()
	var hosts []string
	for _, t := range targets {
		if u, err := url.Parse(t.URL); err == nil && !slices.Contains(hosts, u.Hostname()) {
			hosts = append(hosts, u.Hostname())
		}
	}

	// 不依賴本機資訊的三組探測先開始：結果寫入區域變數，最後再組成 Facts
	direct := make([]Probe, len(directTargets))
	publicDNSRes := make([]Probe, len(publicDNS))
	dnsRes := make([]Probe, len(hosts))
	// group：跑一組探測，組內全部完成時 emit
	group := func(stage string, run func()) *sync.WaitGroup {
		g := &sync.WaitGroup{}
		g.Add(1)
		go func() {
			defer g.Done()
			run()
			fire(stage)
		}()
		return g
	}
	var early sync.WaitGroup
	gDirect := group(stageDirect, func() {
		var wg sync.WaitGroup
		for i, a := range directTargets {
			wg.Go(func() { direct[i] = tcpProbe(ctx, a, directTimeout) })
		}
		wg.Wait()
	})
	gPublicDNS := group(stagePublicDNS, func() {
		var wg sync.WaitGroup
		for i, s := range publicDNS {
			wg.Go(func() { publicDNSRes[i] = publicDNSProbe(ctx, s, "www.google.com", dnsTimeout) })
		}
		wg.Wait()
	})
	gDNS := group(stageDNS, func() {
		var wg sync.WaitGroup
		for i, h := range hosts {
			wg.Go(func() { dnsRes[i] = dnsProbe(ctx, net.DefaultResolver, h, dnsTimeout) })
		}
		wg.Wait()
	})
	for _, g := range []*sync.WaitGroup{gDirect, gPublicDNS, gDNS} {
		early.Add(1)
		go func() {
			g.Wait()
			early.Done()
		}()
	}

	lo := collectLocal(ctx)
	fire(stageLocal)
	f := Facts{Local: lo, NoLink: lo.IP == ""}
	if f.NoLink {
		cancel() // 讓先啟動的探測盡快結束，避免 goroutine 洩漏
		early.Wait()
		return f
	}
	f.Direct, f.PublicDNS, f.DNS = direct, publicDNSRes, dnsRes
	f.Sites = make([]Site, len(targets))

	// 每個 goroutine 只寫自己的欄位或切片元素，不需要鎖
	var wg sync.WaitGroup

	// 設定的 DNS 伺服器逐台探測（前 3 台）；結果只用於 dnsFail 時的說法選擇
	dnsServers := lo.DNSServers
	if len(dnsServers) > 3 {
		dnsServers = dnsServers[:3]
	}
	f.DNSServers = make([]Probe, len(dnsServers))
	for i, addr := range dnsServers {
		i, addr := i, addr // 供 goroutine 使用
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.DNSServers[i] = publicDNSProbe(ctx, net.JoinHostPort(addr, "53"), "www.google.com", dnsTimeout)
		}()
	}

	var gateway GatewayResult
	var gatewayWg *sync.WaitGroup
	if lo.Gateway != "" {
		gatewayWg = group(stageGateway, func() { gateway = gatewayProbe(ctx, lo.Gateway) })
		wg.Add(1)
		go func() {
			defer wg.Done()
			gatewayWg.Wait()
		}()
	}
	cl := newClient(lo.Proxy, nil, siteTimeout)
	defer cl.CloseIdleConnections()

	// 對外 IP：對每個在探測目標內的預設目標送 Cloudflare trace（不 emit stage）
	var traces []TraceResult
	if cfg.publicIPEnabled() {
		traces = make([]TraceResult, len(defaultTargets))
		for i, dt := range defaultTargets {
			if !slices.ContainsFunc(targets, func(t Target) bool { return t.URL == dt.URL }) {
				continue
			}
			i, dt := i, dt
			wg.Add(1)
			go func() {
				defer wg.Done()
				if tr, ok := traceProbe(ctx, cl, dt); ok {
					traces[i] = tr
				}
			}()
		}
	}
	sitesWg := group(stageSites, func() {
		var swg sync.WaitGroup
		for i, t := range targets {
			swg.Go(func() { f.Sites[i] = siteProbe(ctx, cl, t) })
		}
		swg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		sitesWg.Wait()
	}()
	captiveWg := group(stageCaptive, func() {
		cctx, ccancel := context.WithTimeout(ctx, captiveTimeout)
		defer ccancel()
		ccl := newClient(lo.Proxy, nil, captiveTimeout)
		defer ccl.CloseIdleConnections()
		f.Captive = captiveCheck(cctx, ccl, captiveURLs)
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		captiveWg.Wait()
	}()
	wg.Wait()
	// trace 結果在 wg.Wait() 之後收集（goroutine 全部完成，資料已寫入）
	for _, tr := range traces {
		if tr.IP != "" {
			f.PublicIP = append(f.PublicIP, tr)
		}
	}
	f.Gateway = gateway
	early.Wait() // 各組 emit 都在 group goroutine 內，early.Wait 保證 emit 在回傳前完成
	return f
}

// splitCSV：以逗號切開並去除每段空白（NO_PROXY 等環境變數格式）
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}
