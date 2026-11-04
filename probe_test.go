package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		err  error
		want ErrClass
	}{
		{nil, ErrNone},
		{context.DeadlineExceeded, ErrTimeout},
		{&net.DNSError{Err: "no such host", IsNotFound: true}, ErrNotFound},
		{&net.DNSError{Err: "server misbehaving"}, ErrDNS},
		{&net.DNSError{Err: "i/o timeout", IsTimeout: true}, ErrTimeout},
		{x509.UnknownAuthorityError{}, ErrCertUnknown},
		{x509.HostnameError{Host: "x"}, ErrCertHostname},
		{x509.CertificateInvalidError{Reason: x509.Expired}, ErrCertExpired},
		{x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign}, ErrCertUnknown},
		{&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, ErrRefused},
		{&net.OpError{Op: "read", Err: syscall.ECONNRESET}, ErrReset},
		{&net.OpError{Op: "dial", Err: syscall.ENETUNREACH}, ErrUnreachable},
		{&net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}, ErrUnreachable},
		{&url.Error{Op: "Get", Err: &net.OpError{Op: "proxyconnect", Err: syscall.ECONNREFUSED}}, ErrProxy},
		{fmt.Errorf("包裝：%w", x509.UnknownAuthorityError{}), ErrCertUnknown},
		{io.EOF, ErrReset},
		{&net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}, ErrTimeout},
		{fmt.Errorf("包裝：%w", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}), ErrRefused},
		{errors.New("怪錯誤"), ErrOther},
	}
	for _, c := range cases {
		if got := classify(c.err); got != c.want {
			t.Errorf("classify(%v) = %q，預期 %q", c.err, got, c.want)
		}
	}
}

func TestTCPProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if p := tcpProbe(context.Background(), addr, time.Second); !p.OK {
		t.Errorf("開著的埠應成功：%+v", p)
	}
	ln.Close()
	refusedTimeout := time.Second
	if runtime.GOOS == "windows" {
		refusedTimeout = 5 * time.Second
	}
	if p := tcpProbe(context.Background(), addr, refusedTimeout); p.OK || p.Err != ErrRefused {
		t.Errorf("關閉的埠應為被拒絕：%+v", p)
	}
}

func TestSiteProbe(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/down" {
			w.WriteHeader(503)
		}
	}))
	defer srv.Close()
	ctx := context.Background()

	// 用系統根憑證連自簽伺服器 → 憑證不受信任（模擬 HTTPS 攔截）
	s := siteProbe(ctx, newClient(Proxy{}, nil, 2*time.Second), Target{"自簽", srv.URL})
	if s.OK || s.Err != ErrCertUnknown {
		t.Errorf("自簽憑證應為 cert_unknown：%+v", s)
	}

	trusted := newClient(Proxy{}, srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs, 2*time.Second)
	if s := siteProbe(ctx, trusted, Target{"正常", srv.URL}); !s.OK || s.Status != 200 {
		t.Errorf("信任後應成功 200：%+v", s)
	}
	if s := siteProbe(ctx, trusted, Target{"故障", srv.URL + "/down"}); !s.OK || s.Status != 503 {
		t.Errorf("503 仍算連得到：%+v", s)
	}
}

func TestSiteRoute(t *testing.T) {
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
	cases := []struct {
		name   string
		px     Proxy
		rawURL string
		env    map[string]string
		want   string
	}{
		{name: "無代理直連", px: Proxy{}, rawURL: "https://www.google.com", want: "direct"},
		{name: "PAC 未執行、實際直連", px: Proxy{Mode: ProxyPAC, Addr: "http://wpad/wpad.dat"}, rawURL: "https://www.google.com", want: "pac"},
		{name: "明確代理", px: Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128"}, rawURL: "https://www.google.com", want: "proxy"},
		{name: "明確代理但命中例外", px: Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128", Bypass: []string{"*.corp.example"}}, rawURL: "https://erp.corp.example", want: "direct"},
		{name: "無法解析的網址", px: Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128"}, rawURL: "://bad", want: ""},
		{name: "只設 HTTP_PROXY 時 https 直連", px: Proxy{Mode: ProxyEnv}, rawURL: "https://www.google.com",
			env: map[string]string{"HTTP_PROXY": "http://127.0.0.1:7998"}, want: "direct"},
		{name: "設 HTTPS_PROXY 時走代理", px: Proxy{Mode: ProxyEnv}, rawURL: "https://www.google.com",
			env: map[string]string{"HTTP_PROXY": "http://127.0.0.1:7998", "HTTPS_PROXY": "http://127.0.0.1:7999"}, want: "proxy"},
		{name: "NO_PROXY 命中直連", px: Proxy{Mode: ProxyEnv}, rawURL: "https://erp.corp.example",
			env: map[string]string{"HTTPS_PROXY": "http://127.0.0.1:7999", "NO_PROXY": "*.corp.example"}, want: "direct"},
		{name: "localhost 直連", px: Proxy{Mode: ProxyEnv}, rawURL: "https://localhost/",
			env: map[string]string{"HTTPS_PROXY": "http://127.0.0.1:7999"}, want: "direct"},
		{name: "明確代理位址無法解析", px: Proxy{Mode: ProxyExplicit, Addr: "[::1"}, rawURL: "https://www.google.com", want: ""},
		{name: "環境變數代理位址無法解析", px: Proxy{Mode: ProxyEnv}, rawURL: "https://www.google.com",
			env: map[string]string{"HTTPS_PROXY": "http://[::1"}, want: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			if got := siteRoute(c.px, c.rawURL); got != c.want {
				t.Errorf("siteRoute = %q，預期 %q", got, c.want)
			}
		})
	}
}

func TestCaptiveCheck(t *testing.T) {
	serverTime := time.Now().Add(-72 * time.Hour) // 登入頁的錯誤時鐘
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", serverTime.UTC().Format(http.TimeFormat))
		http.Redirect(w, r, "http://login.hotel/", http.StatusFound)
	}))
	defer portal.Close()
	clean := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/204" {
			w.WriteHeader(204)
			return
		}
		fmt.Fprint(w, "<HTML><BODY>Success</BODY></HTML>")
	}))
	defer clean.Close()

	ctx := context.Background()
	cl := newClient(Proxy{}, nil, 2*time.Second)

	c := captiveCheck(ctx, cl, []captiveURL{{portal.URL + "/204", 204, ""}})
	if !c.Checked || !c.Portal {
		t.Errorf("重新導向應判為登入頁：%+v", c)
	}
	if c.SkewKnown {
		t.Errorf("登入頁的 Date 不可信，不應計算時間差：%+v", c)
	}

	c = captiveCheck(ctx, cl, []captiveURL{{clean.URL + "/204", 204, ""}, {clean.URL + "/ok", 200, "Success"}})
	if !c.Checked || c.Portal || !c.SkewKnown {
		t.Errorf("正常回應不應判為登入頁，且應算出時間差：%+v", c)
	}

	c = captiveCheck(ctx, cl, []captiveURL{{clean.URL + "/ok", 200, "NotThere"}})
	if !c.Portal {
		t.Errorf("內容不符應判為登入頁：%+v", c)
	}
	c = captiveCheck(ctx, cl, []captiveURL{{"http://127.0.0.1:1/x", 204, ""}})
	if c.Portal {
		t.Errorf("連不上不應判為登入頁：%+v", c)
	}

	// 4xx/5xx 不是登入頁（如 407 代理要求、503 檢查點維護）
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer down.Close()
	c = captiveCheck(ctx, cl, []captiveURL{{down.URL, 204, ""}})
	if c.Portal {
		t.Errorf("503 不應判為登入頁：%+v", c)
	}
	if !strings.Contains(c.Note, "503") {
		t.Errorf("Note 應含 503：%+v", c)
	}

	// 兩個檢查都連不上：無法完成檢查
	c = captiveCheck(ctx, cl, []captiveURL{{"http://127.0.0.1:1/a", 204, ""}, {"http://127.0.0.1:1/b", 200, "Success"}})
	if c.Portal {
		t.Errorf("都連不上不應判為登入頁：%+v", c)
	}
	if c.Note != "無法完成檢查" {
		t.Errorf("Note = %q，預期「無法完成檢查」", c.Note)
	}

	// 兩個正常檢查點回應的 Date 相差 3 小時：時間不可信
	t1 := time.Now().Add(-time.Hour)
	t2 := time.Now().Add(-4 * time.Hour)
	skewSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := t1
		if r.URL.Path == "/b" {
			d = t2
		}
		w.Header().Set("Date", d.UTC().Format(http.TimeFormat))
		w.WriteHeader(204)
	}))
	defer skewSrv.Close()
	c = captiveCheck(ctx, cl, []captiveURL{{skewSrv.URL + "/a", 204, ""}, {skewSrv.URL + "/b", 204, ""}})
	if c.Portal || c.SkewKnown {
		t.Errorf("Date 差距過大時不應判為登入頁也不應採信時間：%+v", c)
	}

	// 正常 2xx 的檢查點不留 Note
	c = captiveCheck(ctx, cl, []captiveURL{{clean.URL + "/204", 204, ""}, {clean.URL + "/ok", 200, "Success"}})
	if c.Portal || c.Note != "" {
		t.Errorf("正常回應不應留 Note：%+v", c)
	}

	// 一個正常（索引 0）＋一個 503（索引 1）：Note 取 503 的
	c = captiveCheck(ctx, cl, []captiveURL{
		{clean.URL + "/204", 204, ""},
		{down.URL, 204, ""},
	})
	if c.Portal {
		t.Errorf("503 不應判為登入頁：%+v", c)
	}
	if !strings.Contains(c.Note, "503") {
		t.Errorf("正常＋503 應取 503 的 Note：%+v", c)
	}

	// 三個檢查點 Date：每個都距第一筆 ≤ 1 小時，但兩兩最大差 100 分鐘：時間不可信
	base := time.Now()
	spread := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var d time.Time
		switch r.URL.Path {
		case "/a":
			d = base
		case "/b":
			d = base.Add(50 * time.Minute)
		default:
			d = base.Add(-50 * time.Minute)
		}
		w.Header().Set("Date", d.UTC().Format(http.TimeFormat))
		w.WriteHeader(204)
	}))
	defer spread.Close()
	c = captiveCheck(ctx, cl, []captiveURL{{spread.URL + "/a", 204, ""}, {spread.URL + "/b", 204, ""}, {spread.URL + "/c", 204, ""}})
	if c.Portal || c.SkewKnown {
		t.Errorf("只跟第一筆比會誤過，兩兩最大差距過大時不應採信時間：%+v", c)
	}
}

// 本機 DNS stub：回答一筆 A 紀錄
func dnsStub(t *testing.T, rcode dnsmessage.RCode) string { return dnsStubID(t, rcode, 0) }

// dnsStubID：idDelta 非 0 時回應錯誤的 ID（模擬被竄改或遲到的封包）
func dnsStubID(t *testing.T, rcode dnsmessage.RCode, idDelta uint16) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil {
				continue
			}
			m.Header.Response, m.Header.RCode = true, rcode
			m.Header.ID += idDelta
			if rcode == dnsmessage.RCodeSuccess {
				m.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
					Body:   &dnsmessage.AResource{A: [4]byte{142, 250, 1, 1}},
				}}
			}
			out, _ := m.Pack()
			pc.WriteTo(out, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestPublicDNSProbe(t *testing.T) {
	ctx := context.Background()
	if p := publicDNSProbe(ctx, dnsStub(t, dnsmessage.RCodeSuccess), "www.google.com", time.Second); !p.OK {
		t.Errorf("stub 有回答應成功：%+v", p)
	}
	if p := publicDNSProbe(ctx, dnsStub(t, dnsmessage.RCodeServerFailure), "www.google.com", time.Second); p.OK || p.Err != ErrDNS {
		t.Errorf("SERVFAIL 應為 DNS 失敗：%+v", p)
	}
	if p := publicDNSProbe(ctx, dnsStubID(t, dnsmessage.RCodeSuccess, 1), "www.google.com", 300*time.Millisecond); p.OK {
		t.Errorf("ID 不符的回應不應算成功：%+v", p)
	}
	// 沒有人在聽的埠：逾時或被拒絕都可以，但不能成功
	if p := publicDNSProbe(ctx, "127.0.0.1:1", "www.google.com", 300*time.Millisecond); p.OK {
		t.Errorf("沒有伺服器不應成功：%+v", p)
	}
}

func TestDNSProbe(t *testing.T) {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", dnsStub(t, dnsmessage.RCodeSuccess))
	}}
	if p := dnsProbe(context.Background(), r, "www.example.com", time.Second); !p.OK {
		t.Errorf("系統 DNS 查詢應成功：%+v", p)
	}
	r.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", dnsStub(t, dnsmessage.RCodeNameError))
	}
	if p := dnsProbe(context.Background(), r, "www.example.com", time.Second); p.OK || p.Err != ErrNotFound {
		t.Errorf("NXDOMAIN 應為網址不存在：%+v", p)
	}
}

func TestGatewayProbe(t *testing.T) {
	// 127.0.0.1 一定會回 RST 或接受連線 → 可達
	if g := gatewayProbe(context.Background(), "127.0.0.1"); !g.Alive {
		t.Errorf("本機位址應判為可達：%+v", g)
	}
}

func TestGatewayProbeARP(t *testing.T) {
	if testing.Short() {
		t.Skip("-short 時略過（會有實際 TCP 嘗試）")
	}
	old := arpProbeFn
	arpProbeFn = func(context.Context, string) bool { return true }
	t.Cleanup(func() { arpProbeFn = old })
	// 192.0.2.1（TEST-NET-1）不會回應 ICMP/TCP；ARP 假函式回 true 應判為可達
	g := gatewayProbe(context.Background(), "192.0.2.1")
	if !g.Alive || g.Via != "ARP" {
		t.Errorf("ARP 有回應應判為可達：%+v", g)
	}
}

func TestTraceProbe(t *testing.T) {
	const trace = "fl=abc\nh=example.test\nip=203.0.113.10\nts=1\nloc=TW\nwarp=off\n"
	// 200 ＋合法 trace → ok（並驗證 Host 為主機名稱不含埠）
	okSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, trace)
	}))
	defer okSrv.Close()
	roots := okSrv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	ctx := context.Background()

	tr, ok := traceProbe(ctx, newClient(Proxy{}, roots, 5*time.Second), Target{"測試", okSrv.URL})
	if !ok || tr.IP != "203.0.113.10" || tr.Loc != "TW" || tr.Name != "測試" {
		t.Errorf("trace 應成功解析：%+v, %v", tr, ok)
	}
	if u, err := url.Parse(okSrv.URL); err != nil || tr.Host != u.Hostname() {
		t.Errorf("Host = %q，預期主機名稱（不含埠）%q", tr.Host, u.Hostname())
	}

	// 200 ＋HTML → not ok
	htmlSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>hello</body></html>")
	}))
	defer htmlSrv.Close()
	htmlRoots := htmlSrv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	if _, ok := traceProbe(ctx, newClient(Proxy{}, htmlRoots, 2*time.Second), Target{"HTML", htmlSrv.URL}); ok {
		t.Error("200 但 HTML 內容應為 not ok")
	}

	// 404 ＋合法 trace 內容 → not ok（狀態碼不對）
	nfSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, trace)
	}))
	defer nfSrv.Close()
	nfRoots := nfSrv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	if _, ok := traceProbe(ctx, newClient(Proxy{}, nfRoots, 2*time.Second), Target{"404", nfSrv.URL}); ok {
		t.Error("404 即使內容合法也應為 not ok")
	}
}

// TestTraceProbeTimeout：伺服器慢 5 秒，traceProbe 的 3 秒逾時要在 4 秒內回 not ok
func TestTraceProbeTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("-short 時略過逾時測試")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		fmt.Fprint(w, "h=x\nip=1.2.3.4\n")
	}))
	defer srv.Close()
	roots := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs

	start := time.Now()
	if _, ok := traceProbe(context.Background(), newClient(Proxy{}, roots, 10*time.Second), Target{"慢", srv.URL}); ok {
		t.Error("逾時應為 not ok")
	}
	if el := time.Since(start); el > 4*time.Second {
		t.Errorf("應在 4 秒內回傳（3 秒逾時），實際 %s", el)
	}
}

func TestIsAPIPA(t *testing.T) {
	if !isAPIPA(net.ParseIP("169.254.3.4")) || isAPIPA(net.ParseIP("192.168.1.2")) {
		t.Error("isAPIPA 判斷錯誤")
	}
}

func TestIsVPNName(t *testing.T) {
	for name, want := range map[string]bool{
		"utun4": true, "wg0": true, "tun0": true, "ppp0": true, "tailscale0": true, "ipsec0": true,
		"en0": false, "eth0": false, "wlp2s0": false, "lo": false,
	} {
		if got := isVPNName(name); got != want {
			t.Errorf("isVPNName(%q) = %v", name, got)
		}
	}
}

func TestChooseCandidate(t *testing.T) {
	eg := net.ParseIP("192.168.1.23")
	v6 := net.ParseIP("2001:db8::5")
	fe80 := net.ParseIP("fe80::1")
	cases := []struct {
		name       string
		egress     net.IP
		haveEgress bool
		ips        []net.IP
		want       int
	}{
		{"有 egress 時回相符索引", eg, true, []net.IP{net.ParseIP("10.0.0.1"), eg}, 1},
		{"沒有 egress 時 IPv4 優先於 IPv6", nil, false, []net.IP{v6, net.ParseIP("169.254.1.2")}, 1},
		{"只有 link-local 與全域 IPv6 時回全域 IPv6", nil, false, []net.IP{fe80, v6}, 1},
		{"只有 fe80 時回 -1", nil, false, []net.IP{fe80}, -1},
		{"空切片回 -1", nil, false, nil, -1},
	}
	for _, c := range cases {
		if got := chooseCandidate(c.egress, c.haveEgress, c.ips); got != c.want {
			t.Errorf("%s：chooseCandidate = %d，預期 %d", c.name, got, c.want)
		}
	}
}

// TestPublicDNSProbeCancel：ctx 取消時讀取要立即中斷，不等到 socket 期限
func TestPublicDNSProbeCancel(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() }) // 只收封包不回應
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	p := publicDNSProbe(ctx, pc.LocalAddr().String(), "example.com", 5*time.Second)
	if el := time.Since(start); el > time.Second {
		t.Errorf("取消後應在 1 秒內回傳，實際 %s", el)
	}
	if p.OK {
		t.Errorf("永不回應的伺服器不應成功：%+v", p)
	}
}

// TestCaptiveNoCache：登入頁檢查請求必須要求不使用快取
func TestCaptiveNoCache(t *testing.T) {
	headers := make(chan [2]string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- [2]string{r.Header.Get("Cache-Control"), r.Header.Get("Pragma")}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	cl := newClient(Proxy{}, nil, time.Second)
	c := captiveCheck(context.Background(), cl, []captiveURL{{URL: srv.URL, Status: 204}})
	if c.Portal {
		t.Errorf("204 不應判為登入頁：%+v", c)
	}
	select {
	case h := <-headers:
		if h[0] != "no-cache" {
			t.Errorf("Cache-Control = %q，預期 no-cache", h[0])
		}
		if h[1] != "no-cache" {
			t.Errorf("Pragma = %q，預期 no-cache", h[1])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler 沒有收到登入頁檢查請求")
	}
}

// TestNewClientDialTimeout：撥號逾時要生效（不是整體逾時）
func TestNewClientDialTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("-short 時略過撥號逾時測試")
	}
	old := dialTimeout
	dialTimeout = 300 * time.Millisecond
	t.Cleanup(func() { dialTimeout = old })
	cl := newClient(Proxy{}, nil, 10*time.Second) // 整體逾時明顯較長
	start := time.Now()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://10.255.255.1/", nil)
	_, err := cl.Do(req)
	if err == nil {
		t.Fatal("不可路由位址不應連上")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("應在 2 秒內回錯（撥號逾時），實際 %s", el)
	}
}

func TestCheckpointProbeTCP(t *testing.T) {
	ctx := context.Background()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if r := checkpointProbe(ctx, Checkpoint{Name: "開著的埠", Host: "127.0.0.1", Check: fmt.Sprintf("tcp:%d", port)}); !r.OK {
		t.Errorf("開著的埠應 OK：%+v", r)
	}
	ln.Close()
	if r := checkpointProbe(ctx, Checkpoint{Name: "關閉的埠", Host: "127.0.0.1", Check: fmt.Sprintf("tcp:%d", port)}); !r.OK {
		t.Errorf("關閉的埠收到 RST 也應 OK：%+v", r)
	}
}

func TestCheckpointProbeDNS(t *testing.T) {
	ctx := context.Background()
	old := checkpointDNSPort
	_, portStr, _ := net.SplitHostPort(dnsStub(t, dnsmessage.RCodeSuccess))
	checkpointDNSPort = portStr
	t.Cleanup(func() { checkpointDNSPort = old })
	if r := checkpointProbe(ctx, Checkpoint{Name: "單位 DNS", Host: "127.0.0.1", Check: "dns"}); !r.OK {
		t.Errorf("假 DNS 伺服器有回應應 OK：%+v", r)
	}
	// 沒人聽的埠：不是 OK（逾時或被拒絕都可以）
	checkpointDNSPort = "1"
	if r := checkpointProbe(ctx, Checkpoint{Name: "單位 DNS", Host: "127.0.0.1", Check: "dns"}); r.OK {
		t.Errorf("沒有伺服器不應 OK：%+v", r)
	}
}
