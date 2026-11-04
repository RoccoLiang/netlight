package main

import (
	"cmp"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
)

// ---- 探測結果（純資料，由 probe.go 填入）----

type ErrClass string

const (
	ErrNone         ErrClass = ""
	ErrTimeout      ErrClass = "timeout"
	ErrRefused      ErrClass = "refused"
	ErrUnreachable  ErrClass = "unreachable"
	ErrReset        ErrClass = "reset"
	ErrDNS          ErrClass = "dns"
	ErrNotFound     ErrClass = "nxdomain"
	ErrCertUnknown  ErrClass = "cert_unknown"
	ErrCertHostname ErrClass = "cert_hostname"
	ErrCertExpired  ErrClass = "cert_expired"
	ErrProxy        ErrClass = "proxy"
	ErrOther        ErrClass = "other"
)

var errText = map[ErrClass]string{
	ErrNone:         "失敗",
	ErrTimeout:      "逾時",
	ErrRefused:      "被拒絕",
	ErrUnreachable:  "無法到達",
	ErrReset:        "連線被中斷",
	ErrDNS:          "查不到網址",
	ErrNotFound:     "網址不存在",
	ErrCertUnknown:  "憑證不受信任",
	ErrCertHostname: "憑證與網址不符",
	ErrCertExpired:  "憑證過期或尚未生效",
	ErrProxy:        "代理伺服器錯誤",
	ErrOther:        "其他錯誤",
}

type Probe struct {
	Target string   `json:"target"`
	OK     bool     `json:"ok"`
	Err    ErrClass `json:"error,omitempty"`
	Ms     int64    `json:"ms"`
	Note   string   `json:"note,omitempty"`
}

type ProxyMode string

const (
	ProxyNone     ProxyMode = ""
	ProxyEnv      ProxyMode = "env"
	ProxyExplicit ProxyMode = "explicit"
	ProxyPAC      ProxyMode = "pac"
)

type Proxy struct {
	Mode   ProxyMode `json:"mode,omitempty"`
	Addr   string    `json:"addr,omitempty"`
	Bypass []string  `json:"bypass,omitempty"` // 例外清單（NO_PROXY 等），符合者直連
}

type Local struct {
	OS             string   `json:"os"`
	Iface          string   `json:"iface,omitempty"`
	Kind           string   `json:"kind,omitempty"` // Wi-Fi、有線網路、VPN…
	IP             string   `json:"ip,omitempty"`
	APIPA          bool     `json:"apipa,omitempty"`
	Gateway        string   `json:"gateway,omitempty"`
	GatewayUnknown bool     `json:"gateway_unknown,omitempty"` // 平台讀取閘道資訊失敗（沒有預設路由不算）
	DNSServers     []string `json:"dns_servers,omitempty"`
	VPN            string   `json:"vpn,omitempty"` // 非空表示對外流量經由此 VPN 介面
	Proxy          Proxy    `json:"proxy"`
	Notes          []string `json:"notes,omitempty"`
}

type GatewayResult struct {
	Alive bool   `json:"alive"`
	Via   string `json:"via,omitempty"` // ICMP、TCP、ARP
	Note  string `json:"note,omitempty"`
}

type Site struct {
	Name string `json:"name"`
	Probe
	Status int `json:"status,omitempty"`
}

type Captive struct {
	Checked   bool          `json:"checked"`
	Portal    bool          `json:"portal"`
	Skew      time.Duration `json:"skew_ns,omitempty"` // 本機時間 − 伺服器 Date
	SkewKnown bool          `json:"skew_known"`
	Note      string        `json:"note,omitempty"`
}

// TraceResult：對外 IP 探測（Cloudflare trace）的結果
type TraceResult struct {
	Name string `json:"name"` // 目標名稱，例如 Cloudflare、政府入口網
	Host string `json:"host"` // 主機名稱（不含埠），供代理例外清單比對
	IP   string `json:"ip"`
	Loc  string `json:"loc,omitempty"`
}

// CheckpointResult：設定檔檢查點的探測結果
type CheckpointResult struct {
	Name    string   `json:"name"`
	Host    string   `json:"host"`
	Check   string   `json:"check"`
	OK      bool     `json:"ok"`
	Unknown bool     `json:"unknown,omitempty"` // 這台電腦無法執行此檢查（例如系統不允許一般權限 ping）
	Err     ErrClass `json:"error,omitempty"`
	Ms      int64    `json:"ms"`
}

// Hop：路由追蹤的一站（沒有回應的站不列入）
type Hop struct {
	TTL     int    `json:"ttl"`
	IP      string `json:"ip"`
	Ms      int64  `json:"ms"`
	Reached bool   `json:"reached,omitempty"` // 這一站就是目的地
}

// RouteResult：路由追蹤結果
type RouteResult struct {
	Target  string `json:"target"`
	Hops    []Hop  `json:"hops,omitempty"`    // 依 TTL 由小到大
	Unknown bool   `json:"unknown,omitempty"` // 這台電腦無法執行（系統不允許一般權限 ICMP）
}

type Facts struct {
	Local       Local              `json:"local"`
	NoLink      bool               `json:"no_link"`
	Gateway     GatewayResult      `json:"gateway"`
	Direct      []Probe            `json:"direct"`
	DNS         []Probe            `json:"dns"`
	DNSServers  []Probe            `json:"dns_servers,omitempty"`
	PublicDNS   []Probe            `json:"public_dns"`
	PublicIP    []TraceResult      `json:"public_ip,omitempty"`
	Sites       []Site             `json:"sites"`
	Captive     Captive            `json:"captive"`
	Checkpoints []CheckpointResult `json:"checkpoints,omitempty"`
	Route       RouteResult        `json:"route"`
}

// ---- 判斷結果 ----

type Status int

const (
	Green Status = iota
	Yellow
	Red
	Skip
)

func (s Status) String() string {
	return [...]string{"green", "yellow", "red", "skip"}[s]
}

func (s Status) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

type Code string

const (
	OK           Code = "OK"
	NoLink       Code = "NO_LINK"
	NoDHCP       Code = "NO_DHCP"
	Portal       Code = "PORTAL"
	Clock        Code = "CLOCK"
	VPNBroken    Code = "VPN_BROKEN"
	ProxyCode    Code = "PROXY"
	ProxyPACCode Code = "PROXY_PAC"
	ISP          Code = "ISP"
	RouterOrISP  Code = "ROUTER_OR_ISP"
	OrgNetwork   Code = "ORG_NETWORK"
	DNSCode      Code = "DNS"
	TLSIntercept Code = "TLS_INTERCEPT"
	Filtered     Code = "FILTERED"
	SiteCode     Code = "SITE"
	Unstable     Code = "UNSTABLE"
	Unknown      Code = "UNKNOWN"
)

// ExitCode：0 正常、1 找到問題、2 無法判斷
func (c Code) ExitCode() int {
	switch c {
	case OK:
		return 0
	case Unknown, ProxyPACCode:
		return 2
	}
	return 1
}

type Light struct {
	Name     string   `json:"name"`
	Status   Status   `json:"status"`
	Summary  string   `json:"summary"`
	Evidence []string `json:"evidence,omitempty"`
}

type Verdict struct {
	Code    Code   `json:"code"`
	Text    string `json:"text"`
	Action  string `json:"action"`
	Contact string `json:"contact,omitempty"`
	Org     string `json:"org,omitempty"`
}

type Report struct {
	Lights  []Light `json:"lights"`
	Verdict Verdict `json:"verdict"`
}

// verdictRow：一個結論的全部文字。Egress／Sites 是該結論下「對外連線」黃燈與「網站連線」紅燈的說明，空字串用預設
type verdictRow struct {
	As            Code // 非空時輸出此結論碼（變體列用）
	Text, Action  string
	Egress, Sites string
}

// 內部變體鍵：同一結論碼在特定情境下的說法
const (
	dnsVPN      Code = "DNS_VPN"
	dnsNoServer Code = "DNS_NO_SERVER"
	dnsRouter   Code = "DNS_ROUTER"
	dnsManual   Code = "DNS_MANUAL"
	ispHotspot  Code = "ISP_HOTSPOT"
	ispOrg      Code = "ISP_ORG"
	noGateway   Code = "NO_GATEWAY"
)

// 預設（家用）說法；SITE 的 %s 為失敗網站名稱
var verdicts = map[Code]verdictRow{
	OK:           {Text: "網路正常。", Action: "如果某個 App 還是不能用，可能是該服務本身異常，請稍後再試。"},
	NoLink:       {Text: "這台電腦沒有連上任何網路。", Action: "確認 Wi-Fi 已開啟並連上，或網路線有插好。"},
	NoDHCP:       {Text: "電腦有連上網路，但沒有從路由器拿到位址。", Action: "將路由器拔電 30 秒再插回，等 2 分鐘後再執行一次。"},
	Portal:       {Text: "這個 Wi-Fi 需要先登入（飯店、咖啡廳、機場常見）。", Action: "打開瀏覽器，在網址列輸入 neverssl.com 後按 Enter，完成登入後再執行一次。", Egress: "被導向登入頁面", Sites: "被登入頁面攔截"},
	Clock:        {Text: "電腦的日期或時間不正確，導致加密連線失敗。", Action: "打開電腦的「日期與時間」設定，開啟「自動設定時間」，再執行一次。", Sites: "憑證驗證失敗（時間不正確）"},
	VPNBroken:    {Text: "VPN 已連線但不通，流量卡在 VPN。", Action: "先中斷 VPN 再執行一次；工作需要 VPN 請聯絡公司 IT。"},
	ProxyCode:    {Text: "這台電腦設定了代理伺服器，但透過它連不出去。", Action: "公司電腦請聯絡 IT；家用電腦請在電腦的網路設定中關閉「代理伺服器」，再執行一次。", Sites: "透過代理伺服器連不上"},
	ProxyPACCode: {Text: "這台電腦使用「自動代理設定（PAC）」，直接連線也不通，無法確定是代理還是線路的問題。", Action: "公司電腦請聯絡 IT；家用電腦請在電腦的網路設定中關閉「自動代理設定」再執行一次，仍不通請聯絡網路業者。", Sites: "直接連線也連不上"},
	ISP:          {Text: "路由器正常，但從路由器出去的線路不通。", Action: "將數據機拔電 30 秒再插回；仍不行請聯絡網路業者（如中華電信）報修。"},
	RouterOrISP:  {Text: "問題在路由器或電信線路。", Action: "將路由器和數據機拔電 30 秒再插回；仍不行請聯絡網路業者（如中華電信）。"},
	OrgNetwork:   {Text: "單位設定的網路節點都沒有回應，問題可能在路由器、單位內部網路或出口設備。", Action: "請聯絡單位資訊人員，並提供這個畫面的內容。"},
	DNSCode:      {Text: "線路是通的，但「查網址」的服務（DNS）故障。", Action: "重開路由器；仍不行請聯絡網路業者（如中華電信）。"},
	TLSIntercept: {Text: "加密連線被攔截，常見原因是防毒軟體或公司資安設備。", Action: "暫時關閉防毒軟體的「HTTPS 掃描」再試；公司電腦請聯絡 IT。", Sites: "加密連線被攔截"},
	Filtered:     {Text: "網路是通的，但網站連線被擋住。", Action: "這個網路可能有過濾或防火牆，請聯絡網路管理者（公司 IT 或場地人員）。"},
	SiteCode:     {Text: "你的網路正常，是「%s」本身異常。", Action: "請稍後再試，或聯絡該網站客服。"},
	Unstable:     {Egress: "連線時好時壞", Text: "網路時通時不通，部分連線會中斷或逾時。", Action: "將路由器與數據機拔電 30 秒再插回；使用 Wi-Fi 請靠近路由器再試。仍不行請聯絡網路業者，並說明「網路時好時壞」。"},
	Unknown:      {Text: "證據不足，無法判斷問題在哪。", Action: "重開路由器後再執行一次；仍不行請把這個畫面截圖給協助你的人。"},
	dnsVPN:       {As: DNSCode, Text: "線路是通的，但「查網址」的服務（DNS）故障。目前經由 VPN，DNS 通常由公司提供。", Action: "請聯絡公司 IT 檢查 VPN 的 DNS 設定；沒有在用公司 VPN 的話，先中斷 VPN 再執行一次。"},
	dnsNoServer:  {As: DNSCode, Text: "電腦沒有拿到查網址的設定（DNS 伺服器）。", Action: "將路由器拔電 30 秒再插回，等 2 分鐘後再執行一次；手動設定過網路的電腦，請把 DNS 改回「自動取得」。"},
	dnsRouter:    {As: DNSCode, Text: "路由器負責的查網址功能（DNS）沒有正常回應，可能是路由器或電信業者的 DNS 故障。", Action: "將路由器拔電 30 秒再插回；仍不行請聯絡網路業者（如中華電信）。"},
	dnsManual:    {As: DNSCode, Text: "這台電腦設定的公共 DNS（例如 8.8.8.8）在這個網路查不到網址。", Action: "如果是自己手動設定的，請到網路設定把 DNS 改回「自動取得」再試；公司電腦請聯絡 IT。"},
	ispHotspot:   {As: ISP, Text: "手機熱點有連上，但手機本身沒有網路。", Action: "確認手機的行動數據已開啟、有訊號且流量沒有用完；或改用其他網路。"},
	ispOrg:       {As: ISP, Text: "單位網路有節點回應，但從單位往外的線路不通。", Action: "請聯絡單位資訊人員；單位的對外線路通常由資訊人員向電信業者或 GSN 報修。"},
	noGateway:    {As: NoDHCP, Text: "電腦有位址，但找不到路由器（沒有預設閘道）。", Action: "將路由器拔電 30 秒再插回，等 2 分鐘後再執行一次；如果這台電腦的 IP 是手動設定的，請確認有填寫「路由器」（預設閘道）。"},
}

func isIPv4(s string) bool { return net.ParseIP(s).To4() != nil }

func anyOK(ps []Probe) bool { return slices.ContainsFunc(ps, func(p Probe) bool { return p.OK }) }

// allEqual：gw 非空且每個 server 都等於 gw（IP 比較，容許寫法差異）
func allEqual(servers []string, gw string) bool {
	if gw == "" || len(servers) == 0 {
		return false
	}
	g := net.ParseIP(gw)
	if g == nil {
		return false
	}
	return !slices.ContainsFunc(servers, func(s string) bool { return !net.ParseIP(s).Equal(g) })
}

// wellKnownDNS：常見公共 DNS 伺服器（IPv4 與其 IPv6 對應位址）
var wellKnownDNS = []string{
	"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
	"168.95.1.1", "168.95.192.1", "101.101.101.101", "101.102.103.104",
	"208.67.222.222", "208.67.220.220",
	"2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001",
}

// allWellKnownPublic：每個 server 都在常見公共 DNS 清單內
func allWellKnownPublic(servers []string) bool {
	if len(servers) == 0 {
		return false
	}
	known := make([]net.IP, 0, len(wellKnownDNS))
	for _, s := range wellKnownDNS {
		if ip := net.ParseIP(s); ip != nil {
			known = append(known, ip)
		}
	}
	return !slices.ContainsFunc(servers, func(s string) bool {
		ip := net.ParseIP(s)
		if ip == nil {
			return true
		}
		return !slices.ContainsFunc(known, func(k net.IP) bool { return k.Equal(ip) })
	})
}

func healthySite(s Site) bool { return s.OK && s.Status < 500 }

// isDefaultTarget：是否為預設的公開網站（不是公司自訂目標）
func isDefaultTarget(s Site) bool {
	return slices.ContainsFunc(defaultTargets, func(t Target) bool { return t.URL == s.Target })
}

// paren：非空字串加上全形括號
func paren(s string) string {
	if s == "" {
		return ""
	}
	return "（" + s + "）"
}

func decide(f Facts, cfg Config) Report {
	// ---- 彙整事實 ----
	anyDirect := anyOK(f.Direct)
	pubDNSOK := anyOK(f.PublicDNS)
	anyReached, badSites := false, []string{}
	seen := map[string]bool{}
	certErrAny := false                          // 任何網站（含內網）的憑證錯誤
	pubCertBad, pubCertExpired, flaky := 0, 0, 0 // 只算公開網站，且同一網址只算一次
	allNotFound := len(f.Sites) > 0
	for _, s := range f.Sites {
		if s.OK {
			anyReached = true
		}
		if !healthySite(s) {
			badSites = append(badSites, s.Name)
		}
		if s.OK || s.Err != ErrNotFound {
			allNotFound = false
		}
		isCert := s.Err == ErrCertUnknown || s.Err == ErrCertHostname || s.Err == ErrCertExpired
		if isCert {
			certErrAny = true
		}
		if !isDefaultTarget(s) || seen[s.Target] {
			continue
		}
		seen[s.Target] = true
		switch s.Err {
		case ErrCertUnknown, ErrCertHostname:
			pubCertBad++
		case ErrCertExpired:
			pubCertExpired++
		case ErrTimeout, ErrReset:
			flaky++
		}
	}
	certAny := pubCertBad+pubCertExpired > 0
	internetOK := anyDirect || anyReached || pubDNSOK || certAny
	dnsOK := anyOK(f.DNS)
	// DNS 伺服器有回「網址不存在」代表 DNS 服務本身正常
	dnsFail := len(f.DNS) > 0 && !dnsOK && slices.ContainsFunc(f.DNS, func(p Probe) bool { return p.Err != ErrNotFound })
	// 經由代理時由代理伺服器查網址，本機 DNS 不通不影響上網
	dnsViaProxy := dnsFail && f.Local.Proxy.Mode != ProxyNone && anyReached
	hasIP := f.Local.IP != ""
	// 一般 IPv4 網路卻沒有閘道（VPN、IPv6 本來就可能沒有）；讀取失敗時不算
	noRouter := f.Local.Gateway == "" && f.Local.VPN == "" && !f.Local.GatewayUnknown && isIPv4(f.Local.IP)
	skewBad := f.Captive.SkewKnown && f.Captive.Skew.Abs() > 24*time.Hour
	skewGood := f.Captive.SkewKnown && f.Captive.Skew.Abs() <= time.Hour

	// 單位網路檢查點彙整
	orgConfigured := len(f.Checkpoints) > 0 && slices.ContainsFunc(f.Checkpoints, func(c CheckpointResult) bool { return !c.Unknown })
	orgAny := slices.ContainsFunc(f.Checkpoints, func(c CheckpointResult) bool { return c.OK })
	orgOK := orgConfigured && !slices.ContainsFunc(f.Checkpoints, func(c CheckpointResult) bool { return !c.Unknown && !c.OK })

	// ---- 結論（由上往下，第一個符合者勝出）----
	var key Code
	switch {
	case !hasIP:
		key = NoLink
	case (f.Local.APIPA || noRouter) && !internetOK:
		key = NoDHCP
	case f.Captive.Portal && !anyReached:
		key = Portal
	case (skewBad && certErrAny) || (!skewGood && pubCertExpired >= 2):
		key = Clock
	case f.Local.VPN != "" && !internetOK:
		key = VPNBroken
	case len(f.Sites) > 0 && !anyReached && pubCertBad >= 2:
		key = TLSIntercept
	case len(f.Sites) > 0 && f.Local.Proxy.Mode == ProxyPAC && !anyReached:
		key = ProxyPACCode
	case len(f.Sites) > 0 && f.Local.Proxy.Mode != ProxyNone && !anyReached:
		key = ProxyCode
	case orgConfigured && !orgAny && !internetOK:
		key = OrgNetwork
	case !internetOK && f.Gateway.Alive:
		key = ISP
	case !internetOK:
		key = RouterOrISP
	case dnsFail && !dnsViaProxy:
		key = DNSCode
	case allNotFound:
		key = SiteCode
	case len(f.Sites) > 0 && !anyReached:
		key = Filtered
	case anyReached && flaky >= 2:
		key = Unstable
	case anyReached && len(badSites) > 0:
		key = SiteCode
	case len(f.Sites) > 0 && len(badSites) == 0:
		key = OK
	default:
		key = Unknown
	}
	// 情境變體
	switch {
	case key == DNSCode && f.Local.VPN != "":
		key = dnsVPN
	case key == DNSCode && len(f.Local.DNSServers) == 0:
		key = dnsNoServer
	case key == DNSCode && allEqual(f.Local.DNSServers, f.Local.Gateway):
		key = dnsRouter
	case key == DNSCode && allWellKnownPublic(f.Local.DNSServers) && len(f.DNSServers) > 0 && !anyOK(f.DNSServers):
		key = dnsManual
	case (key == ISP || key == RouterOrISP) && f.Local.Kind == "手機網路共享":
		key = ispHotspot
	case (key == ISP || key == RouterOrISP) && orgAny:
		key = ispOrg
	case key == NoDHCP && !f.Local.APIPA:
		key = noGateway
	}

	row := verdicts[key]
	code := cmp.Or(row.As, key)
	v := Verdict{Code: code, Text: row.Text, Action: row.Action}
	if code == SiteCode {
		v.Text = fmt.Sprintf(row.Text, strings.Join(badSites, "、"))
	}
	if code != OK {
		v.Contact = cfg.contactFor(code)
		if v.Contact != "" {
			v.Org = cfg.Org
		}
	}

	// ---- 燈號（有設定檢查點時多一盞「單位網路」）----
	var L []Light
	l0 := lightLocal(f, hasIP)
	L = append(L, l0, lightGateway(f, l0, internetOK, noRouter))
	prev := L[len(L)-1]
	if len(f.Checkpoints) > 0 {
		l := lightOrg(f, prev, orgOK, internetOK)
		L = append(L, l)
		prev = l
	}
	L = append(L, lightEgress(f, prev, internetOK, anyDirect, anyReached, certAny, pubDNSOK, cfg.ReplaceDefaultTargets, row))
	L = append(L, lightDNS(f, L[len(L)-1], dnsFail, dnsOK, dnsViaProxy))
	L = append(L, lightSites(f, L[len(L)-1], anyReached, badSites, row))
	return Report{Lights: L, Verdict: v}
}

// lightNames：依設定回傳燈號名稱（與 decide() 的燈號順序相同）
func lightNames(cfg Config) []string {
	names := []string{"本機網路", "路由器", "對外連線", "網址查詢", "網站連線"}
	if len(cfg.Checkpoints) > 0 {
		names = slices.Insert(names, 2, "單位網路")
	}
	return names
}

func probeEvidence(ps []Probe) []string {
	var ev []string
	for _, p := range ps {
		ev = append(ev, probeLine(p.Target, p))
	}
	return ev
}

func probeLine(label string, p Probe) string {
	s := label + "："
	if p.OK {
		s += fmt.Sprintf("成功 %dms", p.Ms)
	} else {
		s += errText[p.Err]
	}
	return s + paren(p.Note)
}

func lightLocal(f Facts, hasIP bool) Light {
	l := Light{Name: "本機網路"}
	lo := f.Local
	if lo.Iface != "" {
		l.Evidence = append(l.Evidence, fmt.Sprintf("介面：%s（%s）", lo.Iface, lo.Kind))
	}
	if len(lo.DNSServers) > 0 {
		l.Evidence = append(l.Evidence, "DNS 伺服器："+strings.Join(lo.DNSServers, ", "))
	}
	l.Evidence = append(l.Evidence, lo.Notes...)
	switch {
	case !hasIP:
		l.Status, l.Summary = Red, "沒有連上網路（Wi-Fi 未連線或網路線未接）"
	case lo.APIPA:
		l.Status, l.Summary = Yellow, "只有自動位址 "+lo.IP+"（沒拿到正常位址）"
	default:
		l.Status, l.Summary = Green, strings.TrimSpace(lo.Kind+" "+lo.IP)
	}
	return l
}

func lightGateway(f Facts, prev Light, internetOK, noRouter bool) Light {
	l := Light{Name: "路由器"}
	gw := f.Local.Gateway
	if gw != "" {
		var ev string
		if f.Gateway.Alive {
			ev = "路由器位址：" + gw + "，" + f.Gateway.Via + " 有回應"
		} else {
			ev = "路由器位址：" + gw + "，沒有回應"
		}
		l.Evidence = []string{ev + paren(f.Gateway.Note)}
	}
	switch {
	case prev.Status == Red:
		l.Status, l.Summary = Skip, "前一段異常，未檢查"
	case gw == "" && f.Local.GatewayUnknown:
		l.Status, l.Summary = Yellow, "無法取得路由器資訊"
	case gw == "" && internetOK:
		l.Status, l.Summary = Green, "經由 "+f.Local.VPN+" 對外"
		if f.Local.VPN == "" {
			l.Summary = "沒有一般路由器，但可以對外"
		}
	case noRouter:
		l.Status, l.Summary = Red, "找不到路由器"
	case gw == "" && f.Local.VPN != "":
		l.Status, l.Summary = Yellow, "經由 VPN "+f.Local.VPN+"（沒有一般路由器資訊）"
	case gw == "":
		l.Status, l.Summary = Yellow, "IPv6 網路（未檢查路由器）"
	case f.Gateway.Alive:
		l.Status, l.Summary = Green, gw+" 正常"
	case internetOK:
		l.Status, l.Summary = Green, gw+" 正常（不回應測試，但網路可用）"
	default:
		l.Status, l.Summary = Yellow, gw+" 沒有回應（無法確認）"
	}
	return l
}

// lightOrg：「單位網路」燈，只在設定檔有檢查點時出現
func lightOrg(f Facts, prev Light, orgOK, internetOK bool) Light {
	l := Light{Name: "單位網路"}
	var names []string
	ok, n := 0, 0
	for _, c := range f.Checkpoints {
		if c.Unknown {
			l.Evidence = append(l.Evidence, c.Name+"（"+c.Host+"，"+c.Check+"）：無法在這台電腦執行")
			continue
		}
		n++
		if c.OK {
			ok++
			l.Evidence = append(l.Evidence, fmt.Sprintf("%s（%s，%s）：成功 %dms", c.Name, c.Host, c.Check, c.Ms))
		} else {
			names = append(names, c.Name)
			l.Evidence = append(l.Evidence, c.Name+"（"+c.Host+"，"+c.Check+"）："+errText[c.Err])
		}
	}
	switch {
	case prev.Status == Red || prev.Status == Skip:
		l.Status, l.Summary = Skip, "前一段異常，未檢查"
	case n == 0:
		l.Status, l.Summary = Yellow, "這台電腦無法執行設定的檢查"
	case ok == n && orgOK:
		s := "節點有回應"
		if n != 1 {
			s = fmt.Sprintf("%d 個節點都有回應", n)
		}
		l.Status, l.Summary = Green, s
	case ok > 0:
		l.Status = Yellow
		l.Summary = fmt.Sprintf("%d/%d 個節點有回應，「%s」沒有回應", ok, n, strings.Join(names, "、"))
	case ok == 0 && internetOK:
		l.Status, l.Summary = Yellow, "單位網路節點都沒有回應，但可以連到網際網路"
	default:
		l.Status, l.Summary = Red, "單位網路節點都沒有回應"
	}
	return l
}

// routeEvidence：路由追蹤的證據行（只作證據，不影響燈號與結論）
func routeEvidence(f Facts, internetOK bool) []string {
	if f.Route.Target == "" {
		return nil // 探測沒有執行（例如測試或 NoLink）
	}
	if f.Route.Unknown {
		return []string{"路由追蹤：這台電腦無法執行（系統不允許一般權限 ICMP）"}
	}
	if len(f.Route.Hops) == 0 {
		return []string{"路由追蹤（往 " + f.Route.Target + "）：沒有任何節點回應"}
	}
	var items []string
	prevTTL := 0
	for _, h := range f.Route.Hops {
		if prevTTL > 0 && h.TTL > prevTTL+1 {
			items = append(items, "*") // 兩站之間有沒有回應的站
		}
		prevTTL = h.TTL
		items = append(items, fmt.Sprintf("%d. %s%s", h.TTL, h.IP, hopLabel(f, h)))
	}
	ev := []string{"路由追蹤（往 " + f.Route.Target + "）：" + strings.Join(items, " → ")}
	if last := f.Route.Hops[len(f.Route.Hops)-1]; !internetOK && !last.Reached {
		ev = append(ev, fmt.Sprintf("最後回應的節點：第 %d 站 %s%s", last.TTL, last.IP, hopLabel(f, last)))
	}
	return ev
}

// hopLabel：一站的標註（路由器、單位網路檢查點、抵達），可累加以「、」連接
func hopLabel(f Facts, h Hop) string {
	var labels []string
	if h.IP == f.Local.Gateway {
		labels = append(labels, "路由器")
	}
	for _, c := range f.Checkpoints {
		if c.Host == h.IP {
			labels = append(labels, c.Name)
		}
	}
	if h.Reached {
		labels = append(labels, "抵達")
	}
	if len(labels) == 0 {
		return ""
	}
	return "（" + strings.Join(labels, "、") + "）"
}

func lightEgress(f Facts, prev Light, internetOK, anyDirect, anyReached, certAny, pubDNSOK, onlyCustom bool, row verdictRow) Light {
	l := Light{Name: "對外連線", Evidence: probeEvidence(f.Direct)}
	var notes []string
	if f.Local.VPN != "" {
		notes = append(notes, "經由 VPN "+f.Local.VPN)
		l.Evidence = append(l.Evidence, "VPN 介面："+f.Local.VPN)
	}
	if f.Local.Proxy.Mode != ProxyNone {
		if f.Local.Proxy.Mode == ProxyPAC {
			notes = append(notes, "使用自動代理設定")
		} else {
			notes = append(notes, "經由代理")
		}
		l.Evidence = append(l.Evidence, fmt.Sprintf("代理伺服器（%s）：%s", f.Local.Proxy.Mode, f.Local.Proxy.Addr))
	}
	note := paren(strings.Join(notes, "、"))
	switch {
	case row.Egress != "":
		l.Status, l.Summary = Yellow, row.Egress
	case internetOK && !anyDirect && !anyReached && !certAny:
		l.Status, l.Summary = Yellow, "只有部分連線能對外"+note
		l.Evidence = append(l.Evidence, "直連 IP 與網站都失敗，但公共 DNS 查詢成功：線路可對外，連線可能被過濾")
	case internetOK:
		l.Status, l.Summary = Green, "可連到網際網路"+note
		if !anyDirect && len(f.Direct) > 0 {
			l.Evidence = append(l.Evidence, "直連 IP 失敗但網站可連（可能為 IPv6／NAT64 或公司防火牆），以網站結果為準")
		}
	case prev.Status == Red || prev.Status == Skip:
		l.Status, l.Summary = Skip, "前一段異常，未檢查"
	default:
		l.Status, l.Summary = Red, "連不到網際網路"+note
	}
	if l.Status == Green && onlyCustom && !anyDirect && !pubDNSOK {
		l.Status, l.Summary = Yellow, "只確認了自訂網站，未確認網際網路"
	}
	// 對外 IP 與分流（只作為證據，不影響判斷）
	if len(f.PublicIP) > 0 {
		first := f.PublicIP[0]
		line := "對外 IP：" + first.IP
		if first.Loc != "" {
			line += "（" + first.Loc + "）"
		}
		switch {
		case (f.Local.Proxy.Mode == ProxyExplicit || f.Local.Proxy.Mode == ProxyEnv) && !bypassed(first.Host, f.Local.Proxy.Bypass):
			line += "，經由代理（顯示的是代理的出口）"
		case f.Local.Proxy.Mode == ProxyPAC:
			line += "，使用自動代理設定（無法確定是否經由代理）"
		case f.Local.VPN != "":
			line += "，經由 VPN"
		}
		l.Evidence = append(l.Evidence, line)
		for _, p := range f.PublicIP[1:] {
			if p.IP == first.IP {
				l.Evidence = append(l.Evidence, "連往"+p.Name+"時相同")
			} else {
				l.Evidence = append(l.Evidence, "連往"+p.Name+"時改用 "+p.IP+"（可能依目的地分流）")
			}
		}
	}
	l.Evidence = append(l.Evidence, routeEvidence(f, internetOK)...)
	return l
}

func lightDNS(f Facts, prev Light, dnsFail, dnsOK, viaProxy bool) Light {
	l := Light{Name: "網址查詢", Evidence: probeEvidence(f.DNS)}
	for _, p := range f.PublicDNS {
		l.Evidence = append(l.Evidence, probeLine("公共 DNS "+p.Target, p))
	}
	for _, p := range f.DNSServers {
		l.Evidence = append(l.Evidence, probeLine("DNS 伺服器 "+p.Target, p))
	}
	switch {
	case !dnsFail && len(f.DNS) > 0:
		l.Status = Green
		if dnsOK {
			l.Summary = "正常"
		} else {
			l.Summary = "正常（查詢的網址不存在）"
		}
	case viaProxy:
		l.Status, l.Summary = Green, "由代理伺服器代查"
	case prev.Status == Red || prev.Status == Skip:
		l.Status, l.Summary = Skip, "前一段異常，未檢查"
	case len(f.DNS) == 0:
		l.Status, l.Summary = Yellow, "沒有可查詢的網址"
	default:
		l.Status, l.Summary = Red, "無法查詢網址（DNS 故障）"
		if anyOK(f.PublicDNS) {
			l.Evidence = append(l.Evidence, "公共 DNS 可用：可把 DNS 改成 8.8.8.8 暫時解決")
		}
	}
	return l
}

func lightSites(f Facts, prev Light, anyReached bool, bad []string, row verdictRow) Light {
	l := Light{Name: "網站連線"}
	for _, s := range f.Sites {
		line := probeLine(s.Name+" "+s.Target, s.Probe)
		if s.OK {
			line += fmt.Sprintf(" HTTP %d", s.Status)
		}
		l.Evidence = append(l.Evidence, line)
	}
	if f.Captive.Checked {
		c := "登入頁面檢查：沒有被導向"
		if f.Captive.Portal {
			c = "登入頁面檢查：被導向"
		}
		c += paren(f.Captive.Note)
		if f.Captive.SkewKnown {
			c += fmt.Sprintf("；本機時間差 %s", f.Captive.Skew.Round(time.Second))
		}
		l.Evidence = append(l.Evidence, c)
	}
	n := len(f.Sites)
	switch {
	case !anyReached && prev.Status == Skip:
		l.Status, l.Summary = Skip, "前一段異常，未檢查"
	case !anyReached && prev.Status == Red:
		l.Status, l.Summary = Skip, "需要先能查網址"
	case n == 0:
		l.Status, l.Summary = Yellow, "沒有可測試的網站"
	case len(bad) == 0:
		l.Status, l.Summary = Green, fmt.Sprintf("%d/%d 個網站正常", n, n)
	case anyReached:
		l.Status = Yellow
		l.Summary = fmt.Sprintf("%d/%d 個網站正常，「%s」異常", n-len(bad), n, strings.Join(bad, "、"))
	default:
		l.Status, l.Summary = Red, cmp.Or(row.Sites, "連不上任何網站")
	}
	return l
}
