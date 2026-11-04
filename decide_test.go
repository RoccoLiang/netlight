package main

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// 健康網路的基準 Facts，各案例在此之上修改
func healthy() Facts {
	return Facts{
		Local: Local{
			OS: "macOS", Iface: "en0", Kind: "Wi-Fi", IP: "192.168.1.23",
			Gateway: "192.168.1.1", DNSServers: []string{"192.168.1.1"},
		},
		Gateway: GatewayResult{Alive: true, Via: "ICMP"},
		Direct: []Probe{
			{Target: "1.1.1.1:443", OK: true},
			{Target: "8.8.8.8:443", OK: true},
		},
		DNS: []Probe{
			{Target: "www.google.com", OK: true},
			{Target: "www.cloudflare.com", OK: true},
		},
		PublicDNS: []Probe{{Target: "8.8.8.8", OK: true}},
		Sites: []Site{
			{Name: "Google", Probe: Probe{Target: "https://www.google.com", OK: true}, Status: 200},
			{Name: "Cloudflare", Probe: Probe{Target: "https://www.cloudflare.com", OK: true}, Status: 200},
			{Name: "Microsoft", Probe: Probe{Target: "https://www.microsoft.com", OK: true}, Status: 200},
			{Name: "政府入口網", Probe: Probe{Target: "https://www.gov.tw", OK: true}, Status: 200},
		},
	}
}

func failAll(ps []Probe, e ErrClass) []Probe {
	out := make([]Probe, len(ps))
	for i, p := range ps {
		out[i] = Probe{Target: p.Target, Err: e}
	}
	return out
}

func failSites(ss []Site, e ErrClass) []Site {
	out := make([]Site, len(ss))
	for i, s := range ss {
		out[i] = Site{Name: s.Name, Probe: Probe{Target: s.Target, Err: e}}
	}
	return out
}

func TestDecide(t *testing.T) {
	cases := []struct {
		name   string
		mod    func(f *Facts)
		code   Code
		lights [5]Status // 本機、路由器、對外、網址、網站（沒有檢查點時共 5 盞）
	}{
		{"全部正常", func(f *Facts) {}, OK, [5]Status{Green, Green, Green, Green, Green}},

		{"沒有網路介面", func(f *Facts) {
			*f = Facts{Local: Local{OS: "macOS"}, NoLink: true}
		}, NoLink, [5]Status{Red, Skip, Skip, Skip, Skip}},

		{"只有 169.254 自動位址", func(f *Facts) {
			f.Local.IP, f.Local.APIPA, f.Local.Gateway = "169.254.10.2", true, ""
			f.Gateway = GatewayResult{}
			f.Direct = failAll(f.Direct, ErrUnreachable)
			f.DNS = failAll(f.DNS, ErrTimeout)
			f.PublicDNS = failAll(f.PublicDNS, ErrUnreachable)
			f.Sites = failSites(f.Sites, ErrUnreachable)
		}, NoDHCP, [5]Status{Yellow, Red, Skip, Skip, Skip}},

		{"有 IP 但沒有閘道", func(f *Facts) {
			f.Local.Gateway = ""
			f.Gateway = GatewayResult{}
			f.Direct = failAll(f.Direct, ErrUnreachable)
			f.DNS = failAll(f.DNS, ErrTimeout)
			f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
			f.Sites = failSites(f.Sites, ErrUnreachable)
		}, NoDHCP, [5]Status{Green, Red, Skip, Skip, Skip}},

		{"讀不到閘道資訊且出不去 → 不判 NO_DHCP", func(f *Facts) {
			f.Local.Gateway = ""
			f.Local.GatewayUnknown = true
			f.Gateway = GatewayResult{}
			f.Direct = failAll(f.Direct, ErrTimeout)
			f.DNS = failAll(f.DNS, ErrTimeout)
			f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
			f.Sites = failSites(f.Sites, ErrTimeout)
		}, RouterOrISP, [5]Status{Green, Yellow, Red, Skip, Skip}},

		{"路由器不回 ping 但網路正常，路由器燈仍為綠", func(f *Facts) {
			f.Gateway = GatewayResult{}
		}, OK, [5]Status{Green, Green, Green, Green, Green}},

		{"Captive portal", func(f *Facts) {
			f.Captive = Captive{Checked: true, Portal: true}
			f.Sites = failSites(f.Sites, ErrCertHostname)
		}, Portal, [5]Status{Green, Green, Yellow, Green, Red}},

		{"公司 HTTP 擋頁但 HTTPS 正常，不是 portal", func(f *Facts) {
			f.Captive = Captive{Checked: true, Portal: true}
		}, OK, [5]Status{Green, Green, Green, Green, Green}},

		{"憑證過期兩站以上 → 時間不正確", func(f *Facts) {
			f.Sites = failSites(f.Sites, ErrCertExpired)
		}, Clock, [5]Status{Green, Green, Green, Green, Red}},

		{"Date 標頭差超過一天且網站失敗 → 時間不正確", func(f *Facts) {
			f.Captive = Captive{Checked: true, Skew: 3 * 24 * time.Hour, SkewKnown: true}
			f.Sites = failSites(f.Sites, ErrCertUnknown)
		}, Clock, [5]Status{Green, Green, Green, Green, Red}},

		{"VPN 全通道斷線", func(f *Facts) {
			f.Local.VPN = "utun4"
			f.Direct = failAll(f.Direct, ErrTimeout)
			f.Sites = failSites(f.Sites, ErrTimeout)
			f.DNS = failAll(f.DNS, ErrTimeout)
			f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
		}, VPNBroken, [5]Status{Green, Green, Red, Skip, Skip}},
		{"代理伺服器失效", func(f *Facts) {
			f.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128"}
			f.Direct = failAll(f.Direct, ErrTimeout)
			f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
			f.Sites = failSites(f.Sites, ErrRefused)
		}, ProxyCode, [5]Status{Green, Green, Red, Green, Red}},

		{"PAC 環境直連失敗", func(f *Facts) {
			f.Local.Proxy = Proxy{Mode: ProxyPAC, Addr: "http://wpad/wpad.dat"}
			f.Direct = failAll(f.Direct, ErrTimeout)
			f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
			f.Sites = failSites(f.Sites, ErrTimeout)
		}, ProxyPACCode, [5]Status{Green, Green, Red, Green, Red}},

		{"路由器有回應但出不去 → ISP", func(f *Facts) {
			f.Direct = failAll(f.Direct, ErrTimeout)
			f.DNS = failAll(f.DNS, ErrTimeout)
			f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
			f.Sites = failSites(f.Sites, ErrTimeout)
		}, ISP, [5]Status{Green, Green, Red, Skip, Skip}},

		{"路由器沒回應也出不去 → 路由器或業者", func(f *Facts) {
			f.Gateway = GatewayResult{}
			f.Direct = failAll(f.Direct, ErrTimeout)
			f.DNS = failAll(f.DNS, ErrTimeout)
			f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
			f.Sites = failSites(f.Sites, ErrTimeout)
		}, RouterOrISP, [5]Status{Green, Yellow, Red, Skip, Skip}},

		{"DNS 故障", func(f *Facts) {
			f.DNS = failAll(f.DNS, ErrDNS)
			f.Sites = failSites(f.Sites, ErrDNS)
		}, DNSCode, [5]Status{Green, Green, Green, Red, Skip}},

		{"系統 DNS 正常、公共 DNS 被擋 → 正常", func(f *Facts) {
			f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
		}, OK, [5]Status{Green, Green, Green, Green, Green}},

		{"NAT64：直連 IP 失敗但網站正常 → 正常", func(f *Facts) {
			f.Direct = failAll(f.Direct, ErrUnreachable)
		}, OK, [5]Status{Green, Green, Green, Green, Green}},

		{"HTTPS 被攔截（未知憑證）", func(f *Facts) {
			f.Sites = failSites(f.Sites, ErrCertUnknown)
		}, TLSIntercept, [5]Status{Green, Green, Green, Green, Red}},

		{"HTTPS 全部逾時 → 被過濾", func(f *Facts) {
			f.Sites = failSites(f.Sites, ErrTimeout)
		}, Filtered, [5]Status{Green, Green, Green, Green, Red}},

		{"單一網站故障", func(f *Facts) {
			f.Sites[3] = Site{Name: "政府入口網", Probe: Probe{Target: "https://www.gov.tw", Err: ErrTimeout}}
		}, SiteCode, [5]Status{Green, Green, Green, Green, Yellow}},

		{"單一網站回 5xx 也算網站問題", func(f *Facts) {
			f.Sites[1].Status = 503
		}, SiteCode, [5]Status{Green, Green, Green, Green, Yellow}},

		{"4xx/429 視為可連線", func(f *Facts) {
			f.Sites[0].Status = 429
			f.Sites[2].Status = 403
		}, OK, [5]Status{Green, Green, Green, Green, Green}},

		{"經由 VPN 且正常，沒有一般閘道", func(f *Facts) {
			f.Local.VPN, f.Local.Gateway = "wg0", ""
			f.Gateway = GatewayResult{}
		}, OK, [5]Status{Green, Green, Green, Green, Green}},

		{"經由代理可上網但本機 DNS 不通 → 正常", func(f *Facts) {
			f.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128"}
			f.DNS = failAll(f.DNS, ErrTimeout)
		}, OK, [5]Status{Green, Green, Green, Green, Green}},

		{"全通道 VPN 沒有閘道位址且不通 → VPN 異常", func(f *Facts) {
			f.Local.VPN, f.Local.Gateway = "utun3", ""
			f.Gateway = GatewayResult{}
			f.Direct = failAll(f.Direct, ErrTimeout)
			f.DNS = failAll(f.DNS, ErrTimeout)
			f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
			f.Sites = failSites(f.Sites, ErrTimeout)
		}, VPNBroken, [5]Status{Green, Yellow, Red, Skip, Skip}},

		{"只有 IPv6 且不通 → 不是 NO_DHCP", func(f *Facts) {
			f.Local.IP, f.Local.Gateway = "2001:db8::5", ""
			f.Gateway = GatewayResult{}
			f.Direct = failAll(f.Direct, ErrUnreachable)
			f.DNS = failAll(f.DNS, ErrTimeout)
			f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
			f.Sites = failSites(f.Sites, ErrTimeout)
		}, RouterOrISP, [5]Status{Green, Yellow, Red, Skip, Skip}},

		{"時間差大但只是單一網站 503 → 網站問題", func(f *Facts) {
			f.Captive = Captive{Checked: true, Skew: 48 * time.Hour, SkewKnown: true}
			f.Sites[3].Status = 503
		}, SiteCode, [5]Status{Green, Green, Green, Green, Yellow}},

		{"沒有任何網站目標 → 無法判斷", func(f *Facts) {
			f.Sites = nil
			f.DNS = nil
		}, Unknown, [5]Status{Green, Green, Green, Yellow, Yellow}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := healthy()
			c.mod(&f)
			r := decide(f, Config{})
			if r.Verdict.Code != c.code {
				t.Errorf("結論 = %s，預期 %s", r.Verdict.Code, c.code)
			}
			for i, want := range c.lights {
				if got := r.Lights[i].Status; got != want {
					t.Errorf("燈 %d（%s）= %v，預期 %v（%s）", i+1, r.Lights[i].Name, got, want, r.Lights[i].Summary)
				}
			}
			if r.Verdict.Text == "" || r.Verdict.Action == "" {
				t.Errorf("結論文字或建議為空：%+v", r.Verdict)
			}
		})
	}
}

func TestDecideNoGatewayWording(t *testing.T) {
	// 手動 IP 沒填閘道（讀取成功但沒有預設路由）：NoDHCP 專屬說法
	f := healthy()
	f.Local.Gateway = ""
	f.Gateway = GatewayResult{}
	f.Direct = failAll(f.Direct, ErrUnreachable)
	f.DNS = failAll(f.DNS, ErrTimeout)
	f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
	f.Sites = failSites(f.Sites, ErrUnreachable)
	r := decide(f, Config{})
	if r.Verdict.Code != NoDHCP || !strings.Contains(r.Verdict.Text, "找不到路由器") {
		t.Errorf("結論 = %s（%q），預期 NoDHCP 且文字含「找不到路由器」", r.Verdict.Code, r.Verdict.Text)
	}
	// APIPA 情境仍用原本「沒有從路由器拿到位址」
	f = healthy()
	f.Local.IP, f.Local.APIPA, f.Local.Gateway = "169.254.10.2", true, ""
	f.Gateway = GatewayResult{}
	f.Direct = failAll(f.Direct, ErrUnreachable)
	f.DNS = failAll(f.DNS, ErrTimeout)
	f.PublicDNS = failAll(f.PublicDNS, ErrUnreachable)
	f.Sites = failSites(f.Sites, ErrUnreachable)
	r = decide(f, Config{})
	if r.Verdict.Code != NoDHCP || !strings.Contains(r.Verdict.Text, "沒有從路由器拿到位址") {
		t.Errorf("APIPA 結論 = %s（%q），預期 NoDHCP 且文字含「沒有從路由器拿到位址」", r.Verdict.Code, r.Verdict.Text)
	}
}

func TestDecideSiteNamesInSummary(t *testing.T) {
	f := healthy()
	f.Sites[3].Probe = Probe{Target: "https://www.gov.tw", Err: ErrTimeout}
	r := decide(f, Config{})
	if !strings.Contains(r.Lights[4].Summary, "3/4") || !strings.Contains(r.Lights[4].Summary, "政府入口網") {
		t.Errorf("網站燈摘要 = %q", r.Lights[4].Summary)
	}
	if !strings.Contains(r.Verdict.Text, "政府入口網") {
		t.Errorf("結論 = %q", r.Verdict.Text)
	}
}

func TestDecideContact(t *testing.T) {
	cfg := Config{Contact: map[string]string{"default": "IT 分機 1234", "isp": "網管組 分機 99"}}

	f := healthy()
	f.DNS = failAll(f.DNS, ErrDNS)
	f.Sites = failSites(f.Sites, ErrDNS)
	if got := decide(f, cfg).Verdict.Contact; got != "IT 分機 1234" {
		t.Errorf("DNS 窗口 = %q，預期使用 default", got)
	}

	f = healthy()
	f.Direct = failAll(f.Direct, ErrTimeout)
	f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
	f.Sites = failSites(f.Sites, ErrTimeout)
	if got := decide(f, cfg).Verdict.Contact; got != "網管組 分機 99" {
		t.Errorf("ISP 窗口 = %q，預期使用 isp", got)
	}

	if got := decide(healthy(), cfg).Verdict.Contact; got != "" {
		t.Errorf("正常時不應顯示窗口，得到 %q", got)
	}
	if got := decide(f, Config{}).Verdict.Contact; got != "" {
		t.Errorf("沒有設定檔時不應有窗口，得到 %q", got)
	}
}

func TestDecideRouteNotes(t *testing.T) {
	f := healthy()
	f.Local.VPN = "utun4"
	if s := decide(f, Config{}).Lights[2].Summary; !strings.Contains(s, "VPN") {
		t.Errorf("對外連線摘要應註明 VPN：%q", s)
	}
	f = healthy()
	f.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128"}
	if s := decide(f, Config{}).Lights[2].Summary; !strings.Contains(s, "代理") {
		t.Errorf("對外連線摘要應註明代理：%q", s)
	}
}

func TestDecidePACWording(t *testing.T) {
	f := healthy()
	f.Local.Proxy = Proxy{Mode: ProxyPAC, Addr: "http://wpad/wpad.dat"}
	f.Direct = failAll(f.Direct, ErrTimeout)
	f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
	f.Sites = failSites(f.Sites, ErrTimeout)
	v := decide(f, Config{}).Verdict
	if v.Code != ProxyPACCode || !strings.Contains(v.Text, "PAC") || !strings.Contains(v.Action, "網路業者") {
		t.Errorf("PAC 結論應說明無法確定並提到業者：%+v", v)
	}
}

func TestLightNames(t *testing.T) {
	want := []string{"本機網路", "路由器", "對外連線", "網址查詢", "網站連線"}
	if got := lightNames(Config{}); !slices.Equal(got, want) {
		t.Errorf("lightNames(Config{}) = %v，應為 %v", got, want)
	}

	cfg := Config{Checkpoints: []Checkpoint{{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443"}}}
	got := lightNames(cfg)
	if len(got) != 6 || got[2] != "單位網路" {
		t.Errorf("有一個檢查點時 lightNames = %v，應為 6 盞且第 3 盞為「單位網路」", got)
	}

	// 一致性：decide() 各盞燈的名稱依序等於 lightNames(cfg)
	f := healthy()
	rep := decide(f, Config{})
	if len(rep.Lights) != len(want) {
		t.Fatalf("沒有檢查點時燈數 = %d，應為 %d", len(rep.Lights), len(want))
	}
	for i, l := range rep.Lights {
		if l.Name != want[i] {
			t.Errorf("沒有檢查點時燈 %d 名稱 = %q，應為 %q", i+1, l.Name, want[i])
		}
	}
	f.Checkpoints = []CheckpointResult{{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", OK: true}}
	rep = decide(f, cfg)
	if len(rep.Lights) != len(got) {
		t.Fatalf("有一個檢查點時燈數 = %d，應為 %d", len(rep.Lights), len(got))
	}
	for i, l := range rep.Lights {
		if l.Name != got[i] {
			t.Errorf("有一個檢查點時燈 %d 名稱 = %q，應為 %q", i+1, l.Name, got[i])
		}
	}
}

func TestExitCode(t *testing.T) {
	for code, want := range map[Code]int{
		OK: 0, NoLink: 1, NoDHCP: 1, Portal: 1, Clock: 1, VPNBroken: 1, ProxyCode: 1,
		ISP: 1, RouterOrISP: 1, OrgNetwork: 1, DNSCode: 1, TLSIntercept: 1, Filtered: 1, SiteCode: 1,
		Unstable: 1, Unknown: 2, ProxyPACCode: 2,
	} {
		if got := code.ExitCode(); got != want {
			t.Errorf("%s exit = %d，預期 %d", code, got, want)
		}
	}
}

func TestRouteEvidence(t *testing.T) {
	base := func(route RouteResult) Facts {
		f := healthy()
		f.Checkpoints = []CheckpointResult{{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", OK: true}}
		f.Route = route
		return f
	}
	cases := []struct {
		name       string
		f          Facts
		internetOK bool
		want       []string
	}{
		{"探測沒有執行（Target 為空）", healthy(), true, nil},
		{"系統不允許一般權限 ICMP", base(RouteResult{Target: "1.1.1.1", Unknown: true}), true,
			[]string{"路由追蹤：這台電腦無法執行（系統不允許一般權限 ICMP）"}},
		{"沒有任何節點回應", base(RouteResult{Target: "1.1.1.1"}), false,
			[]string{"路由追蹤（往 1.1.1.1）：沒有任何節點回應"}},
		{"正常抵達（路由器、檢查點標註與不連續 TTL）", base(RouteResult{Target: "1.1.1.1", Hops: []Hop{
			{TTL: 1, IP: "192.168.1.1", Ms: 2},
			{TTL: 3, IP: "10.1.0.1", Ms: 5},
			{TTL: 4, IP: "203.0.113.9", Ms: 8},
			{TTL: 5, IP: "1.1.1.1", Ms: 10, Reached: true},
		}}), true, []string{
			"路由追蹤（往 1.1.1.1）：1. 192.168.1.1（路由器） → * → 3. 10.1.0.1（單位防火牆） → 4. 203.0.113.9 → 5. 1.1.1.1（抵達）",
		}},
		{"不通時指出最後回應的節點", base(RouteResult{Target: "1.1.1.1", Hops: []Hop{
			{TTL: 1, IP: "192.168.1.1", Ms: 2},
			{TTL: 3, IP: "10.1.0.1", Ms: 5},
		}}), false, []string{
			"路由追蹤（往 1.1.1.1）：1. 192.168.1.1（路由器） → * → 3. 10.1.0.1（單位防火牆）",
			"最後回應的節點：第 3 站 10.1.0.1（單位防火牆）",
		}},
		{"不通但已抵達目標時不指出最後節點", base(RouteResult{Target: "1.1.1.1", Hops: []Hop{
			{TTL: 1, IP: "192.168.1.1", Ms: 2},
			{TTL: 2, IP: "1.1.1.1", Ms: 6, Reached: true},
		}}), false, []string{
			"路由追蹤（往 1.1.1.1）：1. 192.168.1.1（路由器） → 2. 1.1.1.1（抵達）",
		}},
		{"路由器同時是檢查點時標註累加", func() Facts {
			f := base(RouteResult{Target: "1.1.1.1", Hops: []Hop{
				{TTL: 1, IP: "192.168.1.1", Ms: 2},
				{TTL: 2, IP: "1.1.1.1", Ms: 6, Reached: true},
			}})
			f.Checkpoints = append(f.Checkpoints, CheckpointResult{Name: "單位交換器", Host: "192.168.1.1", Check: "icmp", OK: true})
			return f
		}(), true, []string{
			"路由追蹤（往 1.1.1.1）：1. 192.168.1.1（路由器、單位交換器） → 2. 1.1.1.1（抵達）",
		}},
		{"目的地同時是檢查點時標註累加", func() Facts {
			f := base(RouteResult{Target: "1.1.1.1", Hops: []Hop{
				{TTL: 1, IP: "192.168.1.1", Ms: 2},
				{TTL: 2, IP: "1.1.1.1", Ms: 6, Reached: true},
			}})
			f.Checkpoints = append(f.Checkpoints, CheckpointResult{Name: "外點閘道", Host: "1.1.1.1", Check: "icmp", OK: true})
			return f
		}(), true, []string{
			"路由追蹤（往 1.1.1.1）：1. 192.168.1.1（路由器） → 2. 1.1.1.1（外點閘道、抵達）",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := routeEvidence(c.f, c.internetOK); !slices.Equal(got, c.want) {
				t.Errorf("routeEvidence = %q，預期 %q", got, c.want)
			}
		})
	}
}
