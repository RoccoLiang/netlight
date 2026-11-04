package main

import (
	"strings"
	"testing"
	"time"
)

// 待辦清單（backlog）編號對應的故障情境：驗證 decide() 的結論碼與指定燈號／文字
func TestDecideScenarios(t *testing.T) {
	cases := []struct {
		name  string
		id    string // backlog 編號
		cfg   Config
		mod   func(f *Facts)
		code  Code
		check func(t *testing.T, r Report)
	}{
		{
			name: "直連被擋＋透明 SSL 攔截",
			id:   "A1",
			mod: func(f *Facts) {
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrCertUnknown)
			},
			code: TLSIntercept,
			check: func(t *testing.T, r Report) {
				if r.Lights[2].Status != Green {
					t.Errorf("對外連線燈 = %v，預期綠燈", r.Lights[2].Status)
				}
			},
		},
		{
			name: "公司代理＋SSL 攔截（CA 未安裝）",
			id:   "A1",
			mod: func(f *Facts) {
				f.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128"}
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrCertUnknown)
			},
			code: TLSIntercept,
		},
		{
			name: "直連被擋、公共 DNS 可查、系統 DNS 故障",
			id:   "A1",
			mod: func(f *Facts) {
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.DNS = failAll(f.DNS, ErrDNS)
				f.Sites = failSites(f.Sites, ErrDNS)
			},
			code: DNSCode,
			check: func(t *testing.T, r Report) {
				if r.Lights[3].Status != Red {
					t.Errorf("網址查詢燈 = %v，預期紅燈", r.Lights[3].Status)
				}
			},
		},
		{
			name: "公司擋 443 且無代理",
			id:   "A1",
			mod: func(f *Facts) {
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrTimeout)
			},
			code: Filtered,
			check: func(t *testing.T, r Report) {
				if r.Lights[2].Status != Yellow || !strings.Contains(r.Lights[2].Summary, "部分") {
					t.Errorf("對外連線燈 = %v（%s），預期黃燈且摘要含「部分」", r.Lights[2].Status, r.Lights[2].Summary)
				}
			},
		},
		{
			name: "真的斷線（回歸保護）",
			id:   "A1",
			mod: func(f *Facts) {
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.DNS = failAll(f.DNS, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrTimeout)
			},
			code: ISP,
		},
		{
			name: "兩站憑證過期但已知時間正確",
			id:   "A3",
			mod: func(f *Facts) {
				f.Sites[0].Probe = Probe{Target: f.Sites[0].Target, Err: ErrCertExpired}
				f.Sites[1].Probe = Probe{Target: f.Sites[1].Target, Err: ErrCertExpired}
				f.Captive = Captive{Checked: true, SkewKnown: true, Skew: 0}
			},
			code: SiteCode,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Verdict.Text, "Google") || !strings.Contains(r.Verdict.Text, "Cloudflare") {
					t.Errorf("結論文字應列出失敗網站：%q", r.Verdict.Text)
				}
			},
		},
		{
			name: "時間差大＋僅一站憑證過期",
			id:   "A3",
			mod: func(f *Facts) {
				f.Sites[0].Probe = Probe{Target: f.Sites[0].Target, Err: ErrCertExpired}
				f.Captive = Captive{Checked: true, SkewKnown: true, Skew: 72 * time.Hour}
			},
			code: Clock,
		},
		{
			name: "只測一個不存在的自訂網域",
			id:   "A4",
			cfg:  Config{ReplaceDefaultTargets: true},
			mod: func(f *Facts) {
				f.DNS = []Probe{{Target: "nope.example.com", Err: ErrNotFound}}
				f.Sites = []Site{{Name: "公司系統", Probe: Probe{Target: "https://nope.example.com", Err: ErrNotFound}}}
			},
			code: SiteCode,
			check: func(t *testing.T, r Report) {
				if r.Lights[3].Status != Green || !strings.Contains(r.Lights[3].Summary, "不存在") {
					t.Errorf("網址查詢燈 = %v（%s），預期綠燈且摘要含「不存在」", r.Lights[3].Status, r.Lights[3].Summary)
				}
				if !strings.Contains(r.Verdict.Text, "公司系統") {
					t.Errorf("結論文字應包含網站名稱：%q", r.Verdict.Text)
				}
			},
		},
		{
			name: "DNS 查詢逾時",
			id:   "A4",
			mod: func(f *Facts) {
				f.DNS = failAll(f.DNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrDNS)
			},
			code: DNSCode,
		},
		{
			name: "只測自訂內網站且直連被擋",
			id:   "A5",
			cfg:  Config{ReplaceDefaultTargets: true},
			mod: func(f *Facts) {
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.DNS = []Probe{{Target: "erp.corp.example", OK: true}}
				f.Sites = []Site{{Name: "公司 ERP", Probe: Probe{Target: "https://erp.corp.example", OK: true}, Status: 200}}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Lights[2].Status != Yellow || !strings.Contains(r.Lights[2].Summary, "自訂網站") {
					t.Errorf("對外連線燈 = %v（%s），預期黃燈且摘要含「自訂網站」", r.Lights[2].Status, r.Lights[2].Summary)
				}
			},
		},
		{
			name: "部分掉包",
			id:   "A6",
			mod: func(f *Facts) {
				f.Direct[1] = Probe{Target: f.Direct[1].Target, Err: ErrTimeout}
				f.Sites[1].Probe = Probe{Target: f.Sites[1].Target, Err: ErrTimeout}
				f.Sites[3].Probe = Probe{Target: f.Sites[3].Target, Err: ErrReset}
			},
			code: Unstable,
			check: func(t *testing.T, r Report) {
				if r.Lights[2].Status != Yellow {
					t.Errorf("對外連線燈 = %v，預期黃燈", r.Lights[2].Status)
				}
				if r.Lights[4].Status != Yellow {
					t.Errorf("網站連線燈 = %v，預期黃燈", r.Lights[4].Status)
				}
				if got := r.Verdict.Code.ExitCode(); got != 1 {
					t.Errorf("UNSTABLE 結束碼 = %d，預期 1", got)
				}
			},
		},
		{
			name: "單站逾時仍是網站問題（回歸保護）",
			id:   "A6",
			mod: func(f *Facts) {
				f.Sites[3].Probe = Probe{Target: f.Sites[3].Target, Err: ErrTimeout}
			},
			code: SiteCode,
		},
		{
			name: "VPN 下的 DNS 故障",
			id:   "A7",
			mod: func(f *Facts) {
				f.Local.VPN = "utun4"
				f.DNS = failAll(f.DNS, ErrDNS)
				f.Sites = failSites(f.Sites, ErrDNS)
			},
			code: DNSCode,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Verdict.Action, "公司 IT") {
					t.Errorf("建議應請使用者找公司 IT：%q", r.Verdict.Action)
				}
			},
		},
		{
			name: "手機熱點沒有行動數據",
			id:   "A7",
			mod: func(f *Facts) {
				f.Local.Kind = "手機網路共享"
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.DNS = failAll(f.DNS, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrTimeout)
			},
			code: ISP,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Verdict.Text, "手機") {
					t.Errorf("結論文字應提到手機：%q", r.Verdict.Text)
				}
			},
		},
		{
			name: "PAC 且直連不通",
			id:   "A8",
			cfg:  Config{Contact: map[string]string{"proxy": "網管組", "default": "總機"}},
			mod: func(f *Facts) {
				f.Local.Proxy = Proxy{Mode: ProxyPAC, Addr: "http://wpad/wpad.dat"}
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrTimeout)
			},
			code: ProxyPACCode,
			check: func(t *testing.T, r Report) {
				if got := r.Verdict.Code.ExitCode(); got != 2 {
					t.Errorf("PROXY_PAC 結束碼 = %d，預期 2", got)
				}
				if r.Verdict.Contact != "網管組" {
					t.Errorf("窗口 = %q，預期網管組", r.Verdict.Contact)
				}
				if !strings.Contains(r.Verdict.Text, "PAC") {
					t.Errorf("結論文字應提到 PAC：%q", r.Verdict.Text)
				}
			},
		},
		{
			name: "外線斷但內網 ERP 回自簽憑證",
			id:   "A1",
			mod: func(f *Facts) {
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrTimeout)
				f.Sites = append(f.Sites, Site{Name: "公司 ERP", Probe: Probe{Target: "https://erp.corp.example", Err: ErrCertUnknown}})
			},
			code: ISP,
			check: func(t *testing.T, r Report) {
				if r.Lights[2].Status != Red {
					t.Errorf("對外連線燈 = %v，預期紅燈", r.Lights[2].Status)
				}
			},
		},
		{
			name: "四個預設網站正常、兩個自訂內網站逾時",
			id:   "A6",
			mod: func(f *Facts) {
				f.Sites = append(f.Sites,
					Site{Name: "內網 A", Probe: Probe{Target: "https://a.corp.example", Err: ErrTimeout}},
					Site{Name: "內網 B", Probe: Probe{Target: "https://b.corp.example", Err: ErrTimeout}},
				)
			},
			code: SiteCode,
		},
		{
			name: "沒有測試目標時不判代理問題",
			id:   "A8",
			mod: func(f *Facts) {
				f.Sites = nil
				f.DNS = nil
				f.Local.Proxy = Proxy{Mode: ProxyPAC, Addr: "http://wpad/wpad.dat"}
			},
			code: Unknown,
		},
		{
			name: "外線斷、兩個內網站自簽憑證",
			id:   "A1",
			mod: func(f *Facts) {
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrTimeout)
				f.Sites = append(f.Sites,
					Site{Name: "內網 A", Probe: Probe{Target: "https://a.corp.example", Err: ErrCertUnknown}},
					Site{Name: "內網 B", Probe: Probe{Target: "https://b.corp.example", Err: ErrCertUnknown}},
				)
			},
			code: ISP,
		},
		{
			name: "公開網站正常、兩個內網站憑證過期、時間未知",
			id:   "A3",
			mod: func(f *Facts) {
				f.Sites = append(f.Sites,
					Site{Name: "內網 A", Probe: Probe{Target: "https://a.corp.example", Err: ErrCertExpired}},
					Site{Name: "內網 B", Probe: Probe{Target: "https://b.corp.example", Err: ErrCertExpired}},
				)
				f.Captive = Captive{Checked: true}
			},
			code: SiteCode,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Verdict.Text, "內網 A") || !strings.Contains(r.Verdict.Text, "內網 B") {
					t.Errorf("結論文字應列出兩個內網站名稱：%q", r.Verdict.Text)
				}
			},
		},
		{
			name: "時間確定偏差＋內網站憑證過期、外線斷",
			id:   "A3",
			mod: func(f *Facts) {
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrTimeout)
				f.Sites = append(f.Sites, Site{Name: "內網 A", Probe: Probe{Target: "https://a.corp.example", Err: ErrCertExpired}})
				f.Captive = Captive{Checked: true, SkewKnown: true, Skew: 72 * time.Hour}
			},
			code: Clock,
		},
		{
			name: "重複列出同一公開網址",
			id:   "A6",
			mod: func(f *Facts) {
				f.Sites[0].Probe = Probe{Target: f.Sites[0].Target, Err: ErrTimeout}
				f.Sites = append(f.Sites, Site{Name: "Google", Probe: Probe{Target: f.Sites[0].Target, Err: ErrTimeout}})
			},
			code: SiteCode,
		},
		{
			name: "讀不到閘道資訊但網路正常",
			id:   "B5",
			mod: func(f *Facts) {
				f.Local.Gateway = ""
				f.Local.GatewayUnknown = true
				f.Gateway = GatewayResult{}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Lights[1].Status != Yellow || !strings.Contains(r.Lights[1].Summary, "無法取得路由器資訊") {
					t.Errorf("路由器燈 = %v（%s），預期黃燈且摘要含「無法取得路由器資訊」", r.Lights[1].Status, r.Lights[1].Summary)
				}
			},
		},
		{
			name: "系統 DNS 故障、沒有 DNS 設定",
			id:   "T11",
			mod: func(f *Facts) {
				f.Local.DNSServers = nil
				f.DNS = failAll(f.DNS, ErrDNS)
				f.Sites = failSites(f.Sites, ErrDNS)
			},
			code: DNSCode,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Verdict.Text, "沒有拿到") {
					t.Errorf("結論文字應含「沒有拿到」：%q", r.Verdict.Text)
				}
			},
		},
		{
			name: "系統 DNS 故障、DNS 指向路由器",
			id:   "T11",
			mod: func(f *Facts) {
				f.Local.DNSServers = []string{"192.168.1.1"}
				f.DNS = failAll(f.DNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrDNS)
			},
			code: DNSCode,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Verdict.Text, "路由器") {
					t.Errorf("結論文字應含「路由器」：%q", r.Verdict.Text)
				}
			},
		},
		{
			name: "手動設 8.8.8.8 被擋",
			id:   "T11",
			mod: func(f *Facts) {
				f.Local.DNSServers = []string{"8.8.8.8"}
				f.DNSServers = []Probe{{Target: "8.8.8.8", Err: ErrTimeout}}
				f.DNS = failAll(f.DNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrDNS)
			},
			code: DNSCode,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Verdict.Text, "公共 DNS") {
					t.Errorf("結論文字應含「公共 DNS」：%q", r.Verdict.Text)
				}
			},
		},
		{
			name: "強制 DoH：系統查網址正常、直接查詢被擋",
			id:   "T11",
			mod: func(f *Facts) {
				f.DNSServers = []Probe{{Target: "192.168.1.1", Err: ErrTimeout}}
			},
			code: OK,
		},
		{
			name: "VPN 下 DNS 故障仍用 VPN 說法",
			id:   "T11",
			mod: func(f *Facts) {
				f.Local.VPN = "utun4"
				f.Local.DNSServers = nil
				f.DNS = failAll(f.DNS, ErrDNS)
				f.Sites = failSites(f.Sites, ErrDNS)
			},
			code: DNSCode,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Verdict.Action, "公司 IT") {
					t.Errorf("建議應請使用者找公司 IT：%q", r.Verdict.Action)
				}
			},
		},
		{
			name: "對外 IP 相同",
			id:   "T11",
			mod: func(f *Facts) {
				f.PublicIP = []TraceResult{
					{Name: "Cloudflare", IP: "1.2.3.4", Loc: "TW"},
					{Name: "政府入口網", IP: "1.2.3.4"},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				ev := strings.Join(r.Lights[2].Evidence, "\n")
				if !strings.Contains(ev, "對外 IP：1.2.3.4（TW）") {
					t.Errorf("證據應含對外 IP：%q", ev)
				}
				if !strings.Contains(ev, "連往政府入口網時相同") {
					t.Errorf("證據應含「連往政府入口網時相同」：%q", ev)
				}
			},
		},
		{
			name: "依目的地分流",
			id:   "T11",
			mod: func(f *Facts) {
				f.PublicIP = []TraceResult{
					{Name: "Cloudflare", IP: "1.2.3.4", Loc: "TW"},
					{Name: "政府入口網", IP: "5.6.7.8"},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				ev := strings.Join(r.Lights[2].Evidence, "\n")
				if !strings.Contains(ev, "連往政府入口網時改用 5.6.7.8（可能依目的地分流）") {
					t.Errorf("證據應含分流說明：%q", ev)
				}
			},
		},
		{
			name: "經由代理",
			id:   "T11",
			mod: func(f *Facts) {
				f.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128"}
				f.PublicIP = []TraceResult{
					{Name: "Cloudflare", IP: "1.2.3.4", Loc: "TW"},
					{Name: "政府入口網", IP: "1.2.3.4"},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				ev := strings.Join(r.Lights[2].Evidence, "\n")
				if !strings.Contains(ev, "經由代理（這是代理伺服器的對外 IP）") {
					t.Errorf("證據應含代理說明：%q", ev)
				}
			},
		},
		{
			name: "PAC 模式的對外 IP 標註",
			id:   "T11",
			mod: func(f *Facts) {
				f.Local.Proxy = Proxy{Mode: ProxyPAC, Addr: "http://wpad/wpad.dat"}
				f.PublicIP = []TraceResult{
					{Name: "Cloudflare", Host: "www.cloudflare.com", IP: "1.2.3.4", Loc: "TW"},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				ev := strings.Join(r.Lights[2].Evidence, "\n")
				if !strings.Contains(ev, "使用自動代理設定（無法確定是否經由代理）") {
					t.Errorf("證據應含自動代理設定說明：%q", ev)
				}
			},
		},
		{
			name: "明確代理但第一筆命中例外清單（直連）",
			id:   "T11",
			mod: func(f *Facts) {
				f.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128", Bypass: []string{"*.gov.tw", "*.cloudflare.com"}}
				f.PublicIP = []TraceResult{
					{Name: "Cloudflare", Host: "www.cloudflare.com", IP: "1.2.3.4", Loc: "TW"},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				ev := strings.Join(r.Lights[2].Evidence, "\n")
				if strings.Contains(ev, "代理伺服器的對外 IP") {
					t.Errorf("命中例外清單不應標註代理出口：%q", ev)
				}
				if !strings.Contains(ev, "對外 IP：") {
					t.Errorf("證據應含對外 IP：%q", ev)
				}
			},
		},
		{
			name: "ICMP、TCP 全擋但 ARP 有回應、網路正常",
			id:   "T11",
			mod: func(f *Facts) {
				f.Gateway = GatewayResult{Alive: true, Via: "ARP"}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Lights[1].Status != Green {
					t.Errorf("路由器燈 = %v，預期綠燈", r.Lights[1].Status)
				}
			},
		},
		{
			name: "單位節點全掛、出不去",
			id:   "T14",
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", Err: ErrTimeout},
					{Name: "GSN DNS", Host: "210.69.1.1", Check: "dns", Err: ErrTimeout},
				}
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.DNS = failAll(f.DNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrTimeout)
			},
			code: OrgNetwork,
			check: func(t *testing.T, r Report) {
				if len(r.Lights) != 6 {
					t.Fatalf("燈數 = %d，預期 6", len(r.Lights))
				}
				if r.Lights[2].Name != "單位網路" || r.Lights[2].Status != Red {
					t.Errorf("燈 3 = %s（%v），預期單位網路紅燈", r.Lights[2].Name, r.Lights[2].Status)
				}
				if r.Lights[3].Status != Skip {
					t.Errorf("燈 4 = %v，預期略過", r.Lights[3].Status)
				}
			},
		},
		{
			name: "單位節點正常、往外不通",
			id:   "T14",
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", OK: true, Ms: 12},
					{Name: "GSN DNS", Host: "210.69.1.1", Check: "dns", OK: true, Ms: 20},
				}
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.DNS = failAll(f.DNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrTimeout)
			},
			code: ISP,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Verdict.Text, "單位網路有節點回應") {
					t.Errorf("結論文字應含「單位網路有節點回應」：%q", r.Verdict.Text)
				}
			},
		},
		{
			name: "單位節點全掛、網路正常",
			id:   "T14",
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", Err: ErrTimeout},
					{Name: "GSN DNS", Host: "210.69.1.1", Check: "dns", Err: ErrTimeout},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Lights[2].Status != Yellow {
					t.Errorf("單位網路燈 = %v，預期黃燈", r.Lights[2].Status)
				}
				for _, i := range []int{3, 4, 5} {
					if r.Lights[i].Status == Skip {
						t.Errorf("燈 %d 不應為略過（%s）", i+1, r.Lights[i].Summary)
					}
				}
			},
		},
		{
			name: "部分節點沒回應、網路正常",
			id:   "T14",
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", OK: true, Ms: 8},
					{Name: "GSN DNS", Host: "210.69.1.1", Check: "dns", Err: ErrTimeout},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Lights[2].Status != Yellow {
					t.Errorf("單位網路燈 = %v，預期黃燈", r.Lights[2].Status)
				}
				if !strings.Contains(r.Lights[2].Summary, "GSN DNS") {
					t.Errorf("摘要應含失敗節點名稱：%q", r.Lights[2].Summary)
				}
			},
		},
		{
			name: "只有一個節點且正常",
			id:   "T14",
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", OK: true, Ms: 12},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Lights[2].Summary != "節點有回應" {
					t.Errorf("單位網路摘要 = %q，預期「節點有回應」", r.Lights[2].Summary)
				}
			},
		},
		{
			name: "ping 無法執行",
			id:   "T14",
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "內網主機 A", Host: "10.1.0.2", Check: "ping", Unknown: true},
					{Name: "內網主機 B", Host: "10.1.0.3", Check: "ping", Unknown: true},
				}
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.DNS = failAll(f.DNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrTimeout)
			},
			code: ISP,
			check: func(t *testing.T, r Report) {
				if r.Lights[2].Status != Yellow {
					t.Errorf("單位網路燈 = %v，預期黃燈", r.Lights[2].Status)
				}
			},
		},
		{
			name: "路由追蹤只是輔助證據",
			id:   "T16",
			mod: func(f *Facts) {
				f.Route = RouteResult{Target: "1.1.1.1", Hops: []Hop{
					{TTL: 1, IP: "192.168.1.1", Ms: 2},
					{TTL: 2, IP: "203.0.113.9", Ms: 5},
					{TTL: 3, IP: "1.1.1.1", Ms: 8, Reached: true},
				}}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				base := decide(healthy(), Config{})
				if r.Verdict != base.Verdict {
					t.Errorf("結論應與沒有 Route 時相同：%+v vs %+v", r.Verdict, base.Verdict)
				}
				if len(r.Lights) != len(base.Lights) || len(base.Lights) != 5 {
					t.Fatalf("燈數 = %d，預期 5", len(r.Lights))
				}
				for i := range base.Lights {
					if r.Lights[i].Name != base.Lights[i].Name || r.Lights[i].Status != base.Lights[i].Status || r.Lights[i].Summary != base.Lights[i].Summary {
						t.Errorf("燈 %d（%s）與沒有 Route 時不同：%v（%s）vs %v（%s）", i+1,
							r.Lights[i].Name, r.Lights[i].Status, r.Lights[i].Summary,
							base.Lights[i].Status, base.Lights[i].Summary)
					}
				}
				ev := strings.Join(r.Lights[2].Evidence, "\n")
				if !strings.Contains(ev, "路由追蹤（往 1.1.1.1）") {
					t.Errorf("對外連線證據應含路由追蹤：%q", ev)
				}
			},
		},
		{
			name: "沒有設定檢查點",
			id:   "T14",
			mod:  func(f *Facts) {},
			code: OK,
			check: func(t *testing.T, r Report) {
				if len(r.Lights) != 5 {
					t.Fatalf("燈數 = %d，預期 5", len(r.Lights))
				}
				for i, want := range []string{"本機網路", "路由器", "對外連線", "網址查詢", "網站連線"} {
					if r.Lights[i].Name != want {
						t.Errorf("燈 %d 名稱 = %s，預期 %s", i+1, r.Lights[i].Name, want)
					}
				}
			},
		},
		{
			name: "代理例外的網站直連成功、DNS 全部失敗",
			id:   "T19",
			mod: func(f *Facts) {
				f.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128", Bypass: []string{"*"}}
				f.DNS = failAll(f.DNS, ErrTimeout)
				f.DNSServers = []Probe{{Target: "192.168.1.1", Err: ErrTimeout}}
				for i := range f.Sites {
					f.Sites[i].Route = "direct"
				}
			},
			code: DNSCode,
			check: func(t *testing.T, r Report) {
				if strings.Contains(r.Lights[3].Summary, "由代理伺服器代查") {
					t.Errorf("全部直連時不應說由代理伺服器代查：%q", r.Lights[3].Summary)
				}
				if r.Verdict.Code == OK {
					t.Errorf("結論不應為 OK：%s", r.Verdict.Code)
				}
			},
		},
		{
			name: "經由代理的網站成功、DNS 全部失敗",
			id:   "T19",
			mod: func(f *Facts) {
				f.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128"}
				f.DNS = failAll(f.DNS, ErrTimeout)
				f.DNSServers = []Probe{{Target: "192.168.1.1", Err: ErrTimeout}}
				for i := range f.Sites {
					f.Sites[i].Route = "proxy"
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Lights[3].Summary != "由代理伺服器代查" {
					t.Errorf("網址查詢摘要 = %q，預期「由代理伺服器代查」", r.Lights[3].Summary)
				}
			},
		},
		{
			name: "設定代理但全部網站直連且都失敗",
			id:   "T19",
			mod: func(f *Facts) {
				f.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128", Bypass: []string{"*"}}
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrTimeout)
				for i := range f.Sites {
					f.Sites[i].Route = "direct"
				}
			},
			code: ISP,
			check: func(t *testing.T, r Report) {
				if r.Verdict.Code == ProxyCode {
					t.Errorf("全部直連時不應判 PROXY：%s", r.Verdict.Code)
				}
			},
		},
		{
			name: "經由代理的網站全部失敗",
			id:   "T19",
			mod: func(f *Facts) {
				f.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128"}
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrTimeout)
				for i := range f.Sites {
					f.Sites[i].Route = "proxy"
				}
			},
			code: ProxyCode,
		},
		{
			name: "網站回應 403",
			id:   "T19",
			mod: func(f *Facts) {
				f.Sites[0].Status = 403
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Lights[4].Status != Green {
					t.Errorf("網站連線燈 = %v，預期綠燈", r.Lights[4].Status)
				}
				if !strings.Contains(r.Lights[4].Summary, "Google") || !strings.Contains(r.Lights[4].Summary, "連得上但拒絕或限制這次請求") {
					t.Errorf("摘要應含網站名稱與拒絕說明：%q", r.Lights[4].Summary)
				}
				if ev := strings.Join(r.Lights[4].Evidence, "\n"); !strings.Contains(ev, "可能需要登入或權限") {
					t.Errorf("證據行應含「可能需要登入或權限」：%q", ev)
				}
			},
		},
		{
			name: "網站回應 429",
			id:   "T19",
			mod: func(f *Facts) {
				f.Sites[0].Status = 429
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if ev := strings.Join(r.Lights[4].Evidence, "\n"); !strings.Contains(ev, "暫時限制請求次數") {
					t.Errorf("證據行應含「暫時限制請求次數」：%q", ev)
				}
			},
		},
		{
			name: "經由代理的網站回應 403",
			id:   "T19",
			mod: func(f *Facts) {
				f.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128"}
				f.Sites[0].Status = 403
				f.Sites[0].Route = "proxy"
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				var line string
				for _, ev := range r.Lights[4].Evidence {
					if strings.Contains(ev, "HTTP 403") {
						line = ev
					}
				}
				if line == "" {
					t.Fatalf("證據行應含「HTTP 403」：%q", r.Lights[4].Evidence)
				}
				i403 := strings.Index(line, "HTTP 403")
				iperm := strings.Index(line, "可能需要登入或權限")
				iproxy := strings.Index(line, "（經由代理）")
				if !(i403 < iperm && iperm < iproxy) {
					t.Errorf("證據行順序應為 HTTP 403 → 拒絕說明 → （經由代理）：%q", line)
				}
			},
		},
		{
			name: "PAC、網站成功、DNS 全部失敗",
			id:   "T19",
			mod: func(f *Facts) {
				f.Local.Proxy = Proxy{Mode: ProxyPAC, Addr: "http://wpad/wpad.dat"}
				f.DNS = failAll(f.DNS, ErrTimeout)
				f.DNSServers = []Probe{{Target: "192.168.1.1", Err: ErrTimeout}}
			},
			code: DNSCode,
			check: func(t *testing.T, r Report) {
				if strings.Contains(r.Lights[3].Summary, "由代理伺服器代查") {
					t.Errorf("PAC 不應說由代理伺服器代查：%q", r.Lights[3].Summary)
				}
			},
		},
		{
			name: "設定代理但網站都直連",
			id:   "T19",
			mod: func(f *Facts) {
				f.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128", Bypass: []string{"*"}}
				for i := range f.Sites {
					f.Sites[i].Route = "direct"
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Lights[2].Summary, "設定了代理，但測試的網站都直連") {
					t.Errorf("對外連線摘要應含直連說明：%q", r.Lights[2].Summary)
				}
				if strings.Contains(r.Lights[2].Summary, "經由代理") {
					t.Errorf("對外連線摘要不應含「經由代理」：%q", r.Lights[2].Summary)
				}
			},
		},
		{
			name: "混合選路且全部失敗",
			id:   "T19",
			mod: func(f *Facts) {
				f.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128", Bypass: []string{"*"}}
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrTimeout)
				for i := range f.Sites {
					f.Sites[i].Route = "direct"
				}
				f.Sites[0].Route = "proxy"
			},
			code: ProxyCode,
		},
		{
			name: "網站回應 401",
			id:   "T19",
			mod: func(f *Facts) {
				f.Sites[0].Status = 401
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if ev := strings.Join(r.Lights[4].Evidence, "\n"); !strings.Contains(ev, "可能需要登入或權限") {
					t.Errorf("證據行應含「可能需要登入或權限」：%q", ev)
				}
			},
		},
		{
			name: "一個逾時、一個 403",
			id:   "T19",
			mod: func(f *Facts) {
				f.Sites[0].Probe = Probe{Target: f.Sites[0].Target, Err: ErrTimeout}
				f.Sites[1].Status = 403
			},
			code: SiteCode,
			check: func(t *testing.T, r Report) {
				if r.Lights[4].Status != Yellow {
					t.Errorf("網站連線燈 = %v，預期黃燈", r.Lights[4].Status)
				}
				if !strings.Contains(r.Lights[4].Summary, "異常") || !strings.Contains(r.Lights[4].Summary, "連得上但拒絕或限制這次請求") {
					t.Errorf("摘要應同時含「異常」與「連得上但拒絕或限制這次請求」：%q", r.Lights[4].Summary)
				}
			},
		},
		{
			name: "兩個網站分別 403、429",
			id:   "T19",
			mod: func(f *Facts) {
				f.Sites[0].Status = 403
				f.Sites[1].Status = 429
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Lights[4].Summary, "「Google、Cloudflare」連得上但拒絕或限制這次請求") {
					t.Errorf("摘要應以「、」連接兩個名稱：%q", r.Lights[4].Summary)
				}
			},
		},
		{
			name: "一個網站查不到網址、其他正常",
			id:   "T20",
			mod: func(f *Facts) {
				f.DNS[0] = Probe{Target: "www.google.com", Err: ErrDNS}
				f.Sites[0].Probe = Probe{Target: f.Sites[0].Target, Err: ErrDNS}
			},
			code: SiteCode,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Verdict.Text, "查不到") || !strings.Contains(r.Verdict.Text, "Google") {
					t.Errorf("結論文字應說查不到網址並列出網站名稱：%q", r.Verdict.Text)
				}
				if strings.Contains(r.Verdict.Text, "問題出在") {
					t.Errorf("結論不應說成網站本身異常：%q", r.Verdict.Text)
				}
				if r.Lights[3].Status != Yellow || !strings.Contains(r.Lights[3].Summary, "部分網址在這台電腦查不到") || !strings.Contains(r.Lights[3].Summary, "www.google.com") {
					t.Errorf("網址查詢燈 = %v（%s），預期黃燈且摘要含本機查詢說明與主機名稱", r.Lights[3].Status, r.Lights[3].Summary)
				}
			},
		},
		{
			name: "網址查詢逾時、其他正常",
			id:   "T20",
			mod: func(f *Facts) {
				f.DNS[0] = Probe{Target: "www.google.com", Err: ErrTimeout}
				f.Sites[0].Probe = Probe{Target: f.Sites[0].Target, Err: ErrTimeout}
			},
			code: SiteCode,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Verdict.Text, "查不到") {
					t.Errorf("DNS 查詢逾時仍應套用查不到網址的說法：%q", r.Verdict.Text)
				}
			},
		},
		{
			name: "一個網站查不到網址、另一個網站本身逾時",
			id:   "T20",
			mod: func(f *Facts) {
				f.DNS[0] = Probe{Target: "www.google.com", Err: ErrDNS}
				f.Sites[0].Probe = Probe{Target: f.Sites[0].Target, Err: ErrDNS}
				f.Sites[1].Probe = Probe{Target: f.Sites[1].Target, Err: ErrTimeout}
			},
			code: SiteCode,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Verdict.Text, "問題出在") {
					t.Errorf("混有非 DNS 因素時應維持既有 SITE 說法：%q", r.Verdict.Text)
				}
			},
		},
		{
			name: "部分查詢回應網址不存在",
			id:   "T20",
			mod: func(f *Facts) {
				f.DNS[0] = Probe{Target: "www.google.com", Err: ErrNotFound}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Lights[3].Status != Green {
					t.Errorf("網址查詢燈 = %v（%s），預期綠燈", r.Lights[3].Status, r.Lights[3].Summary)
				}
			},
		},
		{
			name: "只測自訂網站、沒有確認網際網路",
			id:   "T20",
			cfg:  Config{ReplaceDefaultTargets: true},
			mod: func(f *Facts) {
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.DNS = []Probe{{Target: "erp.example.com", OK: true}}
				f.Sites = []Site{{Name: "公司 ERP", Probe: Probe{Target: "https://erp.example.com", OK: true}, Status: 200}}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Verdict.Text != "測試的網站都連得上，但這次沒有確認網際網路。" {
					t.Errorf("結論文字 = %q，預期說明這次沒有確認網際網路", r.Verdict.Text)
				}
			},
		},
		{
			name: "單位節點都沒有回應但可上網",
			id:   "T20",
			cfg:  Config{Org: "範例機關", Contact: map[string]string{"org_network": "資訊室 分機 100"}},
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", Err: ErrTimeout},
					{Name: "GSN DNS", Host: "210.69.1.1", Check: "dns", Err: ErrTimeout},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Verdict.Text != "可以連到網際網路，但單位網路的節點都沒有回應。" {
					t.Errorf("結論文字 = %q，預期 okOrgDown 的說法", r.Verdict.Text)
				}
				if r.Verdict.Contact != "資訊室 分機 100" {
					t.Errorf("窗口 = %q，預期資訊室 分機 100", r.Verdict.Contact)
				}
				if r.Verdict.Org != "範例機關" {
					t.Errorf("單位 = %q，預期範例機關", r.Verdict.Org)
				}
				if got := r.Verdict.Code.ExitCode(); got != 0 {
					t.Errorf("結束碼 = %d，預期 0", got)
				}
			},
		},
		{
			name: "部分單位節點沒有回應",
			id:   "T20",
			cfg:  Config{Org: "範例機關", Contact: map[string]string{"org_network": "資訊室 分機 100"}},
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", OK: true, Ms: 8},
					{Name: "GSN DNS", Host: "210.69.1.1", Check: "dns", Err: ErrTimeout},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Verdict.Text != "網路正常，但部分單位網路節點沒有回應。" {
					t.Errorf("結論文字 = %q，預期 okOrgPartial 的說法", r.Verdict.Text)
				}
				if r.Verdict.Contact != "資訊室 分機 100" {
					t.Errorf("窗口 = %q，預期資訊室 分機 100", r.Verdict.Contact)
				}
				if r.Verdict.Org != "範例機關" {
					t.Errorf("單位 = %q，預期範例機關", r.Verdict.Org)
				}
			},
		},
		{
			name: "單位節點都正常",
			id:   "T20",
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", OK: true, Ms: 12},
					{Name: "GSN DNS", Host: "210.69.1.1", Check: "dns", OK: true, Ms: 20},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Verdict.Text != "網路正常。" {
					t.Errorf("結論文字 = %q，預期「網路正常。」", r.Verdict.Text)
				}
				if r.Verdict.Contact != "" {
					t.Errorf("單位節點正常時不應顯示窗口：%q", r.Verdict.Contact)
				}
			},
		},
		{
			name: "經由代理的網站回 503、本機 DNS 逾時",
			id:   "T20",
			mod: func(f *Facts) {
				f.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128"}
				f.DNS[0] = Probe{Target: "www.google.com", Err: ErrTimeout}
				f.Sites[0] = Site{Name: "Google", Probe: Probe{Target: f.Sites[0].Target, OK: true}, Status: 503, Route: "proxy"}
			},
			code: SiteCode,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Verdict.Text, "問題出在") || strings.Contains(r.Verdict.Text, "查不到") {
					t.Errorf("已有回應的網站應維持問題出在網站本身的說法：%q", r.Verdict.Text)
				}
			},
		},
		{
			name: "經由代理的網站逾時、本機 DNS 失敗",
			id:   "T20",
			mod: func(f *Facts) {
				f.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128"}
				f.DNS[0] = Probe{Target: "www.google.com", Err: ErrDNS}
				f.Sites[0] = Site{Name: "Google", Probe: Probe{Target: f.Sites[0].Target, Err: ErrTimeout}, Route: "proxy"}
			},
			code: SiteCode,
			check: func(t *testing.T, r Report) {
				if strings.Contains(r.Verdict.Text, "查不到") {
					t.Errorf("經由代理的網站不應歸因為查不到網址：%q", r.Verdict.Text)
				}
			},
		},
		{
			name: "兩個網站共用同一主機、該主機 DNS 失敗",
			id:   "T20",
			mod: func(f *Facts) {
				f.DNS = append(f.DNS, Probe{Target: "erp.example.com", Err: ErrDNS})
				f.Sites = append(f.Sites,
					Site{Name: "公文系統", Probe: Probe{Target: "https://erp.example.com/a", Err: ErrDNS}},
					Site{Name: "差勤系統", Probe: Probe{Target: "https://erp.example.com/b", Err: ErrDNS}},
				)
			},
			code: SiteCode,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Verdict.Text, "「公文系統、差勤系統」") {
					t.Errorf("結論應套用查不到網址並依序列出兩個名稱：%q", r.Verdict.Text)
				}
			},
		},
		{
			name: "直連網站回 503、本機 DNS 逾時",
			id:   "T20",
			mod: func(f *Facts) {
				f.DNS[0] = Probe{Target: "www.google.com", Err: ErrTimeout}
				f.Sites[0] = Site{Name: "Google", Probe: Probe{Target: f.Sites[0].Target, OK: true}, Status: 503}
			},
			code: SiteCode,
			check: func(t *testing.T, r Report) {
				if !strings.Contains(r.Verdict.Text, "問題出在") || strings.Contains(r.Verdict.Text, "查不到") {
					t.Errorf("直連且已有回應的網站應維持問題出在網站本身的說法：%q", r.Verdict.Text)
				}
			},
		},
		{
			name: "不健康網站的主機沒有對應 DNS 查詢",
			id:   "T20",
			mod: func(f *Facts) {
				f.DNS = []Probe{
					{Target: "www.cloudflare.com", OK: true},
					{Target: "www.microsoft.com", OK: true},
					{Target: "www.gov.tw", OK: true},
				}
				f.Sites[0].Probe = Probe{Target: f.Sites[0].Target, Err: ErrTimeout}
			},
			code: SiteCode,
			check: func(t *testing.T, r Report) {
				if strings.Contains(r.Verdict.Text, "查不到") {
					t.Errorf("沒有對應 DNS 查詢時不應套用查不到網址：%q", r.Verdict.Text)
				}
			},
		},
		{
			name: "單位節點都沒有回應、窗口 fallback 到 default",
			id:   "T20",
			cfg:  Config{Org: "範例機關", Contact: map[string]string{"default": "IT 服務台"}},
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", Err: ErrTimeout},
					{Name: "GSN DNS", Host: "210.69.1.1", Check: "dns", Err: ErrTimeout},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Verdict.Text != "可以連到網際網路，但單位網路的節點都沒有回應。" {
					t.Errorf("結論文字 = %q，預期 okOrgDown 的說法", r.Verdict.Text)
				}
				if r.Verdict.Contact != "IT 服務台" {
					t.Errorf("窗口 = %q，預期 fallback 到 default「IT 服務台」", r.Verdict.Contact)
				}
			},
		},
		{
			name: "部分單位節點沒有回應、沒有設定窗口",
			id:   "T20",
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", OK: true, Ms: 8},
					{Name: "GSN DNS", Host: "210.69.1.1", Check: "dns", Err: ErrTimeout},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Verdict.Text != "網路正常，但部分單位網路節點沒有回應。" {
					t.Errorf("結論文字 = %q，預期 okOrgPartial 的說法", r.Verdict.Text)
				}
				if r.Verdict.Contact != "" {
					t.Errorf("沒有設定窗口時不應顯示：%q", r.Verdict.Contact)
				}
			},
		},
		{
			name: "只有參考節點沒有回應、必要節點正常",
			id:   "T23",
			cfg:  Config{Org: "範例機關", Contact: map[string]string{"org_network": "單位資訊室 分機 2211"}},
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", OK: true, Ms: 8},
					{Name: "內部入口網", Host: "10.1.0.2", Check: "tcp:443", Reference: true, Err: ErrTimeout},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Verdict.Text != "網路正常。" {
					t.Errorf("結論文字 = %q，預期一般「網路正常。」", r.Verdict.Text)
				}
				if r.Verdict.Contact != "" {
					t.Errorf("參考節點失敗不應顯示窗口：%q", r.Verdict.Contact)
				}
				if r.Lights[2].Name != "單位網路" || r.Lights[2].Status != Yellow {
					t.Errorf("單位網路燈 = %s（%v），預期黃燈", r.Lights[2].Name, r.Lights[2].Status)
				}
				if !strings.Contains(r.Lights[2].Summary, "（參考）") {
					t.Errorf("單位網路摘要應含「（參考）」：%q", r.Lights[2].Summary)
				}
			},
		},
		{
			name: "必要節點沒有回應、參考節點正常",
			id:   "T23",
			cfg:  Config{Org: "範例機關", Contact: map[string]string{"org_network": "單位資訊室 分機 2211"}},
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", Err: ErrTimeout},
					{Name: "內部入口網", Host: "10.1.0.2", Check: "tcp:443", Reference: true, OK: true, Ms: 5},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Verdict.Text != "網路正常，但部分單位網路節點沒有回應。" {
					t.Errorf("結論文字 = %q，預期 okOrgPartial 的說法", r.Verdict.Text)
				}
				if r.Verdict.Contact != "單位資訊室 分機 2211" {
					t.Errorf("窗口 = %q，預期單位資訊室 分機 2211", r.Verdict.Contact)
				}
				if r.Lights[2].Name != "單位網路" || r.Lights[2].Status != Yellow {
					t.Errorf("單位網路燈 = %s（%v），預期黃燈", r.Lights[2].Name, r.Lights[2].Status)
				}
			},
		},
		{
			name: "所有節點都沒有回應、其中有必要節點",
			id:   "T23",
			cfg:  Config{Org: "範例機關", Contact: map[string]string{"org_network": "單位資訊室 分機 2211"}},
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", Err: ErrTimeout},
					{Name: "內部入口網", Host: "10.1.0.2", Check: "tcp:443", Reference: true, Err: ErrTimeout},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Verdict.Text != "可以連到網際網路，但單位網路的節點都沒有回應。" {
					t.Errorf("結論文字 = %q，預期 okOrgDown 的說法", r.Verdict.Text)
				}
				if r.Lights[2].Name != "單位網路" || r.Lights[2].Status != Yellow {
					t.Errorf("單位網路燈 = %s（%v），預期黃燈", r.Lights[2].Name, r.Lights[2].Status)
				}
			},
		},
		{
			name: "全部都是參考節點且都沒有回應、網路正常",
			id:   "T23",
			cfg:  Config{Org: "範例機關", Contact: map[string]string{"org_network": "單位資訊室 分機 2211"}},
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "內部入口網", Host: "10.1.0.2", Check: "tcp:443", Reference: true, Err: ErrTimeout},
					{Name: "內部檔案伺服器", Host: "10.1.0.3", Check: "tcp:443", Reference: true, Err: ErrTimeout},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Verdict.Text != "網路正常。" {
					t.Errorf("結論文字 = %q，預期一般「網路正常。」", r.Verdict.Text)
				}
				if r.Verdict.Contact != "" {
					t.Errorf("只有參考節點失敗不應顯示窗口：%q", r.Verdict.Contact)
				}
				if r.Lights[2].Name != "單位網路" || r.Lights[2].Status != Yellow {
					t.Errorf("單位網路燈 = %s（%v），預期黃燈", r.Lights[2].Name, r.Lights[2].Status)
				}
			},
		},
		{
			name: "全部都是參考節點且都沒有回應、連不出去",
			id:   "T23",
			cfg:  Config{Org: "範例機關", Contact: map[string]string{"org_network": "單位資訊室 分機 2211"}},
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "內部入口網", Host: "10.1.0.2", Check: "tcp:443", Reference: true, Err: ErrTimeout},
					{Name: "內部檔案伺服器", Host: "10.1.0.3", Check: "tcp:443", Reference: true, Err: ErrTimeout},
				}
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.DNS = failAll(f.DNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrTimeout)
			},
			code: OrgNetwork,
			check: func(t *testing.T, r Report) {
				if r.Lights[2].Name != "單位網路" || r.Lights[2].Status != Red {
					t.Errorf("單位網路燈 = %s（%v），預期紅燈", r.Lights[2].Name, r.Lights[2].Status)
				}
			},
		},
		{
			name: "必要節點沒有回應、只有參考節點有回應、連不出去",
			id:   "T23",
			cfg:  Config{Org: "範例機關", Contact: map[string]string{"org_network": "單位資訊室 分機 2211"}},
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", Err: ErrTimeout},
					{Name: "內部入口網", Host: "10.1.0.2", Check: "tcp:443", Reference: true, OK: true, Ms: 5},
				}
				f.Direct = failAll(f.Direct, ErrTimeout)
				f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
				f.DNS = failAll(f.DNS, ErrTimeout)
				f.Sites = failSites(f.Sites, ErrTimeout)
			},
			code: ISP,
			check: func(t *testing.T, r Report) {
				if r.Verdict.Text != "單位網路有節點回應，但從單位往外的線路不通。" {
					t.Errorf("結論文字 = %q，預期 ispOrg 的說法", r.Verdict.Text)
				}
				if r.Lights[2].Name != "單位網路" || r.Lights[2].Status != Yellow {
					t.Errorf("單位網路燈 = %s（%v），預期黃燈", r.Lights[2].Name, r.Lights[2].Status)
				}
			},
		},
		{
			name: "必要節點無法執行、參考節點失敗、可上網",
			id:   "T23",
			cfg:  Config{Org: "範例機關", Contact: map[string]string{"org_network": "單位資訊室 分機 2211"}},
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "內網主機", Host: "10.1.0.4", Check: "ping", Unknown: true},
					{Name: "內部入口網", Host: "10.1.0.2", Check: "tcp:443", Reference: true, Err: ErrTimeout},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Verdict.Text != "網路正常。" {
					t.Errorf("結論文字 = %q，預期一般「網路正常。」", r.Verdict.Text)
				}
				if r.Verdict.Contact != "" {
					t.Errorf("必要節點 Unknown 且參考節點失敗不應顯示窗口：%q", r.Verdict.Contact)
				}
			},
		},
		{
			name: "必要節點一個成功一個無法執行、參考節點失敗",
			id:   "T23",
			cfg:  Config{Org: "範例機關", Contact: map[string]string{"org_network": "單位資訊室 分機 2211"}},
			mod: func(f *Facts) {
				f.Checkpoints = []CheckpointResult{
					{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443", OK: true, Ms: 8},
					{Name: "內網主機", Host: "10.1.0.4", Check: "ping", Unknown: true},
					{Name: "內部入口網", Host: "10.1.0.2", Check: "tcp:443", Reference: true, Err: ErrTimeout},
				}
			},
			code: OK,
			check: func(t *testing.T, r Report) {
				if r.Verdict.Text != "網路正常。" {
					t.Errorf("結論文字 = %q，預期一般「網路正常。」", r.Verdict.Text)
				}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.id+" "+c.name, func(t *testing.T) {
			f := healthy()
			c.mod(&f)
			r := decide(f, c.cfg)
			if r.Verdict.Code != c.code {
				t.Errorf("結論 = %s，預期 %s", r.Verdict.Code, c.code)
			}
			if c.check != nil {
				c.check(t, r)
			}
		})
	}
}
