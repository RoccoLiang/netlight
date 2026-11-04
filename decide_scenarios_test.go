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
				if !strings.Contains(ev, "經由代理（顯示的是代理的出口）") {
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
				if strings.Contains(ev, "代理的出口") {
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
