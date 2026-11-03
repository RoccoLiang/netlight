package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "重新產生 testdata/*.golden")

var fixedTime = time.Date(2026, 11, 2, 14, 3, 0, 0, time.FixedZone("CST", 8*3600))

func screens() map[string]func() (Facts, Config) {
	return map[string]func() (Facts, Config){
		"a_ok": func() (Facts, Config) { return healthy(), Config{} },
		"b_dns": func() (Facts, Config) {
			f := healthy()
			f.DNS = failAll(f.DNS, ErrDNS)
			f.Sites = failSites(f.Sites, ErrDNS)
			return f, Config{}
		},
		"c_nolink": func() (Facts, Config) {
			return Facts{Local: Local{OS: "macOS"}, NoLink: true}, Config{}
		},
		"c_router": func() (Facts, Config) {
			f := healthy()
			f.Gateway = GatewayResult{}
			f.Direct = failAll(f.Direct, ErrTimeout)
			f.DNS = failAll(f.DNS, ErrTimeout)
			f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
			f.Sites = failSites(f.Sites, ErrTimeout)
			return f, Config{}
		},
		"d_portal": func() (Facts, Config) {
			f := healthy()
			f.Local.IP, f.Local.Gateway = "10.0.0.57", "10.0.0.1"
			f.Captive = Captive{Checked: true, Portal: true, Note: "HTTP 302 Found → http://login.hotel/"}
			f.Sites = failSites(f.Sites, ErrCertHostname)
			return f, Config{}
		},
		"e_site_company": func() (Facts, Config) {
			f := healthy()
			f.Local.Kind, f.Local.IP, f.Local.Gateway = "有線網路", "10.20.3.44", "10.20.0.1"
			f.Sites = append(f.Sites, Site{Name: "公司 ERP", Probe: Probe{Target: "https://erp.example.com", Err: ErrTimeout}})
			return f, Config{Org: "範例公司", Contact: map[string]string{"default": "IT 服務台 分機 1234／Teams「IT Helpdesk」"}}
		},
		"f_nodhcp": func() (Facts, Config) {
			f := healthy()
			f.Local.IP, f.Local.APIPA, f.Local.Gateway = "169.254.10.2", true, ""
			f.Gateway = GatewayResult{}
			f.Direct = failAll(f.Direct, ErrUnreachable)
			f.DNS = failAll(f.DNS, ErrUnreachable)
			f.PublicDNS = failAll(f.PublicDNS, ErrUnreachable)
			f.Sites = failSites(f.Sites, ErrUnreachable)
			return f, Config{}
		},
		"g_clock": func() (Facts, Config) {
			f := healthy()
			f.Sites = failSites(f.Sites, ErrCertExpired)
			return f, Config{}
		},
		"h_vpn": func() (Facts, Config) {
			f := healthy()
			f.Local.VPN, f.Local.Gateway = "utun4", ""
			f.Gateway = GatewayResult{}
			f.Direct = failAll(f.Direct, ErrTimeout)
			f.DNS = failAll(f.DNS, ErrTimeout)
			f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
			f.Sites = failSites(f.Sites, ErrTimeout)
			return f, Config{}
		},
		"i_proxy": func() (Facts, Config) {
			f := healthy()
			f.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128"}
			f.Direct = failAll(f.Direct, ErrTimeout)
			f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
			f.Sites = failSites(f.Sites, ErrProxy)
			return f, Config{}
		},
		"i_proxypac": func() (Facts, Config) {
			f := healthy()
			f.Local.Proxy = Proxy{Mode: ProxyPAC, Addr: "http://wpad/wpad.dat"}
			f.Direct = failAll(f.Direct, ErrTimeout)
			f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
			f.Sites = failSites(f.Sites, ErrTimeout)
			return f, Config{}
		},
		"j_isp": func() (Facts, Config) {
			f := healthy()
			f.Direct = failAll(f.Direct, ErrTimeout)
			f.DNS = failAll(f.DNS, ErrTimeout)
			f.PublicDNS = failAll(f.PublicDNS, ErrTimeout)
			f.Sites = failSites(f.Sites, ErrTimeout)
			return f, Config{}
		},
		"k_tls": func() (Facts, Config) {
			f := healthy()
			f.Sites = failSites(f.Sites, ErrCertUnknown)
			return f, Config{}
		},
		"l_filtered": func() (Facts, Config) {
			f := healthy()
			f.Sites = failSites(f.Sites, ErrTimeout)
			return f, Config{}
		},
		"m_unstable": func() (Facts, Config) {
			f := healthy()
			f.Direct[1] = Probe{Target: f.Direct[1].Target, Err: ErrTimeout}
			f.Sites[1] = Site{Name: f.Sites[1].Name, Probe: Probe{Target: f.Sites[1].Target, Err: ErrTimeout}}
			f.Sites[3] = Site{Name: f.Sites[3].Name, Probe: Probe{Target: f.Sites[3].Target, Err: ErrReset}}
			return f, Config{}
		},
		"n_unknown": func() (Facts, Config) {
			f := healthy()
			f.Sites = nil
			f.DNS = nil
			return f, Config{}
		},
	}
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatalf("寫入 %s：%v", p, err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("讀取 %s：%v（先執行 go test -update）", p, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s 輸出不符：\n--- 得到 ---\n%s\n--- 預期 ---\n%s", name, got, want)
	}
}

func TestRenderGolden(t *testing.T) {
	wantCode := map[string]Code{
		"a_ok": OK, "b_dns": DNSCode, "c_nolink": NoLink, "c_router": RouterOrISP,
		"d_portal": Portal, "e_site_company": SiteCode, "f_nodhcp": NoDHCP, "g_clock": Clock,
		"h_vpn": VPNBroken, "i_proxy": ProxyCode, "i_proxypac": ProxyPACCode, "j_isp": ISP,
		"k_tls": TLSIntercept, "l_filtered": Filtered, "m_unstable": Unstable, "n_unknown": Unknown,
	}
	for name, mk := range screens() {
		f, cfg := mk()
		r := decide(f, cfg)
		if r.Verdict.Code != wantCode[name] {
			t.Errorf("%s 結論 = %s，預期 %s", name, r.Verdict.Code, wantCode[name])
		}
		for mode, m := range map[string]renderMode{"emoji": {Emoji: true}, "plain": {}} {
			var b bytes.Buffer
			render(&b, r, "macOS", fixedTime, m)
			checkGolden(t, name+"."+mode, b.Bytes())
		}
	}
}

func TestRenderDetailAndColor(t *testing.T) {
	f := healthy()
	var b bytes.Buffer
	render(&b, decide(f, Config{}), "macOS", fixedTime, renderMode{Color: true, Detail: true})
	out := b.String()
	for _, want := range []string{"\x1b[32m[正常]\x1b[0m", "· 路由器位址：192.168.1.1，ICMP 有回應", "· 1.1.1.1:443：成功"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("輸出缺少 %q：\n%s", want, out)
		}
	}
}

func TestRenderJSON(t *testing.T) {
	f := healthy()
	var b bytes.Buffer
	if err := renderJSON(&b, decide(f, Config{}), f, fixedTime); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["verdict"].(map[string]any)["code"] != "OK" || got["lights"].([]any)[0].(map[string]any)["status"] != "green" {
		t.Errorf("JSON 內容不符：%s", b.String())
	}
}

func TestRenderEmojiStatusWordAndOrg(t *testing.T) {
	f := healthy()
	f.Sites = append(f.Sites, Site{Name: "公司 ERP", Probe: Probe{Target: "https://erp.example.com", Err: ErrTimeout}})
	var b bytes.Buffer
	render(&b, decide(f, Config{Org: "範例公司", Contact: map[string]string{"default": "IT 服務台"}}), "macOS", fixedTime, renderMode{Emoji: true})
	out := b.String()
	if !bytes.Contains([]byte(out), []byte("🟢 正常 本機網路")) {
		t.Errorf("emoji 模式第一盞燈應以「🟢 正常 」開頭：\n%s", out)
	}
	if !bytes.Contains([]byte(out), []byte("聯絡（範例公司）：IT 服務台")) {
		t.Errorf("聯絡行應顯示公司名稱：\n%s", out)
	}
}
