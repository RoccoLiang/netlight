package main

import (
	"reflect"
	"testing"
)

func TestParseProcRoute(t *testing.T) {
	const s = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
		"eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	if got := parseProcRoute(s, "eth0"); got != "10.0.0.1" {
		t.Errorf("eth0 閘道 = %q", got)
	}
	if got := parseProcRoute(s, "wlan0"); got != "192.168.1.1" {
		t.Errorf("wlan0 閘道 = %q", got)
	}
	if got := parseProcRoute(s, "tun0"); got != "10.0.0.1" {
		t.Errorf("介面沒有預設路由時應取 metric 最小者，得到 %q", got)
	}
	if got := parseProcRoute("Iface\tDestination\n", "eth0"); got != "" {
		t.Errorf("沒有預設路由應回空字串，得到 %q", got)
	}
	// 同介面多條預設路由時取 metric 最小者
	const s2 = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n" +
		"eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\n"
	if got := parseProcRoute(s2, "eth0"); got != "10.0.0.1" {
		t.Errorf("同介面應取 metric 最小者，得到 %q", got)
	}
}

func TestParseResolvConf(t *testing.T) {
	const s = "# comment\nnameserver 127.0.0.53\nnameserver  8.8.8.8 \nsearch lan\noptions edns0\n"
	if got := parseResolvConf(s); !reflect.DeepEqual(got, []string{"127.0.0.53", "8.8.8.8"}) {
		t.Errorf("得到 %v", got)
	}
}

func TestParseScutilProxy(t *testing.T) {
	cases := []struct {
		in   string
		want Proxy
	}{
		{"<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 0\n}\n", Proxy{}},
		{"<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n  }\n  HTTPSEnable : 1\n  HTTPSPort : 3128\n  HTTPSProxy : 10.0.0.8\n}\n",
			Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128", Bypass: []string{"*.local"}}},
		{"<dictionary> {\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://wpad/wpad.dat\n}\n",
			Proxy{Mode: ProxyPAC, Addr: "http://wpad/wpad.dat"}},
		{"<dictionary> {\n  ProxyAutoDiscoveryEnable : 1\n}\n", Proxy{Mode: ProxyPAC, Addr: "WPAD 自動偵測"}},
	}
	for _, c := range cases {
		if got := parseScutilProxy(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseScutilProxy = %+v，預期 %+v", got, c.want)
		}
	}
}

func TestParseScutilProxyExceptions(t *testing.T) {
	const s = "<dictionary> {\n" +
		"  ExceptionsList : <array> {\n" +
		"    0 : localhost\n" +
		"    1 : 127.0.0.1\n" +
		"    2 : *.local\n" +
		"    3 : 169.254/16\n" +
		"    4 : 10.0.0.0/8\n" +
		"    5 : 172.16.0.0/12\n" +
		"    6 : 192.168.0.0/16\n" +
		"    7 : 100.64.0.0/10\n" +
		"  }\n" +
		"  FTPPassive : 1\n" +
		"  HTTPEnable : 1\n" +
		"  HTTPPort : 8080\n" +
		"  HTTPProxy : 127.0.0.1\n" +
		"  HTTPSEnable : 1\n" +
		"  HTTPSPort : 8080\n" +
		"  HTTPSProxy : 127.0.0.1\n" +
		"}\n"
	want := Proxy{Mode: ProxyExplicit, Addr: "127.0.0.1:8080", Bypass: []string{
		"localhost", "127.0.0.1", "*.local", "169.254/16",
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
	}}
	if got := parseScutilProxy(s); !reflect.DeepEqual(got, want) {
		t.Errorf("parseScutilProxy = %+v，預期 %+v", got, want)
	}
}

func TestParseHardwarePorts(t *testing.T) {
	const s = "\nHardware Port: Ethernet Adapter (en4)\nDevice: en4\nEthernet Address: aa\n\n" +
		"Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: bb\n\n" +
		"Hardware Port: iPhone USB\nDevice: en7\n\n" +
		"Hardware Port: Thunderbolt Bridge\nDevice: bridge0\n"
	for dev, want := range map[string]string{"en0": "Wi-Fi", "en4": "有線網路", "en7": "手機網路共享", "bridge0": "Thunderbolt Bridge", "en9": ""} {
		if got := parseHardwarePorts(s, dev); got != want {
			t.Errorf("parseHardwarePorts(%s) = %q，預期 %q", dev, got, want)
		}
	}
}

func TestParseWinProxyServer(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.8:3128":                   "10.0.0.8:3128",
		"http=a:80;https=b:8443;ftp=c:21": "b:8443",
		"http=a:80;ftp=c:21":              "",
		"":                                "",
		"http://proxy.corp:8080":          "proxy.corp:8080",
	} {
		if got := parseWinProxyServer(in); got != want {
			t.Errorf("parseWinProxyServer(%q) = %q，預期 %q", in, got, want)
		}
	}
}

func TestBypassed(t *testing.T) {
	cases := []struct {
		host  string
		rules []string
		want  bool
	}{
		{"a.b", []string{"*"}, true},
		{"intranet", []string{"<local>"}, true},
		{"a.b", []string{"<local>"}, false},
		{"169.254.3.4", []string{"169.254/16"}, true},
		{"10.1.2.3", []string{"10.0.0.0/8"}, true},
		{"11.0.0.1", []string{"10.0.0.0/8"}, false},
		{"erp.corp.example", []string{"*.corp.example"}, true},
		{"corp.example", []string{"*.corp.example"}, true},
		{"notcorp.example", []string{"*.corp.example"}, false},
		{"erp.corp.example", []string{".corp.example"}, true},
		{"corp.example", []string{".corp.example"}, true},
		{"notcorp.example", []string{".corp.example"}, false},
		{"localhost", []string{"localhost:8080"}, true},
		{"erp.corp.example", []string{"corp.example"}, true},
		{"notcorp.example", []string{"corp.example"}, false},
		{"2001:0db8::1", []string{"2001:db8::1"}, true},
		{"ERP.Corp.Example", []string{"*.Corp.Example"}, true},
		{"a.b", nil, false},
	}
	for _, c := range cases {
		if got := bypassed(c.host, c.rules); got != c.want {
			t.Errorf("bypassed(%q, %v) = %v，預期 %v", c.host, c.rules, got, c.want)
		}
	}
}

func TestBypassAll(t *testing.T) {
	if !bypassAll([]string{" * "}) {
		t.Error(`bypassAll([" * "]) 應為 true`)
	}
	if bypassAll([]string{"*.local"}) {
		t.Error(`bypassAll(["*.local"]) 應為 false`)
	}
}

func TestParseGsettingsProxy(t *testing.T) {
	// manual
	got := parseGsettingsProxy("'manual'\n", "'proxy.corp'\n", "3128\n", "''\n", "['localhost', '127.0.0.0/8']\n")
	want := Proxy{Mode: ProxyExplicit, Addr: "proxy.corp:3128", Bypass: []string{"localhost", "127.0.0.0/8"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("manual = %+v，預期 %+v", got, want)
	}
	// auto 有 pac
	got = parseGsettingsProxy("'auto'\n", "''\n", "0\n", "'http://wpad/wpad.dat'\n", "@as []\n")
	want = Proxy{Mode: ProxyPAC, Addr: "http://wpad/wpad.dat"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("auto（有 pac）= %+v，預期 %+v", got, want)
	}
	// auto 沒有 pac → WPAD 自動偵測
	got = parseGsettingsProxy("'auto'\n", "''\n", "0\n", "''\n", "@as []\n")
	want = Proxy{Mode: ProxyPAC, Addr: "WPAD 自動偵測"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("auto（沒有 pac）= %+v，預期 %+v", got, want)
	}
	// none → 沒有代理
	if got := parseGsettingsProxy("'none'\n", "'proxy.corp'\n", "3128\n", "''\n", "@as []\n"); !reflect.DeepEqual(got, Proxy{}) {
		t.Errorf("none = %+v，預期空 Proxy", got)
	}
	// manual 但 host 空 → 沒有代理
	if got := parseGsettingsProxy("'manual'\n", "''\n", "0\n", "''\n", "@as []\n"); !reflect.DeepEqual(got, Proxy{}) {
		t.Errorf("manual（host 空）= %+v，預期空 Proxy", got)
	}
	// manual 且 ignore 為 @as [] → Bypass 為 nil，Mode 仍為 Explicit
	got = parseGsettingsProxy("'manual'\n", "'proxy.corp'\n", "3128\n", "''\n", "@as []\n")
	if got.Mode != ProxyExplicit || got.Addr != "proxy.corp:3128" || got.Bypass != nil {
		t.Errorf("manual（@as []）= %+v，預期 Explicit 且 Bypass nil", got)
	}
}

func TestParseIPNeigh(t *testing.T) {
	if !parseIPNeigh("192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n") {
		t.Error("REACHABLE 應為 true")
	}
	for _, s := range []string{
		"192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff STALE\n",
		"192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff FAILED\n",
		"192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff DELAY\n",
		"",
	} {
		if parseIPNeigh(s) {
			t.Errorf("%q 應為 false", s)
		}
	}
}

func TestParseScutilDNS(t *testing.T) {
	// macOS 實機輸出
	const s = "DNS configuration\n" +
		"\n" +
		"resolver #1\n" +
		"  nameserver[0] : 10.10.0.53\n" +
		"  nameserver[1] : 10.10.0.54\n" +
		"  flags    : Request A records\n" +
		"  reach    : 0x00000002 (Reachable)\n" +
		"  order    : 50000\n" +
		"\n" +
		"resolver #2\n" +
		"  domain   : local\n" +
		"  options  : mdns\n" +
		"  timeout  : 5\n" +
		"  flags    : Request A records\n" +
		"  reach    : 0x00000000 (Not Reachable)\n" +
		"  order    : 300000\n" +
		"\n" +
		"DNS configuration (for scoped queries)\n" +
		"\n" +
		"resolver #1\n" +
		"  nameserver[0] : 10.0.0.1\n" +
		"  if_index : 6 (en0)\n"
	if got := parseScutilDNS(s); !reflect.DeepEqual(got, []string{"10.10.0.53", "10.10.0.54"}) {
		t.Errorf("parseScutilDNS = %v，預期 [10.10.0.53 10.10.0.54]", got)
	}
	// 第一個 resolver 有 domain 應跳過、取下一個沒有 domain 的
	const s2 = "DNS configuration\n" +
		"\n" +
		"resolver #1\n" +
		"  domain   : local\n" +
		"  options  : mdns\n" +
		"\n" +
		"resolver #2\n" +
		"  nameserver[0] : 192.168.1.1\n" +
		"\n" +
		"resolver #3\n" +
		"  nameserver[0] : 8.8.8.8\n"
	if got := parseScutilDNS(s2); !reflect.DeepEqual(got, []string{"192.168.1.1"}) {
		t.Errorf("有 domain 的 resolver 應跳過，parseScutilDNS = %v，預期 [192.168.1.1]", got)
	}
	// 沒有任何 nameserver → nil
	if got := parseScutilDNS("DNS configuration\n\nresolver #1\n  domain : local\n"); got != nil {
		t.Errorf("沒有 nameserver 應回 nil，得到 %v", got)
	}
	// 第一個沒有 domain 的 resolver 沒有任何 nameserver：應在此停止回 nil，不得取後面的區塊
	const s3 = "DNS configuration\n" +
		"\n" +
		"resolver #1\n" +
		"  flags    : Request A records\n" +
		"  reach    : 0x00000002 (Reachable)\n" +
		"\n" +
		"resolver #2\n" +
		"  nameserver[0] : 8.8.8.8\n"
	if got := parseScutilDNS(s3); got != nil {
		t.Errorf("第一個無 domain 區塊沒有 nameserver 應回 nil（不取後續區塊），得到 %v", got)
	}
	if got := parseScutilDNS(""); got != nil {
		t.Errorf("空輸入應回 nil，得到 %v", got)
	}
}

func TestParseCFTrace(t *testing.T) {
	const s = "fl=abc\n" +
		"h=www.gov.tw\n" +
		"ip=203.0.113.10\n" +
		"ts=1730000000.123\n" +
		"visit_scheme=https\n" +
		"uag=Mozilla/5.0\n" +
		"colo=TPE\n" +
		"sliver=none\n" +
		"http=http/2\n" +
		"loc=TW\n" +
		"tls=TLSv1.3\n" +
		"sni=plaintext\n" +
		"warp=off\n" +
		"gateway=off\n"
	ip, loc, ok := parseCFTrace(s)
	if !ok || ip != "203.0.113.10" || loc != "TW" {
		t.Errorf("parseCFTrace = %q, %q, %v，預期 203.0.113.10, TW, true", ip, loc, ok)
	}
	// 缺 h= → not ok
	if _, _, ok := parseCFTrace("ip=1.2.3.4\nloc=TW\n"); ok {
		t.Error("缺 h= 應為 not ok")
	}
	// ip 不合法 → not ok
	if _, _, ok := parseCFTrace("h=example.com\nip=not-an-ip\n"); ok {
		t.Error("ip 不合法應為 not ok")
	}
	// HTML 404 頁 → not ok
	if _, _, ok := parseCFTrace("<html><body>404 Not Found</body></html>"); ok {
		t.Error("HTML 404 頁應為 not ok")
	}
}
