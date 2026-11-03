package main

// 各平台文字輸出的解析器。不加 build tag，任何平台都能跑測試。

import (
	"encoding/hex"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"
)

// parseProcRoute：解析 Linux /proc/net/route，取指定介面 metric 最小的預設路由；
// 該介面沒有時取所有介面中 metric 最小者
func parseProcRoute(s, iface string) string {
	type candidate struct {
		ip     string
		metric int
	}
	var same, any []candidate
	for _, line := range strings.Split(s, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		b, err := hex.DecodeString(f[2])
		if err != nil || len(b) != 4 {
			continue
		}
		slices.Reverse(b) // 核心以小端序儲存
		ip := net.IP(b)
		if ip.IsUnspecified() {
			continue
		}
		metric, err := strconv.Atoi(f[6])
		if err != nil {
			metric = math.MaxInt // 無法解析的列當作最大值
		}
		if f[0] == iface {
			same = append(same, candidate{ip.String(), metric})
		}
		any = append(any, candidate{ip.String(), metric})
	}
	best := func(cs []candidate) string {
		if len(cs) == 0 {
			return ""
		}
		out := cs[0]
		for _, c := range cs[1:] {
			if c.metric < out.metric {
				out = c
			}
		}
		return out.ip
	}
	if got := best(same); got != "" {
		return got
	}
	return best(any)
}

func parseResolvConf(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}

// parseScutilProxy：解析 macOS `scutil --proxy` 的輸出（含 ExceptionsList 例外清單）
func parseScutilProxy(s string) Proxy {
	kv := map[string]string{}
	var exceptions []string
	inArray := false
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if inArray {
			if t == "}" {
				inArray = false
			} else if i := strings.Index(t, ": "); i >= 0 {
				if v := strings.TrimSpace(t[i+2:]); v != "" {
					exceptions = append(exceptions, v)
				}
			}
			continue
		}
		if strings.HasPrefix(t, "ExceptionsList : <array> {") {
			inArray = true
			continue
		}
		if k, v, ok := strings.Cut(t, " : "); ok {
			kv[k] = v
		}
	}
	switch {
	case kv["HTTPSEnable"] == "1" && kv["HTTPSProxy"] != "":
		addr := kv["HTTPSProxy"]
		if kv["HTTPSPort"] != "" {
			addr = net.JoinHostPort(addr, kv["HTTPSPort"])
		}
		return Proxy{Mode: ProxyExplicit, Addr: addr, Bypass: exceptions}
	case kv["ProxyAutoConfigEnable"] == "1":
		return Proxy{Mode: ProxyPAC, Addr: kv["ProxyAutoConfigURLString"], Bypass: exceptions}
	case kv["ProxyAutoDiscoveryEnable"] == "1":
		return Proxy{Mode: ProxyPAC, Addr: "WPAD 自動偵測", Bypass: exceptions}
	}
	return Proxy{}
}

// parseHardwarePorts：從 `networksetup -listallhardwareports` 找出介面的中文類型
func parseHardwarePorts(s, dev string) string {
	port := ""
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, "Hardware Port: "); ok {
			port = v
		} else if v, ok := strings.CutPrefix(line, "Device: "); ok && v == dev {
			return portKind(port)
		}
	}
	return ""
}

func portKind(port string) string {
	switch {
	case strings.Contains(port, "Wi-Fi"):
		return "Wi-Fi"
	case strings.Contains(port, "iPhone"), strings.Contains(port, "iPad"):
		return "手機網路共享"
	case strings.Contains(port, "Ethernet"), strings.Contains(port, "LAN"):
		return "有線網路"
	}
	return port
}

// parseWinProxyServer：Windows 登錄檔 ProxyServer 可能是 "host:port" 或 "http=...;https=..."
func parseWinProxyServer(s string) string {
	if !strings.Contains(s, "=") {
		return strings.TrimPrefix(strings.TrimPrefix(s, "http://"), "https://")
	}
	for _, part := range strings.Split(s, ";") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "https="); ok {
			return v
		}
	}
	return ""
}

// parseIPNeigh：Linux `ip -4 neigh show` 的輸出中是否有任一鄰居狀態為 REACHABLE
func parseIPNeigh(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[len(f)-1] == "REACHABLE" {
			return true
		}
	}
	return false
}

// parseGsettingsProxy：解析 GNOME 代理設定（各參數為 gsettings get 的原始輸出，含引號與換行）
func parseGsettingsProxy(mode, host, port, pac, ignore string) Proxy {
	clean := func(s string) string {
		return strings.Trim(strings.ReplaceAll(s, "\n", ""), "'")
	}
	switch clean(mode) {
	case "manual":
		if h := clean(host); h != "" {
			p := Proxy{Mode: ProxyExplicit, Addr: h, Bypass: parseGsettingsIgnore(ignore)}
			if v := clean(port); v != "" && v != "0" {
				p.Addr = net.JoinHostPort(h, v)
			}
			return p
		}
	case "auto":
		addr := clean(pac)
		if addr == "" {
			addr = "WPAD 自動偵測"
		}
		return Proxy{Mode: ProxyPAC, Addr: addr, Bypass: parseGsettingsIgnore(ignore)}
	}
	return Proxy{}
}

// parseGsettingsIgnore：解析 ignore-hosts（gsettings 陣列格式，如 ['localhost', '127.0.0.0/8']；空陣列為 @as []）
func parseGsettingsIgnore(ignore string) []string {
	start := strings.Index(ignore, "[")
	end := strings.LastIndex(ignore, "]")
	if start < 0 || end <= start {
		return nil
	}
	var out []string
	for _, part := range strings.Split(ignore[start+1:end], ",") {
		if v := strings.Trim(strings.TrimSpace(part), "'"); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// bypassed：主機是否符合代理例外規則（NO_PROXY、macOS ExceptionsList、Windows ProxyOverride、GNOME ignore-hosts）
func bypassed(host string, rules []string) bool {
	for _, rule := range rules {
		r := strings.TrimSpace(rule)
		if r == "" {
			continue
		}
		switch {
		case r == "*":
			return true
		case strings.EqualFold(r, "<local>"):
			if !strings.Contains(host, ".") {
				return true
			}
		case strings.Contains(r, "/"):
			if ip := net.ParseIP(host); ip != nil {
				if cidr, ok := expandCIDR(r); ok {
					if cidr.Contains(ip) {
						return true
					}
				}
			}
		default:
			if matchHostRule(host, r) {
				return true
			}
		}
	}
	return false
}

// expandCIDR：補齊 macOS 簡寫的 IPv4 段數（169.254/16 → 169.254.0.0/16）再解析
func expandCIDR(r string) (*net.IPNet, bool) {
	sep := strings.Index(r, "/")
	ipPart, mask := r[:sep], r[sep+1:]
	if !strings.Contains(ipPart, ":") { // IPv4 才補簡寫
		for strings.Count(ipPart, ".") < 3 {
			ipPart += ".0"
		}
	}
	_, cidr, err := net.ParseCIDR(ipPart + "/" + mask)
	if err != nil {
		return nil, false
	}
	return cidr, true
}

// matchHostRule：比對字尾（*.example 或 .example）與完全相同的規則；
// 「其他」規則（不以 * 或 . 開頭）也涵蓋子網域（與 curl／Go 的 NO_PROXY 慣例一致）
func matchHostRule(host, rule string) bool {
	// 規則帶埠時只比對主機部分
	if h, _, err := net.SplitHostPort(rule); err == nil {
		rule = h
	}
	host, rule = strings.ToLower(host), strings.ToLower(rule)
	switch {
	case strings.HasPrefix(rule, "*."):
		rest := rule[1:] // ".example"
		return strings.HasSuffix(host, rest) || host == rest[1:]
	case strings.HasPrefix(rule, "."):
		return strings.HasSuffix(host, rule) || host == rule[1:]
	}
	// 純 IP 規則：以 ParseIP 比較（2001:db8::1 與 2001:0db8::1 視為相同）
	if rip := net.ParseIP(rule); rip != nil {
		return net.ParseIP(host).Equal(rip)
	}
	return host == rule || strings.HasSuffix(host, "."+rule)
}

// bypassAll：任一規則為 * 時代表全部直連（視同沒有代理）
func bypassAll(rules []string) bool {
	for _, r := range rules {
		if strings.TrimSpace(r) == "*" {
			return true
		}
	}
	return false
}

// parseScutilDNS：解析 macOS `scutil --dns`，取第一個沒有 domain 行的 resolver 之所有 nameserver。
// 只看 "DNS configuration" 段（遇到 "DNS configuration (for scoped queries)" 就停止）
func parseScutilDNS(s string) []string {
	var out []string
	inConfig := false // 在 "DNS configuration" 段內
	inBlock := false  // 在某個 resolver 區塊內
	hasDomain := false
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "DNS configuration") {
			if strings.Contains(t, "(for scoped queries)") {
				break
			}
			inConfig = true
			continue
		}
		if !inConfig {
			continue
		}
		f := strings.Fields(t)
		// resolver #N 行：前一個區塊結束。若該區塊沒有 domain，它就是目標區塊，
		// 不論有沒有 nameserver 都在此停止（沒有則回 nil，由呼叫端退回 resolv.conf）
		if len(f) == 2 && f[0] == "resolver" {
			if inBlock && !hasDomain {
				return out
			}
			out, hasDomain, inBlock = nil, false, true
			continue
		}
		if len(f) >= 2 && f[0] == "domain" {
			hasDomain = true
		}
		if len(f) >= 3 && strings.HasPrefix(f[0], "nameserver[") {
			out = append(out, f[len(f)-1])
		}
	}
	// 段結束或輸入結束：最後一個區塊沒有 domain 時，它就是目標區塊
	if inBlock && !hasDomain {
		return out
	}
	return nil
}

// parseCFTrace：解析 Cloudflare /cdn-cgi/trace 回應（key=value 每行一組），
// 必須同時有 h= 與合法 ip= 才回 ok
func parseCFTrace(body string) (ip, loc string, ok bool) {
	var haveHost bool
	for _, line := range strings.Split(body, "\n") {
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "h":
			haveHost = v != ""
		case "ip":
			if net.ParseIP(v) != nil {
				ip = v
			}
		case "loc":
			loc = v
		}
	}
	return ip, loc, haveHost && ip != ""
}
