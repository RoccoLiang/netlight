package main

import (
	"context"
	"os"
	"strings"
	"time"
)

func osName() string {
	for _, line := range strings.Split(readFile("/etc/os-release"), "\n") {
		if v, ok := strings.CutPrefix(line, "NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return "Linux"
}

func platformLocal(ctx context.Context, lo *Local) {
	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		lo.Gateway = parseProcRoute(string(b), lo.Iface)
	} else {
		lo.GatewayUnknown = true
	}
	dns := parseResolvConf(readFile("/etc/resolv.conf"))
	// Ubuntu 的 systemd-resolved 本機 stub，真正的上游伺服器在另一個檔案
	if len(dns) == 1 && dns[0] == "127.0.0.53" {
		if real := parseResolvConf(readFile("/run/systemd/resolve/resolv.conf")); len(real) > 0 {
			dns = real
		}
	}
	lo.DNSServers = dns
	lo.Kind = "有線網路"
	if _, err := os.Stat("/sys/class/net/" + lo.Iface + "/wireless"); err == nil {
		lo.Kind = "Wi-Fi"
	}
	if strings.Contains(strings.ToLower(readFile("/proc/sys/kernel/osrelease")), "microsoft") {
		lo.Notes = append(lo.Notes, "偵測到 WSL：檢查到的是虛擬網路，不是 Windows 實際使用的網路，請改用 Windows 版")
	}
	lo.Proxy = parseGsettingsProxy(
		command(ctx, "gsettings", "get", "org.gnome.system.proxy", "mode"),
		command(ctx, "gsettings", "get", "org.gnome.system.proxy.https", "host"),
		command(ctx, "gsettings", "get", "org.gnome.system.proxy.https", "port"),
		command(ctx, "gsettings", "get", "org.gnome.system.proxy", "autoconfig-url"),
		command(ctx, "gsettings", "get", "org.gnome.system.proxy", "ignore-hosts"))
}

// arpProbe：主動探測後再檢查一次 ARP 鄰居狀態（同時進行的 ICMP／TCP 探測會觸發 ARP 解析）
func arpProbe(ctx context.Context, ip string) bool {
	if parseIPNeigh(command(ctx, "ip", "-4", "neigh", "show", ip)) {
		return true
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(400 * time.Millisecond):
	}
	return parseIPNeigh(command(ctx, "ip", "-4", "neigh", "show", ip))
}
