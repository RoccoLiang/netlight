package main

import (
	"context"
	"net"
	"sync"
	"syscall"

	"golang.org/x/net/route"
)

func osName() string { return "macOS" }
func platformLocal(ctx context.Context, lo *Local) {
	gw, ok := darwinGateway(lo.Iface)
	if !ok {
		lo.GatewayUnknown = true
	}
	lo.Gateway = gw
	lo.DNSServers = parseScutilDNS(command(ctx, "scutil", "--dns"))
	if len(lo.DNSServers) == 0 {
		lo.DNSServers = parseResolvConf(readFile("/etc/resolv.conf"))
	}
	// 兩個外部指令並行執行（各寫不同欄位），最多多花 2 秒；經由 VPN 時不需要硬體類型
	var wg sync.WaitGroup
	wg.Go(func() { lo.Proxy = parseScutilProxy(command(ctx, "scutil", "--proxy")) })
	if lo.VPN == "" {
		wg.Go(func() { lo.Kind = parseHardwarePorts(command(ctx, "networksetup", "-listallhardwareports"), lo.Iface) })
	}
	wg.Wait()
}

// darwinGateway：讀路由表，優先取對外介面上的預設路由（macOS 每個介面都有一條 scoped 預設路由）。
// 第二個回傳值表示讀取是否成功（FetchRIB／ParseRIB 失敗為 false）
func darwinGateway(iface string) (string, bool) {
	b, err := route.FetchRIB(syscall.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return "", false
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, b)
	if err != nil {
		return "", false
	}
	idx := 0
	if it, err := net.InterfaceByName(iface); err == nil {
		idx = it.Index
	}
	unscoped := ""
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_GATEWAY == 0 || len(rm.Addrs) <= syscall.RTAX_NETMASK {
			continue
		}
		dst, ok := rm.Addrs[syscall.RTAX_DST].(*route.Inet4Addr)
		if !ok || dst.IP != [4]byte{} {
			continue
		}
		if mask, ok := rm.Addrs[syscall.RTAX_NETMASK].(*route.Inet4Addr); ok && mask.IP != [4]byte{} {
			continue
		}
		gw, ok := rm.Addrs[syscall.RTAX_GATEWAY].(*route.Inet4Addr)
		if !ok {
			continue
		}
		ip := net.IP(gw.IP[:]).String()
		if rm.Index == idx {
			return ip, true
		}
		if unscoped == "" && rm.Flags&syscall.RTF_IFSCOPE == 0 {
			unscoped = ip
		}
	}
	return unscoped, true
}

func arpProbe(context.Context, string) bool { return false }
