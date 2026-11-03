package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"slices"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func osName() string { return "Windows" }

var vpnWords = []string{"wireguard", "wintun", "tap-", "openvpn", "fortinet", "anyconnect", "pangp", "globalprotect", "juniper", "pulse", "vpn"}

// platformLocal：用 GetAdaptersAddresses 一次取得閘道、DNS 與介面類型（不解析在地化的指令輸出）
func platformLocal(ctx context.Context, lo *Local) {
	a := adapterFor(lo.IP)
	if a == nil {
		lo.GatewayUnknown = true
	} else {
		lo.Iface = windows.UTF16PtrToString(a.FriendlyName)
		desc := strings.ToLower(windows.UTF16PtrToString(a.Description))
		for g := a.FirstGatewayAddress; g != nil; g = g.Next {
			if ip := g.Address.IP(); ip != nil && ip.To4() != nil {
				lo.Gateway = ip.String()
				break
			}
		}
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			if ip := d.Address.IP(); ip != nil {
				lo.DNSServers = append(lo.DNSServers, ip.String())
			}
		}
		// 53 = IF_TYPE_PROP_VIRTUAL（x/sys 沒有此常數）
		isVPN := a.IfType == windows.IF_TYPE_PPP || a.IfType == 53 || a.TunnelType != 0 ||
			slices.ContainsFunc(vpnWords, func(w string) bool { return strings.Contains(desc, w) })
		if isVPN {
			lo.VPN = lo.Iface
		}
		switch a.IfType {
		case windows.IF_TYPE_IEEE80211:
			lo.Kind = "Wi-Fi"
		case windows.IF_TYPE_ETHERNET_CSMACD:
			lo.Kind = "有線網路"
		}
	}
	lo.Proxy = winProxy()
}

func adapterFor(ip string) *windows.IpAdapterAddresses {
	size := uint32(16 * 1024)
	for range 3 {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_GATEWAYS, 0, aa, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil
		}
		for a := aa; a != nil; a = a.Next {
			for u := a.FirstUnicastAddress; u != nil; u = u.Next {
				if u.Address.IP().String() == ip {
					return a
				}
			}
		}
		return nil
	}
	return nil
}

func winProxy() Proxy {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return Proxy{}
	}
	defer k.Close()
	var bypass []string
	if enabled, _, _ := k.GetIntegerValue("ProxyEnable"); enabled == 1 {
		s, _, _ := k.GetStringValue("ProxyServer")
		if addr := parseWinProxyServer(s); addr != "" {
			if o, _, _ := k.GetStringValue("ProxyOverride"); o != "" {
				for _, part := range strings.Split(o, ";") {
					if v := strings.TrimSpace(part); v != "" {
						bypass = append(bypass, v)
					}
				}
			}
			return Proxy{Mode: ProxyExplicit, Addr: addr, Bypass: bypass}
		}
	}
	if pac, _, _ := k.GetStringValue("AutoConfigURL"); pac != "" {
		return Proxy{Mode: ProxyPAC, Addr: pac}
	}
	return Proxy{}
}

var (
	iphlpapi       = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreate = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose  = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSend   = iphlpapi.NewProc("IcmpSendEcho")
	procSendARP    = iphlpapi.NewProc("SendARP")
)

// icmpEchoReply 對應 ICMP_ECHO_REPLY（64 位元版面配置）
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       [16]byte
}

// icmpPing：Windows 的 IcmpSendEcho 不需要系統管理員權限
func icmpPing(ctx context.Context, ip string) error {
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return errICMPUnavailable
	}
	h, _, _ := procIcmpCreate.Call()
	if windows.Handle(h) == windows.InvalidHandle {
		return errICMPUnavailable
	}
	defer procIcmpClose.Call(h)
	data := []byte("netlight")
	reply := make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+len(data)+8)
	// 第一個封包常遺失，最多試 3 次，每次 400ms，且不超過 ctx 期限
	for range 3 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		dl, ok := ctx.Deadline()
		wait := 400 * time.Millisecond
		if ok {
			wait = min(wait, time.Until(dl))
		}
		if wait <= 0 {
			break
		}
		n, _, _ := procIcmpSend.Call(h, uintptr(binary.LittleEndian.Uint32(v4)),
			uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0,
			uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(wait.Milliseconds()))
		if n > 0 && (*icmpEchoReply)(unsafe.Pointer(&reply[0])).Status == 0 {
			return nil
		}
	}
	return errors.New("沒有回應")
}

// arpProbe：以 SendARP 送出 ARP 詢問；ctx 結束時直接回 false（呼叫自然結束後被丟棄）
func arpProbe(ctx context.Context, ip string) bool {
	if ctx.Err() != nil {
		return false
	}
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return false
	}
	type arpResult struct{ ok bool }
	done := make(chan arpResult, 1)
	go func() {
		var mac [2]uint32 // MAC 位址緩衝（6 bytes）
		size := uint32(6)
		n, _, _ := procSendARP.Call(uintptr(binary.LittleEndian.Uint32(v4)), 0,
			uintptr(unsafe.Pointer(&mac[0])), uintptr(unsafe.Pointer(&size)))
		done <- arpResult{ok: n == 0} // 0 = NO_ERROR
	}()
	select {
	case r := <-done:
		return r.ok
	case <-ctx.Done():
		return false
	}
}

func platformErrClass(err error) ErrClass {
	var errno windows.Errno
	if !errors.As(err, &errno) {
		return ErrNone
	}
	switch errno {
	case windows.WSAECONNREFUSED:
		return ErrRefused
	case windows.WSAECONNRESET:
		return ErrReset
	case windows.WSAENETUNREACH, windows.WSAEHOSTUNREACH:
		return ErrUnreachable
	case windows.WSAETIMEDOUT:
		return ErrTimeout
	}
	return ErrNone
}
