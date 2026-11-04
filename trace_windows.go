//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ipOptionInformation 對應 IP_OPTION_INFORMATION（64 位元版面），Ttl 用來設定這一站的 TTL
type ipOptionInformation struct {
	Ttl         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	_           [4]byte
	OptionsData uintptr
}

// traceRoute：每個 TTL 一個 goroutine，以 IcmpSendEcho＋IP_OPTION_INFORMATION{Ttl} 送出
func traceRoute(ctx context.Context, target string, maxHops int) ([]Hop, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, traceTimeout)
		defer cancel()
	}
	v4 := net.ParseIP(target).To4()
	if v4 == nil {
		return nil, errors.New("路由追蹤僅支援 IPv4 位址")
	}
	hops := make([]Hop, maxHops) // index = TTL-1
	got := make([]bool, maxHops)
	var unavailable atomic.Bool
	var mu sync.Mutex
	var wg sync.WaitGroup
	for ttl := 1; ttl <= maxHops; ttl++ {
		wg.Add(1)
		go func(ttl int) {
			defer wg.Done()
			h, _, _ := procIcmpCreate.Call()
			if windows.Handle(h) == windows.InvalidHandle {
				unavailable.Store(true)
				return
			}
			defer procIcmpClose.Call(h)
			// 逾時最多 2 秒，且不超過 ctx 剩餘時間
			wait := 2000 * time.Millisecond
			if dl, ok := ctx.Deadline(); ok {
				wait = min(wait, time.Until(dl))
			}
			if wait <= 0 {
				return
			}
			data := []byte("netlight")
			opts := ipOptionInformation{Ttl: uint8(ttl)}
			reply := make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+len(data)+8)
			n, _, _ := procIcmpSend.Call(h, uintptr(binary.LittleEndian.Uint32(v4)),
				uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
				uintptr(unsafe.Pointer(&opts)),
				uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(wait.Milliseconds()))
			if n == 0 {
				return
			}
			r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
			var b [4]byte // Address 的 4 個位址 byte 還原成 IP 字串
			binary.LittleEndian.PutUint32(b[:], r.Address)
			mu.Lock()
			defer mu.Unlock()
			if got[ttl-1] {
				return
			}
			switch r.Status {
			case 11013: // IP_TTL_EXPIRED_TRANSIT：回應的就是這一站的路由器
				got[ttl-1], hops[ttl-1] = true, Hop{TTL: ttl, IP: net.IP(b[:]).String(), Ms: int64(r.RoundTripTime)}
			case 0: // 抵達目的地
				got[ttl-1], hops[ttl-1] = true, Hop{TTL: ttl, IP: net.IP(b[:]).String(), Ms: int64(r.RoundTripTime), Reached: true}
			}
		}(ttl)
	}
	wg.Wait()
	if unavailable.Load() {
		return nil, errICMPUnavailable
	}
	var out []Hop
	for ttl := 1; ttl <= maxHops; ttl++ { // 依 TTL 由小到大
		if got[ttl-1] {
			out = append(out, hops[ttl-1])
		}
	}
	return out, nil
}
