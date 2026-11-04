//go:build windows

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
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

// traceRoute：每個 TTL 一個 goroutine，以 IcmpSendEcho＋IP_OPTION_INFORMATION{Ttl} 送出。
// IcmpSendEcho 是阻斷式呼叫，無法中斷，因此各 goroutine 把結果送進容量為 maxHops 的
// channel（永不阻塞），主流程達成結束條件（已抵達且較小 TTL 都已收到，或所有 TTL 都已
// 回報）或 ctx 結束時立即回傳，不等待尚未返回的 goroutine；這些 goroutine 最多再執行
// 約 2 秒，只對 channel 傳送結果，不碰回傳的切片。handle 由各 goroutine 在自己的呼叫
// 結束後自行關閉（Windows 上的例外：spec「回傳前關閉所有 handle」在此改為「各 goroutine
// 結束時自行關閉」）。
// 每個 TTL 不論成功、失敗（IcmpCreateFile 失敗、IcmpSendEcho 回傳 0、未處理的 Status）
// 都會回報一筆結果，主流程以「已回報的 TTL 數」判斷全部結束，以「有 hop 的 TTL」判斷
// 已抵達與較小 TTL 是否齊全。
func traceRoute(ctx context.Context, target string, maxHops int) ([]Hop, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, traceTimeout)
		defer cancel()
	}
	v4 := net.ParseIP(target).To4()
	if v4 == nil {
		return nil, errors.New("路由追蹤僅支援 IPv4 位址")
	}

	type result struct {
		ttl int
		hop *Hop // nil 表示這一站沒有結果（失敗或無回應）
	}
	results := make(chan result, maxHops) // 容量 maxHops：各 goroutine 傳送永不阻塞
	unavailable := make(chan struct{})    // IcmpCreateFile 失敗
	var unavailableOnce sync.Once
	for ttl := 1; ttl <= maxHops; ttl++ {
		go func(ttl int) {
			h, _, _ := procIcmpCreate.Call()
			if windows.Handle(h) == windows.InvalidHandle {
				results <- result{ttl, nil}
				unavailableOnce.Do(func() { close(unavailable) })
				return
			}
			defer procIcmpClose.Call(h)
			// 逾時最多 2 秒，且不超過 ctx 剩餘時間
			wait := 2000 * time.Millisecond
			if dl, ok := ctx.Deadline(); ok {
				wait = min(wait, time.Until(dl))
			}
			if wait <= 0 {
				results <- result{ttl, nil}
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
				results <- result{ttl, nil}
				return
			}
			r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
			var b [4]byte // Address 的 4 個位址 byte 還原成 IP 字串
			binary.LittleEndian.PutUint32(b[:], r.Address)
			switch r.Status {
			case 11013: // IP_TTL_EXPIRED_TRANSIT：回應的就是這一站的路由器
				results <- result{ttl, &Hop{TTL: ttl, IP: net.IP(b[:]).String(), Ms: int64(r.RoundTripTime)}}
			case 0: // 抵達目的地
				results <- result{ttl, &Hop{TTL: ttl, IP: net.IP(b[:]).String(), Ms: int64(r.RoundTripTime), Reached: true}}
			default: // 未處理的 Status：視為這一站沒有結果
				results <- result{ttl, nil}
			}
		}(ttl)
	}

	hops := make([]*Hop, maxHops+1) // index = TTL（0 不用）；nil 表示該站沒有結果
	reachedTTL := 0
	reported := 0             // 已回報的 TTL 數（不論有沒有 hop）
	finished := func() bool { // 已抵達且較小的 TTL 都有結果 → 可結束
		if reachedTTL == 0 {
			return false
		}
		for i := 1; i < reachedTTL; i++ {
			if hops[i] == nil {
				return false
			}
		}
		return true
	}
	collect := func() []Hop {
		var out []Hop
		for ttl := 1; ttl <= maxHops; ttl++ { // 依 TTL 由小到大
			if hops[ttl] != nil {
				out = append(out, *hops[ttl])
			}
		}
		return out
	}
	for reported < maxHops { // 所有 TTL 都已回報時結束；沒回報的由 ctx 期限收尾
		select {
		case <-ctx.Done():
			return collect(), nil
		case <-unavailable:
			return nil, errICMPUnavailable
		case r := <-results:
			reported++
			if r.hop != nil && hops[r.ttl] == nil {
				hops[r.ttl] = r.hop
				if r.hop.Reached && (reachedTTL == 0 || r.ttl < reachedTTL) { // 只記最小的抵達 TTL
					reachedTTL = r.ttl
				}
			}
			if finished() {
				return collect(), nil
			}
		}
	}
	return collect(), nil
}
