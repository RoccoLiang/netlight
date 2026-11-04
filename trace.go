package main

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"time"
)

const (
	traceTarget  = "1.1.1.1"
	traceMaxHops = 15
	traceTimeout = 3 * time.Second
)

// traceFn：測試可替換；回傳依 TTL 排序、只含有回應的站；errICMPUnavailable 表示無法執行
var traceFn = traceRoute

// routeProbe：執行路由追蹤並整理成 RouteResult（ctx 另加 traceTimeout 上限）
func routeProbe(ctx context.Context) RouteResult {
	ctx, cancel := context.WithTimeout(ctx, traceTimeout)
	defer cancel()
	r := RouteResult{Target: traceTarget}
	hops, err := traceFn(ctx, traceTarget, traceMaxHops)
	switch {
	case errors.Is(err, errICMPUnavailable):
		r.Unknown = true
	case err != nil:
		// 其他錯誤：Hops 為空
	default:
		r.Hops = sortHops(hops)
	}
	return r
}

// innerEchoSeq：從 Time Exceeded 內附的原始封包（IPv4 標頭＋ICMP 前 8 byte）取出 echo 序號
func innerEchoSeq(data []byte) (int, bool) {
	if len(data) < 8 {
		return 0, false
	}
	if data[0]>>4 != 4 {
		return 0, false
	}
	hl := int(data[0]&0x0f) * 4
	if hl+8 > len(data) {
		return 0, false
	}
	if data[hl] != 8 { // 內層必須是 echo request
		return 0, false
	}
	return int(binary.BigEndian.Uint16(data[hl+6 : hl+8])), true
}

// sortHops：依 TTL 排序、去除重複 TTL（保留第一個）、截斷到第一個 Reached 為止
func sortHops(h []Hop) []Hop {
	slices.SortStableFunc(h, func(a, b Hop) int { return a.TTL - b.TTL })
	var out []Hop
	for _, hop := range h {
		if len(out) > 0 && out[len(out)-1].TTL == hop.TTL {
			continue // 重複 TTL，保留第一個
		}
		out = append(out, hop)
		if hop.Reached {
			break
		}
	}
	return out
}
