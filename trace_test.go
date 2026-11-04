package main

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"time"
)

// echoInner：構造 Time Exceeded 內附的原始封包（IPv4 標頭＋ICMP echo 前 8 byte）
func echoInner(ihl int, typ byte, id, seq int) []byte {
	b := make([]byte, ihl*4+8)
	b[0] = byte(0x40 | ihl)
	b[ihl*4] = typ
	b[ihl*4+4] = byte(id >> 8)
	b[ihl*4+5] = byte(id)
	b[ihl*4+6] = byte(seq >> 8)
	b[ihl*4+7] = byte(seq)
	return b
}

func TestInnerEcho(t *testing.T) {
	if id, seq, ok := innerEcho(echoInner(5, 8, 0x4321, 0x1234)); !ok || id != 0x4321 || seq != 0x1234 {
		t.Errorf("應取出 id 0x4321、seq 0x1234，得到 %#x, %#x, %v", id, seq, ok)
	}
	// IHL 6（24 byte 標頭）也能正確取出
	if id, _, ok := innerEcho(echoInner(6, 8, 0x4321, 0x1234)); !ok || id != 0x4321 {
		t.Errorf("IHL 6 應取出 id 0x4321，得到 %#x, %v", id, ok)
	}
	// IHL 小於 5（不合法的標頭）
	if _, _, ok := innerEcho(echoInner(4, 8, 1, 1)); ok {
		t.Error("IHL 小於 5 應回傳 false")
	}
}

func TestInnerEchoSeq(t *testing.T) {
	if seq, ok := innerEchoSeq(echoInner(5, 8, 0x4321, 0x1234)); !ok || seq != 0x1234 {
		t.Errorf("20 byte 標頭應取出 seq 0x1234，得到 %#x, %v", seq, ok)
	}
	// IHL 6（24 byte 標頭）也能正確取出
	if seq, ok := innerEchoSeq(echoInner(6, 8, 0x4321, 0x1234)); !ok || seq != 0x1234 {
		t.Errorf("IHL 6 應取出 seq 0x1234，得到 %#x, %v", seq, ok)
	}
	// 長度不足（只剩標頭，沒有 ICMP 前 8 byte）
	if _, ok := innerEchoSeq(echoInner(5, 8, 1, 1)[:20]); ok {
		t.Error("長度不足應回傳 false")
	}
	// 版本不是 4
	bad := echoInner(5, 8, 1, 1)
	bad[0] = 0x65 // 版本 6
	if _, ok := innerEchoSeq(bad); ok {
		t.Error("版本不是 4 應回傳 false")
	}
	// 內層 type 不是 8（echo request）
	bad = echoInner(5, 0, 1, 1)
	if _, ok := innerEchoSeq(bad); ok {
		t.Error("內層 type 不是 8 應回傳 false")
	}
	// IHL 小於 5
	bad = echoInner(4, 8, 1, 1)
	if _, ok := innerEchoSeq(bad); ok {
		t.Error("IHL 小於 5 應回傳 false")
	}
}

func TestSortHops(t *testing.T) {
	in := []Hop{
		{TTL: 3, IP: "198.51.100.3"},
		{TTL: 1, IP: "192.0.2.1"},
		{TTL: 1, IP: "192.0.2.9"},                // 重複 TTL，應保留第一個
		{TTL: 2, IP: "192.0.2.2", Reached: true}, // 抵達
		{TTL: 4, IP: "198.51.100.4"},             // 抵達之後的站應被截斷
	}
	want := []Hop{
		{TTL: 1, IP: "192.0.2.1"},
		{TTL: 2, IP: "192.0.2.2", Reached: true},
	}
	if got := sortHops(in); !slices.Equal(got, want) {
		t.Errorf("sortHops = %v，預期 %v", got, want)
	}
}

func TestRouteProbe(t *testing.T) {
	old := traceFn
	t.Cleanup(func() { traceFn = old })

	traceFn = func(context.Context, string, int) ([]Hop, error) {
		return nil, errICMPUnavailable
	}
	if r := routeProbe(context.Background()); !r.Unknown || len(r.Hops) != 0 || r.Target != traceTarget {
		t.Errorf("errICMPUnavailable → Unknown：%+v", r)
	}

	traceFn = func(context.Context, string, int) ([]Hop, error) {
		return nil, errors.New("路由追蹤失敗")
	}
	if r := routeProbe(context.Background()); r.Unknown || len(r.Hops) != 0 || r.Target != traceTarget {
		t.Errorf("一般錯誤 → Hops 為空：%+v", r)
	}

	traceFn = func(ctx context.Context, target string, maxHops int) ([]Hop, error) {
		if target != traceTarget || maxHops != traceMaxHops {
			t.Errorf("收到 target=%q maxHops=%d，預期 %q/%d", target, maxHops, traceTarget, traceMaxHops)
		}
		dl, ok := ctx.Deadline()
		if !ok {
			t.Error("ctx 應有 deadline")
		} else if remain := time.Until(dl); remain > traceTimeout || remain <= 0 {
			t.Errorf("deadline 應不超過 3 秒，剩餘 %s", remain)
		}
		return []Hop{
			{TTL: 2, IP: "203.0.113.2", Ms: 3},
			{TTL: 1, IP: "192.0.2.1", Ms: 1},
		}, nil
	}
	r := routeProbe(context.Background())
	if r.Unknown || r.Target != traceTarget || len(r.Hops) != 2 || r.Hops[0].TTL != 1 || r.Hops[1].TTL != 2 {
		t.Errorf("正常結果應依 TTL 排序：%+v", r)
	}
}

// 實機整合測試：以真正的 traceRoute 追蹤往 1.1.1.1 的路徑
func TestTraceRouteLive(t *testing.T) {
	if testing.Short() {
		t.Skip("-short 時略過實機網路測試")
	}
	ctx, cancel := context.WithTimeout(context.Background(), traceTimeout)
	defer cancel()
	start := time.Now()
	hops, err := traceRoute(ctx, "1.1.1.1", 15)
	if el := time.Since(start); el > 3500*time.Millisecond {
		t.Errorf("耗時 %s，超過 3.5 秒", el)
	}
	if errors.Is(err, errICMPUnavailable) {
		t.Skipf("這台電腦不允許一般權限 ICMP：%v", err)
	}
	if err != nil {
		t.Fatalf("traceRoute 發生錯誤：%v", err)
	}
	if len(hops) == 0 {
		t.Fatal("應至少有一站回應")
	}
	for i, h := range hops {
		if net.ParseIP(h.IP) == nil {
			t.Errorf("第 %d 站 IP 無法解析：%q", i, h.IP)
		}
		if i > 0 && h.TTL <= hops[i-1].TTL {
			t.Errorf("TTL 應遞增：%+v", hops)
		}
	}
}
