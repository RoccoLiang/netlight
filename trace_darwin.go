//go:build darwin

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"slices"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// traceSendGap：macOS 的 DGRAM ICMP socket 實際送出時間晚於 WriteTo 呼叫，
// SetTTL 與下一次送出之間需要間隔，否則全部封包會用到最後設定的 TTL
const traceSendGap = 50 * time.Millisecond

// traceRoute：macOS 以單一非特權 ICMP DGRAM socket 送出 TTL 1～maxHops 的 echo，
// 中間路由器的 Time Exceeded 會直接以 ReadFrom 收到（來源位址即該站）
func traceRoute(ctx context.Context, target string, maxHops int) ([]Hop, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, traceTimeout)
		defer cancel()
	}
	dst := &net.UDPAddr{IP: net.ParseIP(target)}
	if dst.IP == nil || dst.IP.To4() == nil {
		return nil, errors.New("路由追蹤僅支援 IPv4 位址")
	}
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EPROTONOSUPPORT) {
			return nil, errICMPUnavailable
		}
		return nil, err
	}
	defer c.Close()
	// ctx 結束時立即關閉 socket 中斷讀取（同 icmpPing 寫法）
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}

	// 送出 TTL 1～maxHops 的 echo（seq = base+ttl，回來時可反推該站的 TTL）；
	// 間隔送出讓每個封包套用各自的 TTL（見 traceSendGap），並在背景送出以便同時讀取
	pc := c.IPv4PacketConn()
	base := int(time.Now().UnixNano() & 0x3fff)
	sent := make([]time.Time, maxHops+1)
	var sentMu sync.Mutex // 送出與讀取在不同 goroutine，保護 sent
	go func() {
		for ttl := 1; ttl <= maxHops; ttl++ {
			if err := pc.SetTTL(ttl); err != nil {
				return
			}
			msg, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: base + ttl, Data: []byte("netlight")}}).Marshal(nil)
			if err != nil {
				return
			}
			sentMu.Lock()
			sent[ttl] = time.Now()
			sentMu.Unlock()
			if _, err := c.WriteTo(msg, dst); err != nil {
				return
			}
			if ttl < maxHops {
				select {
				case <-ctx.Done():
				case <-time.After(traceSendGap):
				}
			}
		}
	}()

	received := make([]bool, maxHops+1)
	reachedTTL := 0
	finished := func() bool { // 已抵達且較小的 TTL 都有回應 → 可結束
		if reachedTTL == 0 {
			return false
		}
		for i := 1; i < reachedTTL; i++ {
			if !received[i] {
				return false
			}
		}
		return true
	}
	var hops []Hop
	buf := make([]byte, 1500)
loop:
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			break // ctx 結束（socket 被關閉）或其他讀取錯誤
		}
		b := buf[:n]
		// macOS 的 ICMP 錯誤訊息（Time Exceeded）會帶完整 IP 封包，先剝掉外層標頭
		if b[0]>>4 == 4 {
			if hl := int(b[0]&0x0f) * 4; hl+8 <= len(b) {
				b = b[hl:]
			}
		}
		m, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), b)
		if err != nil {
			continue
		}
		switch m.Type {
		case ipv4.ICMPTypeTimeExceeded: // 中間路由器回報 TTL 超過
			te, ok := m.Body.(*icmp.TimeExceeded)
			if !ok {
				continue
			}
			seq, ok := innerEchoSeq(te.Data)
			if !ok {
				continue
			}
			if ttl := seq - base; ttl >= 1 && ttl <= maxHops && !received[ttl] {
				received[ttl] = true
				sentMu.Lock()
				ms := time.Since(sent[ttl]).Milliseconds()
				sentMu.Unlock()
				hops = append(hops, Hop{TTL: ttl, IP: from.(*net.UDPAddr).IP.String(), Ms: ms})
				if finished() {
					break loop
				}
			}
		case ipv4.ICMPTypeEchoReply: // 抵達目的地
			e, ok := m.Body.(*icmp.Echo)
			if !ok {
				continue
			}
			if ttl := e.Seq - base; ttl >= 1 && ttl <= maxHops && from.(*net.UDPAddr).IP.Equal(dst.IP) && !received[ttl] {
				received[ttl] = true
				reachedTTL = ttl
				sentMu.Lock()
				ms := time.Since(sent[ttl]).Milliseconds()
				sentMu.Unlock()
				hops = append(hops, Hop{TTL: ttl, IP: from.(*net.UDPAddr).IP.String(), Ms: ms, Reached: true})
				if finished() {
					break loop
				}
			}
		}
	}
	slices.SortStableFunc(hops, func(a, b Hop) int { return a.TTL - b.TTL })
	return hops, nil
}
