//go:build darwin

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// traceEchoID：路由追蹤的 echo ID，避開 icmpPing 使用的 os.Getpid() & 0xffff
var traceEchoID = (os.Getpid() + 1) & 0xffff

// traceRoute：macOS 以非特權 ICMP DGRAM socket 送出 TTL 1～maxHops 的 echo，
// 中間路由器的 Time Exceeded 會直接以 ReadFrom 收到（來源位址即該站）。
// macOS 上同一個 socket 連續 SetTTL 會讓尚未真正送出的封包用到最後設定的 TTL，
// 因此每個 TTL 開一個 socket，開啟後只設定一次 TTL 再送出。
// 此外 macOS 會把收到的所有 ICMP 訊息送給每一個 ICMP DGRAM socket，
// 所以每個 socket 都會收到其他 TTL 的回覆，以序號反推 TTL 並去除重複。
func traceRoute(ctx context.Context, target string, maxHops int) ([]Hop, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, traceTimeout)
		defer cancel()
	}
	deadline, _ := ctx.Deadline() // 函式開頭已確保 ctx 有期限
	dst := &net.UDPAddr{IP: net.ParseIP(target)}
	if dst.IP == nil || dst.IP.To4() == nil {
		return nil, errors.New("路由追蹤僅支援 IPv4 位址")
	}

	type tracer struct {
		c   *icmp.PacketConn
		ttl int
	}
	var mu sync.Mutex // 保護 tracers（協調 goroutine 可能同時關閉 socket）
	tracers := make([]*tracer, 0, maxHops)
	closeAll := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, tr := range tracers {
			tr.c.Close()
		}
	}

	// 共用的結果狀態（每個 socket 的讀取 goroutine 都會寫入）
	var rmu sync.Mutex
	received := make([]bool, maxHops+1) // index = TTL
	hops := make([]Hop, maxHops+1)
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
	done := make(chan struct{}) // 結束條件達成
	var doneOnce sync.Once
	record := func(ttl int, hop Hop) {
		rmu.Lock()
		defer rmu.Unlock()
		if received[ttl] { // 已記錄的 TTL 不再加入（同一回覆會送到每個 socket）
			return
		}
		received[ttl], hops[ttl] = true, hop
		if hop.Reached && (reachedTTL == 0 || ttl < reachedTTL) { // 只記最小的抵達 TTL
			reachedTTL = ttl
		}
		if finished() {
			doneOnce.Do(func() { close(done) })
		}
	}

	// 讀取 goroutine 的收尾：等全部結束後通知 readersDone（只會關一次）
	var wg sync.WaitGroup
	readersDone := make(chan struct{})
	var readersOnce sync.Once
	readersFinished := func() {
		wg.Wait()
		readersOnce.Do(func() { close(readersDone) })
	}

	// 協調 goroutine：在第一次送出之前啟動；ctx 結束或結束條件達成時關閉所有 socket
	// 中斷讀取，並在所有讀取 goroutine 結束後退出（讀取 goroutine 自行全部結束時
	// 經由 readersDone 直接退出，不關閉 socket）。
	abandon := make(chan struct{}) // 送出階段失敗，提早回傳時通知協調 goroutine 退出
	coordExited := make(chan struct{})
	go func() {
		defer close(coordExited)
		select {
		case <-ctx.Done():
		case <-done:
		case <-readersDone:
			return
		case <-abandon:
			return
		}
		closeAll()
		<-readersDone
	}()
	// 送出階段失敗時的收尾：通知協調 goroutine 退出、關閉所有 socket、等讀取 goroutine 結束
	abort := func(err error) ([]Hop, error) {
		close(abandon)
		closeAll()
		readersFinished()
		<-coordExited
		return nil, err
	}

	// 每個 TTL 一個 socket：開啟後先以 ctx 期限設定讀寫期限（送出受期限保護），
	// 再只 SetTTL 一次送出，TTL 才會正確
	base := int(time.Now().UnixNano() & 0x3fff)
	sent := make([]time.Time, maxHops+1) // index = TTL
	for ttl := 1; ttl <= maxHops; ttl++ {
		c, err := icmp.ListenPacket("udp4", "0.0.0.0")
		if err != nil {
			if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EPROTONOSUPPORT) {
				return abort(errICMPUnavailable)
			}
			return abort(err)
		}
		if err := c.SetDeadline(deadline); err != nil {
			c.Close()
			return abort(err)
		}
		if err := c.IPv4PacketConn().SetTTL(ttl); err != nil {
			c.Close()
			return abort(err)
		}
		tr := &tracer{c: c, ttl: ttl}
		msg, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: traceEchoID, Seq: base + ttl, Data: []byte("netlight")}}).Marshal(nil)
		if err != nil {
			c.Close()
			return abort(err)
		}
		sent[ttl] = time.Now()
		if _, err := c.WriteTo(msg, dst); err != nil {
			c.Close()
			if ctx.Err() != nil { // 期限已到（送出受 SetDeadline 保護）
				return abort(ctx.Err())
			}
			return abort(err)
		}
		mu.Lock()
		tracers = append(tracers, tr)
		mu.Unlock()
	}

	// 每個 socket 一個讀取 goroutine；socket 關閉（結束時）、期限到或讀取錯誤時結束
	for _, tr := range tracers {
		wg.Add(1)
		go func(tr *tracer) {
			defer wg.Done()
			buf := make([]byte, 1500)
			for {
				n, from, err := tr.c.ReadFrom(buf)
				if err != nil {
					return // socket 關閉（結束時）、期限到或其他讀取錯誤
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
					id, seq, ok := innerEcho(te.Data)
					if !ok || id != traceEchoID { // macOS 不改寫 ID，可比對是不是自己的 echo
						continue
					}
					if ttl := seq - base; ttl >= 1 && ttl <= maxHops {
						record(ttl, Hop{TTL: ttl, IP: from.(*net.UDPAddr).IP.String(), Ms: time.Since(sent[ttl]).Milliseconds()})
					}
				case ipv4.ICMPTypeEchoReply: // 抵達目的地
					e, ok := m.Body.(*icmp.Echo)
					if !ok || e.ID != traceEchoID {
						continue
					}
					if ttl := e.Seq - base; ttl >= 1 && ttl <= maxHops && from.(*net.UDPAddr).IP.Equal(dst.IP) {
						record(ttl, Hop{TTL: ttl, IP: from.(*net.UDPAddr).IP.String(), Ms: time.Since(sent[ttl]).Milliseconds(), Reached: true})
					}
				}
			}
		}(tr)
	}
	readersFinished() // 等所有讀取 goroutine 結束並通知協調 goroutine
	<-coordExited     // 等協調 goroutine 結束
	closeAll()        // 保險：讀取 goroutine 自行結束的路徑不會由協調 goroutine 關閉 socket

	var out []Hop
	for ttl := 1; ttl <= maxHops; ttl++ { // 依 TTL 由小到大
		if received[ttl] {
			out = append(out, hops[ttl])
		}
	}
	return out, nil
}
