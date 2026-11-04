//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// pollTimeout：每次輪詢最多等 100ms，且不超過 ctx 剩餘時間（至少 1ms）
func pollTimeout(ctx context.Context) int {
	timeout := 100
	if dl, ok := ctx.Deadline(); ok {
		if remain := int(time.Until(dl).Milliseconds()); remain < timeout {
			timeout = remain
		}
	}
	if timeout < 1 {
		timeout = 1
	}
	return timeout
}

// traceRoute：Linux 的非特權 ICMP DGRAM socket 收不到 Time Exceeded 的一般讀取，
// 必須設定 IP_RECVERR 再以 MSG_ERRQUEUE 讀錯誤佇列；每個 TTL 一個 socket 平行處理
func traceRoute(ctx context.Context, target string, maxHops int) ([]Hop, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, traceTimeout)
		defer cancel()
	}
	ip := net.ParseIP(target)
	if ip == nil || ip.To4() == nil {
		return nil, errors.New("路由追蹤僅支援 IPv4 位址")
	}
	var sa unix.SockaddrInet4
	copy(sa.Addr[:], ip.To4())
	// 全部收到（或 ctx 結束）時提早結束所有 goroutine
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var fds []int
	defer func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	}()
	for ttl := 1; ttl <= maxHops; ttl++ {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
		if err != nil {
			if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EPROTONOSUPPORT) {
				return nil, errICMPUnavailable
			}
			return nil, err
		}
		fds = append(fds, fd)
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl); err != nil {
			return nil, err
		}
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
			return nil, err
		}
	}

	// 同時送出 TTL 1～maxHops 的 echo；DGRAM ICMP socket 由核心填 checksum 與 ID
	base := int(time.Now().UnixNano() & 0x3fff)
	sent := make([]time.Time, maxHops+1)
	for ttl := 1; ttl <= maxHops; ttl++ {
		msg := make([]byte, 8+len("netlight"))
		msg[0] = 8 // echo request
		binary.BigEndian.PutUint16(msg[6:8], uint16(base+ttl))
		copy(msg[8:], "netlight")
		sent[ttl] = time.Now()
		if err := unix.Sendto(fds[ttl-1], msg, unix.MSG_DONTWAIT, &sa); err != nil {
			return nil, err
		}
	}

	hops := make([]Hop, maxHops+1) // index = TTL（0 不用）
	got := make([]bool, maxHops+1)
	var mu sync.Mutex
	record := func(ttl int, hop Hop) {
		mu.Lock()
		defer mu.Unlock()
		if got[ttl] {
			return
		}
		got[ttl], hops[ttl] = true, hop
		// 已抵達且較小的 TTL 都有回應 → 提早結束
		for r := 1; r <= maxHops; r++ {
			if !hops[r].Reached {
				continue
			}
			for i := 1; i < r; i++ {
				if !got[i] {
					return
				}
			}
			cancel()
			return
		}
	}
	var wg sync.WaitGroup
	for ttl := 1; ttl <= maxHops; ttl++ {
		wg.Add(1)
		go func(ttl, fd int) {
			defer wg.Done()
			buf := make([]byte, 1500)
			oob := make([]byte, 128)
			for ctx.Err() == nil {
				pfds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR}}
				if _, err := unix.Poll(pfds, pollTimeout(ctx)); err != nil {
					if errors.Is(err, unix.EINTR) {
						continue
					}
					return
				}
				// 錯誤佇列：Time Exceeded 以 IP_RECVERR control message 送達
				if _, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT); err == nil {
					cms, _ := unix.ParseSocketControlMessage(oob[:oobn])
					for _, cm := range cms {
						if cm.Header.Level != unix.IPPROTO_IP || cm.Header.Type != unix.IP_RECVERR {
							continue
						}
						eeSize := int(unsafe.Sizeof(unix.SockExtendedErr{}))
						if len(cm.Data) < eeSize+8 {
							continue
						}
						ee := (*unix.SockExtendedErr)(unsafe.Pointer(&cm.Data[0]))
						if ee.Origin != unix.SO_EE_ORIGIN_ICMP || ee.Type != 11 { // 只取 TTL 超過
							continue
						}
						// offender 的 sockaddr_in 緊接在 SockExtendedErr 之後，位址在其第 4～8 byte
						addr := make(net.IP, 4)
						copy(addr, cm.Data[eeSize+4:eeSize+8])
						record(ttl, Hop{TTL: ttl, IP: addr.String(), Ms: time.Since(sent[ttl]).Milliseconds()})
					}
				}
				// 一般讀取：抵達目的地時收到 type 0 echo reply
				if n, from, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT); err == nil && n >= 8 {
					if f, ok := from.(*unix.SockaddrInet4); ok && buf[0] == 0 &&
						binary.BigEndian.Uint16(buf[6:8]) == uint16(base+ttl) && f.Addr == sa.Addr {
						record(ttl, Hop{TTL: ttl, IP: net.IP(f.Addr[:]).String(), Ms: time.Since(sent[ttl]).Milliseconds(), Reached: true})
					}
				}
			}
		}(ttl, fds[ttl-1])
	}
	wg.Wait()
	var out []Hop
	for ttl := 1; ttl <= maxHops; ttl++ { // 依 TTL 由小到大
		if got[ttl] {
			out = append(out, hops[ttl])
		}
	}
	return out, nil
}
