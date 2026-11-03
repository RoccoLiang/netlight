//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// icmpPing：使用非特權 ICMP socket（macOS 預設允許；Linux 需 ping_group_range 允許）
func icmpPing(ctx context.Context, ip string) error {
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EPROTONOSUPPORT) {
			return errICMPUnavailable
		}
		return err
	}
	defer c.Close()
	// ctx 取消時立即關閉 socket 中斷讀取，不等到 socket 期限
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	dst := &net.UDPAddr{IP: net.ParseIP(ip)}
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	// 第一個封包常因 Wi-Fi 省電或 ARP 解析而遺失，間隔送出 3 個，收到任一個即可
	base := int(time.Now().UnixNano() & 0x7fff)
	go func() {
		for i := range 3 {
			msg, _ := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: base + i, Data: []byte("netlight")}}).Marshal(nil)
			if _, err := c.WriteTo(msg, dst); err != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(300 * time.Millisecond):
			}
		}
	}()
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return err
		}
		m, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), buf[:n])
		if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		// Linux 會改寫 echo ID，只比對序號與來源
		if e, ok := m.Body.(*icmp.Echo); ok && e.Seq >= base && e.Seq < base+3 && from.(*net.UDPAddr).IP.Equal(dst.IP) {
			return nil
		}
	}
}

func platformErrClass(error) ErrClass { return ErrNone }

func readFile(p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}

// command：執行外部指令（2 秒上限、受 ctx 約束），失敗或不存在時回空字串
func command(ctx context.Context, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, name, args...).Output()
	return string(out)
}
