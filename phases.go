package main

import (
	"crypto/tls"
	"fmt"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"
)

// SitePhases：一次網站請求的分段耗時（毫秒；-1 表示這次沒有觀察到該階段）
type SitePhases struct {
	DNSMs     int64  `json:"dns_ms"`
	ConnectMs int64  `json:"connect_ms"`
	TLSMs     int64  `json:"tls_ms"`
	WaitMs    int64  `json:"wait_ms"`           // 送出請求後到收到第一個回應位元組
	Reached   string `json:"reached"`           // 最後完成的階段：""、"dns"、"connect"、"tls"、"response"
	Stalled   string `json:"stalled,omitempty"` // 已開始但沒有成功完成的第一個階段："dns"、"connect"、"tls"、"wait"；都沒有則為空
}

// phaseRecorder：收集 httptrace 事件（可並行呼叫，snapshot 之後的事件一律忽略）
type phaseRecorder struct {
	mu     sync.Mutex
	frozen bool

	dnsStart   time.Time
	dnsDoneAt  time.Time
	dnsStarted bool // DNSStart 是否發生過
	dnsDone    bool // DNS 查詢成功完成

	connectStarts  map[string]time.Time // 每個位址嘗試的開始時間
	connectStarted bool                 // 任一 ConnectStart 是否發生過
	connectOK      bool                 // 已有成功的連線
	connectMs      int64                // 第一個成功嘗試的耗時

	tlsStart   time.Time
	tlsDoneAt  time.Time
	tlsStarted bool // TLSHandshakeStart 是否發生過
	tlsDone    bool // TLS 交握成功完成

	waitStart   time.Time
	waitDoneAt  time.Time
	waitStarted bool // WroteRequest 是否成功過
	waitDone    bool // 收到第一個回應位元組
}

func newPhaseRecorder() *phaseRecorder {
	return &phaseRecorder{connectStarts: make(map[string]time.Time)}
}

func (r *phaseRecorder) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			r.mu.Lock()
			if !r.frozen {
				r.dnsStarted, r.dnsStart = true, time.Now()
			}
			r.mu.Unlock()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			r.mu.Lock()
			if !r.frozen && info.Err == nil {
				r.dnsDone, r.dnsDoneAt = true, time.Now()
			}
			r.mu.Unlock()
		},
		ConnectStart: func(network, addr string) {
			r.mu.Lock()
			if !r.frozen {
				r.connectStarted = true
				r.connectStarts[network+addr] = time.Now()
			}
			r.mu.Unlock()
		},
		ConnectDone: func(network, addr string, err error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.frozen || err != nil || r.connectOK {
				return // 只取第一個成功的嘗試；失敗的嘗試不影響
			}
			start, ok := r.connectStarts[network+addr]
			if !ok {
				return
			}
			r.connectOK = true
			r.connectMs = time.Since(start).Milliseconds()
		},
		TLSHandshakeStart: func() {
			r.mu.Lock()
			if !r.frozen {
				// HTTPS 代理等情境會交握兩次：只有最後一次的結果有效
				r.tlsStarted, r.tlsStart, r.tlsDone = true, time.Now(), false
			}
			r.mu.Unlock()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			r.mu.Lock()
			if !r.frozen && err == nil {
				r.tlsDone, r.tlsDoneAt = true, time.Now()
			}
			r.mu.Unlock()
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			r.mu.Lock()
			if !r.frozen && info.Err == nil {
				r.waitStarted, r.waitStart = true, time.Now()
			}
			r.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			r.mu.Lock()
			if !r.frozen {
				r.waitDone, r.waitDoneAt = true, time.Now()
			}
			r.mu.Unlock()
		},
	}
}

// snapshot：結束收集並算出各段耗時；之後任何 hook 都不再改動資料
func (r *phaseRecorder) snapshot() *SitePhases {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frozen = true
	ms := func(start, done time.Time) int64 {
		if done.Before(start) {
			return 0 // 時鐘倒退等極端情況，仍視為成功完成
		}
		return done.Sub(start).Milliseconds()
	}
	p := &SitePhases{DNSMs: -1, ConnectMs: -1, TLSMs: -1, WaitMs: -1}
	if r.dnsStarted && r.dnsDone {
		p.DNSMs = ms(r.dnsStart, r.dnsDoneAt)
	}
	if r.connectOK {
		p.ConnectMs = r.connectMs
	}
	if r.tlsStarted && r.tlsDone {
		p.TLSMs = ms(r.tlsStart, r.tlsDoneAt)
	}
	if r.waitStarted && r.waitDone {
		p.WaitMs = ms(r.waitStart, r.waitDoneAt)
	}
	// Stalled：依序取第一個「開始過、但沒有成功完成」的階段
	switch {
	case r.dnsStarted && !r.dnsDone:
		p.Stalled = "dns"
	case r.connectStarted && !r.connectOK:
		p.Stalled = "connect"
	case r.tlsStarted && !r.tlsDone:
		p.Stalled = "tls"
	case r.waitStarted && !r.waitDone:
		p.Stalled = "wait"
	}
	// Reached：取最後一個成功完成的階段（DNS 沒有發生不影響後面的判斷）
	for _, st := range []struct {
		name string
		ok   bool
	}{
		{"dns", r.dnsDone},
		{"connect", r.connectOK},
		{"tls", r.tlsDone},
		{"response", r.waitDone},
	} {
		if st.ok {
			p.Reached = st.name
		}
	}
	return p
}

// phaseSegments：各段「名稱 <n>ms」的列表（-1 的段省略）
func phaseSegments(p *SitePhases) []string {
	var segs []string
	if p.DNSMs >= 0 {
		segs = append(segs, fmt.Sprintf("DNS %dms", p.DNSMs))
	}
	if p.ConnectMs >= 0 {
		segs = append(segs, fmt.Sprintf("TCP %dms", p.ConnectMs))
	}
	if p.TLSMs >= 0 {
		segs = append(segs, fmt.Sprintf("TLS %dms", p.TLSMs))
	}
	if p.WaitMs >= 0 {
		segs = append(segs, fmt.Sprintf("等待回應 %dms", p.WaitMs))
	}
	return segs
}

// phaseProxyNote：經由代理時的註記
func phaseProxyNote(route string) string {
	if route == "proxy" {
		return "；經由代理時 DNS 與 TCP 是連往代理伺服器"
	}
	return ""
}

// phaseLine：分段計時的證據文字；沒有資料時回傳空字串
func phaseLine(s Site, mode ProxyMode) string {
	if s.Phases == nil {
		return ""
	}
	segs := phaseSegments(s.Phases)
	note := phaseProxyNote(siteRouteOf(s, mode))
	if s.OK {
		if len(segs) == 0 {
			return ""
		}
		return "↳ 分段：" + strings.Join(segs, "、") + note
	}
	stage := map[string]string{
		"dns":     "查網址（DNS）",
		"connect": "建立連線（TCP）",
		"tls":     "加密交握（TLS）",
		"wait":    "等待網站回應",
	}[s.Phases.Stalled]
	if stage == "" {
		// 沒有停住的階段（例如代理位址錯誤而根本沒有撥號）
		if len(segs) == 0 {
			return ""
		}
		return "↳ 分段：" + strings.Join(segs, "、") + note
	}
	line := "↳ 停在：" + stage
	if len(segs) > 0 {
		line += "（已完成：" + strings.Join(segs, "、") + "）"
	}
	return line + note
}
