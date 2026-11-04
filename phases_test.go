package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http/httptrace"
	"sync"
	"testing"
	"time"
)

// 完整成功的事件序列
func recordFullSuccess(tr *httptrace.ClientTrace) {
	tr.DNSStart(httptrace.DNSStartInfo{})
	tr.DNSDone(httptrace.DNSDoneInfo{})
	tr.ConnectStart("tcp", "192.0.2.1:443")
	tr.ConnectDone("tcp", "192.0.2.1:443", nil)
	tr.TLSHandshakeStart()
	tr.TLSHandshakeDone(tls.ConnectionState{}, nil)
	tr.WroteRequest(httptrace.WroteRequestInfo{})
	tr.GotFirstResponseByte()
}

func TestPhaseRecorderFullSuccess(t *testing.T) {
	r := newPhaseRecorder()
	recordFullSuccess(r.trace())
	p := r.snapshot()
	if p.DNSMs < 0 || p.ConnectMs < 0 || p.TLSMs < 0 || p.WaitMs < 0 {
		t.Errorf("完整成功時四段都應非負：%+v", p)
	}
	if p.Reached != "response" {
		t.Errorf("Reached = %q，預期 \"response\"", p.Reached)
	}
	if p.Stalled != "" {
		t.Errorf("完整成功時 Stalled 應為空：%+v", p)
	}
}

func TestPhaseRecorderTLSFail(t *testing.T) {
	r := newPhaseRecorder()
	tr := r.trace()
	tr.DNSStart(httptrace.DNSStartInfo{})
	tr.DNSDone(httptrace.DNSDoneInfo{})
	tr.ConnectStart("tcp", "192.0.2.1:443")
	tr.ConnectDone("tcp", "192.0.2.1:443", nil)
	tr.TLSHandshakeStart()
	tr.TLSHandshakeDone(tls.ConnectionState{}, errors.New("交握失敗"))
	p := r.snapshot()
	if p.TLSMs != -1 {
		t.Errorf("TLS 失敗時 TLSMs 應為 -1：%+v", p)
	}
	if p.Reached != "connect" {
		t.Errorf("Reached = %q，預期 \"connect\"", p.Reached)
	}
	if p.Stalled != "tls" {
		t.Errorf("Stalled = %q，預期 \"tls\"", p.Stalled)
	}
	if p.DNSMs < 0 || p.ConnectMs < 0 {
		t.Errorf("DNS 與 TCP 已完成，應非負：%+v", p)
	}
}

// 兩個位址並行嘗試：A 先開始但失敗、B 後開始且成功 → ConnectMs 以 B 自己的開始時間計算
func TestPhaseRecorderParallelConnect(t *testing.T) {
	r := newPhaseRecorder()
	tr := r.trace()
	tr.ConnectStart("tcp", "192.0.2.10:443") // A
	time.Sleep(30 * time.Millisecond)
	tr.ConnectStart("tcp", "192.0.2.11:443") // B
	tr.ConnectDone("tcp", "192.0.2.10:443", errors.New("A 失敗"))
	tr.ConnectDone("tcp", "192.0.2.11:443", nil)
	p := r.snapshot()
	if p.ConnectMs < 0 || p.ConnectMs > 20 {
		t.Errorf("ConnectMs = %d，應以 B 自己的開始時間計算（介於 0～20ms）", p.ConnectMs)
	}
}

// 只有 connect（沒有 DNS，例如網址是 IP）
func TestPhaseRecorderConnectOnly(t *testing.T) {
	r := newPhaseRecorder()
	tr := r.trace()
	tr.ConnectStart("tcp", "192.0.2.1:443")
	tr.ConnectDone("tcp", "192.0.2.1:443", nil)
	p := r.snapshot()
	if p.DNSMs != -1 {
		t.Errorf("沒有 DNS 時 DNSMs 應為 -1：%+v", p)
	}
	if p.Reached != "connect" {
		t.Errorf("Reached = %q，預期 \"connect\"", p.Reached)
	}
	if p.Stalled != "" {
		t.Errorf("connect 已完成，Stalled 應為空：%+v", p)
	}
}

// connect 成功後 WroteRequest 帶錯誤：等待階段不算開始過
func TestPhaseRecorderWroteRequestError(t *testing.T) {
	r := newPhaseRecorder()
	tr := r.trace()
	tr.ConnectStart("tcp", "192.0.2.1:443")
	tr.ConnectDone("tcp", "192.0.2.1:443", nil)
	tr.WroteRequest(httptrace.WroteRequestInfo{Err: errors.New("寫入失敗")})
	p := r.snapshot()
	if p.Reached != "connect" {
		t.Errorf("Reached = %q，預期 \"connect\"", p.Reached)
	}
	if p.Stalled != "" {
		t.Errorf("等待階段沒有開始過，Stalled 應為空：%+v", p)
	}
}

// DNSStart 後 DNSDone 帶錯誤
func TestPhaseRecorderDNSFail(t *testing.T) {
	r := newPhaseRecorder()
	tr := r.trace()
	tr.DNSStart(httptrace.DNSStartInfo{})
	tr.DNSDone(httptrace.DNSDoneInfo{Err: errors.New("查詢失敗")})
	p := r.snapshot()
	if p.Reached != "" {
		t.Errorf("DNS 失敗時 Reached 應為空：%+v", p)
	}
	if p.Stalled != "dns" {
		t.Errorf("Stalled = %q，預期 \"dns\"", p.Stalled)
	}
	if p.DNSMs != -1 {
		t.Errorf("DNS 失敗時 DNSMs 應為 -1：%+v", p)
	}
}

// 沒有任何事件
func TestPhaseRecorderNoEvents(t *testing.T) {
	p := newPhaseRecorder().snapshot()
	if p.Reached != "" || p.Stalled != "" {
		t.Errorf("沒有事件時 Reached 與 Stalled 都應為空：%+v", p)
	}
	if p.DNSMs != -1 || p.ConnectMs != -1 || p.TLSMs != -1 || p.WaitMs != -1 {
		t.Errorf("沒有事件時四段都應為 -1：%+v", p)
	}
}

// snapshot 之後的事件一律忽略
func TestPhaseRecorderFrozen(t *testing.T) {
	r := newPhaseRecorder()
	recordFullSuccess(r.trace())
	first := r.snapshot()
	tr := r.trace()
	tr.DNSStart(httptrace.DNSStartInfo{})
	tr.ConnectStart("tcp", "192.0.2.2:443")
	tr.ConnectDone("tcp", "192.0.2.2:443", nil)
	tr.TLSHandshakeStart()
	tr.TLSHandshakeDone(tls.ConnectionState{}, nil)
	tr.GotFirstResponseByte()
	if second := r.snapshot(); *first != *second {
		t.Errorf("snapshot 之後的事件不應改變結果：%+v vs %+v", first, second)
	}
}

// 多個 goroutine 同時呼叫 hook（搭配 -race 檢查）
func TestPhaseRecorderConcurrent(t *testing.T) {
	r := newPhaseRecorder()
	tr := r.trace()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // 同時 snapshot：frozen 路徑也要在 race 下安全
		defer wg.Done()
		_ = r.snapshot()
	}()
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := fmt.Sprintf("192.0.2.%d:443", i)
			tr.ConnectStart("tcp", key)
			tr.DNSStart(httptrace.DNSStartInfo{})
			tr.DNSDone(httptrace.DNSDoneInfo{})
			tr.ConnectDone("tcp", key, nil)
			tr.TLSHandshakeStart()
			tr.TLSHandshakeDone(tls.ConnectionState{}, nil)
			tr.WroteRequest(httptrace.WroteRequestInfo{})
			tr.GotFirstResponseByte()
		}()
	}
	wg.Wait()
	if p := r.snapshot(); p.Reached != "response" {
		t.Errorf("並行呼叫後 Reached = %q，預期 \"response\"", p.Reached)
	}
}

func TestPhaseLine(t *testing.T) {
	cases := []struct {
		name string
		s    Site
		mode ProxyMode
		want string
	}{
		{"nil", Site{Probe: Probe{OK: true}}, ProxyNone, ""},
		{"成功四段", Site{Probe: Probe{OK: true},
			Phases: &SitePhases{DNSMs: 3, ConnectMs: 5, TLSMs: 7, WaitMs: 9, Reached: "response"}},
			ProxyNone, "    分段：DNS 3ms、TCP 5ms、TLS 7ms、等待回應 9ms"},
		{"成功但 DNS 為 -1", Site{Probe: Probe{OK: true},
			Phases: &SitePhases{DNSMs: -1, ConnectMs: 5, TLSMs: 7, WaitMs: 9, Reached: "response"}},
			ProxyNone, "    分段：TCP 5ms、TLS 7ms、等待回應 9ms"},
		{"失敗停在 TLS", Site{Probe: Probe{},
			Phases: &SitePhases{DNSMs: 3, ConnectMs: 5, TLSMs: -1, WaitMs: -1, Reached: "connect", Stalled: "tls"}},
			ProxyNone, "    停在：加密交握（TLS）（已完成：DNS 3ms、TCP 5ms）"},
		{"失敗停在 DNS", Site{Probe: Probe{},
			Phases: &SitePhases{DNSMs: -1, ConnectMs: -1, TLSMs: -1, WaitMs: -1, Stalled: "dns"}},
			ProxyNone, "    停在：查網址（DNS）"},
		{"IP 目標連線失敗", Site{Probe: Probe{},
			Phases: &SitePhases{DNSMs: -1, ConnectMs: -1, TLSMs: -1, WaitMs: -1, Stalled: "connect"}},
			ProxyNone, "    停在：建立連線（TCP）"},
		{"失敗但沒有停住的階段與已完成段", Site{Probe: Probe{},
			Phases: &SitePhases{DNSMs: -1, ConnectMs: -1, TLSMs: -1, WaitMs: -1}}, ProxyNone, ""},
		{"ProxyExplicit 且 Route 為空（推定經由代理）時加註", Site{Probe: Probe{OK: true},
			Phases: &SitePhases{DNSMs: 3, ConnectMs: 5, TLSMs: 7, WaitMs: 9, Reached: "response"}},
			ProxyExplicit, "    分段：DNS 3ms、TCP 5ms、TLS 7ms、等待回應 9ms；經由代理時 DNS 與 TCP 是連往代理伺服器"},
		{"成功但全部 -1", Site{Probe: Probe{OK: true},
			Phases: &SitePhases{DNSMs: -1, ConnectMs: -1, TLSMs: -1, WaitMs: -1, Reached: "response"}},
			ProxyNone, ""},
	}
	for _, c := range cases {
		if got := phaseLine(c.s, c.mode); got != c.want {
			t.Errorf("%s：phaseLine = %q，預期 %q", c.name, got, c.want)
		}
	}
}
