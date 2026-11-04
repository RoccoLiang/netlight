package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testToken = "0123456789abcdef"
	testHost  = "127.0.0.1:8123"
)

const wantCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func webReq(method, path string) *http.Request {
	return httptest.NewRequest(method, "http://"+testHost+path, nil)
}

// webHealthyProbe：把 webProbe 換成 healthy() 並在測試結束還原
func webHealthyProbe(t *testing.T) {
	t.Helper()
	old := webProbe
	webProbe = func(ctx context.Context, cfg Config, emit func(stage string)) Facts { return healthy() }
	t.Cleanup(func() { webProbe = old })
}

func newTestState() *webState {
	return &webState{started: time.Now()}
}

// checkWebHeaders：比對四個安全標頭的完整值
func checkWebHeaders(t *testing.T, h http.Header) {
	t.Helper()
	if got := h.Get("Content-Security-Policy"); got != wantCSP {
		t.Errorf("Content-Security-Policy = %q，應為 %q", got, wantCSP)
	}
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q，應為 nosniff", got)
	}
	if got := h.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q，應為 no-store", got)
	}
	if got := h.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q，應為 no-referrer", got)
	}
}

func TestWebBadToken(t *testing.T) {
	h := newWebHandler(Config{}, testToken, testHost, newTestState(), func() {})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, webReq(http.MethodGet, "/t/wrongtoken/"))
	if w.Code != http.StatusNotFound {
		t.Errorf("錯誤 token 應 404，得到 %d", w.Code)
	}
	checkWebHeaders(t, w.Header())
}

func TestWebBadHost(t *testing.T) {
	h := newWebHandler(Config{}, testToken, testHost, newTestState(), func() {})
	req := webReq(http.MethodGet, "/t/"+testToken+"/")
	req.Host = "evil.example:80"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Host 不符應 403，得到 %d", w.Code)
	}
}

func TestWebBadOrigin(t *testing.T) {
	h := newWebHandler(Config{}, testToken, testHost, newTestState(), func() {})
	req := webReq(http.MethodPost, "/t/"+testToken+"/api/run")
	req.Header.Set("Origin", "http://evil.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Origin 不符應 403，得到 %d", w.Code)
	}
}

func TestWebStaticFiles(t *testing.T) {
	h := newWebHandler(Config{}, testToken, testHost, newTestState(), func() {})
	for _, tc := range []struct{ path, ctype string }{
		{"/", "text/html"},
		{"/app.js", "text/javascript"},
		{"/app.css", "text/css"},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, webReq(http.MethodGet, "/t/"+testToken+tc.path))
		if w.Code != http.StatusOK {
			t.Errorf("GET %s 應 200，得到 %d", tc.path, w.Code)
			continue
		}
		checkWebHeaders(t, w.Header())
		if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, tc.ctype) {
			t.Errorf("GET %s Content-Type = %q，應含 %q", tc.path, ct, tc.ctype)
		}
		if w.Body.Len() == 0 {
			t.Errorf("GET %s 內容為空", tc.path)
		}
		if tc.path == "/" && !strings.Contains(w.Body.String(), `id="lights"`) {
			t.Errorf("index.html 應含 id=\"lights\"（燈號列由 app.js 動態建立）")
		}
	}
}

func TestWebLayout(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"沒有檢查點", Config{}},
		{"有一個檢查點", Config{Checkpoints: []Checkpoint{{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443"}}}},
	} {
		h := newWebHandler(tc.cfg, testToken, testHost, newTestState(), func() {})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, webReq(http.MethodGet, "/t/"+testToken+"/api/layout"))
		if w.Code != http.StatusOK {
			t.Fatalf("%s：api/layout 應 200，得到 %d：%s", tc.name, w.Code, w.Body.String())
		}
		checkWebHeaders(t, w.Header())
		if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("%s：Content-Type = %q，應含 application/json", tc.name, ct)
		}
		var got struct {
			Lights []string `json:"lights"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s：解析 JSON 失敗：%v", tc.name, err)
		}
		if want := lightNames(tc.cfg); !slices.Equal(got.Lights, want) {
			t.Errorf("%s：lights = %v，應與 lightNames(cfg) 逐項相等：%v", tc.name, got.Lights, want)
		}
	}
}

// TestWebAppLightNeeds：app.js 的燈號—stage 對應與設定的燈名一致
func TestWebAppLightNeeds(t *testing.T) {
	b, err := fs.ReadFile(webDir, "app.js")
	if err != nil {
		t.Fatalf("讀取 app.js 失敗：%v", err)
	}
	js := string(b)
	// LIGHT_NEEDS 的完整對應字串（逐字，含空白）
	entries := map[string]string{
		"本機網路": `"本機網路": ["local"]`,
		"路由器":  `"路由器": ["gateway"]`,
		"單位網路": `"單位網路": ["checkpoints"]`,
		"對外連線": `"對外連線": ["direct"]`,
		"網址查詢": `"網址查詢": ["dns", "public_dns"]`,
		"網站連線": `"網站連線": ["sites", "captive"]`,
	}
	for name, want := range entries {
		if !strings.Contains(js, want) {
			t.Errorf("app.js 缺少 %q 的 LIGHT_NEEDS 條目：%s", name, want)
		}
	}
	cfg := Config{Checkpoints: []Checkpoint{{Name: "單位防火牆", Host: "10.1.0.1", Check: "tcp:443"}}}
	for _, name := range lightNames(cfg) {
		if _, ok := entries[name]; !ok {
			t.Errorf("燈名 %q 沒有對應的 LIGHT_NEEDS 條目，新增燈名時 app.js 也要加對應", name)
		}
	}
	if !strings.Contains(js, `fetch("api/layout")`) {
		t.Error("app.js 應呼叫 fetch(\"api/layout\") 取得燈名")
	}
	if !strings.Contains(js, "buildRows(layoutNames)") {
		t.Error("app.js 的 startRun 應以 buildRows(layoutNames) 恢復設定的燈號列")
	}
	if strings.Contains(js, "STAGE_LIGHTS") {
		t.Error("app.js 不應再使用 STAGE_LIGHTS")
	}
}

func TestWebRun(t *testing.T) {
	webHealthyProbe(t)
	h := newWebHandler(Config{}, testToken, testHost, newTestState(), func() {})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, webReq(http.MethodPost, "/t/"+testToken+"/api/run"))
	if w.Code != http.StatusOK {
		t.Fatalf("api/run 應 200，得到 %d：%s", w.Code, w.Body.String())
	}
	checkWebHeaders(t, w.Header())

	// api/run 改為 NDJSON 串流：取最後一行（report 事件）解析
	lines := strings.Split(strings.TrimSuffix(w.Body.String(), "\n"), "\n")
	var got map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &got); err != nil {
		t.Fatalf("解析 JSON 失敗：%v", err)
	}
	result, _ := got["result"].(map[string]any)
	if result == nil {
		t.Fatalf("回應缺少 result：%s", w.Body.String())
	}
	verdict, _ := result["verdict"].(map[string]any)
	if verdict == nil || verdict["code"] != "OK" {
		t.Errorf("result.verdict.code 應為 OK：%v", verdict)
	}
	lights, _ := result["lights"].([]any)
	if len(lights) != 5 {
		t.Errorf("lights 數量 = %d，應為 5", len(lights))
	} else if first, _ := lights[0].(map[string]any); first == nil || first["status"] != "green" {
		t.Errorf("lights[0].status 應為 green：%v", lights[0])
	}
	text, _ := got["text"].(string)
	for _, want := range []string{"【netlight 網路診斷回報】", "結論碼：OK", "台灣標準時間"} {
		if !strings.Contains(text, want) {
			t.Errorf("回報文字缺少 %q：\n%s", want, text)
		}
	}
}

func TestWebRunStream(t *testing.T) {
	old := webProbe
	webProbe = func(ctx context.Context, cfg Config, emit func(stage string)) Facts {
		emit("local")
		emit("direct")
		emit("dns")
		return healthy()
	}
	t.Cleanup(func() { webProbe = old })

	h := newWebHandler(Config{}, testToken, testHost, newTestState(), func() {})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, webReq(http.MethodPost, "/t/"+testToken+"/api/run"))
	if w.Code != http.StatusOK {
		t.Fatalf("api/run 應 200，得到 %d：%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("Content-Type = %q，應為 application/x-ndjson", ct)
	}

	lines := strings.Split(strings.TrimSuffix(w.Body.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("串流行數 = %d，應為 4：%q", len(lines), w.Body.String())
	}
	for i, want := range []string{"local", "direct", "dns"} {
		var ev struct {
			Type  string `json:"type"`
			Stage string `json:"stage"`
		}
		if err := json.Unmarshal([]byte(lines[i]), &ev); err != nil {
			t.Fatalf("解析第 %d 行失敗：%v", i+1, err)
		}
		if ev.Type != "stage" || ev.Stage != want {
			t.Errorf("第 %d 行應為 stage %s，得到 %s", i+1, want, lines[i])
		}
	}
	var rep struct {
		Type     string         `json:"type"`
		Result   map[string]any `json:"result"`
		Text     string         `json:"text"`
		SafeText string         `json:"safe_text"`
	}
	if err := json.Unmarshal([]byte(lines[3]), &rep); err != nil {
		t.Fatalf("解析最後一行失敗：%v", err)
	}
	if rep.Type != "report" {
		t.Errorf("最後一行應為 report，得到 %s", lines[3])
	}
	verdict, _ := rep.Result["verdict"].(map[string]any)
	if verdict == nil || verdict["code"] != "OK" {
		t.Errorf("report.result.verdict.code 應為 OK：%v", verdict)
	}
	if !strings.Contains(rep.Text, "【netlight 網路診斷回報】") {
		t.Errorf("report.text 應含「【netlight 網路診斷回報】」：%q", rep.Text)
	}
	if !strings.Contains(rep.SafeText, "【netlight 網路診斷摘要】") {
		t.Errorf("report.safe_text 應含「【netlight 網路診斷摘要】」且非空：%q", rep.SafeText)
	}
	// healthy() 的燈號說明含 IP（192.168.1.23 等），安全摘要不得出現任何 IPv4
	if regexp.MustCompile(`\b(\d{1,3}\.){3}\d{1,3}\b`).MatchString(rep.SafeText) {
		t.Errorf("report.safe_text 不得含 IPv4：%q", rep.SafeText)
	}
}

func TestWebRunStreamFlush(t *testing.T) {
	proceed := make(chan struct{})
	release := sync.OnceFunc(func() { close(proceed) })
	old := webProbe
	webProbe = func(ctx context.Context, cfg Config, emit func(stage string)) Facts {
		emit("local")
		<-proceed
		return healthy()
	}
	t.Cleanup(func() { webProbe = old })

	srv := httptest.NewUnstartedServer(nil)
	srv.Config.Handler = newWebHandler(Config{}, testToken, srv.Listener.Addr().String(), newTestState(), func() {})
	srv.Start()
	defer srv.Close()
	defer release()

	// 3 秒內讀不到第一行（沒有即時 flush）就視為失敗
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+srv.Listener.Addr().String()+"/t/"+testToken+"/api/run", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("請求失敗：%v", err)
	}
	defer resp.Body.Close()

	br := bufio.NewReader(resp.Body)
	first, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("讀不到第一行（沒有即時 flush？）：%v", err)
	}
	var ev struct {
		Type  string `json:"type"`
		Stage string `json:"stage"`
	}
	if err := json.Unmarshal([]byte(first), &ev); err != nil {
		t.Fatalf("解析第一行失敗：%v", err)
	}
	if ev.Type != "stage" || ev.Stage != "local" {
		t.Errorf("第一行應為 stage local，得到 %q", strings.TrimSpace(first))
	}

	release()
	rest, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("讀取剩餘回應失敗：%v", err)
	}
	var rep struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(rest))), &rep); err != nil {
		t.Fatalf("解析剩餘回應失敗：%v（%q）", err, rest)
	}
	if rep.Type != "report" {
		t.Errorf("最後一行應為 report，得到 type %q", rep.Type)
	}
}

func TestWebRunConflict(t *testing.T) {
	blocked := make(chan struct{})
	release := make(chan struct{})
	old := webProbe
	webProbe = func(ctx context.Context, cfg Config, emit func(stage string)) Facts {
		close(blocked)
		<-release
		return healthy()
	}
	t.Cleanup(func() { webProbe = old })

	h := newWebHandler(Config{}, testToken, testHost, newTestState(), func() {})
	w1 := httptest.NewRecorder()
	w2 := httptest.NewRecorder()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		h.ServeHTTP(w1, webReq(http.MethodPost, "/t/"+testToken+"/api/run"))
	}()
	<-blocked

	h.ServeHTTP(w2, webReq(http.MethodPost, "/t/"+testToken+"/api/run"))
	if w2.Code != http.StatusConflict {
		t.Errorf("並行檢測應 409，得到 %d", w2.Code)
	}
	checkWebHeaders(t, w2.Header())

	close(release)
	<-finished
	if w1.Code != http.StatusOK {
		t.Errorf("第一個檢測應 200，得到 %d", w1.Code)
	}
}

func TestWebRunGoodOrigin(t *testing.T) {
	webHealthyProbe(t)
	h := newWebHandler(Config{}, testToken, testHost, newTestState(), func() {})
	req := webReq(http.MethodPost, "/t/"+testToken+"/api/run")
	req.Header.Set("Origin", "http://"+testHost)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("合法 Origin 的 api/run 應 200，得到 %d：%s", w.Code, w.Body.String())
	}
}

func TestWebMissingPageParam(t *testing.T) {
	h := newWebHandler(Config{}, testToken, testHost, newTestState(), func() {})
	for _, path := range []string{"api/heartbeat", "api/bye"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, webReq(http.MethodPost, "/t/"+testToken+"/"+path))
		if w.Code != http.StatusBadRequest {
			t.Errorf("缺少 p 參數的 %s 應 400，得到 %d", path, w.Code)
		}
	}
}

func TestWebRunClosing(t *testing.T) {
	// 讓 state 判定閒置而進入結束程序
	st := &webState{started: time.Now().Add(-2 * time.Minute)}
	if !st.idle(time.Now()) {
		t.Fatal("兩分鐘無心跳應判定閒置")
	}
	h := newWebHandler(Config{}, testToken, testHost, st, func() {})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, webReq(http.MethodPost, "/t/"+testToken+"/api/run"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("closing 時 api/run 應 503，得到 %d", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "netlight 正在結束" {
		t.Errorf("503 文字應為「netlight 正在結束」，得到 %q", got)
	}
}

func TestWebRunRunningFlag(t *testing.T) {
	blocked := make(chan struct{})
	release := make(chan struct{})
	old := webProbe
	webProbe = func(ctx context.Context, cfg Config, emit func(stage string)) Facts {
		close(blocked)
		<-release
		return healthy()
	}
	t.Cleanup(func() { webProbe = old })

	st := newTestState()
	h := newWebHandler(Config{}, testToken, testHost, st, func() {})
	w := httptest.NewRecorder()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		h.ServeHTTP(w, webReq(http.MethodPost, "/t/"+testToken+"/api/run"))
	}()
	<-blocked

	// 檢測中：running 為 true、不判斷閒置
	st.mu.Lock()
	runningMid := st.running
	closingMid := st.closing
	st.mu.Unlock()
	if !runningMid {
		t.Error("檢測中 running 應為 true")
	}
	if closingMid {
		t.Error("檢測中不應進入結束程序")
	}
	if st.idle(time.Now()) {
		t.Error("檢測中 idle 應為 false")
	}

	close(release)
	<-finished
	if w.Code != http.StatusOK {
		t.Errorf("檢測應 200，得到 %d", w.Code)
	}
	st.mu.Lock()
	runningEnd := st.running
	st.mu.Unlock()
	if runningEnd {
		t.Error("檢測結束後 running 應回到 false")
	}
}

func TestWebStateByePageOrder(t *testing.T) {
	// 重新整理後，舊頁面晚到的關閉通知不得關掉新頁面
	t0 := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	t1 := t0.Add(1 * time.Second)
	t2 := t1.Add(1 * time.Second)
	st := &webState{started: t0}
	st.beat(t0, "A")
	st.beat(t1, "B")
	st.bye(t2, "A")
	if st.idle(t2.Add(10 * time.Second)) {
		t.Error("舊頁面（A）的 bye 不應結束新頁面（B）")
	}
	t3 := t2.Add(1 * time.Second)
	st.bye(t3, "B")
	if !st.idle(t3.Add(webBye)) {
		t.Error("最新頁面（B）的 bye 後 5 秒應結束")
	}
}

func TestWebStateClosingAfterIdle(t *testing.T) {
	base := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	st := &webState{started: base}
	if !st.idle(base.Add(webFirstBeat)) {
		t.Fatal("從未心跳 60 秒應判定閒置")
	}
	if st.tryStart() {
		t.Error("idle 回 true 之後 tryStart 應為 false")
	}
	// finish 不影響 closing 的拒絕
	st.finish()
	if st.tryStart() {
		t.Error("closing 之後即使 finish，tryStart 也應為 false")
	}
}

func TestWebStateIdle(t *testing.T) {
	base := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		setup func(*webState)
		now   time.Time
		want  bool
	}{
		{"從未心跳 59 秒", nil, base.Add(59 * time.Second), false},
		{"從未心跳 60 秒", nil, base.Add(60 * time.Second), true},
		{"心跳後 89 秒", func(s *webState) { s.beat(base.Add(10*time.Second), "A") }, base.Add(99 * time.Second), false},
		{"心跳後 90 秒", func(s *webState) { s.beat(base.Add(10*time.Second), "A") }, base.Add(100 * time.Second), true},
		{"bye 後 4 秒", func(s *webState) {
			s.beat(base.Add(5*time.Second), "A")
			s.bye(base.Add(10*time.Second), "A")
		}, base.Add(14 * time.Second), false},
		{"bye 後 5 秒", func(s *webState) {
			s.beat(base.Add(5*time.Second), "A")
			s.bye(base.Add(10*time.Second), "A")
		}, base.Add(15 * time.Second), true},
		{"bye 後又心跳則取消", func(s *webState) {
			s.beat(base.Add(5*time.Second), "A")
			s.bye(base.Add(10*time.Second), "A")
			s.beat(base.Add(12*time.Second), "A")
		}, base.Add(22 * time.Second), false},
		{"bye 後又心跳，依心跳規則逾時", func(s *webState) {
			s.beat(base.Add(5*time.Second), "A")
			s.bye(base.Add(10*time.Second), "A")
			s.beat(base.Add(12*time.Second), "A")
		}, base.Add(12*time.Second + webIdle), true},
		{"檢測中不結束", func(s *webState) { s.tryStart() }, base.Add(24 * time.Hour), false},
		{"檢測中收到 bye 也不結束", func(s *webState) {
			s.beat(base.Add(time.Second), "A")
			s.bye(base.Add(2*time.Second), "A")
			s.tryStart()
		}, base.Add(time.Hour), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &webState{started: base}
			if tc.setup != nil {
				tc.setup(st)
			}
			if got := st.idle(tc.now); got != tc.want {
				t.Errorf("idle(%s) = %v，應為 %v", tc.now.Sub(base), got, tc.want)
			}
		})
	}
}

// TestWebStatePages：多分頁生命週期（beat／bye／idle 以假時間驅動，不睡眠）
func TestWebStatePages(t *testing.T) {
	base := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	type idleCheck struct {
		after time.Duration
		want  bool
	}
	cases := []struct {
		name   string
		setup  func(*webState)
		checks []idleCheck
	}{
		{"兩分頁之一關閉，另一分頁還在", func(s *webState) {
			s.beat(base, "A")
			s.beat(base, "B")
			s.bye(base, "B")
		}, []idleCheck{{10 * time.Second, false}}},
		{"兩分頁都關閉：4 秒不結束、5 秒結束", func(s *webState) {
			s.beat(base, "A")
			s.beat(base, "B")
			s.bye(base, "A")
			s.bye(base, "B")
		}, []idleCheck{{4 * time.Second, false}, {5 * time.Second, true}}},
		{"重新整理（新頁心跳先到）：舊頁 bye 不誤關", func(s *webState) {
			s.beat(base, "A")
			s.beat(base, "B")
			s.bye(base, "A")
		}, []idleCheck{{10 * time.Second, false}}},
		{"重新整理（舊頁 bye 先到）：新頁心跳取消結束", func(s *webState) {
			s.beat(base, "A")
			s.bye(base, "A")
			s.beat(base.Add(time.Second), "B")
		}, []idleCheck{{10 * time.Second, false}}},
		{"單一分頁不再心跳：89 秒不結束、90 秒結束", func(s *webState) {
			s.beat(base, "A")
		}, []idleCheck{{89 * time.Second, false}, {90 * time.Second, true}}},
		{"從未心跳：59 秒不結束、60 秒結束", func(s *webState) {}, []idleCheck{{59 * time.Second, false}, {60 * time.Second, true}}},
		{"檢測中一律不結束", func(s *webState) {
			s.beat(base, "A")
			s.beat(base, "B")
			s.bye(base, "B")
			s.tryStart()
		}, []idleCheck{{10 * time.Second, false}, {time.Hour, false}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &webState{started: base}
			tc.setup(st)
			for _, c := range tc.checks {
				if got := st.idle(base.Add(c.after)); got != c.want {
					t.Errorf("idle(+%s) = %v，應為 %v", c.after, got, c.want)
				}
			}
		})
	}
}

func TestWebHeartbeatAndBye(t *testing.T) {
	st := newTestState()
	h := newWebHandler(Config{}, testToken, testHost, st, func() {})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, webReq(http.MethodPost, "/t/"+testToken+"/api/heartbeat?p=pageA"))
	if w.Code != http.StatusNoContent {
		t.Fatalf("api/heartbeat 應 204，得到 %d", w.Code)
	}
	st.mu.Lock()
	beatAt, ok := st.pages["pageA"]
	everBeat := st.everBeat
	st.mu.Unlock()
	if !ok || beatAt.IsZero() {
		t.Fatal("api/heartbeat 應記錄頁面心跳時間")
	}
	if !everBeat {
		t.Fatal("api/heartbeat 應記錄曾收到心跳")
	}
	if st.idle(beatAt.Add(webIdle - time.Second)) {
		t.Error("心跳後 89 秒不應判定閒置")
	}
	if !st.idle(beatAt.Add(webIdle)) {
		t.Error("心跳後 90 秒應判定閒置")
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, webReq(http.MethodPost, "/t/"+testToken+"/api/bye?p=pageA"))
	if w.Code != http.StatusNoContent {
		t.Fatalf("api/bye 應 204，得到 %d", w.Code)
	}
	st.mu.Lock()
	byeAt := st.byeAt
	pages := len(st.pages)
	st.mu.Unlock()
	if pages != 0 {
		t.Error("api/bye 應移除頁面")
	}
	if byeAt.IsZero() {
		t.Fatal("api/bye 應在頁面清空後記錄關閉通知時間")
	}
	if st.idle(byeAt.Add(webBye - time.Second)) {
		t.Error("bye 後 4 秒不應判定結束")
	}
	if !st.idle(byeAt.Add(webBye)) {
		t.Error("bye 後 5 秒應判定結束")
	}

	// 分頁關閉後又收到心跳（重新整理），取消結束
	w = httptest.NewRecorder()
	h.ServeHTTP(w, webReq(http.MethodPost, "/t/"+testToken+"/api/heartbeat?p=pageA"))
	if w.Code != http.StatusNoContent {
		t.Fatalf("api/heartbeat 應 204，得到 %d", w.Code)
	}
	st.mu.Lock()
	byeAt = st.byeAt
	pages = len(st.pages)
	st.mu.Unlock()
	if !byeAt.IsZero() {
		t.Error("收到心跳應取消關閉通知")
	}
	if pages != 1 {
		t.Error("收到心跳應重新記錄頁面")
	}
}

func TestWebShutdown(t *testing.T) {
	called := false
	h := newWebHandler(Config{}, testToken, testHost, newTestState(), func() { called = true })
	w := httptest.NewRecorder()
	h.ServeHTTP(w, webReq(http.MethodPost, "/t/"+testToken+"/api/shutdown"))
	if w.Code != http.StatusNoContent {
		t.Errorf("api/shutdown 應 204，得到 %d", w.Code)
	}
	if !called {
		t.Error("api/shutdown 應呼叫 done")
	}
}

func TestWebMethodNotAllowed(t *testing.T) {
	h := newWebHandler(Config{}, testToken, testHost, newTestState(), func() {})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, webReq(http.MethodPut, "/t/"+testToken+"/api/run"))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("方法不符應 405，得到 %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, webReq(http.MethodPost, "/t/"+testToken+"/"))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("方法不符應 405，得到 %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, webReq(http.MethodPost, "/t/"+testToken+"/api/layout"))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("方法不符應 405，得到 %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, webReq(http.MethodGet, "/t/"+testToken+"/no-such-file"))
	if w.Code != http.StatusNotFound {
		t.Errorf("未知路徑應 404，得到 %d", w.Code)
	}
}

func TestWebReportText(t *testing.T) {
	f := healthy()
	rep := decide(f, Config{})
	// 傳入 UTC 的 now：回報文字應轉為台灣標準時間
	text := webReportText(rep, f, time.Date(2026, 11, 2, 6, 3, 0, 0, time.UTC))
	for _, want := range []string{
		"【netlight 網路診斷回報】",
		"時間：2026-11-02 14:03 台灣標準時間",
		"版本：netlight v" + version + " · macOS",
		"結論碼：OK",
		"結論：網路正常。",
		"· 路由器位址：192.168.1.1，ICMP 有回應",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("回報文字缺少 %q：\n%s", want, text)
		}
	}
}

// TestSafeVerdictText：SITE 結論由結構化資料重新產生，設定檔的網站名稱（不論寫成什麼）都不會進入安全摘要
func TestSafeVerdictText(t *testing.T) {
	leaky := []string{
		"erp.internal", "10.1.2.3", "https://erp.example.com/a", "fe80::1", "erp_server.internal",
		"erp_server.corp.internal", "10.1.2.3:8080", "http://host/path", "2001:db8::1234",
		"[fe80::1%en0]:8080", "admin@erp", "erp．internal", "財務。內網", "ERPSRV01", `\\ERPSRV01\Payroll`,
		"ERP」https://erp.internal/login?next=PAYROLL_SECRET", "「內網」", "Google、erp.internal", "",
	}
	for _, name := range leaky {
		f := healthy()
		f.Sites = append(f.Sites, Site{Name: name, Probe: Probe{Target: "https://custom.example", Err: ErrTimeout}})
		cfg := Config{Targets: []Target{{Name: name, URL: "https://custom.example"}}}
		rep := decide(f, cfg)
		if rep.Verdict.Code != SiteCode {
			t.Fatalf("名稱 %q：預期 SITE，得到 %s", name, rep.Verdict.Code)
		}
		got := safeVerdictText(rep, f, cfg)
		want := fmt.Sprintf(verdicts[SiteCode].Text, "設定檔第 1 個網站")
		if got != want {
			t.Errorf("名稱 %q：安全結論 = %q，應為 %q", name, got, want)
		}
	}

	// 預設網站用內建名稱；多個失敗網站依序列出；設定檔第 N 個對應 targets 的順序（含重複網址）
	f := healthy()
	f.Sites[1] = Site{Name: "公司首頁", Probe: Probe{Target: f.Sites[1].Target, Err: ErrTimeout}} // 預設位置、自訂名稱
	f.Sites = append(f.Sites,
		Site{Name: "甲", Probe: Probe{Target: "https://a.example", OK: true}, Status: 200},
		Site{Name: "乙", Probe: Probe{Target: "https://a.example", Err: ErrTimeout}},
		Site{Name: "丙", Probe: Probe{Target: "https://c.example", Err: ErrTimeout}},
	)
	cfg := Config{Targets: []Target{{Name: "甲", URL: "https://a.example"}, {Name: "乙", URL: "https://a.example"}, {Name: "丙", URL: "https://c.example"}}}
	rep := decide(f, cfg)
	if got, want := safeVerdictText(rep, f, cfg), fmt.Sprintf(verdicts[SiteCode].Text, defaultTargets[1].Name+"、設定檔第 2 個網站、設定檔第 3 個網站"); got != want {
		t.Errorf("多個失敗網站：%q，應為 %q", got, want)
	}

	// replace_default_targets：全部都是設定檔的網站，從第 1 個起算
	fr := healthy()
	fr.Sites = []Site{
		{Name: "內網 A", Probe: Probe{Target: "https://a.internal", OK: true}, Status: 200},
		{Name: "內網 B", Probe: Probe{Target: "https://b.internal", Err: ErrTimeout}},
	}
	cfgR := Config{ReplaceDefaultTargets: true, Targets: []Target{{Name: "內網 A", URL: "https://a.internal"}, {Name: "內網 B", URL: "https://b.internal"}}}
	repR := decide(fr, cfgR)
	if repR.Verdict.Code != SiteCode {
		t.Fatalf("取代預設網站：預期 SITE，得到 %s", repR.Verdict.Code)
	}
	if got, want := safeVerdictText(repR, fr, cfgR), fmt.Sprintf(verdicts[SiteCode].Text, "設定檔第 2 個網站"); got != want {
		t.Errorf("取代預設網站：%q，應為 %q", got, want)
	}

	// SITE_DNS 變體（由 decide 實際產生）用自己的範本
	fd := healthy()
	fd.DNS = append(fd.DNS, Probe{Target: "erp.internal", Err: ErrDNS})
	fd.Sites = append(fd.Sites, Site{Name: "ERP」惡意", Probe: Probe{Target: "https://erp.internal", Err: ErrDNS}})
	cfgD := Config{Targets: []Target{{Name: "ERP」惡意", URL: "https://erp.internal"}}}
	repD := decide(fd, cfgD)
	if p, _, _ := strings.Cut(verdicts[siteDNS].Text, "%s"); repD.Verdict.Code != SiteCode || !strings.HasPrefix(repD.Verdict.Text, p) {
		t.Fatalf("預期 SITE_DNS 變體，得到 %s：%q", repD.Verdict.Code, repD.Verdict.Text)
	}
	if got, want := safeVerdictText(repD, fd, cfgD), fmt.Sprintf(verdicts[siteDNS].Text, "設定檔第 1 個網站"); got != want {
		t.Errorf("SITE_DNS：%q，應為 %q", got, want)
	}

	// 反向偽造：一般 SITE 的網站名稱含 SITE_DNS 的整段開頭，也不能讓摘要改用 SITE_DNS 範本
	dnsPrefix, _, _ := strings.Cut(verdicts[siteDNS].Text, "%s")
	ff := healthy()
	ff.Sites = append(ff.Sites, Site{Name: dnsPrefix + "假", Probe: Probe{Target: "https://x.example", Err: ErrTimeout}})
	cfgF := Config{Targets: []Target{{Name: dnsPrefix + "假", URL: "https://x.example"}}}
	repF := decide(ff, cfgF)
	if got, want := safeVerdictText(repF, ff, cfgF), fmt.Sprintf(verdicts[SiteCode].Text, "設定檔第 1 個網站"); got != want {
		t.Errorf("偽造 SITE_DNS 開頭：%q，應為 %q", got, want)
	}

	// 非 SITE 原樣保留；作業系統名稱只用固定值
	if got := safeVerdictText(Report{Verdict: Verdict{Code: DNSCode, Text: verdicts[dnsManual].Text}}, healthy(), Config{}); got != verdicts[dnsManual].Text {
		t.Errorf("非 SITE 結論應原樣保留：%q", got)
	}
	for in, want := range map[string]string{"macOS": "macOS", "Windows": "Windows", "Ubuntu 26.04 內部版 erp.internal": "Linux"} {
		if got := safeOSName(in); got != want {
			t.Errorf("safeOSName(%q) = %q，應為 %q", in, got, want)
		}
	}
}

// TestWebAppSafeCopyWiring：資料指派與按鈕綁定沒有對調（摘要按鈕必須複製安全摘要）
func TestWebAppSafeCopyWiring(t *testing.T) {
	b, err := fs.ReadFile(webDir, "app.js")
	if err != nil {
		t.Fatalf("讀取 app.js 失敗：%v", err)
	}
	js := string(b)
	for _, want := range []string{
		`safeText = data && data.safe_text ? data.safe_text : "";`,
		`reportText = data && data.text ? data.text : "";`,
		`copyBtn.addEventListener("click", copyReport);`,
		`copyFullBtn.addEventListener("click", copyFullReport);`,
		`copyFullBtn = document.getElementById("copy-full")`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js 缺少 %q（資料指派或按鈕綁定可能被改動或對調）", want)
		}
	}
}

func TestWebSafeReportText(t *testing.T) {
	ipRe := regexp.MustCompile(`\b(\d{1,3}\.){3}\d{1,3}\b`)
	now := time.Date(2026, 11, 2, 6, 3, 0, 0, time.UTC)

	// healthy()：逐字比對（燈號說明含 IP，安全摘要不得含）
	f := healthy()
	rep := decide(f, Config{})
	text := webSafeReportText(rep, f, Config{}, now)
	want := "【netlight 網路診斷摘要】\n" +
		"時間：2026-11-02 14:03 台灣標準時間\n" +
		"版本：netlight v" + version + " · macOS\n" +
		"結論碼：OK\n" +
		"燈號：本機網路 正常｜路由器 正常｜對外連線 正常｜網址查詢 正常｜網站連線 正常\n" +
		"結論：網路正常。\n" +
		"建議：如果某個 App 還是不能用，可能是該服務本身異常，請稍後再試。\n" +
		"（這份摘要不含這台電腦的 IP、網址與技術細節；資訊人員需要時，請另外提供完整技術資料。）\n"
	if text != want {
		t.Errorf("安全摘要 =\n%s\n應為\n%s", text, want)
	}
	if ipRe.MatchString(text) {
		t.Errorf("安全摘要不得含 IPv4：\n%s", text)
	}
	if strings.Contains(text, "http") {
		t.Errorf("安全摘要不得含網址（http）：\n%s", text)
	}
	if strings.Contains(text, "\n      · ") {
		t.Errorf("安全摘要不得含技術證據前綴：\n%s", text)
	}

	// 非 SITE 的結論是程式固定文字：其中的公開位址（8.8.8.8）原樣保留，不被遮蔽
	fixed := Report{Verdict: Verdict{Code: DNSCode, Text: verdicts[dnsManual].Text, Action: verdicts[dnsManual].Action}}
	ft := webSafeReportText(fixed, Facts{Local: Local{OS: "macOS"}}, Config{}, now)
	if !strings.Contains(ft, "結論："+verdicts[dnsManual].Text+"\n") || strings.Contains(ft, "已隱藏") {
		t.Errorf("固定結論文字不應被遮蔽：\n%s", ft)
	}

	// 代理情境：完整回報含代理位址，安全摘要不得含
	fp := healthy()
	fp.Local.Proxy = Proxy{Mode: ProxyExplicit, Addr: "10.0.0.8:3128"}
	repProxy := decide(fp, Config{})
	if full := webReportText(repProxy, fp, now); !strings.Contains(full, "10.0.0.8") {
		t.Errorf("代理情境的完整回報應含代理位址（證明摘要確實有排除）：\n%s", full)
	}
	if proxyText := webSafeReportText(repProxy, fp, Config{}, now); strings.Contains(proxyText, "10.0.0.8") {
		t.Errorf("代理情境的安全摘要不得含代理位址 10.0.0.8：\n%s", proxyText)
	}

	// 網站名稱被填成內部主機名稱：SITE 結論的這個名稱要隱藏，完整回報保留
	fe := healthy()
	fe.Sites = append(fe.Sites, Site{Name: "erp.internal", Probe: Probe{Target: "https://erp.example.com", Err: ErrTimeout}})
	repSite := decide(fe, Config{})
	siteText := webSafeReportText(repSite, fe, Config{}, now)
	if strings.Contains(siteText, "erp.internal") {
		t.Errorf("網站名稱為內部主機名稱時，安全摘要不得含 erp.internal：\n%s", siteText)
	}
	if !strings.Contains(siteText, "「設定檔第 1 個網站」") {
		t.Errorf("設定檔的網站在安全摘要中應改為「設定檔第 1 個網站」：\n%s", siteText)
	}
	if full := webReportText(repSite, fe, now); !strings.Contains(full, "erp.internal") {
		t.Errorf("完整回報仍應含網站名稱 erp.internal：\n%s", full)
	}

	// 有聯絡窗口：Org 非空時列出單位，Org 空時只列聯絡
	fc := healthy()
	fc.Sites = append(fc.Sites, Site{Name: "公司 ERP", Probe: Probe{Target: "https://erp.example.com", Err: ErrTimeout}})
	repContact := decide(fc, Config{Org: "範例公司", Contact: map[string]string{"default": "IT 服務台"}})
	contactText := webSafeReportText(repContact, fc, Config{}, now)
	if !strings.Contains(contactText, "聯絡（範例公司）：IT 服務台\n") {
		t.Errorf("有聯絡窗口的摘要應含「聯絡（範例公司）：IT 服務台」：\n%s", contactText)
	}
	repNoOrg := decide(fc, Config{Contact: map[string]string{"default": "IT 服務台"}})
	noOrgText := webSafeReportText(repNoOrg, fc, Config{}, now)
	if !strings.Contains(noOrgText, "聯絡：IT 服務台\n") {
		t.Errorf("沒有 Org 的摘要應為「聯絡：IT 服務台」：\n%s", noOrgText)
	}
	if strings.Contains(noOrgText, "聯絡（") {
		t.Errorf("沒有 Org 的摘要不得出現「聯絡（」：\n%s", noOrgText)
	}
}

// TestWebAppSafeCopy：前端有兩個複製按鈕，分別複製安全摘要與完整技術資料
func TestWebAppSafeCopy(t *testing.T) {
	b, err := fs.ReadFile(webDir, "app.js")
	if err != nil {
		t.Fatalf("讀取 app.js 失敗：%v", err)
	}
	js := string(b)
	for _, want := range []string{"data.safe_text", "copy-full", "copyText(", "copyText(safeText", "copyText(reportText"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js 缺少 %q", want)
		}
	}
	// 「複製回報給 IT」只複製安全摘要：copyReport 本體用 safeText，不得用 reportText
	i := strings.Index(js, "function copyReport()")
	if i < 0 {
		t.Fatalf("app.js 找不到 copyReport 函式")
	}
	body := js[i:]
	if j := strings.Index(body, "\n\t}"); j >= 0 {
		body = body[:j]
	}
	if !strings.Contains(body, "safeText") {
		t.Errorf("copyReport 本體應使用 safeText：\n%s", body)
	}
	if strings.Contains(body, "reportText") {
		t.Errorf("copyReport 本體不得使用 reportText：\n%s", body)
	}
	h, err := fs.ReadFile(webDir, "index.html")
	if err != nil {
		t.Fatalf("讀取 index.html 失敗：%v", err)
	}
	html := string(h)
	for _, want := range []string{`id="copy-full"`, "copy-hint", "不含這台電腦的 IP、網址與技術細節"} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html 缺少 %q", want)
		}
	}
}

// TestWebMainConfigError：設定檔錯誤時 webMain 的結束碼為 3（此路徑不會開 port）
func TestWebMainConfigError(t *testing.T) {
	if code := webMain("/nonexistent/netlight.json", false); code != 3 {
		t.Errorf("設定檔錯誤的結束碼應為 3，得到 %d", code)
	}
}

// captureStdout：暫時以 pipe 取代 os.Stdout 擷取輸出，回傳讀取函式；測試結束還原
func captureStdout(t *testing.T) func() string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("無法建立 pipe：%v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = old })
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	return func() string {
		w.Close()
		return <-done
	}
}

// setOpenBrowserFn：替換 openBrowserFn，測試結束還原
func setOpenBrowserFn(t *testing.T, f func(string) error) {
	t.Helper()
	old := openBrowserFn
	openBrowserFn = f
	t.Cleanup(func() { openBrowserFn = old })
}

// TestWebMainAutoFallback：自動網頁版開瀏覽器失敗時，只印提示並退回文字版
func TestWebMainAutoFallback(t *testing.T) {
	finish := captureStdout(t)
	setOpenBrowserFn(t, func(string) error { return errors.New("open failed") })

	done := make(chan int, 1)
	go func() { done <- webMain("", true) }()
	select {
	case code := <-done:
		if code != webFallback {
			t.Errorf("結束碼應為 webFallback，得到 %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webMain 未在 3 秒內回傳")
	}
	if out := finish(); out != "無法開啟瀏覽器，改用文字版。\n" {
		t.Errorf("stdout = %q，預期只有退回文字版提示", out)
	}
}

// TestWebMainAutoConfigError：自動網頁版設定檔錯誤時靜默退回文字版
func TestWebMainAutoConfigError(t *testing.T) {
	finish := captureStdout(t)

	done := make(chan int, 1)
	go func() { done <- webMain("/nonexistent/netlight.json", true) }()
	select {
	case code := <-done:
		if code != webFallback {
			t.Errorf("結束碼應為 webFallback，得到 %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webMain 未在 3 秒內回傳")
	}
	if out := finish(); out != "" {
		t.Errorf("stdout = %q，預期沒有任何輸出", out)
	}
}

// TestWebMainAutoBanner：自動網頁版成功時印三行，/api/shutdown 後回傳 0
func TestWebMainAutoBanner(t *testing.T) {
	pageCh := make(chan string, 1)
	setOpenBrowserFn(t, func(u string) error { pageCh <- u; return nil })
	finish := captureStdout(t)

	done := make(chan int, 1)
	go func() { done <- webMain("", true) }()

	page := <-pageCh
	// page = http://host/t/token/；Origin 檢查只允許 http://host
	base := strings.TrimSuffix(page, "/")
	req, err := http.NewRequest(http.MethodPost, base+"/api/shutdown", nil)
	if err != nil {
		t.Fatalf("建立請求失敗：%v", err)
	}
	req.Header.Set("Origin", base[:strings.Index(base, "/t/")])
	// 伺服器啟動前先重試幾次
	var resp *http.Response
	for range 50 {
		resp, err = http.DefaultClient.Do(req)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if resp == nil {
		t.Fatalf("無法送達 /api/shutdown：%v", err)
	}
	resp.Body.Close()

	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("結束碼應為 0，得到 %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webMain 未在 3 秒內回傳")
	}
	out := finish()
	for _, want := range []string{
		"網路紅綠燈網頁版：" + page + "\n",
		"關閉網頁後會自動結束；按 Ctrl+C 可立即結束。\n",
		"這個視窗是 netlight 本體，請不要關閉；關掉網頁後會自動結束。\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout 缺少 %q：\n%s", want, out)
		}
	}
}
