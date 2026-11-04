package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web
var webFS embed.FS

// webDir：內嵌的 web/ 前端檔案
var webDir = func() fs.FS {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err) // go:embed 保證 web/ 存在，實際不會發生
	}
	return sub
}()

// webProbe：網頁版的檢測函式（測試可替換）
var webProbe = func(ctx context.Context, cfg Config, emit func(stage string)) Facts {
	return runWithEvents(ctx, cfg, emit)
}

// webFallback：自動網頁版失敗時的回傳值，main 收到後改跑文字版
const webFallback = -1

// openBrowserFn：開啟瀏覽器的函式（測試可替換）
var openBrowserFn = openBrowser

// webTPE：回報文字統一使用的時區（台灣標準時間）
var webTPE = time.FixedZone("CST", 8*3600)

// 閒置結束規則
var (
	webFirstBeat = 60 * time.Second // 從未收到心跳的首班逾時
	webIdle      = 90 * time.Second // 一般閒置逾時
	webBye       = 5 * time.Second  // 收到關閉通知後的寬限
)

const webCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// webTypes：靜態檔的 Content-Type
var webTypes = map[string]string{
	"index.html": "text/html; charset=utf-8",
	"app.js":     "text/javascript; charset=utf-8",
	"app.css":    "text/css; charset=utf-8",
}

// webStageEvent：POST /api/run 串流回應中的 stage 事件（一行 NDJSON）
type webStageEvent struct {
	Type  string `json:"type"`
	Stage string `json:"stage"`
}

// webRunResult：POST /api/run 串流回應的最後一行（report 事件）
type webRunResult struct {
	Type     string     `json:"type"`
	Result   jsonReport `json:"result"`
	Text     string     `json:"text"`
	SafeText string     `json:"safe_text"`
}

// webState：handler 與 webMain 共用的狀態（handler 內不啟動任何 goroutine 或計時器）
type webState struct {
	mu       sync.Mutex
	started  time.Time            // 伺服器啟動時間
	pages    map[string]time.Time // 各分頁的最後心跳時間
	everBeat bool                 // 是否收過任何心跳
	byeAt    time.Time            // 全部分頁都關閉後的時間，零值表示沒有；收到心跳時清為零值
	running  bool                 // 檢測進行中
	closing  bool                 // 已判定結束，不再接受新的檢測
}

// beat：記錄分頁心跳，並取消關閉通知
func (s *webState) beat(now time.Time, page string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pages == nil {
		s.pages = make(map[string]time.Time)
	}
	s.pages[page] = now
	s.everBeat = true
	s.byeAt = time.Time{}
}

// bye：移除分頁；最後一個分頁也關閉時記錄時間，之後在寬限時間結束
func (s *webState) bye(now time.Time, page string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pages, page)
	if len(s.pages) == 0 {
		s.byeAt = now
	}
}

// tryStart：已進入結束程序時回 false，否則標記檢測進行中
func (s *webState) tryStart() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	s.running = true
	return true
}

// finish：檢測結束，解除進行中標記
func (s *webState) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
}

// idle 回傳是否該結束：檢測進行中一律 false；先淘汰心跳超過 webIdle 的分頁；
// 全部分頁都 bye 且滿 webBye → true（寬限期內不得落到後面的規則）；
// 從未心跳且 now-started ≥ webFirstBeat → true；曾收過心跳且分頁全部過期 → true。
// 回 true 時同時設 closing，之後 tryStart 拒絕新的檢測。
func (s *webState) idle(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return false
	}
	for page, at := range s.pages {
		if now.Sub(at) >= webIdle {
			delete(s.pages, page)
		}
	}
	stop := false
	switch {
	case !s.byeAt.IsZero() && len(s.pages) == 0:
		stop = now.Sub(s.byeAt) >= webBye
	case !s.everBeat:
		stop = now.Sub(s.started) >= webFirstBeat
	case s.byeAt.IsZero() && len(s.pages) == 0:
		stop = true
	}
	if stop {
		s.closing = true
	}
	return stop
}

// webMain：--web 進入點，回傳結束碼；auto 為雙擊啟動的自動網頁版，
// 失敗時回傳 webFallback 由 main 改跑文字版
func webMain(cfgPath string, auto bool) int {
	cfg, err := resolveConfig(cfgPath)
	if err != nil {
		if auto {
			return webFallback
		}
		fmt.Fprintln(os.Stderr, err)
		return 3
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if auto {
			return webFallback
		}
		fmt.Fprintln(os.Stderr, "無法開啟本機網頁服務："+err.Error())
		return 2
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		if auto {
			_ = ln.Close()
			return webFallback
		}
		fmt.Fprintln(os.Stderr, "無法產生安全網址："+err.Error())
		return 2
	}
	token := hex.EncodeToString(raw)

	host := net.JoinHostPort("127.0.0.1", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	page := "http://" + host + "/t/" + token + "/"

	if auto {
		// 先開瀏覽器，失敗就退回文字版（伺服器尚未開始服務，直接關 listener）
		if err := openBrowserFn(page); err != nil {
			fmt.Println("無法開啟瀏覽器，改用文字版。")
			_ = ln.Close()
			return webFallback
		}
		fmt.Println("網路紅綠燈網頁版：" + page)
		fmt.Println("關閉網頁後會自動結束；按 Ctrl+C 可立即結束。")
		fmt.Println("這個視窗是 netlight 本體，請不要關閉；關掉網頁後會自動結束。")
	} else {
		fmt.Println("網路紅綠燈網頁版：" + page)
		fmt.Println("關閉網頁後會自動結束；按 Ctrl+C 可立即結束。")
		if err := openBrowserFn(page); err != nil {
			fmt.Println("無法自動開啟瀏覽器，請複製上面的網址貼到瀏覽器。")
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// done：非阻塞的結束通知（只關閉一次 channel）
	var once sync.Once
	shutdown := make(chan struct{})
	done := func() { once.Do(func() { close(shutdown) }) }

	st := &webState{started: time.Now()}
	srv := &http.Server{
		Handler:           newWebHandler(cfg, token, host, st, done),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// 每秒檢查是否該閒置結束
	ticker := time.NewTicker(time.Second)
	tickStop := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				if st.idle(time.Now()) {
					done()
					return
				}
			case <-ctx.Done():
				return
			case <-tickStop:
				return
			}
		}
	}()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	code := 0
	select {
	case <-ctx.Done(): // Ctrl+C
	case <-shutdown: // /api/shutdown、閒置或分頁關閉逾時
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "網頁服務異常結束："+err.Error())
			code = 2
		}
	}

	ticker.Stop()
	close(tickStop)

	shCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(shCtx); err != nil {
		_ = srv.Close() // 逾時，直接關閉剩餘連線
	}
	return code
}

// webMethod：路徑對應的唯一允許方法；空字串表示路徑不存在
func webMethod(rest string) string {
	switch rest {
	case "", "app.js", "app.css", "api/layout":
		return http.MethodGet
	case "api/run", "api/heartbeat", "api/bye", "api/shutdown":
		return http.MethodPost
	}
	return ""
}

// newWebHandler：建立網頁版 handler。host 為「127.0.0.1:<port>」；done 必須是非阻塞的。
func newWebHandler(cfg Config, token, host string, st *webState, done func()) http.Handler {
	prefix := "/t/" + token + "/"
	var runMu sync.Mutex // 同時間只允許一個檢測
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 安全標頭（所有回應）
		w.Header().Set("Content-Security-Policy", webCSP)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")

		// Host 檢查
		if r.Host != host {
			http.Error(w, "禁止存取", http.StatusForbidden)
			return
		}
		// Origin 檢查（非 GET 請求）
		if r.Method != http.MethodGet {
			if o := r.Header.Get("Origin"); o != "" && o != "http://"+host {
				http.Error(w, "禁止存取", http.StatusForbidden)
				return
			}
		}
		// 路徑檢查
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		rest := r.URL.Path[len(prefix):]

		if m := webMethod(rest); m != "" && r.Method != m {
			w.Header().Set("Allow", m)
			http.Error(w, "方法不允許", http.StatusMethodNotAllowed)
			return
		}

		switch rest {
		case "", "app.js", "app.css":
			name := "index.html"
			if rest != "" {
				name = rest
			}
			b, err := fs.ReadFile(webDir, name)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", webTypes[name])
			_, _ = w.Write(b)
		case "api/layout":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			enc := json.NewEncoder(w)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(struct {
				Lights []string `json:"lights"`
			}{lightNames(cfg)})
		case "api/run":
			if !runMu.TryLock() {
				http.Error(w, "已有一個檢查正在進行", http.StatusConflict)
				return
			}
			defer runMu.Unlock()
			if !st.tryStart() {
				http.Error(w, "netlight 正在結束", http.StatusServiceUnavailable)
				return
			}
			defer st.finish()
			// NDJSON 串流：每組探測完成就輸出一行 stage 事件，最後一行是 report 事件；每行輸出後立即 flush
			w.Header().Set("Content-Type", "application/x-ndjson")
			w.WriteHeader(http.StatusOK)
			flusher, _ := w.(http.Flusher)
			enc := json.NewEncoder(w)
			enc.SetEscapeHTML(false)
			var streamErr error // 用戶端斷線後不再寫後續行，檢測流程照常結束
			emit := func(stage string) {
				if streamErr != nil {
					return
				}
				streamErr = enc.Encode(webStageEvent{Type: "stage", Stage: stage})
				if streamErr == nil && flusher != nil {
					flusher.Flush()
				}
			}
			f := webProbe(r.Context(), cfg, emit)
			rep := decide(f, cfg)
			now := time.Now()
			if streamErr == nil {
				streamErr = enc.Encode(webRunResult{
					Type:     "report",
					Result:   jsonReport{version, now.Format(time.RFC3339), f.Local.OS, rep, f},
					Text:     webReportText(rep, f, now),
					SafeText: webSafeReportText(rep, f.Local.OS, now),
				})
				if streamErr == nil && flusher != nil {
					flusher.Flush()
				}
			}
		case "api/heartbeat":
			page := r.URL.Query().Get("p")
			if page == "" {
				http.Error(w, "缺少頁面識別", http.StatusBadRequest)
				return
			}
			st.beat(time.Now(), page)
			w.WriteHeader(http.StatusNoContent)
		case "api/bye":
			page := r.URL.Query().Get("p")
			if page == "" {
				http.Error(w, "缺少頁面識別", http.StatusBadRequest)
				return
			}
			st.bye(time.Now(), page)
			w.WriteHeader(http.StatusNoContent)
		case "api/shutdown":
			w.WriteHeader(http.StatusNoContent)
			done()
		default:
			http.NotFound(w, r)
		}
	})
}

// webReportText：組出「複製回報給 IT」用的純文字
func webReportText(rep Report, f Facts, now time.Time) string {
	now = now.In(webTPE)
	var b strings.Builder
	fmt.Fprintln(&b, "【netlight 網路診斷回報】")
	fmt.Fprintf(&b, "時間：%s 台灣標準時間\n", now.Format("2006-01-02 15:04"))
	fmt.Fprintf(&b, "版本：netlight v%s · %s\n", version, f.Local.OS)
	fmt.Fprintf(&b, "結論碼：%s\n", rep.Verdict.Code)
	render(&b, rep, f.Local.OS, now, renderMode{Detail: true})
	return b.String()
}

// safeLabelRe：看起來像位址的片段（IPv4、含 :// 的網址、含冒號的 IPv6 片段、帶點的主機名稱）。
// 網址的比對到下一個空白或全形標點（含「」）為止。
var safeLabelRe = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b` +
	`|[A-Za-z][A-Za-z0-9+.-]*://[^\s「」『』（）〈〉《》【】、。，；：？！…・]+` +
	`|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,}` +
	`|\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b`)

// safeLabel：把看起來像位址的文字換成「（已隱藏）」，一般名稱原樣保留。
// 只用於設定檔可能填入位址的欄位（網站名稱）；程式固定文字與聯絡資訊不套用。
func safeLabel(s string) string {
	return safeLabelRe.ReplaceAllString(s, "（已隱藏）")
}

// webSafeReportText：可放心貼到群組的回報摘要（不含燈號說明、技術證據、IP 與網址）
func webSafeReportText(rep Report, osName string, now time.Time) string {
	now = now.In(webTPE)
	var b strings.Builder
	fmt.Fprintln(&b, "【netlight 網路診斷摘要】")
	fmt.Fprintf(&b, "時間：%s 台灣標準時間\n", now.Format("2006-01-02 15:04"))
	fmt.Fprintf(&b, "版本：netlight v%s · %s\n", version, osName)
	fmt.Fprintf(&b, "結論碼：%s\n", rep.Verdict.Code)
	rows := make([]string, len(rep.Lights))
	for i, l := range rep.Lights {
		rows[i] = l.Name + " " + statusWord[l.Status]
	}
	fmt.Fprintf(&b, "燈號：%s\n", strings.Join(rows, "｜"))
	fmt.Fprintf(&b, "結論：%s\n", safeLabel(rep.Verdict.Text))
	fmt.Fprintf(&b, "建議：%s\n", rep.Verdict.Action)
	if rep.Verdict.Contact != "" {
		if rep.Verdict.Org != "" {
			fmt.Fprintf(&b, "聯絡（%s）：%s\n", rep.Verdict.Org, rep.Verdict.Contact)
		} else {
			fmt.Fprintf(&b, "聯絡：%s\n", rep.Verdict.Contact)
		}
	}
	fmt.Fprintln(&b, "（這份摘要不含這台電腦的 IP、網址與技術細節；資訊人員需要時，請另外提供完整技術資料。）")
	return b.String()
}
