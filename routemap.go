package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// mapState：路線圖進行中畫面的站點狀態（0 等待中、1 已完成判斷中）
type mapState int

const (
	statePending mapState = iota
	stateDone
)

var spinner = [...]string{"◐", "◓", "◑", "◒"}

// lightNeeds：燈名 → 需要哪些 stage 都完成才點亮
var lightNeeds = map[string][]string{
	"本機網路": {"local"}, "路由器": {"gateway"}, "單位網路": {"checkpoints"},
	"對外連線": {"direct"}, "網址查詢": {"dns", "public_dns"}, "網站連線": {"sites", "captive"},
}

// mapStates：某站在 lightNeeds[名稱] 的 stage 全部出現在 done 時為 1，否則為 0
func mapStates(names []string, done map[string]bool) []mapState {
	states := make([]mapState, len(names))
	for i, name := range names {
		ok := true
		for _, s := range lightNeeds[name] {
			if !done[s] {
				ok = false
				break
			}
		}
		if ok {
			states[i] = stateDone
		}
	}
	return states
}

// mapFrame：回傳進行中畫面的各行（不含換行字元），spin 是轉動字元的索引
func mapFrame(names []string, states []mapState, spin int) []string {
	var lines []string
	for i, name := range names {
		if i > 0 {
			lines = append(lines, "  │")
		}
		if states[i] == stateDone {
			lines = append(lines, "  ● "+padName(name)+"已完成，判斷中")
		} else {
			lines = append(lines, "  ◌ "+padName(name)+spinner[spin%4]+" 檢查中")
		}
	}
	return lines
}

// renderMap：以路線圖輸出燈號（不含標題與結論，由呼叫端處理）
func renderMap(w io.Writer, lights []Light, detail bool) {
	broken := -1 // 第一個 Red 的站
	for i, l := range lights {
		if l.Status == Red {
			broken = i
			break
		}
	}
	for i, l := range lights {
		sym := "●"
		switch l.Status {
		case Red:
			sym = "╳"
		case Skip:
			sym = "○"
		}
		line := "  " + sym + " " + padName(l.Name) + emojiMark[l.Status] + " " + statusWord[l.Status] + "  " + l.Summary
		if i == broken {
			line += "  ◀ 斷在這裡"
		}
		fmt.Fprintln(w, line)
		if detail {
			evPrefix := "  │     · "
			if i == len(lights)-1 {
				evPrefix = "        · "
			}
			for _, e := range l.Evidence {
				fmt.Fprintf(w, "%s%s\n", evPrefix, e)
			}
		}
		if i < len(lights)-1 {
			if broken >= 0 && i >= broken {
				fmt.Fprintln(w, "  ┆")
			} else {
				fmt.Fprintln(w, "  │")
			}
		}
	}
}

// clearMapFrame：游標上移 lines 行、逐行清除畫面後，回到畫面第一行
func clearMapFrame(lines int) {
	fmt.Fprintf(os.Stdout, "\x1b[%dA", lines)
	for i := range lines {
		fmt.Print("\r\x1b[2K")
		if i < lines-1 {
			fmt.Print("\x1b[1B")
		}
	}
	if lines > 1 {
		fmt.Fprintf(os.Stdout, "\x1b[%dA", lines-1)
	}
}

// runMap：路線圖模式的主流程：逐站重畫進行中畫面，結束後輸出最終路線圖與結論
func runMap(cfg Config, detail bool) int {
	names := lightNames(cfg)
	now := time.Now()
	fmt.Fprintf(os.Stdout, "網路紅綠燈 netlight v%s · %s · %s\n", version, osName(), now.Format("2006-01-02 15:04"))
	fmt.Fprintln(os.Stdout)

	var mu sync.Mutex
	done := map[string]bool{}
	emit := func(stage string) {
		mu.Lock()
		done[stage] = true
		mu.Unlock()
	}
	draw := func(lines []string) {
		for _, ln := range lines {
			fmt.Fprintln(os.Stdout, ln)
		}
	}
	draw(mapFrame(names, mapStates(names, done), 0))
	prevLines := len(names)*2 - 1

	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		spin := 0
		ticker := time.NewTicker(120 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				spin++
				mu.Lock()
				states := mapStates(names, done)
				mu.Unlock()
				clearMapFrame(prevLines)
				draw(mapFrame(names, states, spin))
				prevLines = len(names)*2 - 1
			}
		}
	}()

	f := runWithEvents(context.Background(), cfg, emit)
	close(stop)
	<-stopped

	// 只清除一次進行中畫面（標題與空行保留）
	clearMapFrame(prevLines)

	r := decide(f, cfg)
	renderMap(os.Stdout, r.Lights, detail)
	fmt.Fprintln(os.Stdout)
	renderVerdict(os.Stdout, r.Verdict)
	return r.Verdict.Code.ExitCode()
}

// useMapMode：路線圖模式只在互動式終端機、支援顏色與 emoji、非 plain、非 JSON 時使用
func useMapMode(isTTY, color, emoji, plain, asJSON bool) bool {
	return isTTY && color && emoji && !plain && !asJSON
}
