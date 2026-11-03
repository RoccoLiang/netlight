package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

var version = "1.0.0"

func main() {
	detail := flag.Bool("detail", false, "列出每一盞燈的技術證據")
	asJSON := flag.Bool("json", false, "以 JSON 輸出（給腳本或回報問題用）")
	plain := flag.Bool("plain", false, "不使用 emoji 與顏色")
	noPause := flag.Bool("no-pause", false, "結束時不等待按鍵")
	cfgPath := flag.String("config", "", "設定檔路徑（預設找執行檔旁或目前目錄的 netlight.json）")
	web := flag.Bool("web", false, "在瀏覽器開啟網頁版")
	showVer := flag.Bool("version", false, "顯示版本")
	flag.Parse()

	if *showVer {
		fmt.Println("netlight", version)
		return
	}
	if *web {
		os.Exit(webMain(*cfgPath, false))
	}
	if autoWeb(flag.NFlag(), flag.NArg(), launchedByDoubleClick()) {
		if code := webMain(*cfgPath, true); code != webFallback {
			os.Exit(code)
		}
	}
	code := runMain(*detail, *asJSON, *plain, *cfgPath)
	if !*noPause && !*asJSON {
		pauseIfDoubleClicked()
	}
	os.Exit(code)
}

// autoWeb：雙擊啟動且沒有任何命令列參數時，改用網頁版
func autoWeb(nflag, narg int, doubleClick bool) bool {
	return doubleClick && nflag == 0 && narg == 0
}

// resolveConfig：cfgPath 為空時自動尋找設定檔，載入失敗回傳錯誤
func resolveConfig(cfgPath string) (Config, error) {
	if cfgPath == "" {
		exeDir := ""
		if exe, err := os.Executable(); err == nil {
			if p, err := filepath.EvalSymlinks(exe); err == nil {
				exeDir = filepath.Dir(p)
			}
		}
		cwd, _ := os.Getwd()
		cfgPath = findConfig(exeDir, cwd)
	}
	var cfg Config
	if cfgPath != "" {
		var err error
		if cfg, err = loadConfig(cfgPath); err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

func runMain(detail, asJSON, plain bool, cfgPath string) int {
	cfg, err := resolveConfig(cfgPath)
	if err != nil {
		return configErrorExit(os.Stdout, os.Stderr, err, asJSON)
	}

	emoji, color := setupConsole()
	progress := stdoutIsTerminal() && !asJSON // stdout 是終端機時顯示進度提示
	const progressMsg = "檢查中，最多約 10 秒…"
	if progress {
		fmt.Print(progressMsg)
	}
	f := run(context.Background(), cfg)
	r := decide(f, cfg)
	now := time.Now()
	if asJSON {
		if err := renderJSON(os.Stdout, r, f, now); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		return r.Verdict.Code.ExitCode()
	}
	if progress {
		if color {
			fmt.Print("\r\x1b[K")
		} else {
			fmt.Print("\r" + strings.Repeat(" ", 2*utf8.RuneCountInString(progressMsg)) + "\r")
		}
	}
	render(os.Stdout, r, f.Local.OS, now, renderMode{Emoji: emoji && !plain, Color: color && !plain, Detail: detail})
	return r.Verdict.Code.ExitCode()
}

// configErrorExit：設定檔錯誤的輸出與結束碼（3）
func configErrorExit(w io.Writer, errw io.Writer, err error, asJSON bool) int {
	if asJSON {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
	} else {
		fmt.Fprintln(errw, err)
	}
	return 3
}

// stdoutIsTerminal：stdout 是否為終端機
func stdoutIsTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
