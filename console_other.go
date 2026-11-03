//go:build !windows

package main

import (
	"os"
	"runtime"
	"strings"
)

// setupConsole：回傳是否可用 emoji、是否可用 ANSI 顏色
func setupConsole() (emoji, color bool) {
	st, err := os.Stdout.Stat()
	tty := err == nil && st.Mode()&os.ModeCharDevice != 0
	if runtime.GOOS == "darwin" {
		return true, tty
	}
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := strings.ToUpper(os.Getenv(k)); v != "" {
			return strings.Contains(v, "UTF-8") || strings.Contains(v, "UTF8"), tty
		}
	}
	return false, tty
}

// launchedByDoubleClick：macOS 雙擊會開 Terminal 並保留視窗，不視為雙擊啟動
func launchedByDoubleClick() bool { return false }

// macOS 雙擊會開 Terminal 並保留視窗，不需要暫停
func pauseIfDoubleClicked() {}
