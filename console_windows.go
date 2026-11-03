package main

import (
	"bufio"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetConsoleProcessList = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")

// setupConsole：只有 Windows Terminal 才顯示 emoji；舊版主控台改用文字燈號
func setupConsole() (emoji, color bool) {
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) == nil {
		color = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
	}
	return os.Getenv("WT_SESSION") != "", color
}

// launchedByDoubleClick：從檔案總管雙擊時，主控台只屬於本程式（n == 1）
func launchedByDoubleClick() bool {
	var pids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), 2)
	return n == 1
}

// pauseIfDoubleClicked：從檔案總管雙擊啟動時，結束前等使用者按 Enter
func pauseIfDoubleClicked() {
	if launchedByDoubleClick() {
		fmt.Print("\n按 Enter 鍵結束…")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
}
