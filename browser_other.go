//go:build !windows

package main

import (
	"os/exec"
	"runtime"
)

func openBrowser(u string) error {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	cmd := exec.Command(name, u)
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait() // 回收子程序
	return nil
}
