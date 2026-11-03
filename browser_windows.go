//go:build windows

package main

import "os/exec"

func openBrowser(u string) error {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait() // 回收子程序
	return nil
}
