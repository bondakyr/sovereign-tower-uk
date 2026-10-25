//go:build windows

package main

import "syscall"

func setupConsole() {
	k := syscall.NewLazyDLL("kernel32.dll")
	if p := k.NewProc("SetConsoleOutputCP"); p.Find() == nil {
		p.Call(65001)
	}
	if p := k.NewProc("SetConsoleCP"); p.Find() == nil {
		p.Call(65001)
	}
}
