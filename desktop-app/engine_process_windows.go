//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

const createNoWindowFlag = 0x08000000

func applyHiddenProcessWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindowFlag,
	}
}
