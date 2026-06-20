//go:build !windows

package main

import "os/exec"

func applyHiddenProcessWindow(cmd *exec.Cmd) {}
