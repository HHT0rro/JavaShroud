package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

func validateObfuscationRequest(request ObfuscationRequest) error {
	if strings.TrimSpace(request.InputJarPath) == "" {
		return fmt.Errorf("start obfuscation failed: inputJarPath is empty: request=%+v", request)
	}
	if strings.TrimSpace(request.OutputJarPath) == "" {
		return fmt.Errorf("start obfuscation failed: outputJarPath is empty: request=%+v", request)
	}
	if len(request.Passes) == 0 {
		return fmt.Errorf("start obfuscation failed: passes is empty: request=%+v", request)
	}
	enabledPassCount := 0
	for index, passSpec := range request.Passes {
		if strings.TrimSpace(passSpec.ID) == "" {
			return fmt.Errorf("start obfuscation failed: pass id is empty: index=%d", index)
		}
		if passSpec.Enabled {
			enabledPassCount++
		}
	}
	if enabledPassCount == 0 {
		return fmt.Errorf("start obfuscation failed: no enabled passes")
	}
	for index, rule := range request.Rules {
		if strings.TrimSpace(rule.Target) == "" {
			return fmt.Errorf("start obfuscation failed: rule target is empty: index=%d", index)
		}
		if !isKnownDesktopRuleAction(rule.Action) {
			return fmt.Errorf("start obfuscation failed: rule action is invalid: index=%d action=%s", index, rule.Action)
		}
	}
	return nil
}

func isKnownDesktopRuleAction(action string) bool {
	switch strings.TrimSpace(action) {
	case "exclude", "obfuscate":
		return true
	default:
		return false
	}
}

func (a *App) StartObfuscation(request ObfuscationRequest) error {
	if err := validateObfuscationRequest(request); err != nil {
		return err
	}

	runContext, err := a.beginObfuscationRun()
	if err != nil {
		return err
	}

	go func() {
		defer a.clearCancellation()
		a.runEngine(runContext, request)
	}()

	return nil
}

func (a *App) beginObfuscationRun() (context.Context, error) {
	if a.ctx == nil {
		return nil, errors.New("start obfuscation failed: Wails context is nil")
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cancelCurrent != nil {
		return nil, errors.New("start obfuscation failed: another task is already running")
	}

	runContext, cancel := context.WithCancel(a.ctx)
	a.cancelCurrent = cancel
	return runContext, nil
}

func (a *App) CancelObfuscation() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cancelCurrent == nil {
		return errors.New("cancel obfuscation failed: no running task")
	}

	a.cancelCurrent()
	return nil
}

func (a *App) runEngine(runContext context.Context, request ObfuscationRequest) {
	tempDir, tempFilePath, cleanup, err := prepareConfigFile(request)
	if err != nil {
		a.emitLocalError("prepare config failed", err)
		return
	}
	defer cleanup()
	defer os.RemoveAll(tempDir)

	launchSpec, err := resolveEngineLaunchSpec(tempFilePath)
	if err != nil {
		a.emitLocalError("resolve engine command failed", err)
		return
	}

	runEngineProcess(runContext, launchSpec, a.engineRunCallbacks())
}

func (a *App) clearCancellation() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cancelCurrent = nil
}
