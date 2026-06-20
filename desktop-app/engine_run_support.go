package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
)

type EngineRunCallbacks struct {
	EmitEvent      func(EngineEvent)
	EmitLocalError func(string, error)
	EmitCanceled   func(EngineLaunchSpec, context.Context)
}

func (callbacks EngineRunCallbacks) emitEvent(event EngineEvent) {
	if callbacks.EmitEvent != nil {
		callbacks.EmitEvent(event)
	}
}

func (callbacks EngineRunCallbacks) emitLocalError(contextMessage string, err error) {
	if callbacks.EmitLocalError != nil {
		callbacks.EmitLocalError(contextMessage, err)
	}
}

func (callbacks EngineRunCallbacks) emitCanceled(launchSpec EngineLaunchSpec, runContext context.Context) {
	if callbacks.EmitCanceled != nil {
		callbacks.EmitCanceled(launchSpec, runContext)
	}
}

func runEngineProcess(runContext context.Context, launchSpec EngineLaunchSpec, callbacks EngineRunCallbacks) {
	cmd := exec.CommandContext(runContext, launchSpec.CommandPath, launchSpec.CommandArgs...)
	cmd.Dir = launchSpec.CommandDir
	applyHiddenProcessWindow(cmd)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		callbacks.emitLocalError("stdout pipe failed", fmt.Errorf("command=%s args=%v: %w", launchSpec.CommandPath, launchSpec.CommandArgs, err))
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		callbacks.emitLocalError("stderr pipe failed", fmt.Errorf("command=%s args=%v: %w", launchSpec.CommandPath, launchSpec.CommandArgs, err))
		return
	}

	if err = cmd.Start(); err != nil {
		callbacks.emitLocalError("command start failed", fmt.Errorf("command=%s args=%v dir=%s mode=%s: %w", launchSpec.CommandPath, launchSpec.CommandArgs, launchSpec.CommandDir, launchSpec.Mode, err))
		return
	}

	stderrBuffer := new(strings.Builder)
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)

	go func() {
		defer waitGroup.Done()
		consumeEngineStdout(stdoutPipe, callbacks)
	}()

	go func() {
		defer waitGroup.Done()
		consumeEngineStderr(stderrPipe, stderrBuffer, callbacks)
	}()

	waitErr := cmd.Wait()
	waitGroup.Wait()

	if waitErr != nil {
		if isCanceledRun(runContext, waitErr) {
			callbacks.emitCanceled(launchSpec, runContext)
			return
		}

		callbacks.emitEvent(EngineEvent{
			Level:   "error",
			Type:    "error",
			Message: fmt.Sprintf("engine process failed: mode=%s command=%s args=%v dir=%s exit=%v stderr=%s", launchSpec.Mode, launchSpec.CommandPath, launchSpec.CommandArgs, launchSpec.CommandDir, waitErr, truncateString(stderrBuffer.String(), 1200)),
		})
		return
	}

	if runContext.Err() != nil {
		callbacks.emitCanceled(launchSpec, runContext)
	}
}

func consumeEngineStdout(reader io.Reader, callbacks EngineRunCallbacks) {
	scanner := bufio.NewScanner(reader)
	configureEngineScanner(scanner)
	for scanner.Scan() {
		line := scanner.Text()
		event, err := parseEngineEventLine(line)
		if err != nil {
			callbacks.emitLocalError("parse engine stdout failed", fmt.Errorf("line=%s: %w", line, err))
			continue
		}
		callbacks.emitEvent(event)
	}

	if err := scanner.Err(); err != nil {
		callbacks.emitLocalError("read engine stdout failed", err)
	}
}

func consumeEngineStderr(reader io.Reader, stderrBuffer *strings.Builder, callbacks EngineRunCallbacks) {
	scanner := bufio.NewScanner(reader)
	configureEngineScanner(scanner)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		stderrBuffer.WriteString(line)
		stderrBuffer.WriteByte('\n')
		callbacks.emitEvent(EngineEvent{
			Level:   "warn",
			Type:    "warn",
			Message: line,
		})
	}

	if err := scanner.Err(); err != nil {
		callbacks.emitLocalError("read engine stderr failed", err)
	}
}

func configureEngineScanner(scanner *bufio.Scanner) {
	const maxEngineLineSize = 1024 * 1024
	scanner.Buffer(make([]byte, 0, 64*1024), maxEngineLineSize)
}
