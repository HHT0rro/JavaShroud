package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEngineProcessCanceledBeforeStart(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runContext, cancel := context.WithCancel(context.Background())
	cancel()
	var canceled int
	var localErrors []error
	runEngineProcess(runContext, EngineLaunchSpec{CommandPath: binary}, EngineRunCallbacks{
		EmitCanceled:   func(EngineLaunchSpec, context.Context) { canceled++ },
		EmitLocalError: func(_ string, err error) { localErrors = append(localErrors, err) },
	})
	if canceled != 1 || len(localErrors) != 0 {
		t.Fatalf("expected cancellation before start: canceled=%d errors=%v", canceled, localErrors)
	}
}

func TestEngineProcessCancellationDrainsBothStreams(t *testing.T) {
	t.Setenv("JAVASHROUD_TEST_ENGINE_PROCESS", "cancel")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var mu sync.Mutex
	var events []EngineEvent
	var localErrors []error
	var canceled, working int
	var terminalDiagnostic bool
	runEngineProcess(runContext, EngineLaunchSpec{
		CommandPath: binary,
		CommandArgs: []string{"-test.run=^TestFixtureEngineProcess$"},
	}, EngineRunCallbacks{
		EmitEvent: func(event EngineEvent) {
			mu.Lock()
			defer mu.Unlock()
			events = append(events, event)
			if event.Message == "working" {
				working++
			}
			terminalDiagnostic = terminalDiagnostic || event.Message == "fixture terminal diagnostic"
			if event.Message == "ready to cancel" {
				cancel()
			}
		},
		EmitCanceled: func(EngineLaunchSpec, context.Context) {
			mu.Lock()
			defer mu.Unlock()
			canceled++
			events = append(events, EngineEvent{Type: "canceled"})
		},
		EmitLocalError: func(_ string, err error) {
			mu.Lock()
			defer mu.Unlock()
			localErrors = append(localErrors, err)
		},
	})
	if working != 400 || !terminalDiagnostic || canceled != 1 || len(localErrors) != 0 {
		t.Fatalf("cancellation lost output: working=%d diagnostic=%t canceled=%d errors=%v", working, terminalDiagnostic, canceled, localErrors)
	}
	if events[len(events)-1].Type != "canceled" {
		t.Fatalf("cancellation must follow stream output, got final event %+v", events[len(events)-1])
	}
}

func TestEngineProcessDeliversEventsWrittenAtExit(t *testing.T) {
	t.Setenv("JAVASHROUD_TEST_ENGINE_PROCESS", "1")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var done, finalDiagnostic bool
	var readErrors []error
	runEngineProcess(context.Background(), EngineLaunchSpec{
		CommandPath: binary,
		CommandArgs: []string{"-test.run=^TestFixtureEngineProcess$"},
	}, EngineRunCallbacks{
		EmitEvent: func(event EngineEvent) {
			mu.Lock()
			defer mu.Unlock()
			done = done || event.Type == "done"
			finalDiagnostic = finalDiagnostic || strings.Contains(event.Message, "fixture terminal diagnostic")
		},
		EmitLocalError: func(_ string, err error) {
			mu.Lock()
			defer mu.Unlock()
			readErrors = append(readErrors, err)
		},
	})
	if !done || !finalDiagnostic || len(readErrors) != 0 {
		t.Fatalf("child exit lost output: done=%t diagnostic=%t errors=%v", done, finalDiagnostic, readErrors)
	}
}

func TestFixtureEngineProcess(t *testing.T) {
	mode := os.Getenv("JAVASHROUD_TEST_ENGINE_PROCESS")
	if mode == "" {
		return
	}
	for i := 0; i < 400; i++ {
		fmt.Fprintln(os.Stdout, `event = { level = "info", type = "progress", message = "working", progress = 25 }`)
	}
	if mode == "cancel" {
		fmt.Fprint(os.Stderr, "fixture terminal diagnostic")
		fmt.Fprintln(os.Stdout, `event = { level = "info", type = "progress", message = "ready to cancel" }`)
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	fmt.Fprintln(os.Stdout, `event = { level = "success", type = "done", message = "processed fixture", progress = 100 }`)
	fmt.Fprintln(os.Stderr, "fixture terminal diagnostic")
	os.Exit(0)
}

func TestSummarizeEngineStderrRetainsTerminalDiagnostic(t *testing.T) {
	terminal := "fatal: native compiler failed at js_vm_core.c:6703"
	stderr := strings.Repeat("WARNING: edge injection skipped\n", 200) + terminal

	summary := summarizeEngineStderr(stderr, 180)

	if !strings.Contains(summary, "WARNING: edge injection skipped") {
		t.Fatalf("expected summary to retain leading context, got %q", summary)
	}
	if !strings.Contains(summary, terminal) {
		t.Fatalf("expected summary to retain terminal diagnostic, got %q", summary)
	}
	if !strings.Contains(summary, "final diagnostics retained") {
		t.Fatalf("expected truncation marker, got %q", summary)
	}
}
