package main

import (
	"strings"
	"testing"
)

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
