package main

import (
	"errors"
	"strings"
	"testing"
)

func TestBuildEngineCommandFailureError_IncludesCombinedOutput(t *testing.T) {
	launchSpec := EngineLaunchSpec{
		CommandPath: "engine.exe",
		CommandArgs: []string{"-schema"},
		CommandDir:  "C:/JavaShroud/engine",
		Mode:        "native-exe",
	}

	err := buildEngineCommandFailureError("schema", launchSpec, []byte("schema failure on stderr\n"), errors.New("exit status 2"))
	message := err.Error()

	for _, expected := range []string{
		"schema",
		"mode=native-exe",
		"command=engine.exe",
		"args=[-schema]",
		"dir=C:/JavaShroud/engine",
		"output=schema failure on stderr",
		"exit status 2",
	} {
		if !strings.Contains(message, expected) {
			t.Fatalf("expected error to contain %q, got %q", expected, message)
		}
	}
}

func TestBuildEngineCommandFailureError_RetainsTerminalDiagnostic(t *testing.T) {
	terminal := "fatal: native compiler failed at js_vm_core.c:6703"
	output := []byte(strings.Repeat("WARNING: edge injection skipped\n", 200) + terminal)

	err := buildEngineCommandFailureError("schema", EngineLaunchSpec{
		CommandPath: "engine.exe",
		CommandArgs: []string{"-schema"},
		CommandDir:  "C:/JavaShroud/engine",
		Mode:        "native-exe",
	}, output, errors.New("exit status 2"))

	message := err.Error()
	if !strings.Contains(message, terminal) {
		t.Fatalf("expected terminal diagnostic to be retained, got %q", message)
	}
	if !strings.Contains(message, "final diagnostics retained") {
		t.Fatalf("expected truncation marker, got %q", message)
	}
}
