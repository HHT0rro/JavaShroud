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
