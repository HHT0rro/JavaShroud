package main

import "testing"

func TestParseEngineEventLine_RejectsInvalidTypeLevelAndProgress(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{
			name: "unknown type",
			line: `event = { level = "info", type = "debug", message = "bad event", progress = 1 }`,
		},
		{
			name: "unknown level",
			line: `event = { level = "debug", type = "log", message = "bad event", progress = 1 }`,
		},
		{
			name: "negative progress",
			line: `event = { level = "info", type = "progress", message = "bad event", progress = -1 }`,
		},
		{
			name: "over 100 progress",
			line: `event = { level = "info", type = "progress", message = "bad event", progress = 101 }`,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseEngineEventLine(tt.line); err == nil {
				t.Fatalf("expected parseEngineEventLine to reject %s", tt.name)
			}
		})
	}
}

func TestParseEngineEventLine_AcceptsEngineAndHostEventTypes(t *testing.T) {
	cases := []string{
		`event = { level = "info", type = "progress", message = "running", progress = 50 }`,
		`event = { level = "info", type = "log", message = "running" }`,
		`event = { level = "success", type = "done", message = "done", progress = 100, outPath = "out.jar" }`,
		`event = { level = "error", type = "error", message = "failed" }`,
		`event = { level = "warn", type = "warn", message = "stderr" }`,
		`event = { level = "warn", type = "canceled", message = "canceled" }`,
	}

	for _, line := range cases {
		if _, err := parseEngineEventLine(line); err != nil {
			t.Fatalf("expected parseEngineEventLine to accept %s: %v", line, err)
		}
	}
}
