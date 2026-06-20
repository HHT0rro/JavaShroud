package main

import (
	"strings"
	"testing"
)

func TestValidateObfuscationRequest_RejectsInvalidRuleActions(t *testing.T) {
	request := ObfuscationRequest{
		InputJarPath:  "C:/work/input.jar",
		OutputJarPath: "C:/work/output.jar",
		Passes: []PassSpec{
			{ID: "string-encryption", Enabled: true},
		},
		Rules: []RuleItem{
			{ID: "rule-1", Target: "com/example/App", Action: "delete"},
		},
	}

	err := validateObfuscationRequest(request)
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if !strings.Contains(err.Error(), "rule action is invalid") {
		t.Fatalf("expected invalid rule action error, got %q", err.Error())
	}
}

func TestValidateObfuscationRequest_RequiresEnabledPassWithID(t *testing.T) {
	baseRequest := ObfuscationRequest{
		InputJarPath:  "C:/work/input.jar",
		OutputJarPath: "C:/work/output.jar",
	}

	tests := []struct {
		name    string
		passes  []PassSpec
		wantErr string
	}{
		{
			name:    "all passes disabled",
			passes:  []PassSpec{{ID: "string-encryption", Enabled: false}},
			wantErr: "no enabled passes",
		},
		{
			name:    "enabled pass has empty id",
			passes:  []PassSpec{{ID: "  ", Enabled: true}},
			wantErr: "pass id is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := baseRequest
			request.Passes = tt.passes

			err := validateObfuscationRequest(request)
			if err == nil {
				t.Fatalf("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error to contain %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}
