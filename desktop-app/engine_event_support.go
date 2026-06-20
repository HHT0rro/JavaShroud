package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func parseEngineEventLine(line string) (EngineEvent, error) {
	event, err := parseTomlEventLine(line)
	if err != nil {
		return EngineEvent{}, fmt.Errorf("decode TOML event failed: %w", err)
	}
	if strings.TrimSpace(event.Type) == "" {
		return EngineEvent{}, fmt.Errorf("decode TOML event failed: missing type")
	}
	if !isKnownEventType(event.Type) {
		return EngineEvent{}, fmt.Errorf("decode TOML event failed: unknown type=%s", event.Type)
	}
	if strings.TrimSpace(event.Message) == "" {
		return EngineEvent{}, fmt.Errorf("decode TOML event failed: missing message")
	}
	if strings.TrimSpace(event.Level) == "" {
		event.Level = inferLevel(event.Type)
	}
	if !isKnownEventLevel(event.Level) {
		return EngineEvent{}, fmt.Errorf("decode TOML event failed: unknown level=%s", event.Level)
	}
	if event.Progress != nil && (*event.Progress < 0 || *event.Progress > 100) {
		return EngineEvent{}, fmt.Errorf("decode TOML event failed: progress out of range: %d", *event.Progress)
	}
	return event, nil
}

func parseTomlEventLine(line string) (EngineEvent, error) {
	trimmedLine := strings.TrimSpace(line)
	const prefix = "event = {"
	if !strings.HasPrefix(trimmedLine, prefix) || !strings.HasSuffix(trimmedLine, "}") {
		return EngineEvent{}, fmt.Errorf("expected event inline table")
	}
	body := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmedLine, prefix), "}"))
	fields, err := parseTomlInlineFields(body)
	if err != nil {
		return EngineEvent{}, err
	}

	event := EngineEvent{
		Level:   fields["level"],
		Type:    fields["type"],
		Message: fields["message"],
	}
	if progressValue, ok := fields["progress"]; ok {
		progress, err := strconv.Atoi(progressValue)
		if err != nil {
			return EngineEvent{}, fmt.Errorf("progress is not an integer: %w", err)
		}
		event.Progress = &progress
	}
	if outPath, ok := fields["outPath"]; ok {
		event.OutPath = &outPath
	}
	return event, nil
}

func parseTomlInlineFields(body string) (map[string]string, error) {
	result := map[string]string{}
	for _, rawField := range splitTomlInlineFields(body) {
		field := strings.TrimSpace(rawField)
		if field == "" {
			continue
		}
		separatorIndex := strings.Index(field, "=")
		if separatorIndex <= 0 {
			return nil, fmt.Errorf("invalid inline table field: %s", field)
		}
		key := strings.TrimSpace(field[:separatorIndex])
		value := strings.TrimSpace(field[separatorIndex+1:])
		if key == "progress" {
			result[key] = value
			continue
		}
		unquoted, err := strconv.Unquote(value)
		if err != nil {
			return nil, fmt.Errorf("invalid string value for %s: %w", key, err)
		}
		result[key] = unquoted
	}
	return result, nil
}

func splitTomlInlineFields(body string) []string {
	fields := []string{}
	startIndex := 0
	inString := false
	escaped := false
	for index, char := range body {
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if char == '"' {
			inString = !inString
			continue
		}
		if char == ',' && !inString {
			fields = append(fields, body[startIndex:index])
			startIndex = index + 1
		}
	}
	fields = append(fields, body[startIndex:])
	return fields
}

func inferLevel(eventType string) string {
	if eventType == "error" {
		return "error"
	}
	if eventType == "done" {
		return "success"
	}
	return "info"
}

func isKnownEventType(eventType string) bool {
	switch eventType {
	case "progress", "log", "done", "error", "warn", "canceled":
		return true
	default:
		return false
	}
}

func isKnownEventLevel(level string) bool {
	switch level {
	case "info", "warn", "error", "success":
		return true
	default:
		return false
	}
}

func isCanceledRun(runContext context.Context, waitErr error) bool {
	if runContext.Err() == nil {
		return false
	}

	return errors.Is(waitErr, context.Canceled) || errors.Is(runContext.Err(), context.Canceled)
}

func truncateString(value string, maxLength int) string {
	if maxLength <= 0 {
		return ""
	}
	if len(value) <= maxLength {
		return value
	}
	return value[:maxLength]
}
