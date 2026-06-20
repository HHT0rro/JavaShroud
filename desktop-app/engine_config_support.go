package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func prepareConfigFile(request ObfuscationRequest) (string, string, func(), error) {
	if err := validateObfuscationRequest(request); err != nil {
		return "", "", func() {}, fmt.Errorf("validate desktop request failed: %w", err)
	}

	tempDir, err := os.MkdirTemp("", "javashroud-config-*")
	if err != nil {
		return "", "", func() {}, fmt.Errorf("create temp dir failed: %w", err)
	}

	inputJarPath, err := normalizeEngineConfigPath(request.InputJarPath)
	if err != nil {
		return tempDir, "", func() {}, fmt.Errorf("resolve input jar path failed: path=%s: %w", request.InputJarPath, err)
	}
	outputJarPath, err := normalizeEngineConfigPath(request.OutputJarPath)
	if err != nil {
		return tempDir, "", func() {}, fmt.Errorf("resolve output jar path failed: path=%s: %w", request.OutputJarPath, err)
	}

	config := EngineConfig{
		InputJarPath:         inputJarPath,
		OutputJarPath:        outputJarPath,
		Passes:               clonePasses(request.Passes),
		RuleSet:              RuleSet{Rules: cloneRules(request.Rules)},
		AllowOptInPasses:     request.AllowOptInPasses,
		AllowRedundantPasses: request.AllowRedundantPasses,
	}

	payload, err := formatEngineConfigToml(config)
	if err != nil {
		return tempDir, "", func() {}, fmt.Errorf("marshal config failed: %w", err)
	}

	configPath := filepath.Join(tempDir, "obfuscation-config.toml")
	if err = os.WriteFile(configPath, []byte(payload), 0o600); err != nil {
		return tempDir, "", func() {}, fmt.Errorf("write config failed: path=%s: %w", configPath, err)
	}

	return tempDir, configPath, func() {}, nil
}

func normalizeEngineConfigPath(inputPath string) (string, error) {
	absolutePath, err := filepath.Abs(inputPath)
	if err != nil {
		return "", err
	}

	return filepath.ToSlash(filepath.Clean(absolutePath)), nil
}

func clonePasses(passSpecs []PassSpec) []PassSpec {
	result := make([]PassSpec, 0, len(passSpecs))
	for _, passSpec := range passSpecs {
		result = append(result, PassSpec{ID: passSpec.ID, Enabled: passSpec.Enabled, Params: clonePassParams(passSpec.Params)})
	}
	return result
}

func clonePassParams(params map[string]json.RawMessage) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(params))
	for key, value := range params {
		result[key] = append(json.RawMessage(nil), value...)
	}
	return result
}

func cloneRules(rules []RuleItem) []RuleItem {
	result := make([]RuleItem, 0, len(rules))
	for _, rule := range rules {
		result = append(result, RuleItem{ID: rule.ID, Target: rule.Target, Action: rule.Action})
	}
	return result
}

func formatEngineConfigToml(config EngineConfig) (string, error) {
	var builder strings.Builder
	builder.WriteString("inputJarPath = ")
	builder.WriteString(formatTomlString(config.InputJarPath))
	builder.WriteString("\n")
	builder.WriteString("outputJarPath = ")
	builder.WriteString(formatTomlString(config.OutputJarPath))
	builder.WriteString("\n")
	builder.WriteString("allowOptInPasses = ")
	builder.WriteString(strconv.FormatBool(config.AllowOptInPasses))
	builder.WriteString("\n")
	builder.WriteString("allowRedundantPasses = ")
	builder.WriteString(strconv.FormatBool(config.AllowRedundantPasses))
	builder.WriteString("\n\n")

	for _, passSpec := range config.Passes {
		builder.WriteString("[[passes]]\n")
		builder.WriteString("id = ")
		builder.WriteString(formatTomlString(passSpec.ID))
		builder.WriteString("\n")
		builder.WriteString("enabled = ")
		builder.WriteString(strconv.FormatBool(passSpec.Enabled))
		builder.WriteString("\n")
		if len(passSpec.Params) > 0 {
			formattedParams := make([]string, 0, len(passSpec.Params))
			keys := make([]string, 0, len(passSpec.Params))
			for key := range passSpec.Params {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				value, ok, err := formatTomlRawScalar(passSpec.Params[key])
				if err != nil {
					return "", fmt.Errorf("format pass param failed: pass=%s param=%s: %w", passSpec.ID, key, err)
				}
				if !ok {
					continue
				}
				formattedParams = append(formattedParams, key+" = "+value)
			}
			if len(formattedParams) > 0 {
				builder.WriteString("\n[passes.params]\n")
				for _, formattedParam := range formattedParams {
					builder.WriteString(formattedParam)
					builder.WriteString("\n")
				}
			}
		}
		builder.WriteString("\n")
	}

	builder.WriteString("[ruleSet]\n")
	if len(config.RuleSet.Rules) == 0 {
		builder.WriteString("rules = []\n")
	} else {
		for _, rule := range config.RuleSet.Rules {
			builder.WriteString("[[ruleSet.rules]]\n")
			builder.WriteString("target = ")
			builder.WriteString(formatTomlString(rule.Target))
			builder.WriteString("\n")
			builder.WriteString("action = ")
			builder.WriteString(formatTomlString(rule.Action))
			builder.WriteString("\n\n")
		}
	}

	return builder.String(), nil
}

func formatTomlRawScalar(raw json.RawMessage) (string, bool, error) {
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false, err
	}
	switch typedValue := value.(type) {
	case bool:
		return strconv.FormatBool(typedValue), true, nil
	case string:
		return formatTomlString(typedValue), true, nil
	case float64:
		return strconv.FormatFloat(typedValue, 'f', -1, 64), true, nil
	case nil:
		return "", false, nil
	default:
		return "", false, fmt.Errorf("unsupported TOML scalar type %T", value)
	}
}

func formatTomlString(value string) string {
	return strconv.Quote(value)
}
