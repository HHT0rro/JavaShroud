package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

func validateObfuscationRequest(request ObfuscationRequest) error {
	request = normalizeObfuscationRequest(request)
	if request.InputJarPath == "" {
		return fmt.Errorf("start obfuscation failed: inputJarPath is empty: request=%+v", request)
	}
	if request.OutputJarPath == "" {
		return fmt.Errorf("start obfuscation failed: outputJarPath is empty: request=%+v", request)
	}
	if len(request.Passes) == 0 {
		return fmt.Errorf("start obfuscation failed: passes is empty: request=%+v", request)
	}

	enabledPassIDs := make(map[string]struct{}, len(request.Passes))
	for index, passSpec := range request.Passes {
		if passSpec.ID == "" {
			return fmt.Errorf("start obfuscation failed: pass id is empty: index=%d", index)
		}
		if !passSpec.Enabled {
			continue
		}
		if _, exists := enabledPassIDs[passSpec.ID]; exists {
			return fmt.Errorf("start obfuscation failed: enabled pass id is duplicated: passId=%s", passSpec.ID)
		}
		enabledPassIDs[passSpec.ID] = struct{}{}
	}
	if len(enabledPassIDs) == 0 {
		return fmt.Errorf("start obfuscation failed: no enabled passes")
	}
	for index, rule := range request.Rules {
		if err := validateDesktopRuleItem(rule, fmt.Sprintf("rule index=%d", index)); err != nil {
			return err
		}
	}
	return validatePassSelections(request.PassSelections, enabledPassIDs)
}

func normalizeObfuscationRequest(request ObfuscationRequest) ObfuscationRequest {
	normalized := request
	normalized.InputJarPath = strings.TrimSpace(request.InputJarPath)
	normalized.OutputJarPath = strings.TrimSpace(request.OutputJarPath)
	normalized.Passes = clonePasses(request.Passes)
	normalized.Rules = cloneRules(request.Rules)
	normalized.PassSelections = clonePassSelections(request.PassSelections)
	return normalized
}

func clonePassSelections(passSelections []PassSelection) []PassSelection {
	result := make([]PassSelection, 0, len(passSelections))
	for _, passSelection := range passSelections {
		passID := strings.TrimSpace(passSelection.PassID)
		if isRetiredCurrentFormatPassID(passID) {
			continue
		}
		result = append(result, PassSelection{
			PassID: passID,
			Mode:   PassSelectionMode(strings.TrimSpace(string(passSelection.Mode))),
			Rules:  cloneRules(passSelection.Rules),
		})
	}
	return result
}

func validatePassSelections(passSelections []PassSelection, enabledPassIDs map[string]struct{}) error {
	seenPassIDs := make(map[string]struct{}, len(passSelections))
	for index, passSelection := range passSelections {
		passID := passSelection.PassID
		if passID == "" {
			return fmt.Errorf("start obfuscation failed: pass selection passId is empty: index=%d", index)
		}
		if _, exists := seenPassIDs[passID]; exists {
			return fmt.Errorf("start obfuscation failed: pass selection passId is duplicated: passId=%s", passID)
		}
		seenPassIDs[passID] = struct{}{}
		if _, enabled := enabledPassIDs[passID]; !enabled {
			return fmt.Errorf("start obfuscation failed: pass selection passId is unknown or disabled: passId=%s", passID)
		}
		if !isKnownPassSelectionMode(passSelection.Mode) {
			return fmt.Errorf("start obfuscation failed: pass selection mode is invalid: passId=%s mode=%s", passID, passSelection.Mode)
		}
		if passSelection.Mode != PassSelectionModeSelectedOnly {
			return fmt.Errorf("start obfuscation failed: inherit-global pass selection must not be sent in execution request: passId=%s", passID)
		}

		seenTargets := make(map[string]struct{}, len(passSelection.Rules))
		for ruleIndex, rule := range passSelection.Rules {
			if err := validateDesktopRuleItem(rule, fmt.Sprintf("pass selection passId=%s rule index=%d", passID, ruleIndex)); err != nil {
				return err
			}
			if _, exists := seenTargets[rule.Target]; exists {
				return fmt.Errorf("start obfuscation failed: pass selection rule target is duplicated: passId=%s target=%s", passID, rule.Target)
			}
			seenTargets[rule.Target] = struct{}{}
			if _, err := parseDesktopPassSelectionTarget(rule.Target); err != nil {
				return fmt.Errorf("start obfuscation failed: pass selection rule target is not a concrete class or JVM method selector: passId=%s target=%s: %w", passID, rule.Target, err)
			}		}	}
	return nil
}

func validateDesktopRuleItem(rule RuleItem, context string) error {
	if rule.Target == "" {
		return fmt.Errorf("start obfuscation failed: rule target is empty: %s", context)
	}
	if !isKnownDesktopRuleAction(rule.Action) {
		return fmt.Errorf("start obfuscation failed: rule action is invalid: %s action=%s", context, rule.Action)
	}
	return nil
}

func parseDesktopPassSelectionTarget(target string) (string, error) {
	if target == "" || strings.Contains(target, "*") {
		return "", errors.New("wildcard or empty selector")
	}

	if !strings.Contains(target, "#") {
		if !isConcreteInternalClassName(target) {
			return "", errors.New("invalid class selector")
		}
		return "class", nil
	}
	if strings.Count(target, "#") != 1 {
		return "", errors.New("selector must contain exactly one member separator")
	}

	owner, memberWithDescriptor, _ := strings.Cut(target, "#")
	if !isConcreteInternalClassName(owner) {
		return "", errors.New("invalid method owner")
	}
	if strings.Count(memberWithDescriptor, ":") != 1 {
		return "", errors.New("method selector must contain exactly one descriptor separator")
	}
	memberName, descriptor, _ := strings.Cut(memberWithDescriptor, ":")
	if !isConcreteMethodName(memberName) {
		return "", errors.New("invalid method name")
	}
	if !isJvmMethodDescriptor(descriptor) {
		return "", errors.New("invalid JVM method descriptor")
	}
	if !isCanonicalConstructorSelector(memberName, descriptor) {
		return "", errors.New("invalid JVM constructor selector")
	}
	return "method", nil
}

func isConcreteInternalClassName(value string) bool {
	if value == "" || strings.HasSuffix(value, "/") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" {
			return false
		}
		for _, value := range segment {
			switch value {
			case '\\', '.', '#', ':', ';', '[', ']', '(', ')', '*', '<', '>', ' ', '\t', '\n', '\r':
				return false
			}
		}
	}
	return true
}

func isConcreteMethodName(value string) bool {
	if value == "<init>" || value == "<clinit>" {
		return true
	}
	if value == "" {
		return false
	}
	for _, value := range value {
		switch value {
		case '#', '.', ':', ';', '[', ']', '(', ')', '/', '*', '<', '>', ' ', '\t', '\n', '\r':
			return false
		}
	}
	return true
}

// JVM method descriptors are syntactically broader than valid special-method
// declarations. Keep desktop validation aligned with canonical inspection-tree
// selectors, preventing impossible imported constructors from becoming a
// non-empty independent scope rule that can never match an artifact member.
func isCanonicalConstructorSelector(memberName string, descriptor string) bool {
	if memberName == "<init>" && !strings.HasSuffix(descriptor, "V") {
		return false
	}
	return memberName != "<clinit>" || descriptor == "()V"
}

func isJvmMethodDescriptor(descriptor string) bool {
	if !strings.HasPrefix(descriptor, "(") {
		return false
	}

	index := 1
	for index < len(descriptor) && descriptor[index] != ')' {
		next, ok := consumeJvmFieldDescriptor(descriptor, index)
		if !ok {
			return false
		}
		index = next
	}
	if index >= len(descriptor) || descriptor[index] != ')' {
		return false
	}

	index++
	if index < len(descriptor) && descriptor[index] == 'V' {
		return index+1 == len(descriptor)
	}
	returnEnd, ok := consumeJvmFieldDescriptor(descriptor, index)
	return ok && returnEnd == len(descriptor)
}

func consumeJvmFieldDescriptor(descriptor string, start int) (int, bool) {
	index := start
	for index < len(descriptor) && descriptor[index] == '[' {
		index++
	}
	if index >= len(descriptor) {
		return 0, false
	}

	switch descriptor[index] {
	case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z':
		return index + 1, true
	case 'L':
		end := strings.IndexByte(descriptor[index+1:], ';')
		if end < 0 {
			return 0, false
		}
		end += index + 1
		if !isConcreteInternalClassName(descriptor[index+1 : end]) {
			return 0, false
		}
		return end + 1, true
	default:
		return 0, false
	}
}

func isKnownPassSelectionMode(mode PassSelectionMode) bool {
	switch mode {
	case PassSelectionModeInheritGlobal, PassSelectionModeSelectedOnly:
		return true
	default:
		return false
	}
}

func isKnownDesktopRuleAction(action string) bool {
	switch action {
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
