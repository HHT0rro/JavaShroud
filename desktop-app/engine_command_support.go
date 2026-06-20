package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

func (a *App) GetEngineCapabilities() (string, error) {
	payload, err := getEngineCapabilitiesPayload()
	if err != nil {
		return "", fmt.Errorf("get engine capabilities failed: %w", err)
	}

	return payload, nil
}

func (a *App) InspectJarClasses(inputJarPath string) (string, error) {
	payload, err := inspectJarClassesPayload(inputJarPath)
	if err != nil {
		return "", fmt.Errorf("inspect jar classes failed: %w", err)
	}

	return payload, nil
}

func getEngineCapabilitiesPayload() (string, error) {
	launchSpec, err := resolveEngineSchemaLaunchSpec()
	if err != nil {
		return "", fmt.Errorf("resolve engine command failed: %w", err)
	}

	cmd := exec.Command(launchSpec.CommandPath, launchSpec.CommandArgs...)
	cmd.Dir = launchSpec.CommandDir
	applyHiddenProcessWindow(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", buildEngineCommandFailureError("schema", launchSpec, output, err)
	}

	return string(output), nil
}

func buildEngineCommandFailureError(contextName string, launchSpec EngineLaunchSpec, output []byte, err error) error {
	return fmt.Errorf("%s command failed: mode=%s command=%s args=%v dir=%s output=%s: %w", contextName, launchSpec.Mode, launchSpec.CommandPath, launchSpec.CommandArgs, launchSpec.CommandDir, truncateString(string(output), 1200), err)
}

func inspectJarClassesPayload(inputJarPath string) (string, error) {
	if strings.TrimSpace(inputJarPath) == "" {
		return "", fmt.Errorf("inputJarPath is empty: path=%s", inputJarPath)
	}

	absoluteInputPath, err := filepath.Abs(inputJarPath)
	if err != nil {
		return "", fmt.Errorf("resolve input path failed: path=%s: %w", inputJarPath, err)
	}
	if err = ensureReadableJarPath(absoluteInputPath); err != nil {
		return "", fmt.Errorf("input jar is not readable: path=%s: %w", absoluteInputPath, err)
	}

	launchSpec, err := resolveEngineInspectLaunchSpec(absoluteInputPath)
	if err != nil {
		return "", fmt.Errorf("resolve engine command failed: path=%s: %w", absoluteInputPath, err)
	}

	cmd := exec.Command(launchSpec.CommandPath, launchSpec.CommandArgs...)
	cmd.Dir = launchSpec.CommandDir
	applyHiddenProcessWindow(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("mode=%s command=%s args=%v dir=%s path=%s output=%s: %w", launchSpec.Mode, launchSpec.CommandPath, launchSpec.CommandArgs, launchSpec.CommandDir, absoluteInputPath, truncateString(string(output), 1200), err)
	}

	return string(output), nil
}

func toEngineAbsoluteJarPath(inputJarPath string) (string, error) {
	absoluteInputPath, err := filepath.Abs(inputJarPath)
	if err != nil {
		return "", fmt.Errorf("resolve engine jar path failed: path=%s: %w", inputJarPath, err)
	}

	cleanedPath := filepath.Clean(absoluteInputPath)
	return filepath.ToSlash(cleanedPath), nil
}
