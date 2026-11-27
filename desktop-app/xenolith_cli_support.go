package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const xenolithCliEnvKey = "XENOLITH_EXE"

type XenolithCliInfo struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Source  string `json:"source"`
}

type xenolithCliCandidate struct {
	path   string
	source string
}

// ResolveXenolithCli reports the Xenolith packer CLI the desktop app would hand
// to the engine's nativeshroud pass. Empty path means auto packing is not
// available and the manual packing handoff stays in charge.
func (a *App) ResolveXenolithCli() (string, error) {
	info, err := resolveXenolithCliInfo()
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(info)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func resolveXenolithCliInfo() (XenolithCliInfo, error) {
	path, source := resolveXenolithCliPath()
	if path == "" {
		return XenolithCliInfo{}, fmt.Errorf("xenolith CLI is missing: set %s to an executable, place tools/xenolith.exe next to the app, or add xenolith to PATH", xenolithCliEnvKey)
	}
	version, err := probeXenolithCliVersion(path)
	if err != nil {
		return XenolithCliInfo{}, err
	}
	return XenolithCliInfo{
		Path:    path,
		Version: version,
		Source:  source,
	}, nil
}

// resolveXenolithCliPath resolves the Xenolith CLI in priority order:
// XENOLITH_EXE override, embedded binary, tools dir next to the app exe,
// dev-tree sibling checkout, then PATH. Empty result means not found.
func resolveXenolithCliPath() (string, string) {
	return resolveXenolithCliPathFromSources(
		os.Getenv(xenolithCliEnvKey),
		resolveEmbeddedXenolithCliPath,
		buildXenolithCliCandidates(),
		exec.LookPath,
	)
}

func resolveXenolithCliPathFromSources(
	override string,
	embedded func() (string, error),
	candidates []xenolithCliCandidate,
	pathLookup func(string) (string, error),
) (string, string) {
	if trimmedOverride := strings.TrimSpace(override); trimmedOverride != "" {
		if absoluteOverride, err := filepath.Abs(trimmedOverride); err == nil {
			return absoluteOverride, "env"
		}
		return trimmedOverride, "env"
	}

	if embeddedPath, embeddedErr := embedded(); embeddedErr == nil && embeddedPath != "" {
		return embeddedPath, "embedded"
	}

	for _, candidate := range candidates {
		absoluteCandidate, err := filepath.Abs(candidate.path)
		if err != nil {
			continue
		}
		if _, statErr := os.Stat(absoluteCandidate); statErr == nil {
			return absoluteCandidate, candidate.source
		}
	}

	if pathLookup != nil {
		if lookupResult, lookupErr := pathLookup("xenolith"); lookupErr == nil {
			if absoluteLookup, err := filepath.Abs(lookupResult); err == nil {
				return absoluteLookup, "path"
			}
		}
	}

	return "", ""
}

func buildXenolithCliCandidates() []xenolithCliCandidate {
	executablePath, err := os.Executable()
	if err != nil {
		return xenolithCliCandidatesForExecutableDir("")
	}
	return xenolithCliCandidatesForExecutableDir(filepath.Dir(executablePath))
}

func xenolithCliCandidatesForExecutableDir(executableDir string) []xenolithCliCandidate {
	toolsCandidate := xenolithCliCandidate{
		path:   filepath.Join(executableDir, "tools", "xenolith.exe"),
		source: "tools",
	}
	if executableDir == "" {
		toolsCandidate.path = filepath.Join("tools", "xenolith.exe")
	}
	return []xenolithCliCandidate{
		toolsCandidate,
		{
			path:   filepath.Join(executableDir, "..", "..", "..", "..", "Xenolith", "target", "release", "xenolith.exe"),
			source: "sibling",
		},
		{
			path:   filepath.Join(executableDir, "..", "..", "..", "..", "Xenolith", "dist", "xenolith.exe"),
			source: "sibling",
		},
	}
}

func probeXenolithCliVersion(cliPath string) (string, error) {
	fileInfo, err := os.Stat(cliPath)
	if err != nil {
		return "", fmt.Errorf("probe xenolith CLI version failed: path=%s args=[--version]: %w", cliPath, err)
	}
	if !fileInfo.Mode().IsRegular() {
		return "", fmt.Errorf("probe xenolith CLI version failed: path=%s args=[--version]: executable is not a regular file", cliPath)
	}

	probeContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(probeContext, cliPath, "--version")
	cmd.WaitDelay = time.Second
	applyHiddenProcessWindow(cmd)
	output, err := cmd.Output()
	if err != nil {
		diagnostic := ""
		if exitErr, ok := err.(*exec.ExitError); ok {
			diagnostic = summarizeEngineStderr(string(exitErr.Stderr), 1200)
		}
		if probeContext.Err() != nil {
			err = probeContext.Err()
		}
		return "", fmt.Errorf("probe xenolith CLI version failed: path=%s args=[--version] stderr=%s: %w", cliPath, diagnostic, err)
	}

	version := ""
	for _, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			version = trimmed
			break
		}
	}
	if version == "" {
		return "", fmt.Errorf("probe xenolith CLI version failed: path=%s args=[--version]: version output is empty", cliPath)
	}
	return version, nil
}
