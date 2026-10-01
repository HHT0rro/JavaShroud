package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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
		return XenolithCliInfo{Path: "", Version: "", Source: ""}, nil
	}
	return XenolithCliInfo{
		Path:    path,
		Version: probeXenolithCliVersion(path),
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
			if _, statErr := os.Stat(absoluteOverride); statErr == nil {
				return absoluteOverride, "env"
			}
		}
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
			path:   filepath.Join(executableDir, "..", "..", "..", "..", "Xenolith", "dist", "xenolith.exe"),
			source: "sibling",
		},
	}
}

var xenolithVersionCache sync.Map

func probeXenolithCliVersion(cliPath string) string {
	if cached, ok := xenolithVersionCache.Load(cliPath); ok {
		if version, ok := cached.(string); ok {
			return version
		}
	}

	probeContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(probeContext, cliPath, "--version")
	applyHiddenProcessWindow(cmd)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	version := ""
	for _, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			version = trimmed
			break
		}
	}
	xenolithVersionCache.Store(cliPath, version)
	return version
}
