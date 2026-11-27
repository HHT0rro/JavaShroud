//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fetchFixture struct {
	script   string
	input    string
	output   string
	info     string
	oldBytes []byte
	oldInfo  []byte
}

func newFetchFixture(t *testing.T) fetchFixture {
	t.Helper()
	root := t.TempDir()
	script := filepath.Join(root, "project", "desktop-app", "fetch-xenolith.ps1")
	source, err := os.ReadFile("fetch-xenolith.ps1")
	if err != nil {
		t.Fatal(err)
	}
	writeFetchFile(t, script, source)
	fixture := fetchFixture{
		script: script, input: filepath.Join(root, "input", "owned-cli.exe"),
		output:   filepath.Join(root, "output", "xenolith.exe"),
		info:     filepath.Join(root, "output", "xenolith-info.json"),
		oldBytes: []byte("MZ owned previous CLI"),
	}
	fixture.oldInfo = []byte(`{"included":true,"source":"owned:previous","version":"0.0.0","sha256":"` + fetchDigest(fixture.oldBytes) + `"}`)
	writeFetchFile(t, fixture.input, []byte("MZ owned replacement CLI"))
	writeFetchFile(t, fixture.output, fixture.oldBytes)
	writeFetchFile(t, fixture.info, fixture.oldInfo)
	return fixture
}

func writeFetchFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func fetchDigest(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

func runFetchScript(t *testing.T, fixture fetchFixture, output string, overrides map[string]string, requirePin bool) ([]byte, error) {
	t.Helper()
	input, err := os.ReadFile(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	environment := map[string]string{
		"XENOLITH_EXE": fixture.input, "XENOLITH_SHA256": fetchDigest(input), "XENOLITH_VERSION": "0.1.0",
	}
	for key, value := range overrides {
		environment[key] = value
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-File", fixture.script, "-OutPath", output)
	if requirePin {
		command.Args = append(command.Args, "-RequirePin")
	}
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(variable), "XENOLITH_") {
			command.Env = append(command.Env, variable)
		}
	}
	for key, value := range environment {
		command.Env = append(command.Env, key+"="+value)
	}
	return command.CombinedOutput()
}

func assertFetchFile(t *testing.T, path string, expected []byte) {
	t.Helper()
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatalf("file changed at %s, read error %v, got %q, want %q", path, err, actual, expected)
	}
}

func assertFetchPair(t *testing.T, fixture fetchFixture) {
	t.Helper()
	assertFetchFile(t, fixture.output, fixture.oldBytes)
	assertFetchFile(t, fixture.info, fixture.oldInfo)
}

func TestFetchXenolithFailurePreservesInputsAndPreviousPair(t *testing.T) {
	for _, name := range []string{"missing pin", "wrong pin", "same source with wrong pin", "missing source", "conflicting sources", "source aliases manifest", "output aliases manifest"} {
		t.Run(name, func(t *testing.T) {
			fixture := newFetchFixture(t)
			input, _ := os.ReadFile(fixture.input)
			overrides := map[string]string{}
			output := fixture.output
			switch name {
			case "missing pin":
				overrides["XENOLITH_SHA256"] = ""
			case "wrong pin":
				overrides["XENOLITH_SHA256"] = strings.Repeat("0", 64)
			case "same source with wrong pin":
				overrides["XENOLITH_EXE"] = fixture.output
				overrides["XENOLITH_SHA256"] = strings.Repeat("0", 64)
			case "missing source":
				overrides["XENOLITH_EXE"] = filepath.Join(filepath.Dir(fixture.input), "missing.exe")
			case "conflicting sources":
				overrides["XENOLITH_RELEASE_TAG"] = "owned-unused-tag"
			case "source aliases manifest":
				overrides["XENOLITH_EXE"] = fixture.info
				overrides["XENOLITH_SHA256"] = fetchDigest(fixture.oldInfo)
			case "output aliases manifest":
				output = fixture.info
			}
			log, err := runFetchScript(t, fixture, output, overrides, true)
			if err == nil {
				t.Fatalf("unsafe fetch succeeded: %s", log)
			}
			assertFetchPair(t, fixture)
			assertFetchFile(t, fixture.input, input)
		})
	}
}

func TestFetchXenolithPublishesVerifiedPairAndAcceptsSameSource(t *testing.T) {
	fixture := newFetchFixture(t)
	input, _ := os.ReadFile(fixture.input)
	log, err := runFetchScript(t, fixture, fixture.output, nil, true)
	if err != nil {
		t.Fatalf("verified fetch failed: %v\n%s", err, log)
	}
	assertFetchFile(t, fixture.input, input)
	assertFetchFile(t, fixture.output, input)
	manifestBytes, err := os.ReadFile(fixture.info)
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Included bool   `json:"included"`
		SHA256   string `json:"sha256"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil || !manifest.Included || manifest.SHA256 != fetchDigest(input) {
		t.Fatalf("invalid committed manifest %q, error %v", manifestBytes, err)
	}
	log, err = runFetchScript(t, fixture, fixture.output, map[string]string{"XENOLITH_EXE": fixture.output}, true)
	if err != nil {
		t.Fatalf("verified same-path source failed: %v\n%s", err, log)
	}
	assertFetchFile(t, fixture.output, input)
}

func holdFetchFile(t *testing.T, path string) func() {
	t.Helper()
	wide, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(wide, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	return func() { syscall.CloseHandle(handle) }
}

func TestFetchXenolithManifestFailureRollsBackExecutable(t *testing.T) {
	for _, existing := range []bool{true, false} {
		t.Run(map[bool]string{true: "replacement", false: "first executable"}[existing], func(t *testing.T) {
			fixture := newFetchFixture(t)
			if !existing {
				if err := os.Remove(fixture.output); err != nil {
					t.Fatal(err)
				}
			}
			release := holdFetchFile(t, fixture.info)
			defer release()
			log, err := runFetchScript(t, fixture, fixture.output, nil, true)
			if err == nil {
				t.Fatalf("fetch ignored the unavailable manifest destination: %s", log)
			}
			assertFetchFile(t, fixture.info, fixture.oldInfo)
			if existing {
				assertFetchFile(t, fixture.output, fixture.oldBytes)
			} else if _, err := os.Stat(fixture.output); !os.IsNotExist(err) {
				t.Fatalf("failed first publication left an executable: %v", err)
			}
		})
	}
}

func TestFetchXenolithPublicationLockPreservesPreviousPair(t *testing.T) {
	fixture := newFetchFixture(t)
	lock := filepath.Join(filepath.Dir(fixture.output), ".xenolith-fetch.lock")
	writeFetchFile(t, lock, nil)
	release := holdFetchFile(t, lock)
	defer release()
	log, err := runFetchScript(t, fixture, fixture.output, nil, true)
	if err == nil {
		t.Fatalf("fetch ignored its publication lock: %s", log)
	}
	assertFetchPair(t, fixture)
}

func TestFetchXenolithOmissionCommitsOrRollsBackTheWholePair(t *testing.T) {
	for _, locked := range []bool{false, true} {
		t.Run(map[bool]string{false: "successful omission", true: "failed omission"}[locked], func(t *testing.T) {
			fixture := newFetchFixture(t)
			if locked {
				release := holdFetchFile(t, fixture.info)
				defer release()
			}
			log, err := runFetchScript(t, fixture, fixture.output, map[string]string{"XENOLITH_EXE": "", "XENOLITH_SHA256": ""}, false)
			if locked {
				if err == nil {
					t.Fatalf("omission ignored the unavailable manifest destination: %s", log)
				}
				assertFetchPair(t, fixture)
				return
			}
			if err != nil {
				t.Fatalf("optional omission failed: %v\n%s", err, log)
			}
			if _, err := os.Stat(fixture.output); !os.IsNotExist(err) {
				t.Fatalf("successful omission retained an executable: %v", err)
			}
			manifest, err := os.ReadFile(fixture.info)
			if err != nil {
				t.Fatal(err)
			}
			var info struct {
				Included bool `json:"included"`
			}
			if err := json.Unmarshal(manifest, &info); err != nil || info.Included {
				t.Fatalf("invalid omission manifest %q, error %v", manifest, err)
			}
		})
	}
}

func TestFetchXenolithRejectsHardLinkedExecutableDestination(t *testing.T) {
	fixture := newFetchFixture(t)
	input, _ := os.ReadFile(fixture.input)
	if err := os.Remove(fixture.output); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(fixture.input, fixture.output); err != nil {
		t.Fatal(err)
	}
	log, err := runFetchScript(t, fixture, fixture.output, nil, true)
	if err == nil {
		t.Fatalf("fetch accepted a hard-linked executable destination: %s", log)
	}
	assertFetchFile(t, fixture.input, input)
	assertFetchFile(t, fixture.output, input)
	assertFetchFile(t, fixture.info, fixture.oldInfo)
}

func TestFetchXenolithRestoresBackupWhenReplacementReportsFailure(t *testing.T) {
	for _, state := range []string{"old executable moved to backup", "replacement already at destination"} {
		t.Run(state, func(t *testing.T) {
			fixture := newFetchFixture(t)
			contents, err := os.ReadFile(fixture.script)
			if err != nil {
				t.Fatal(err)
			}
			call := "Set-VerifiedFile $stagePath $OutPath $priorExe"
			if strings.Count(string(contents), call) != 1 {
				t.Fatal("executable replacement fault location is missing or ambiguous")
			}
			replacement := "[IO.File]::Move($OutPath, $priorExe)"
			if state == "replacement already at destination" {
				replacement = call
			}
			// Model the filesystem states possible when replacement fails after saving a backup.
			replacement += "\n                throw 'owned replacement failure after backup creation'"
			writeFetchFile(t, fixture.script, []byte(strings.Replace(string(contents), call, replacement, 1)))
			log, err := runFetchScript(t, fixture, fixture.output, nil, true)
			if err == nil {
				t.Fatalf("injected replacement failure was ignored: %s", log)
			}
			assertFetchPair(t, fixture)
		})
	}
}
