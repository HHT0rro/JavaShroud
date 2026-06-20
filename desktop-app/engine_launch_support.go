package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func resolveEngineLaunchSpec(configPath string) (EngineLaunchSpec, error) {
	nativePath, nativeErr := resolveNativeEnginePath()
	if nativeErr == nil {
		return EngineLaunchSpec{
			CommandPath: nativePath,
			CommandArgs: []string{"-config", configPath},
			CommandDir:  filepath.Dir(nativePath),
			Mode:        "native-exe",
		}, nil
	}

	jarPath, jarErr := resolveEngineJarPath()
	if jarErr == nil {
		return EngineLaunchSpec{
			CommandPath: "java",
			CommandArgs: []string{"-Dfile.encoding=UTF-8", "-jar", jarPath, "-config", configPath},
			CommandDir:  filepath.Dir(jarPath),
			Mode:        "java-jar",
		}, nil
	}

	return EngineLaunchSpec{}, fmt.Errorf("engine binary resolution failed: nativeError=%v jarError=%v", nativeErr, jarErr)
}

func resolveEngineSchemaLaunchSpec() (EngineLaunchSpec, error) {
	nativePath, nativeErr := resolveNativeEnginePath()
	if nativeErr == nil {
		return EngineLaunchSpec{
			CommandPath: nativePath,
			CommandArgs: []string{"-schema"},
			CommandDir:  filepath.Dir(nativePath),
			Mode:        "native-exe",
		}, nil
	}

	jarPath, jarErr := resolveEngineJarPath()
	if jarErr == nil {
		return EngineLaunchSpec{
			CommandPath: "java",
			CommandArgs: []string{"-Dfile.encoding=UTF-8", "-jar", jarPath, "-schema"},
			CommandDir:  filepath.Dir(jarPath),
			Mode:        "java-jar",
		}, nil
	}

	return EngineLaunchSpec{}, fmt.Errorf("engine schema resolution failed: nativeError=%v jarError=%v", nativeErr, jarErr)
}

func resolveEngineInspectLaunchSpec(inputJarPath string) (EngineLaunchSpec, error) {
	engineInputPath, err := toEngineAbsoluteJarPath(inputJarPath)
	if err != nil {
		return EngineLaunchSpec{}, fmt.Errorf("engine inspect resolution failed: path=%s: %w", inputJarPath, err)
	}

	nativePath, nativeErr := resolveNativeEnginePath()
	if nativeErr == nil {
		return EngineLaunchSpec{
			CommandPath: nativePath,
			CommandArgs: []string{"-inspect", engineInputPath},
			CommandDir:  filepath.Dir(nativePath),
			Mode:        "native-exe",
		}, nil
	}

	jarPath, jarErr := resolveEngineJarPath()
	if jarErr == nil {
		return EngineLaunchSpec{
			CommandPath: "java",
			CommandArgs: []string{"-Dfile.encoding=UTF-8", "-jar", jarPath, "-inspect", engineInputPath},
			CommandDir:  filepath.Dir(jarPath),
			Mode:        "java-jar",
		}, nil
	}

	return EngineLaunchSpec{}, fmt.Errorf("engine inspect resolution failed: nativeError=%v jarError=%v path=%s", nativeErr, jarErr, engineInputPath)
}

func resolveNativeEnginePath() (string, error) {
	embeddedPath, embeddedErr := resolveEmbeddedNativeEnginePath()
	if embeddedErr == nil {
		return embeddedPath, nil
	}

	candidatePaths := buildNativeEngineCandidates()
	for _, candidatePath := range candidatePaths {
		absoluteCandidatePath, err := filepath.Abs(candidatePath)
		if err != nil {
			return "", fmt.Errorf("resolve native engine path failed: candidate=%s: %w", candidatePath, err)
		}

		if _, err = os.Stat(absoluteCandidatePath); err == nil {
			return absoluteCandidatePath, nil
		}
	}

	return "", fmt.Errorf("native engine is missing: checked=%s", strings.Join(candidatePaths, ", "))
}

func resolveEngineJarPath() (string, error) {
	candidatePaths := buildEngineJarCandidates()
	for _, candidatePath := range candidatePaths {
		absoluteCandidatePath, err := filepath.Abs(candidatePath)
		if err != nil {
			return "", fmt.Errorf("resolve engine jar path failed: candidate=%s: %w", candidatePath, err)
		}

		if _, err = os.Stat(absoluteCandidatePath); err == nil {
			return absoluteCandidatePath, nil
		}
	}

	return "", fmt.Errorf("engine jar is missing: checked=%s", strings.Join(candidatePaths, ", "))
}

func ensureReadableJarPath(inputJarPath string) error {
	fileInfo, err := os.Stat(inputJarPath)
	if err != nil {
		return fmt.Errorf("stat failed: %w", err)
	}
	if fileInfo.IsDir() {
		return fmt.Errorf("path is a directory")
	}
	if strings.ToLower(filepath.Ext(inputJarPath)) != ".jar" {
		return fmt.Errorf("path extension is not .jar")
	}
	return nil
}

func buildNativeEngineCandidates() []string {
	executablePath, err := os.Executable()
	if err != nil {
		return []string{
			filepath.Join("..", "core-engine", "build", "native", "nativeCompile", "obfuscator-engine"+nativeEngineExt()),
		}
	}

	executableDir := filepath.Dir(executablePath)
	return []string{
		filepath.Join(executableDir, "engine", "obfuscator-engine"+nativeEngineExt()),
		filepath.Join("..", "core-engine", "build", "native", "nativeCompile", "obfuscator-engine"+nativeEngineExt()),
		filepath.Join("..", "build", "core-engine", "native", "nativeCompile", "obfuscator-engine"+nativeEngineExt()),
	}
}

func buildEngineJarCandidates() []string {
	executablePath, err := os.Executable()
	if err != nil {
		return []string{
			filepath.Join("..", "core-engine", "build", "libs", "obfuscator-engine.jar"),
		}
	}

	executableDir := filepath.Dir(executablePath)
	return []string{
		filepath.Join(executableDir, "engine", "obfuscator-engine.jar"),
		filepath.Join("..", "core-engine", "build", "libs", "obfuscator-engine.jar"),
		filepath.Join("..", "build", "core-engine", "libs", "obfuscator-engine.jar"),
	}
}

func nativeEngineExt() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func buildDefaultOutputJarName(defaultInputJarPath string) string {
	baseName := filepath.Base(defaultInputJarPath)
	if strings.TrimSpace(baseName) == "" || baseName == "." || baseName == string(filepath.Separator) {
		return "output-shrouded.jar"
	}
	if strings.HasSuffix(strings.ToLower(baseName), ".jar") {
		return strings.TrimSuffix(baseName, filepath.Ext(baseName)) + "-shrouded.jar"
	}
	return baseName + "-shrouded.jar"
}
