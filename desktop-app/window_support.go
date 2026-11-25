package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) WindowMinimise() error {
	if a.ctx == nil {
		return errors.New("window minimise failed: Wails context is nil")
	}

	runtime.WindowMinimise(a.ctx)
	return nil
}

func (a *App) WindowToggleMaximise() error {
	if a.ctx == nil {
		return errors.New("window toggle maximise failed: Wails context is nil")
	}

	isMaximised := runtime.WindowIsMaximised(a.ctx)
	if isMaximised {
		runtime.WindowUnmaximise(a.ctx)
		return nil
	}

	runtime.WindowMaximise(a.ctx)
	return nil
}

func (a *App) WindowIsMaximised() (bool, error) {
	if a.ctx == nil {
		return false, errors.New("window is maximised failed: Wails context is nil")
	}

	return runtime.WindowIsMaximised(a.ctx), nil
}

func (a *App) Quit() error {
	if a.ctx == nil {
		return errors.New("quit failed: Wails context is nil")
	}

	runtime.Quit(a.ctx)
	return nil
}

func (a *App) SelectPackedNative() (string, error) {
	if a.ctx == nil {
		return "", errors.New("select packed native failed: Wails context is nil")
	}

	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择加壳后的 native 镜像",
		Filters: []runtime.FileFilter{
			{DisplayName: "Native library (*.dll;*.so)", Pattern: "*.dll;*.so"},
		},
	})
	if err != nil {
		return "", fmt.Errorf("select packed native failed: mode=open-file path=*.dll;*.so: %w", err)
	}

	return path, nil
}

func (a *App) RevealNativeImage(path string) error {
	trimmedPath := strings.TrimSpace(path)
	if trimmedPath == "" {
		return errors.New("reveal native image failed: path is empty")
	}
	if _, err := os.Stat(trimmedPath); err != nil {
		return fmt.Errorf("reveal native image failed: path=%s: %w", trimmedPath, err)
	}
	if err := revealPathInFileManager(trimmedPath); err != nil {
		return fmt.Errorf("reveal native image failed: path=%s: %w", trimmedPath, err)
	}
	return nil
}

func (a *App) SelectInputJar() (string, error) {
	if a.ctx == nil {
		return "", errors.New("select input jar failed: Wails context is nil")
	}

	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择输入 Jar / APK",
		Filters: []runtime.FileFilter{
			{DisplayName: "Java Archive / Android Package (*.jar;*.apk)", Pattern: "*.jar;*.apk"},
		},
	})
	if err != nil {
		return "", fmt.Errorf("select input jar failed: mode=open-file path=*.jar;*.apk: %w", err)
	}

	return path, nil
}

func (a *App) SelectOutputJar(defaultInputJarPath string) (string, error) {
	if a.ctx == nil {
		return "", errors.New("select output jar failed: Wails context is nil")
	}

	defaultFileName := buildDefaultOutputJarName(defaultInputJarPath)
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "选择输出 Jar / APK",
		DefaultFilename: defaultFileName,
		Filters: []runtime.FileFilter{
			{DisplayName: "Java Archive / Android Package (*.jar;*.apk)", Pattern: "*.jar;*.apk"},
		},
	})
	if err != nil {
		return "", fmt.Errorf("select output jar failed: mode=save-file path=%s request=%s: %w", defaultFileName, defaultInputJarPath, err)
	}

	return path, nil
}

func (a *App) SelectImportConfig() (string, error) {
	if a.ctx == nil {
		return "", errors.New("select import config failed: Wails context is nil")
	}

	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择导入配置",
		Filters: []runtime.FileFilter{
			{DisplayName: "TOML Config (*.toml)", Pattern: "*.toml"},
		},
	})
	if err != nil {
		return "", fmt.Errorf("select import config failed: mode=open-file path=*.toml: %w", err)
	}

	return path, nil
}

func (a *App) SelectExportConfig() (string, error) {
	if a.ctx == nil {
		return "", errors.New("select export config failed: Wails context is nil")
	}

	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "选择导出配置",
		DefaultFilename: "javashroud-config.toml",
		Filters: []runtime.FileFilter{
			{DisplayName: "TOML Config (*.toml)", Pattern: "*.toml"},
		},
	})
	if err != nil {
		return "", fmt.Errorf("select export config failed: mode=save-file path=javashroud-config.toml: %w", err)
	}

	return path, nil
}

func (a *App) ReadTextFile(path string) (string, error) {
	trimmedPath := strings.TrimSpace(path)
	if trimmedPath == "" {
		return "", errors.New("read text file failed: path is empty")
	}

	content, err := os.ReadFile(trimmedPath)
	if err != nil {
		return "", fmt.Errorf("read text file failed: path=%s: %w", trimmedPath, err)
	}

	return string(content), nil
}

func (a *App) WriteTextFile(path string, content string) error {
	trimmedPath := strings.TrimSpace(path)
	if trimmedPath == "" {
		return errors.New("write text file failed: path is empty")
	}

	if err := replaceExportedText(trimmedPath, content); err != nil {
		return fmt.Errorf("write text file failed: path=%s: %w", trimmedPath, err)
	}

	return nil
}

func replaceExportedText(path, content string) error {
	mode := os.FileMode(0o600)
	if target, err := os.Lstat(path); err == nil {
		if !target.Mode().IsRegular() {
			return errors.New("destination is not a regular file")
		}
		mode = target.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	stage, err := os.CreateTemp(filepath.Dir(path), ".javashroud-config-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(stage.Name())
	defer stage.Close()
	if _, err = stage.WriteString(content); err != nil {
		return err
	}
	if err = stage.Chmod(mode); err != nil {
		return err
	}
	if err = stage.Close(); err != nil {
		return err
	}
	return os.Rename(stage.Name(), path)
}
