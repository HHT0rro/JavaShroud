//go:build windows

package main

import (
	"context"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

const (
	dwmWindowAttributeUseImmersiveDarkMode = 20
	dwmWindowAttributeSystemBackdropType   = 38
	dwmWindowAttributeBorderColor          = 34
	dwmWindowAttributeCaptionColor         = 35
	dwmWindowAttributeTextColor            = 36
	dwmSystemBackdropAcrylic               = 3
	windowColorNone                        = -2
)

type blurApplyResult struct {
	mode    string
	warning string
}

type margins struct {
	CXLeftWidth    int32
	CXRightWidth   int32
	CYTopHeight    int32
	CYBottomHeight int32
}

var (
	user32DLL                        = syscall.NewLazyDLL("user32.dll")
	dwmapiDLL                        = syscall.NewLazyDLL("dwmapi.dll")
	procFindWindowW                  = user32DLL.NewProc("FindWindowW")
	procDwmSetWindowAttribute        = dwmapiDLL.NewProc("DwmSetWindowAttribute")
	procDwmExtendFrameIntoClientArea = dwmapiDLL.NewProc("DwmExtendFrameIntoClientArea")
)

func (a *App) applyWindowVisualEffects(ctx context.Context, windowTitle string) {
	if ctx == nil {
		return
	}

	hwnd, err := findWindowHandleByTitle(windowTitle)
	if err != nil {
		runtime.LogWarning(ctx, fmt.Sprintf("窗口视觉效果初始化失败: title=%s error=%v", windowTitle, err))
		return
	}

	result := applyWindowBlurEffect(hwnd)
	if result.warning != "" {
		runtime.LogWarning(ctx, result.warning)
		return
	}

	runtime.LogInfo(ctx, fmt.Sprintf("窗口视觉效果已启用: mode=%s hwnd=%d", result.mode, hwnd))
}

func applyWindowBlurEffect(hwnd uintptr) blurApplyResult {
	if hwnd == 0 {
		return blurApplyResult{warning: "apply window blur failed: hwnd is zero"}
	}

	if err := setBackdropHint(hwnd, dwmSystemBackdropAcrylic); err != nil {
		return blurApplyResult{warning: fmt.Sprintf("apply window blur failed: DWM backdrop unavailable: %v", err)}
	}

	_ = setImmersiveDarkMode(hwnd, 1)
	clearWindowChromeColors(hwnd)
	_ = extendFrameIntoClientArea(hwnd)
	return blurApplyResult{mode: "dwm-acrylic-backdrop"}
}

func findWindowHandleByTitle(windowTitle string) (uintptr, error) {
	if windowTitle == "" {
		return 0, fmt.Errorf("find window failed: windowTitle is empty")
	}

	titlePointer, err := syscall.UTF16PtrFromString(windowTitle)
	if err != nil {
		return 0, fmt.Errorf("find window failed: title=%s: %w", windowTitle, err)
	}

	hwnd, _, callErr := procFindWindowW.Call(0, uintptr(unsafe.Pointer(titlePointer)))
	if hwnd == 0 {
		if callErr != syscall.Errno(0) {
			return 0, fmt.Errorf("FindWindowW failed: title=%s: %w", windowTitle, callErr)
		}
		return 0, fmt.Errorf("FindWindowW failed: title=%s hwnd=0", windowTitle)
	}
	return hwnd, nil
}

func setBackdropHint(hwnd uintptr, backdropType int32) error {
	return setDwmIntAttribute(hwnd, dwmWindowAttributeSystemBackdropType, backdropType)
}

func setImmersiveDarkMode(hwnd uintptr, enabled int32) error {
	return setDwmIntAttribute(hwnd, dwmWindowAttributeUseImmersiveDarkMode, enabled)
}

func clearWindowChromeColors(hwnd uintptr) {
	_ = setDwmIntAttribute(hwnd, dwmWindowAttributeBorderColor, windowColorNone)
	_ = setDwmIntAttribute(hwnd, dwmWindowAttributeCaptionColor, windowColorNone)
	_ = setDwmIntAttribute(hwnd, dwmWindowAttributeTextColor, windowColorNone)
}

func setDwmIntAttribute(hwnd uintptr, attribute uint32, value int32) error {
	result, _, callErr := procDwmSetWindowAttribute.Call(
		hwnd,
		uintptr(attribute),
		uintptr(unsafe.Pointer(&value)),
		unsafe.Sizeof(value),
	)
	if result != 0 {
		if callErr != syscall.Errno(0) {
			return fmt.Errorf("DwmSetWindowAttribute failed: hwnd=%d attribute=%d value=%d: %w", hwnd, attribute, value, callErr)
		}
		return fmt.Errorf("DwmSetWindowAttribute failed: hwnd=%d attribute=%d value=%d result=%d", hwnd, attribute, value, result)
	}
	return nil
}

func extendFrameIntoClientArea(hwnd uintptr) error {
	frameMargins := margins{CXLeftWidth: -1, CXRightWidth: -1, CYTopHeight: -1, CYBottomHeight: -1}
	result, _, callErr := procDwmExtendFrameIntoClientArea.Call(
		hwnd,
		uintptr(unsafe.Pointer(&frameMargins)),
	)
	if result != 0 {
		if callErr != syscall.Errno(0) {
			return fmt.Errorf("DwmExtendFrameIntoClientArea failed: hwnd=%d: %w", hwnd, callErr)
		}
		return fmt.Errorf("DwmExtendFrameIntoClientArea failed: hwnd=%d result=%d", hwnd, result)
	}
	return nil
}
