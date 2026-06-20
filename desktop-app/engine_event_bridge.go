package main

import (
	"context"
	"fmt"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func (a *App) engineRunCallbacks() EngineRunCallbacks {
	return EngineRunCallbacks{
		EmitEvent:      a.emitEvent,
		EmitLocalError: a.emitLocalError,
		EmitCanceled:   a.emitCanceledEvent,
	}
}

func (a *App) emitLocalError(contextMessage string, err error) {
	a.emitEvent(EngineEvent{
		Level:   "error",
		Type:    "error",
		Message: fmt.Sprintf("%s: %v", contextMessage, err),
	})
}

func (a *App) emitCanceledEvent(launchSpec EngineLaunchSpec, runContext context.Context) {
	a.emitEvent(EngineEvent{
		Level:   "warn",
		Type:    "canceled",
		Message: fmt.Sprintf("engine process canceled: mode=%s command=%s args=%v dir=%s reason=%v", launchSpec.Mode, launchSpec.CommandPath, launchSpec.CommandArgs, launchSpec.CommandDir, runContext.Err()),
	})
}

func (a *App) emitEvent(event EngineEvent) {
	if a.ctx == nil {
		return
	}
	runtime.EventsEmit(a.ctx, engineEventName, event)
}
