package main

import (
	"context"
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/dist
var assets embed.FS

const appTitle = "JavaShroud"

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:            appTitle,
		Width:            1440,
		Height:           900,
		StartHidden:      true,
		Frameless:        true,
		BackgroundColour: options.NewRGBA(0, 0, 0, 0),
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		DragAndDrop: &options.DragAndDrop{
			EnableFileDrop: true,
		},
		Windows: &windows.Options{
			WebviewIsTransparent: true,
			WindowIsTranslucent:  true,
			DisableWindowIcon:    true,
			BackdropType:         windows.Acrylic,
			Theme:                windows.Dark,
		},
		OnStartup: app.Startup,
		OnDomReady: func(ctx context.Context) {
			app.applyWindowVisualEffects(ctx, appTitle)
			wailsruntime.Show(ctx)
		},
		Bind: []any{
			app,
		},
	})
	if err != nil {
		panic(err)
	}
}
