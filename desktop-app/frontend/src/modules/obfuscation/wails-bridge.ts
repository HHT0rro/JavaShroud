import type { ObfuscationRequest } from './types'

export interface WailsBridge {
  readonly startObfuscation: (request: ObfuscationRequest) => Promise<void>
  readonly cancelObfuscation: () => Promise<void>
  readonly getEngineCapabilities: () => Promise<string>
  readonly selectInputJar: () => Promise<string>
  readonly selectOutputJar: (defaultInputJarPath: string) => Promise<string>
  readonly selectImportConfig: () => Promise<string>
  readonly selectExportConfig: () => Promise<string>
  readonly readTextFile: (path: string) => Promise<string>
  readonly writeTextFile: (path: string, content: string) => Promise<void>
  readonly inspectJarClasses: (inputJarPath: string) => Promise<string>
  readonly windowMinimise: () => Promise<void>
  readonly windowToggleMaximise: () => Promise<void>
  readonly windowIsMaximised: () => Promise<boolean>
  readonly quit: () => Promise<void>
  readonly onEngineEvent: (handler: (event: unknown) => void) => () => void
}

interface WailsRuntime {
  readonly EventsOn?: (eventName: string, callback: (event: unknown) => void) => (() => void) | void
}

interface WailsGoApp {
  readonly StartObfuscation?: (request: ObfuscationRequest) => Promise<void>
  readonly CancelObfuscation?: () => Promise<void>
  readonly GetEngineCapabilities?: () => Promise<string>
  readonly SelectInputJar?: () => Promise<string>
  readonly SelectOutputJar?: (defaultInputJarPath: string) => Promise<string>
  readonly SelectImportConfig?: () => Promise<string>
  readonly SelectExportConfig?: () => Promise<string>
  readonly ReadTextFile?: (path: string) => Promise<string>
  readonly WriteTextFile?: (path: string, content: string) => Promise<void>
  readonly InspectJarClasses?: (inputJarPath: string) => Promise<string>
  readonly WindowMinimise?: () => Promise<void>
  readonly WindowToggleMaximise?: () => Promise<void>
  readonly WindowIsMaximised?: () => Promise<boolean>
  readonly Quit?: () => Promise<void>
}

interface WailsWindow extends Window {
  readonly runtime?: WailsRuntime
  readonly go?: {
    readonly main?: {
      readonly App?: WailsGoApp
    }
  }
}

const engineEventName = 'engine:event'

export const createWailsBridge = (windowRef: Window): WailsBridge => ({
  startObfuscation: async (request: ObfuscationRequest): Promise<void> => {
    const app: WailsGoApp = resolveWailsApp(windowRef)

    if (typeof app.StartObfuscation !== 'function') {
      throw new Error(`Wails 绑定缺少 StartObfuscation，request=${JSON.stringify(request)}`)
    }

    await app.StartObfuscation(request)
  },
  cancelObfuscation: async (): Promise<void> => {
    const app: WailsGoApp = resolveWailsApp(windowRef)

    if (typeof app.CancelObfuscation !== 'function') {
      throw new Error('Wails 绑定缺少 CancelObfuscation。')
    }

    await app.CancelObfuscation()
  },
  getEngineCapabilities: async (): Promise<string> => {
    const app: WailsGoApp = resolveWailsApp(windowRef)

    if (typeof app.GetEngineCapabilities !== 'function') {
      throw new Error('Wails 绑定缺少 GetEngineCapabilities。')
    }

    return app.GetEngineCapabilities()
  },
  selectInputJar: async (): Promise<string> => {
    const app: WailsGoApp = resolveWailsApp(windowRef)

    if (typeof app.SelectInputJar !== 'function') {
      throw new Error('Wails 绑定缺少 SelectInputJar。')
    }

    return app.SelectInputJar()
  },
  selectOutputJar: async (defaultInputJarPath: string): Promise<string> => {
    const app: WailsGoApp = resolveWailsApp(windowRef)

    if (typeof app.SelectOutputJar !== 'function') {
      throw new Error('Wails 绑定缺少 SelectOutputJar。')
    }

    return app.SelectOutputJar(defaultInputJarPath)
  },
  selectImportConfig: async (): Promise<string> => {
    const app: WailsGoApp = resolveWailsApp(windowRef)

    if (typeof app.SelectImportConfig !== 'function') {
      throw new Error('Wails 绑定缺少 SelectImportConfig。')
    }

    return app.SelectImportConfig()
  },
  selectExportConfig: async (): Promise<string> => {
    const app: WailsGoApp = resolveWailsApp(windowRef)

    if (typeof app.SelectExportConfig !== 'function') {
      throw new Error('Wails 绑定缺少 SelectExportConfig。')
    }

    return app.SelectExportConfig()
  },
  readTextFile: async (path: string): Promise<string> => {
    const app: WailsGoApp = resolveWailsApp(windowRef)

    if (typeof app.ReadTextFile !== 'function') {
      throw new Error('Wails 绑定缺少 ReadTextFile。')
    }

    return app.ReadTextFile(path)
  },
  writeTextFile: async (path: string, content: string): Promise<void> => {
    const app: WailsGoApp = resolveWailsApp(windowRef)

    if (typeof app.WriteTextFile !== 'function') {
      throw new Error('Wails 绑定缺少 WriteTextFile。')
    }

    await app.WriteTextFile(path, content)
  },
  inspectJarClasses: async (inputJarPath: string): Promise<string> => {
    const app: WailsGoApp = resolveWailsApp(windowRef)

    if (typeof app.InspectJarClasses !== 'function') {
      throw new Error('Wails 绑定缺少 InspectJarClasses。')
    }

    return app.InspectJarClasses(inputJarPath)
  },
  windowMinimise: async (): Promise<void> => {
    const app: WailsGoApp = resolveWailsApp(windowRef)

    if (typeof app.WindowMinimise !== 'function') {
      throw new Error('Wails 绑定缺少 WindowMinimise。')
    }

    await app.WindowMinimise()
  },
  windowToggleMaximise: async (): Promise<void> => {
    const app: WailsGoApp = resolveWailsApp(windowRef)

    if (typeof app.WindowToggleMaximise !== 'function') {
      throw new Error('Wails 绑定缺少 WindowToggleMaximise。')
    }

    await app.WindowToggleMaximise()
  },
  windowIsMaximised: async (): Promise<boolean> => {
    const app: WailsGoApp = resolveWailsApp(windowRef)

    if (typeof app.WindowIsMaximised !== 'function') {
      throw new Error('Wails 绑定缺少 WindowIsMaximised。')
    }

    return app.WindowIsMaximised()
  },
  quit: async (): Promise<void> => {
    const app: WailsGoApp = resolveWailsApp(windowRef)

    if (typeof app.Quit !== 'function') {
      throw new Error('Wails 绑定缺少 Quit。')
    }

    await app.Quit()
  },
  onEngineEvent: (handler: (event: unknown) => void): (() => void) => {
    const runtime: WailsRuntime | undefined = (windowRef as WailsWindow).runtime

    if (runtime === undefined || typeof runtime.EventsOn !== 'function') {
      throw new Error(`Wails runtime 缺少 EventsOn，无法订阅 ${engineEventName}。`)
    }

    const off: (() => void) | void = runtime.EventsOn(engineEventName, handler)

    if (typeof off === 'function') {
      return off
    }

    return (): void => undefined
  },
})

const resolveWailsApp = (windowRef: Window): WailsGoApp => {
  const app: WailsGoApp | undefined = (windowRef as WailsWindow).go?.main?.App

  if (app === undefined) {
    throw new Error('缺少 Wails Go App 绑定：未找到 window.go.main.App。')
  }

  return app
}
