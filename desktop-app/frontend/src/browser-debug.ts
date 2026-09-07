import { createApp } from 'vue'
import App from './App.vue'
import './style.css'
import './styles/liquid-glass.css'
import type { ObfuscationRequest } from './modules/obfuscation/types'
import {
  MOCK_SCENARIO_QUERY,
  defaultConfigToml,
  parseMockScenarioId,
  resolveMockScenario,
  type MockEngineEvent,
  type MockScenario,
} from './debug/mock-scenarios'
import { runUiSmokeChecks, type UiCheckResult } from './debug/ui-smoke'

type EngineEventHandler = (event: unknown) => void

interface WailsRuntimeMock {
  EventsOn: (eventName: string, callback: EngineEventHandler) => (() => void)
  BrowserOpenURL: (url: string) => void
  OnFileDrop: (callback: (x: number, y: number, paths: string[]) => void, useDropTarget?: boolean) => void
  OnFileDropOff: () => void
}

interface WailsAppMock {
  StartObfuscation: (request: ObfuscationRequest) => Promise<void>
  CancelObfuscation: () => Promise<void>
  GetEngineCapabilities: () => Promise<string>
  SelectInputJar: () => Promise<string>
  SelectNativeShroudCli: () => Promise<string>
  SelectOutputJar: (defaultInputJarPath: string) => Promise<string>
  SelectImportConfig: () => Promise<string>
  SelectExportConfig: () => Promise<string>
  ReadTextFile: (path: string) => Promise<string>
  WriteTextFile: (path: string, content: string) => Promise<void>
  InspectJarClasses: (inputJarPath: string) => Promise<string>
  WindowMinimise: () => Promise<void>
  WindowToggleMaximise: () => Promise<void>
  WindowIsMaximised: () => Promise<boolean>
  Quit: () => Promise<void>
}

interface DebugWindow extends Window {
  runtime?: WailsRuntimeMock
  go?: {
    main?: {
      App?: WailsAppMock
    }
  }
  __JAVASHROUD_DEBUG_MOCK__?: DebugMockHooks
}

export interface DebugMockHooks {
  readonly developmentOnly: true
  readonly scenarioId: string
  readonly scenario: MockScenario
  readonly emittedEvents: readonly MockEngineEvent[]
  readonly activeRunToken: number | null
  readonly uiCheckResult: UiCheckResult
  setScenario: (id: string) => MockScenario
  reset: () => void
  runUiChecks: () => void
}

if (!import.meta.env.DEV) {
  throw new Error('browser-debug mock is development-only and must not load in production builds')
}

const debugWindow = window as DebugWindow
const engineEventName = 'engine:event'
const eventListeners = new Map<string, Set<EngineEventHandler>>()
let cancelRequested = false
let isWindowMaximised = false
let debugConfigToml = ''
let emittedEvents: MockEngineEvent[] = []
let activeRunToken: number | null = null
let nextRunToken = 1
let uiCheckResult: UiCheckResult = { status: 'idle', passed: [] }
let scenario = resolveMockScenario(parseMockScenarioId(new URLSearchParams(window.location.search).get(MOCK_SCENARIO_QUERY)))

const sleep = async (ms: number): Promise<void> => new Promise((resolve) => {
  window.setTimeout(resolve, ms)
})

const emitEngineEvent = (event: MockEngineEvent): void => {
  emittedEvents = [...emittedEvents, event]
  const listeners = eventListeners.get(engineEventName)
  if (listeners === undefined) {
    return
  }

  for (const listener of listeners) {
    listener(event)
  }
}

const ensureListenerSet = (eventName: string): Set<EngineEventHandler> => {
  const existing = eventListeners.get(eventName)
  if (existing !== undefined) {
    return existing
  }

  const created = new Set<EngineEventHandler>()
  eventListeners.set(eventName, created)
  return created
}

const applyOutputPath = (event: MockEngineEvent, outputJarPath: string): MockEngineEvent => {
  if (event.type === 'done') {
    return { ...event, outPath: outputJarPath }
  }
  return event
}

const runtimeMock: WailsRuntimeMock = {
  EventsOn: (eventName: string, callback: EngineEventHandler): (() => void) => {
    const listeners = ensureListenerSet(eventName)
    listeners.add(callback)

    return (): void => {
      listeners.delete(callback)
    }
  },
  BrowserOpenURL: (url: string): void => {
    window.open(url, '_blank', 'noopener,noreferrer')
  },
  OnFileDrop: (): void => undefined,
  OnFileDropOff: (): void => undefined,
}

const pumpRun = async (token: number, request: ObfuscationRequest): Promise<void> => {
  const delay = scenario.outcome === 'stream' ? 40 : 180
  const steps = scenario.runSteps.filter((step) => !(step.type === 'log' && step.progress === 0))
  const iterable = steps.length > 0 ? steps : scenario.runSteps

  if (scenario.outcome === 'done') {
    await sleep(delay)
    if (activeRunToken !== token) {
      return
    }
    if (cancelRequested) {
      emitEngineEvent({
        type: 'canceled',
        level: 'warn',
        message: '浏览器调试模式已取消当前任务。',
        progress: null,
        outPath: null,
      })
      if (activeRunToken === token) {
        activeRunToken = null
      }
      return
    }
    emitEngineEvent(applyOutputPath(scenario.runSteps[scenario.runSteps.length - 1] ?? {
      type: 'done',
      level: 'success',
      message: '浏览器调试模式已完成模拟输出。',
      progress: 100,
      outPath: request.outputJarPath,
    }, request.outputJarPath))
    if (activeRunToken === token) {
      activeRunToken = null
    }
    return
  }

  for (const step of iterable) {
    await sleep(delay)
    if (activeRunToken !== token) {
      return
    }
    if (cancelRequested && scenario.outcome !== 'canceled') {
      emitEngineEvent({
        type: 'canceled',
        level: 'warn',
        message: '浏览器调试模式已取消当前任务。',
        progress: null,
        outPath: null,
      })
      if (activeRunToken === token) {
        activeRunToken = null
      }
      return
    }
    emitEngineEvent(applyOutputPath(step, request.outputJarPath))
    if (step.type === 'error' || step.type === 'canceled' || step.type === 'done') {
      if (activeRunToken === token) {
        activeRunToken = null
      }
      return
    }
  }
  if (activeRunToken === token) {
    activeRunToken = null
  }
}

const appMock: WailsAppMock = {
  StartObfuscation: async (request: ObfuscationRequest): Promise<void> => {
    cancelRequested = false
    emittedEvents = []
    const token = nextRunToken
    nextRunToken += 1
    activeRunToken = token
    emitEngineEvent({
      type: 'log',
      level: 'info',
      message: `浏览器调试模式已启动: input=${request.inputJarPath} token=${token}`,
      progress: 0,
      outPath: null,
    })
    void pumpRun(token, request)
  },
  CancelObfuscation: async (): Promise<void> => {
    cancelRequested = true
  },
  GetEngineCapabilities: async (): Promise<string> => JSON.stringify(scenario.schema),
  SelectInputJar: async (): Promise<string> => scenario.inputJarPath,
  SelectNativeShroudCli: async (): Promise<string> => 'C:\\XiangMu\\NativeShroud\\target\\release\\nativeshroud.exe',
  SelectOutputJar: async (defaultInputJarPath: string): Promise<string> => {
    if (scenario.id === 'empty') {
      return ''
    }
    if (defaultInputJarPath.trim().length === 0) {
      return scenario.outputJarPath || 'C:\\debug\\demo-app-shrouded.jar'
    }

    if (defaultInputJarPath.toLowerCase().endsWith('.jar')) {
      return `${defaultInputJarPath.slice(0, -4)}-shrouded.jar`
    }

    return `${defaultInputJarPath}-shrouded.jar`
  },
  SelectImportConfig: async (): Promise<string> => scenario.configPath,
  SelectExportConfig: async (): Promise<string> => scenario.configPath,
  ReadTextFile: async (): Promise<string> => debugConfigToml || defaultConfigToml(scenario),
  WriteTextFile: async (_path: string, content: string): Promise<void> => {
    debugConfigToml = content
    emitEngineEvent({
      type: 'log',
      level: 'info',
      message: `浏览器调试模式已保存配置：${content.length} 字符。`,
      progress: null,
      outPath: null,
    })
  },
  InspectJarClasses: async (inputJarPath: string): Promise<string> => JSON.stringify({
    ...scenario.inspection,
    jarPath: inputJarPath || scenario.inspection.jarPath,
  }),
  WindowMinimise: async (): Promise<void> => undefined,
  WindowToggleMaximise: async (): Promise<void> => {
    isWindowMaximised = !isWindowMaximised
  },
  WindowIsMaximised: async (): Promise<boolean> => isWindowMaximised,
  Quit: async (): Promise<void> => {
    emitEngineEvent({
      type: 'warn',
      level: 'warn',
      message: '浏览器调试模式下不执行窗口退出。',
      progress: null,
      outPath: null,
    })
  },
}

const hooks: DebugMockHooks = {
  developmentOnly: true,
  get scenarioId(): string {
    return scenario.id
  },
  get scenario(): MockScenario {
    return scenario
  },
  get emittedEvents(): readonly MockEngineEvent[] {
    return emittedEvents
  },
  get activeRunToken(): number | null {
    return activeRunToken
  },
  get uiCheckResult(): UiCheckResult {
    return uiCheckResult
  },
  setScenario: (id: string): MockScenario => {
    scenario = resolveMockScenario(parseMockScenarioId(id))
    debugConfigToml = ''
    emittedEvents = []
    cancelRequested = false
    return scenario
  },
  reset: (): void => {
    debugConfigToml = ''
    emittedEvents = []
    cancelRequested = false
    isWindowMaximised = false
    activeRunToken = null
  },
  runUiChecks: (): void => {
    if (uiCheckResult.status === 'running') {
      return
    }
    uiCheckResult = { status: 'running', passed: [] }
    void runUiSmokeChecks({
      setScenario: (id: string) => {
        scenario = resolveMockScenario(parseMockScenarioId(id))
        debugConfigToml = ''
        emittedEvents = []
        cancelRequested = false
        return scenario
      },
      getEmittedEvents: () => emittedEvents,
      onProgress: (passed) => {
        uiCheckResult = { status: 'running', passed: [...passed] }
      },
    }).then((result) => {
      uiCheckResult = result
    }).catch((error: unknown) => {
      uiCheckResult = {
        status: 'failed',
        passed: uiCheckResult.passed,
        error: error instanceof Error ? error.message : String(error),
      }
    })
  },
}

debugWindow.runtime = runtimeMock
debugWindow.go = {
  main: {
    App: appMock,
  },
}
debugWindow.__JAVASHROUD_DEBUG_MOCK__ = hooks

const app = createApp(App)
app.directive('motion', {
  mounted: (): void => undefined,
  updated: (): void => undefined,
})
app.mount('#app')
