import { createApp } from 'vue'
import App from './App.vue'
import './style.css'
import './styles/liquid-glass.css'
import type { EngineSchemaPayload, JarInspectionPayload, ObfuscationRequest } from './modules/obfuscation/types'

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
}

const debugWindow = window as DebugWindow
const engineEventName = 'engine:event'
const eventListeners = new Map<string, Set<EngineEventHandler>>()
let cancelRequested = false
let isWindowMaximised = false
let debugConfigToml = ''

const defaultSchema: EngineSchemaPayload = {
  schemaVersion: '2',
  engineVersion: 'browser-mock-dev',
  vbcVersion: 'VBC4-dev',
  tags: [
    { id: 'metadata', name: 'Metadata', description: 'Metadata cleanup and stripping.' },
    { id: 'obfuscation', name: 'Obfuscation', description: 'Name and bytecode transforms.' },
  ],
  modules: [
    {
      id: 'strip-compile-debug-info',
      name: 'Strip Compile Debug Info',
      description: 'Removes source and debug metadata.',
      tagIds: ['metadata'],
      stability: 'stable',
      params: [],
    },
    {
      id: 'rename-classes',
      name: 'Rename Classes',
      description: 'Renames class symbols for debug preview.',
      tagIds: ['obfuscation'],
      stability: 'beta',
      params: [
        {
          key: 'dictionary',
          type: 'enum',
          defaultValue: 'ascii',
          options: ['ascii', 'greek', 'compact'],
          description: 'Select the preview rename dictionary.',
          hidden: false,
        },
      ],
    },
    {
      id: 'junk-code',
      name: 'Junk Code',
      description: 'Injects preview-only junk blocks.',
      tagIds: ['obfuscation'],
      stability: 'experimental',
      params: [
        {
          key: 'intensity',
          type: 'number',
          defaultValue: 2,
          options: null,
          description: 'Preview intensity from 1 to 5.',
          hidden: false,
        },
      ],
    },
  ],
  compatibility: [],
  orderingConstraints: [],
  defaultPipeline: ['strip-compile-debug-info', 'rename-classes'],
}

const defaultInspection: JarInspectionPayload = {
  jarPath: 'C:\\debug\\demo-app.jar',
  classCount: 5,
  packageCount: 3,
  nodes: [
    {
      id: 'pkg-com-example',
      label: 'com.example',
      qualifiedName: 'com.example',
      internalName: 'com/example',
      kind: 'package',
      children: [
        {
          id: 'class-main',
          label: 'MainApplication',
          qualifiedName: 'com.example.MainApplication',
          internalName: 'com/example/MainApplication',
          kind: 'class',
          children: [],
        },
        {
          id: 'class-service',
          label: 'UserService',
          qualifiedName: 'com.example.UserService',
          internalName: 'com/example/UserService',
          kind: 'class',
          children: [],
        },
      ],
    },
    {
      id: 'pkg-com-example-api',
      label: 'com.example.api',
      qualifiedName: 'com.example.api',
      internalName: 'com/example/api',
      kind: 'package',
      children: [
        {
          id: 'class-controller',
          label: 'AuthController',
          qualifiedName: 'com.example.api.AuthController',
          internalName: 'com/example/api/AuthController',
          kind: 'class',
          children: [],
        },
      ],
    },
    {
      id: 'pkg-com-example-model',
      label: 'com.example.model',
      qualifiedName: 'com.example.model',
      internalName: 'com/example/model',
      kind: 'package',
      children: [
        {
          id: 'class-user',
          label: 'UserRecord',
          qualifiedName: 'com.example.model.UserRecord',
          internalName: 'com/example/model/UserRecord',
          kind: 'class',
          children: [],
        },
        {
          id: 'class-role',
          label: 'RoleRecord',
          qualifiedName: 'com.example.model.RoleRecord',
          internalName: 'com/example/model/RoleRecord',
          kind: 'class',
          children: [],
        },
      ],
    },
  ],
}

const sleep = async (ms: number): Promise<void> => new Promise((resolve) => {
  window.setTimeout(resolve, ms)
})

const emitEngineEvent = (event: unknown): void => {
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

const appMock: WailsAppMock = {
  StartObfuscation: async (request: ObfuscationRequest): Promise<void> => {
    cancelRequested = false
    emitEngineEvent({
      type: 'log',
      level: 'info',
      message: `浏览器调试模式已启动: input=${request.inputJarPath}`,
      progress: 0,
      outPath: null,
    })

    const steps = [20, 45, 70, 90, 100]
    for (const progress of steps) {
      await sleep(280)
      if (cancelRequested) {
        emitEngineEvent({
          type: 'canceled',
          level: 'warn',
          message: '浏览器调试模式已取消当前任务。',
          progress: null,
          outPath: null,
        })
        return
      }

      emitEngineEvent({
        type: progress === 100 ? 'done' : 'progress',
        level: progress === 100 ? 'success' : 'info',
        message: progress === 100 ? '浏览器调试模式已完成模拟输出。' : `浏览器调试进度 ${progress}%`,
        progress,
        outPath: progress === 100 ? request.outputJarPath : null,
      })
    }
  },
  CancelObfuscation: async (): Promise<void> => {
    cancelRequested = true
  },
  GetEngineCapabilities: async (): Promise<string> => JSON.stringify(defaultSchema),
  SelectInputJar: async (): Promise<string> => defaultInspection.jarPath,
  SelectOutputJar: async (defaultInputJarPath: string): Promise<string> => {
    if (defaultInputJarPath.trim().length === 0) {
      return 'C:\\debug\\demo-app-shrouded.jar'
    }

    if (defaultInputJarPath.toLowerCase().endsWith('.jar')) {
      return `${defaultInputJarPath.slice(0, -4)}-shrouded.jar`
    }

    return `${defaultInputJarPath}-shrouded.jar`
  },
  SelectImportConfig: async (): Promise<string> => 'C:\\debug\\javashroud-config.toml',
  SelectExportConfig: async (): Promise<string> => 'C:\\debug\\javashroud-config.toml',
  ReadTextFile: async (): Promise<string> => debugConfigToml || [
    '[meta]',
    'format = "javashroud-workbench"',
    'version = 1',
    '',
    '[input]',
    'inputJarPath = "C:\\\\debug\\\\demo-app.jar"',
    'outputJarPath = "C:\\\\debug\\\\demo-app-shrouded.jar"',
    '',
    '[[passes]]',
    'id = "strip-compile-debug-info"',
    'enabled = true',
    '',
    '[passes.params]',
    '',
    '[[passes]]',
    'id = "rename-classes"',
    'enabled = true',
    '',
    '[passes.params]',
    'dictionary = "ascii"',
    '',
    '[[rules]]',
    'target = "com/example/api/*"',
    'action = "exclude"',
    '',
  ].join('\n'),
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
    ...defaultInspection,
    jarPath: inputJarPath,
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

debugWindow.runtime = runtimeMock
debugWindow.go = {
  main: {
    App: appMock,
  },
}

const app = createApp(App)
app.directive('motion', {
  mounted: (): void => undefined,
  updated: (): void => undefined,
})
app.mount('#app')
