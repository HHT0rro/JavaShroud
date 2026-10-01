import { shallowRef } from 'vue'
import { createInitialRunState } from './state.ts'
import { applyEnginePayload } from './frontend-controller.ts'
import { createWorkbenchHandlers } from './workbench-handlers.ts'
import type { RunState } from './types.ts'
import type { WailsBridge } from './wails-bridge.ts'

const assert = (condition: boolean, message: string): void => {
  if (!condition) {
    throw new Error(message)
  }
}

const createDeferred = <T>(): { promise: Promise<T>; resolve: (value: T) => void; reject: (error: unknown) => void } => {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((res, rej): void => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

const createBridge = (overrides: Partial<WailsBridge> = {}): WailsBridge => ({
  startObfuscation: async (): Promise<void> => undefined,
  cancelObfuscation: async (): Promise<void> => undefined,
  resumeNativePack: async (): Promise<void> => undefined,
  getEngineCapabilities: async (): Promise<string> => '{}',
  resolveXenolithCli: async (): Promise<{ path: string; version: string; source: string }> => ({ path: '', version: '', source: '' }),
  selectInputJar: async (): Promise<string> => '',
  selectPackedNative: async (): Promise<string> => '',
  revealNativeImage: async (): Promise<void> => undefined,
  selectOutputJar: async (): Promise<string> => '',
  selectImportConfig: async (): Promise<string> => '',
  selectExportConfig: async (): Promise<string> => '',
  readTextFile: async (): Promise<string> => '',
  writeTextFile: async (): Promise<void> => undefined,
  inspectJarClasses: async (): Promise<string> => JSON.stringify({
    jarPath: 'C:\\tmp\\sample.jar',
    classCount: 1,
    packageCount: 1,
    nodes: [],
  }),
  windowMinimise: async (): Promise<void> => undefined,
  windowToggleMaximise: async (): Promise<void> => undefined,
  windowIsMaximised: async (): Promise<boolean> => false,
  quit: async (): Promise<void> => undefined,
  onEngineEvent: (): (() => void) => (): void => undefined,
  ...overrides,
})

const createHarness = (bridge: WailsBridge, initial: RunState = createInitialRunState()) => {
  const state = shallowRef(initial)
  const activePage = shallowRef<import('./workbench-view.ts').WorkbenchPage>('home')
  const isWindowMaximised = shallowRef(false)
  const errors: string[] = []
  const successes: string[] = []
  const handlers = createWorkbenchHandlers({
    state,
    bridge,
    message: {
      error: (message: string): void => {
        errors.push(message)
      },
      success: (message: string): void => {
        successes.push(message)
      },
    },
    activePage,
    isWindowMaximised,
  })
  return { state, activePage, isWindowMaximised, handlers, errors, successes }
}

const readyState = (): RunState => ({
  ...createInitialRunState(),
  status: 'ready',
  inputJar: {
    fileName: 'sample.jar',
    inputJarPath: 'C:\\tmp\\sample.jar',
    sizeLabel: '系统文件',
    detectedMainClass: null,
  },
  outputJarPath: 'C:\\tmp\\out.jar',
  passes: [{
    id: 'rename',
    name: 'Rename',
    description: '',
    tagIds: [],
    category: 'rename',
    enabled: true,
    params: {},
    paramSchemas: [],
    stability: 'stable',
    risk: 'low',
    requiresOptIn: false,
    requiredPassIds: [],
    requiresAnyPassIds: [],
    variantRequirements: [],
    targeting: { supported: false, targetKinds: [] },
  }],
})

{
  const startGate = createDeferred<void>()
  const { state, activePage, handlers } = createHarness(createBridge({
    startObfuscation: (): Promise<void> => startGate.promise,
  }), readyState())

  const startPromise = handlers.handleStart()
  await Promise.resolve()
  assert(state.value.status === 'running', `expected immediate running, actual=${state.value.status}`)
  assert(activePage.value === 'logs', 'expected start to switch to logs immediately')

  state.value = applyEnginePayload(state.value, {
    type: 'done',
    level: 'info',
    message: 'finished',
    progress: 100,
    outPath: 'C:\\tmp\\out.jar',
  })
  startGate.resolve()
  await startPromise
  assert(state.value.status === 'done', `expected done to survive start await, actual=${state.value.status}`)
}

{
  const cancelGate = createDeferred<void>()
  const { state, handlers } = createHarness(createBridge({
    cancelObfuscation: (): Promise<void> => cancelGate.promise,
  }), { ...readyState(), status: 'running' })

  const cancelPromise = handlers.handleCancel()
  await Promise.resolve()
  assert(state.value.status === 'canceling', `expected immediate canceling, actual=${state.value.status}`)

  state.value = applyEnginePayload(state.value, {
    type: 'canceled',
    level: 'warn',
    message: 'canceled',
    progress: null,
    outPath: null,
  })
  cancelGate.resolve()
  await cancelPromise
  assert(state.value.status === 'ready', `expected canceled event to survive cancel await, actual=${state.value.status}`)
}

{
  const { state, isWindowMaximised, handlers } = createHarness(createBridge({
    windowToggleMaximise: async (): Promise<void> => undefined,
    windowIsMaximised: async (): Promise<boolean> => true,
    getEngineCapabilities: async (): Promise<string> => {
      throw new Error('capabilities must not load on maximize')
    },
  }), { ...readyState(), outputJarPath: 'C:\\keep\\out.jar' })

  await handlers.handleWindowAction('toggle-maximise')
  assert(isWindowMaximised.value === true, 'expected maximise query to update window flag')
  assert(state.value.outputJarPath === 'C:\\keep\\out.jar', 'expected maximize not to reset config')
  assert(state.value.status === 'ready', 'expected maximize not to clobber run status')
}

{
  const inspectGate = createDeferred<string>()
  let inspectingSeen: boolean | undefined
  const { state, handlers } = createHarness(createBridge({
    inspectJarClasses: (): Promise<string> => {
      inspectingSeen = state.value.inspectingClasses
      return inspectGate.promise
    },
  }), readyState())

  const inspectPromise = handlers.inspectCurrentJar()
  await Promise.resolve()
  await Promise.resolve()
  assert(state.value.inspectingClasses === true, 'expected inspecting flag before inspect await')
  inspectGate.resolve(JSON.stringify({
    jarPath: 'C:\\tmp\\sample.jar',
    classCount: 2,
    packageCount: 1,
    nodes: [],
  }))
  await inspectPromise
  assert(inspectingSeen === true, 'expected inspect bridge call to observe inspecting flag')
  assert(state.value.inspectingClasses === false, 'expected inspecting to clear after success')
  assert(state.value.classCount === 2, 'expected inspection payload to apply')
}

{
  const inspectGate = createDeferred<string>()
  const { state, handlers } = createHarness(createBridge({
    inspectJarClasses: (): Promise<string> => inspectGate.promise,
  }), readyState())

  const inspectPromise = handlers.inspectCurrentJar()
  await Promise.resolve()
  await Promise.resolve()
  state.value = { ...state.value, outputJarPath: 'C:\\mutated\\out.jar' }
  inspectGate.resolve(JSON.stringify({
    jarPath: 'C:\\tmp\\sample.jar',
    classCount: 3,
    packageCount: 1,
    nodes: [],
  }))
  await inspectPromise
  assert(state.value.outputJarPath === 'C:\\mutated\\out.jar', 'expected inspect result not to clobber mutated config')
  assert(state.value.classCount === 3, 'expected latest inspect tree to apply')
}

{
  const inspectGate = createDeferred<string>()
  const { state, handlers, successes } = createHarness(createBridge({
    inspectJarClasses: (): Promise<string> => inspectGate.promise,
  }))

  const dropPromise = handlers.handleNativeFileDrop(0, 0, ['C:\\tmp\\dropped.jar'])
  await Promise.resolve()
  await Promise.resolve()
  assert(state.value.inputJar?.inputJarPath === 'C:\\tmp\\dropped.jar', 'expected drop to load jar path')
  assert(state.value.inspectingClasses === true, 'expected drop to inspect immediately')
  inspectGate.resolve(JSON.stringify({
    jarPath: 'C:\\tmp\\dropped.jar',
    classCount: 4,
    packageCount: 1,
    nodes: [],
  }))
  await dropPromise
  assert(successes.includes('已通过拖拽载入 Jar 路径'), 'expected drop success toast')
  assert(state.value.classCount === 4, 'expected drop inspect to apply')
}

{
  let startCalls = 0
  const startGate = createDeferred<void>()
  const { handlers } = createHarness(createBridge({
    startObfuscation: (): Promise<void> => {
      startCalls += 1
      return startGate.promise
    },
  }), readyState())

  const first = handlers.handleStart()
  const second = handlers.handleStart()
  await Promise.resolve()
  assert(startCalls === 1, `expected duplicate start to be refused, calls=${startCalls}`)
  startGate.resolve()
  await first
  await second
}

{
  const startGate = createDeferred<void>()
  let cancelCalls = 0
  const { state, handlers } = createHarness(createBridge({
    startObfuscation: (): Promise<void> => startGate.promise,
    cancelObfuscation: async (): Promise<void> => {
      cancelCalls += 1
    },
  }), readyState())

  const startPromise = handlers.handleStart()
  await Promise.resolve()
  assert(state.value.status === 'running', 'expected start to mark running before RPC')
  await handlers.handleCancel()
  assert(state.value.status === 'canceling', 'expected cancel to cut in before start RPC settles')
  assert(cancelCalls === 1, 'expected cancel RPC during deferred start')
  startGate.resolve()
  await startPromise
  assert(state.value.status === 'canceling' || state.value.status === 'ready', `expected cancel status to survive late start RPC, actual=${state.value.status}`)
}

{
  const { state, handlers, errors } = createHarness(createBridge({
    windowToggleMaximise: async (): Promise<void> => {
      throw new Error('maximise failed')
    },
  }), { ...readyState(), status: 'running' })

  await handlers.handleWindowAction('toggle-maximise')
  assert(state.value.status === 'running', 'expected window error not to fail active run')
  assert(errors.some((message) => message.includes('窗口控制失败')), 'expected window error toast')
}

{
  const inspectGate = createDeferred<string>()
  const sampleNode = {
    id: 'pkg',
    label: 'pkg',
    qualifiedName: 'pkg',
    internalName: 'pkg',
    selector: 'pkg.**',
    kind: 'package' as const,
    children: [],
  }
  const { state, handlers } = createHarness(createBridge({
    inspectJarClasses: (): Promise<string> => inspectGate.promise,
  }), {
    ...readyState(),
    classTree: [sampleNode],
  })

  const inspectPromise = handlers.inspectCurrentJar()
  await Promise.resolve()
  await Promise.resolve()
  handlers.handleNodeRuleChanged(sampleNode, 'exclude')
  assert(state.value.rules.length === 0, 'expected rule edits locked while inspecting')
  state.value = {
    ...state.value,
    rules: [{ id: 'live-rule', target: 'pkg.**', action: 'exclude' }],
  }
  inspectGate.resolve(JSON.stringify({
    jarPath: 'C:\\tmp\\sample.jar',
    classCount: 1,
    packageCount: 1,
    nodes: [sampleNode],
  }))
  await inspectPromise
  assert(state.value.rules.some((rule) => rule.target === 'pkg.**' && rule.action === 'exclude'), 'expected inspect to reconcile latest live rules onto new tree')
}

{
  const { state, handlers } = createHarness(createBridge({
    selectInputJar: async (): Promise<string> => 'C:\\debug\\example.jar',
    inspectJarClasses: async (inputJarPath: string): Promise<string> => JSON.stringify({
      jarPath: inputJarPath,
      classCount: 96,
      packageCount: 12,
      nodes: [],
    }),
  }), createInitialRunState())

  await handlers.handleBrowseInput()
  assert(state.value.inputJar?.inputJarPath === 'C:\\debug\\example.jar', 'expected browse to load selected jar')
  assert(state.value.outputJarPath === 'C:\\debug\\example-shrouded.jar', `expected derived output from setLoadedJar, actual=${state.value.outputJarPath}`)
  assert(state.value.status === 'ready', `expected ready after browse+inspect, actual=${state.value.status}`)
  assert(state.value.classCount === 96, 'expected inspection class count after browse')
}

{
  let selectedJar = 'C:\\jars\\first.jar'
  const { state, handlers } = createHarness(createBridge({
    selectInputJar: async (): Promise<string> => selectedJar,
    inspectJarClasses: async (inputJarPath: string): Promise<string> => JSON.stringify({
      jarPath: inputJarPath,
      classCount: 1,
      packageCount: 1,
      nodes: [],
    }),
  }), createInitialRunState())

  await handlers.handleBrowseInput()
  assert(state.value.outputJarPath === 'C:\\jars\\first-shrouded.jar', `expected first derived output, actual=${state.value.outputJarPath}`)
  selectedJar = 'C:\\jars\\second.jar'
  await handlers.handleBrowseInput()
  assert(state.value.inputJar?.inputJarPath === 'C:\\jars\\second.jar', 'expected second jar path')
  assert(state.value.outputJarPath === 'C:\\jars\\second-shrouded.jar', `expected second derived output, actual=${state.value.outputJarPath}`)
}

{
  const startGate = createDeferred<void>()
  let browseCalls = 0
  const { handlers } = createHarness(createBridge({
    startObfuscation: (): Promise<void> => startGate.promise,
    selectInputJar: async (): Promise<string> => {
      browseCalls += 1
      return 'C:\\debug\\example.jar'
    },
  }), readyState())

  const startPromise = handlers.handleStart()
  await Promise.resolve()
  await handlers.handleBrowseInput()
  assert(browseCalls === 0, 'expected browse to refuse immediately while start is pending')
  startGate.resolve()
  await startPromise
}

{
  let inputBrowseCalls = 0
  let packedBrowseCalls = 0
  let resumePath: string | null = null
  const { state, activePage, handlers } = createHarness(createBridge({
    selectInputJar: async (): Promise<string> => {
      inputBrowseCalls += 1
      return 'C:\\debug\\example.jar'
    },
    selectPackedNative: async (): Promise<string> => {
      packedBrowseCalls += 1
      return 'C:\\tmp\\qp_ffi.packed.dll'
    },
    resumeNativePack: async (path: string): Promise<void> => {
      resumePath = path
    },
  }), {
    ...readyState(),
    status: 'running',
    packHandoffPath: null,
  })

  state.value = applyEnginePayload(state.value, {
    type: 'need-pack',
    level: 'info',
    message: 'awaiting packed native',
    progress: 94,
    outPath: 'C:\\tmp\\qp_ffi.dll',
  })
  assert(state.value.status === 'awaiting-pack', `expected need-pack to enter awaiting-pack, actual=${state.value.status}`)
  assert(state.value.packHandoffPath === 'C:\\tmp\\qp_ffi.dll', `expected packHandoffPath from need-pack, actual=${String(state.value.packHandoffPath)}`)

  await handlers.handleBrowseInput()
  assert(inputBrowseCalls === 0, 'expected awaiting-pack to keep regular jar browse locked')

  const selected = await handlers.handleBrowsePackedNative()
  assert(packedBrowseCalls === 1, 'expected awaiting-pack to allow packed native browse')
  assert(selected === 'C:\\tmp\\qp_ffi.packed.dll', `expected packed path, actual=${String(selected)}`)

  await handlers.handleResumeNativePack('C:\\tmp\\qp_ffi.packed.dll')
  assert(resumePath === 'C:\\tmp\\qp_ffi.packed.dll', `expected resume path, actual=${String(resumePath)}`)
  assert(state.value.status === 'running', `expected resume to return to running, actual=${state.value.status}`)
  assert(activePage.value === 'logs', 'expected resume to switch to logs')
}

{
  let browseCalls = 0
  const { handlers } = createHarness(createBridge({
    selectPackedNative: async (): Promise<string> => {
      browseCalls += 1
      return 'C:\\tmp\\qp_ffi.packed.dll'
    },
  }), {
    ...readyState(),
    status: 'running',
    packHandoffPath: null,
  })

  const selected = await handlers.handleBrowsePackedNative()
  assert(browseCalls === 0, 'expected running status to block packed native browse')
  assert(selected === null, 'expected locked pack browse to return null')
}

{
  let resumeCalls = 0
  const { state, handlers } = createHarness(createBridge({
    resumeNativePack: async (): Promise<void> => {
      resumeCalls += 1
    },
  }), {
    ...readyState(),
    status: 'awaiting-pack',
    packHandoffPath: 'C:\\tmp\\libqp_ffi.so',
  })

  await handlers.handleResumeNativePack('SKIP')
  assert(resumeCalls === 1, 'expected Linux SKIP resume to call bridge')
  assert(state.value.status === 'running', 'expected SKIP resume to mark running')
}

console.log('workbench-handlers checks passed')
