import type { Ref } from 'vue'
import { emitStateError, emitSuccess } from './toast-controller'
import { applyDroppedJarPaths, resolveInspectableJarPath } from './input-flow-controller'
import { loadWorkbenchState } from './page-controller'
import {
  applyBridgeError,
  clearLogs,
  clearRules,
  markCanceling,
  markInspectingClasses,
  markRunStarting,
  replaceRules,
  setAutoScroll,
  setClassTreeRule,
  setPassSelectionMode,
  setPassSelectionRule,
  setInputJarPath,
  setOutputJarPath,
  setJarInspection,
  setPassParam,
  setPasses,
  togglePass,
} from './state'
import {
  browseInputJar,
  browseNativeShroudCli,
  browseOutputJar,
  cancelObfuscationRun,
  exportWorkbenchConfig,
  inspectJarClasses,
  importWorkbenchConfig,
  loadWindowMaximiseState,
  runWindowAction,
  startObfuscationRun,
} from './frontend-controller'
import type { ClassTreeNode, PassItem, PassParamValue, PassSelectionMode, RuleAction, RuleItem, RunState } from './types'
import type { WailsBridge } from './wails-bridge'

interface MessageApi {
  readonly error: (message: string) => void
  readonly success: (message: string) => void
}

interface WorkbenchFacadeOptions {
  readonly state: Ref<RunState>
  readonly bridge: WailsBridge
  readonly message: MessageApi
  readonly activePage: Ref<'home' | 'passes' | 'classes' | 'logs' | 'about'>
  readonly isWindowMaximised: Ref<boolean>
}

const isTerminalRunStatus = (status: RunState['status']): boolean =>
  status === 'done' || status === 'failed' || status === 'ready'

const isBusyRunStatus = (status: RunState['status']): boolean =>
  status === 'running' || status === 'canceling'

const windowControlErrorMessage = (error: unknown): string => {
  const message: string = error instanceof Error ? error.message : String(error)
  return `窗口控制失败: ${message}`
}

export const createWorkbenchHandlers = (options: WorkbenchFacadeOptions) => {
  let mutatingQueue: Promise<void> = Promise.resolve()
  let inspectGeneration = 0
  let startInFlight = false
  let cancelInFlight = false
  let runGeneration = 0

  const enqueueMutating = (work: () => Promise<void>): Promise<void> => {
    const run = mutatingQueue.then(work)
    mutatingQueue = run.then(
      (): void => undefined,
      (): void => undefined,
    )
    return run
  }

  const isRunPending = (): boolean => startInFlight || cancelInFlight || isBusyRunStatus(options.state.value.status)

  const inspectLoadedJar = async (inputJarPath: string): Promise<void> => {
    const generation = ++inspectGeneration
    options.state.value = markInspectingClasses(options.state.value)
    const inspected: RunState = await inspectJarClasses(options.state.value, options.bridge, inputJarPath)
    if (generation !== inspectGeneration) {
      return
    }
    if (options.state.value.inputJar?.inputJarPath !== inputJarPath) {
      if (generation === inspectGeneration) {
        options.state.value = {
          ...options.state.value,
          inspectingClasses: false,
        }
      }
      return
    }
    if (inspected.errorMessage !== null) {
      options.state.value = {
        ...options.state.value,
        inspectingClasses: false,
        errorMessage: inspected.errorMessage,
        logs: inspected.logs.length >= options.state.value.logs.length
          ? inspected.logs
          : options.state.value.logs,
      }
      return
    }
    options.state.value = setJarInspection(options.state.value, {
      jarPath: inputJarPath,
      classCount: inspected.classCount,
      packageCount: inspected.packageCount,
      nodes: inspected.classTree,
    })
  }

  const currentStatus = (): RunState['status'] => options.state.value.status

  const isEditingLocked = (): boolean =>
    startInFlight
    || cancelInFlight
    || options.state.value.inspectingClasses
    || isBusyRunStatus(currentStatus())

  return {
    refreshWindowState: async (): Promise<void> => {
      const result = await loadWorkbenchState(options.state.value, options.bridge)
      options.state.value = result.nextState
      if (result.isWindowMaximised !== null) {
        options.isWindowMaximised.value = result.isWindowMaximised
      }
    },

    handleWindowAction: async (actionId: 'minimise' | 'toggle-maximise' | 'quit'): Promise<void> => {
      try {
        await runWindowAction(options.bridge, actionId)
        if (actionId === 'toggle-maximise') {
          options.isWindowMaximised.value = await loadWindowMaximiseState(options.bridge)
        }
      } catch (error) {
        options.message.error(windowControlErrorMessage(error))
      }
    },

    handleNativeFileDrop: async (_x: number, _y: number, paths: string[]): Promise<void> => {
      if (isRunPending()) {
        return
      }
      await enqueueMutating(async (): Promise<void> => {
        if (isRunPending()) {
          return
        }
        const result = applyDroppedJarPaths(options.state.value, paths)
        options.state.value = result.nextState
        if (result.errorMessage !== null) {
          emitStateError(options.message, result.nextState, '请拖入 .jar 文件')
          return
        }

        emitSuccess(options.message, '已通过拖拽载入 Jar 路径')
        if (result.inputJarPath === null) {
          return
        }
        await inspectLoadedJar(result.inputJarPath)
      })
    },

    handleInputPathChanged: (inputJarPath: string): void => {
      if (isEditingLocked()) {
        return
      }
      options.state.value = setInputJarPath(options.state.value, inputJarPath)
    },

    handleOutputChanged: (outputJarPath: string): void => {
      if (isEditingLocked()) {
        return
      }
      options.state.value = setOutputJarPath(options.state.value, outputJarPath)
    },

    handleBrowseInput: async (): Promise<void> => {
      if (isRunPending()) {
        return
      }
      await enqueueMutating(async (): Promise<void> => {
        if (isRunPending()) {
          return
        }
        const outputBeforeBrowse: string = options.state.value.outputJarPath
        const result = await browseInputJar(options.state.value, options.bridge)
        if (result.failed) {
          options.state.value = {
            ...options.state.value,
            errorMessage: result.nextState.errorMessage,
            logs: result.nextState.logs.length >= options.state.value.logs.length
              ? result.nextState.logs
              : options.state.value.logs,
          }
          emitStateError(options.message, options.state.value, '选择输入 Jar 失败')
          return
        }
        if (result.value === null) {
          return
        }

        const current: RunState = options.state.value
        const loaded: RunState = result.nextState
        const outputChangedDuringBrowse: boolean = current.outputJarPath !== outputBeforeBrowse
        options.state.value = {
          ...current,
          status: isBusyRunStatus(current.status)
            ? current.status
            : loaded.status,
          inputJar: loaded.inputJar,
          outputJarPath: outputChangedDuringBrowse ? current.outputJarPath : loaded.outputJarPath,
          classTree: loaded.classTree,
          classCount: loaded.classCount,
          packageCount: loaded.packageCount,
          errorMessage: loaded.errorMessage,
        }

        let inputJarPath: string
        try {
          inputJarPath = resolveInspectableJarPath(options.state.value)
        } catch (error) {
          options.state.value = applyBridgeError(options.state.value, error, '扫描类树失败')
          return
        }

        await inspectLoadedJar(inputJarPath)
      })
    },

    handleBrowseOutput: async (): Promise<void> => {
      if (isRunPending()) {
        return
      }
      await enqueueMutating(async (): Promise<void> => {
        if (isRunPending()) {
          return
        }
        const result = await browseOutputJar(options.state.value, options.bridge)
        if (result.failed) {
          options.state.value = applyBridgeError(
            options.state.value,
            new Error(result.nextState.errorMessage ?? '选择输出 Jar 失败'),
            '选择输出 Jar 失败',
          )
          emitStateError(options.message, options.state.value, '选择输出 Jar 失败')
          return
        }
        if (result.value === null) {
          return
        }
        options.state.value = setOutputJarPath(options.state.value, result.value)
      })
    },

    handleImportConfig: async (): Promise<void> => {
      if (isRunPending()) {
        return
      }
      await enqueueMutating(async (): Promise<void> => {
        if (isRunPending()) {
          return
        }
        const result = await importWorkbenchConfig(options.state.value, options.bridge)
        options.state.value = result.nextState
        if (result.failed) {
          emitStateError(options.message, options.state.value, '导入配置失败')
          return
        }
        if (result.value === null) {
          return
        }

        if (result.warningMessages.length > 0) {
          options.message.success(`配置已导入，跳过 ${result.warningMessages.length} 项不兼容内容`)
          return
        }
        emitSuccess(options.message, '配置已导入')
      })
    },

    handleExportConfig: async (): Promise<void> => {
      if (isRunPending()) {
        return
      }
      await enqueueMutating(async (): Promise<void> => {
        if (isRunPending()) {
          return
        }
        const result = await exportWorkbenchConfig(options.state.value, options.bridge)
        if (result.failed) {
          options.state.value = applyBridgeError(
            options.state.value,
            new Error(result.nextState.errorMessage ?? '导出配置失败'),
            '导出配置失败',
          )
          emitStateError(options.message, options.state.value, '导出配置失败')
          return
        }
        if (result.value === null) {
          return
        }

        emitSuccess(options.message, '配置已导出')
      })
    },

    inspectCurrentJar: async (): Promise<void> => {
      if (isRunPending()) {
        return
      }
      await enqueueMutating(async (): Promise<void> => {
        if (isRunPending()) {
          return
        }
        let inputJarPath: string
        try {
          inputJarPath = resolveInspectableJarPath(options.state.value)
        } catch (error) {
          options.state.value = applyBridgeError(options.state.value, error, '扫描类树失败')
          return
        }

        await inspectLoadedJar(inputJarPath)
      })
    },

    handlePassesChanged: (passes: readonly PassItem[]): void => {
      if (isEditingLocked()) {
        return
      }
      options.state.value = setPasses(options.state.value, passes)
    },

    handlePassToggled: (passId: string): void => {
      if (isEditingLocked()) {
        return
      }
      options.state.value = togglePass(options.state.value, passId)
    },

    handlePassParamChanged: (passId: string, paramKey: string, value: PassParamValue): void => {
      if (isEditingLocked()) {
        return
      }
      options.state.value = setPassParam(options.state.value, passId, paramKey, value)
    },

    handleBrowseNativeShroudCli: async (passId: string, paramKey: string): Promise<void> => {
      if (isEditingLocked()) {
        return
      }
      await enqueueMutating(async (): Promise<void> => {
        if (isEditingLocked()) {
          return
        }
        const result = await browseNativeShroudCli(options.state.value, options.bridge)
        if (result.failed) {
          options.state.value = {
            ...options.state.value,
            errorMessage: result.nextState.errorMessage,
            logs: result.nextState.logs.length >= options.state.value.logs.length
              ? result.nextState.logs
              : options.state.value.logs,
          }
          emitStateError(options.message, options.state.value, '选择 NativeShroud CLI 失败')
          return
        }
        if (result.value === null) {
          return
        }
        options.state.value = setPassParam(options.state.value, passId, paramKey, result.value)
      })
    },

    handleAutoScrollChanged: (autoScroll: boolean): void => {
      options.state.value = setAutoScroll(options.state.value, autoScroll)
    },

    handleNodeRuleChanged: (node: ClassTreeNode, action: RuleAction): void => {
      if (isEditingLocked()) {
        return
      }
      try {
        options.state.value = setClassTreeRule(options.state.value, node, action)
      } catch (error) {
        options.state.value = applyBridgeError(options.state.value, error, '更新类树规则失败')
      }
    },

    handlePassSelectionModeChanged: (passId: string, mode: PassSelectionMode): void => {
      if (isEditingLocked()) {
        return
      }
      try {
        options.state.value = setPassSelectionMode(options.state.value, passId, mode)
      } catch (error) {
        options.state.value = applyBridgeError(options.state.value, error, '更新 Pass 范围模式失败')
      }
    },

    handlePassSelectionRuleChanged: (passId: string, node: ClassTreeNode, action: RuleAction): void => {
      if (isEditingLocked()) {
        return
      }
      try {
        options.state.value = setPassSelectionRule(options.state.value, passId, node, action)
      } catch (error) {
        options.state.value = applyBridgeError(options.state.value, error, '更新 Pass 范围规则失败')
      }
    },

    handleClearRules: (): void => {
      if (isEditingLocked()) {
        return
      }
      options.state.value = clearRules(options.state.value)
    },

    handleRulesImported: (rules: readonly RuleItem[]): void => {
      if (isEditingLocked()) {
        return
      }
      options.state.value = replaceRules(options.state.value, rules)
      emitSuccess(options.message, `已导入 ${rules.length} 条排除规则`)
    },

    handleClearLogs: (): void => {
      options.state.value = clearLogs(options.state.value)
    },

    handleStart: async (): Promise<void> => {
      if (startInFlight || isBusyRunStatus(currentStatus())) {
        return
      }
      startInFlight = true
      const generation = ++runGeneration
      const requestState: RunState = options.state.value
      options.state.value = markRunStarting(requestState)
      options.activePage.value = 'logs'
      try {
        if (generation !== runGeneration || cancelInFlight || currentStatus() === 'canceling') {
          return
        }
        const result = await startObfuscationRun(requestState, options.bridge)
        const statusAfterStart = currentStatus()
        if (result.failed) {
          if (!isTerminalRunStatus(statusAfterStart) && statusAfterStart !== 'canceling') {
            options.state.value = applyBridgeError(options.state.value, new Error(
              result.nextState.errorMessage ?? '启动混淆失败',
            ), '启动混淆失败')
            emitStateError(options.message, options.state.value, '启动混淆失败')
          }
        }
      } finally {
        startInFlight = false
      }
    },

    handleCancel: async (): Promise<void> => {
      if (cancelInFlight) {
        return
      }
      if (!startInFlight && !isBusyRunStatus(currentStatus())) {
        return
      }
      cancelInFlight = true
      options.state.value = markCanceling(options.state.value)
      try {
        const result = await cancelObfuscationRun(options.state.value, options.bridge)
        const statusAfterCancel = currentStatus()
        if (result.failed) {
          if (isTerminalRunStatus(statusAfterCancel) || statusAfterCancel === 'canceling') {
            return
          }
          options.state.value = applyBridgeError(options.state.value, new Error(
            result.nextState.errorMessage ?? '取消混淆失败',
          ), '取消混淆失败')
          emitStateError(options.message, options.state.value, '取消混淆失败')
        }
      } finally {
        cancelInFlight = false
      }
    },

    loadCapabilities: async (): Promise<void> => {
      const result = await loadWorkbenchState(options.state.value, options.bridge)
      options.state.value = result.nextState
      if (result.isWindowMaximised !== null) {
        options.isWindowMaximised.value = result.isWindowMaximised
      }
    },
  }
}
