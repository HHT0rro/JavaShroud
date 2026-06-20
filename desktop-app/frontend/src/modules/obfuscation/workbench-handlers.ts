import type { Ref } from 'vue'
import { emitStateError, emitSuccess } from './toast-controller'
import { applyDroppedJarPaths, resolveInspectableJarPath } from './input-flow-controller'
import { loadWorkbenchState } from './page-controller'
import {
  applyBridgeError,
  clearLogs,
  clearRules,
  replaceRules,
  setAutoScroll,
  setClassTreeRule,
  setInputJarPath,
  setOutputJarPath,
  setPassParam,
  setPasses,
  togglePass,
} from './state'
import {
  browseInputJar,
  browseOutputJar,
  cancelObfuscationRun,
  exportWorkbenchConfig,
  inspectJarClasses,
  importWorkbenchConfig,
  runWindowAction,
  startObfuscationRun,
} from './frontend-controller'
import type { ClassTreeNode, PassItem, PassParamValue, RuleAction, RuleItem, RunState } from './types'
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

export const createWorkbenchHandlers = (options: WorkbenchFacadeOptions) => ({
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
        const result = await loadWorkbenchState(options.state.value, options.bridge)
        options.state.value = result.nextState
        if (result.isWindowMaximised !== null) {
          options.isWindowMaximised.value = result.isWindowMaximised
        }
      }
    } catch (error) {
      options.state.value = applyBridgeError(options.state.value, error, '窗口控制失败')
      emitStateError(options.message, options.state.value, '窗口控制失败')
    }
  },

  handleNativeFileDrop: async (_x: number, _y: number, paths: string[]): Promise<void> => {
    const result = applyDroppedJarPaths(options.state.value, paths)
    options.state.value = result.nextState
    if (result.errorMessage !== null) {
      emitStateError(options.message, result.nextState, '请拖入 .jar 文件')
      return
    }

    emitSuccess(options.message, '已通过拖拽载入 Jar 路径')
  },

  handleInputPathChanged: (inputJarPath: string): void => {
    options.state.value = setInputJarPath(options.state.value, inputJarPath)
  },

  handleOutputChanged: (outputJarPath: string): void => {
    options.state.value = setOutputJarPath(options.state.value, outputJarPath)
  },

  handleBrowseInput: async (): Promise<void> => {
    const result = await browseInputJar(options.state.value, options.bridge)
    options.state.value = result.nextState
    if (result.failed) {
      emitStateError(options.message, options.state.value, '选择输入 Jar 失败')
      return
    }
    if (result.value === null) {
      return
    }

    let inputJarPath: string
    try {
      inputJarPath = resolveInspectableJarPath(options.state.value)
    } catch (error) {
      options.state.value = applyBridgeError(options.state.value, error, '扫描类树失败')
      return
    }

    options.state.value = await inspectJarClasses(options.state.value, options.bridge, inputJarPath)
  },

  handleBrowseOutput: async (): Promise<void> => {
    const result = await browseOutputJar(options.state.value, options.bridge)
    options.state.value = result.nextState
    if (result.failed) {
      emitStateError(options.message, options.state.value, '选择输出 Jar 失败')
    }
  },

  handleImportConfig: async (): Promise<void> => {
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
  },

  handleExportConfig: async (): Promise<void> => {
    const result = await exportWorkbenchConfig(options.state.value, options.bridge)
    options.state.value = result.nextState
    if (result.failed) {
      emitStateError(options.message, options.state.value, '导出配置失败')
      return
    }
    if (result.value === null) {
      return
    }

    emitSuccess(options.message, '配置已导出')
  },

  inspectCurrentJar: async (): Promise<void> => {
    let inputJarPath: string
    try {
      inputJarPath = resolveInspectableJarPath(options.state.value)
    } catch (error) {
      options.state.value = applyBridgeError(options.state.value, error, '扫描类树失败')
      return
    }

    options.state.value = await inspectJarClasses(options.state.value, options.bridge, inputJarPath)
  },

  handlePassesChanged: (passes: readonly PassItem[]): void => {
    options.state.value = setPasses(options.state.value, passes)
  },

  handlePassToggled: (passId: string): void => {
    options.state.value = togglePass(options.state.value, passId)
  },

  handlePassParamChanged: (passId: string, paramKey: string, value: PassParamValue): void => {
    options.state.value = setPassParam(options.state.value, passId, paramKey, value)
  },

  handleAutoScrollChanged: (autoScroll: boolean): void => {
    options.state.value = setAutoScroll(options.state.value, autoScroll)
  },

  handleNodeRuleChanged: (node: ClassTreeNode, action: RuleAction): void => {
    try {
      options.state.value = setClassTreeRule(options.state.value, node, action)
    } catch (error) {
      options.state.value = applyBridgeError(options.state.value, error, '更新类树规则失败')
    }
  },

  handleClearRules: (): void => {
    options.state.value = clearRules(options.state.value)
  },

  handleRulesImported: (rules: readonly RuleItem[]): void => {
    options.state.value = replaceRules(options.state.value, rules)
    emitSuccess(options.message, `已导入 ${rules.length} 条排除规则`)
  },

  handleClearLogs: (): void => {
    options.state.value = clearLogs(options.state.value)
  },

  handleStart: async (): Promise<void> => {
    const result = await startObfuscationRun(options.state.value, options.bridge)
    options.state.value = result.nextState
    if (result.failed) {
      emitStateError(options.message, options.state.value, '启动混淆失败')
      return
    }

    options.activePage.value = 'logs'
  },

  handleCancel: async (): Promise<void> => {
    const result = await cancelObfuscationRun(options.state.value, options.bridge)
    options.state.value = result.nextState
    if (result.failed) {
      emitStateError(options.message, options.state.value, '取消混淆失败')
    }
  },

  loadCapabilities: async (): Promise<void> => {
    const result = await loadWorkbenchState(options.state.value, options.bridge)
    options.state.value = result.nextState
    if (result.isWindowMaximised !== null) {
      options.isWindowMaximised.value = result.isWindowMaximised
    }
  },
})
