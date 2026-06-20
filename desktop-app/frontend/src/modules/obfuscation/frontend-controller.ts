import { parseEngineSchema } from './capability-parser'
import { exportWorkbenchTomlConfig, importWorkbenchTomlConfig } from './config-toml'
import { parseEngineEvent } from './event-parser'
import { parseJarInspectionPayload } from './inspection-parser'
import {
  applyBridgeError,
  applyEngineEvent,
  buildLoadedJarInfoFromPath,
  buildObfuscationRequest,
  markCanceling,
  markInspectingClasses,
  markRunStarting,
  setEngineSchema,
  setInspectingClassesFailed,
  setJarInspection,
  setLoadedJar,
  setOutputJarPath,
} from './state'
import type { RunState } from './types'
import type { WailsBridge } from './wails-bridge'

interface ControllerResult<T> {
  readonly nextState: RunState
  readonly value: T | null
  readonly failed: boolean
}

interface ConfigImportControllerResult extends ControllerResult<readonly string[]> {
  readonly warningMessages: readonly string[]
}

export const applyEnginePayload = (state: RunState, payload: unknown): RunState => {
  try {
    return applyEngineEvent(state, parseEngineEvent(payload))
  } catch (error) {
    return applyBridgeError(state, error, '处理引擎事件失败')
  }
}

export const loadEngineCapabilities = async (state: RunState, bridge: WailsBridge): Promise<RunState> => {
  try {
    const rawCapabilities: string = await bridge.getEngineCapabilities()
    return setEngineSchema(state, parseEngineSchema(rawCapabilities))
  } catch (error) {
    return applyBridgeError(state, error, '加载引擎能力失败')
  }
}

export const inspectJarClasses = async (
  state: RunState,
  bridge: WailsBridge,
  inputJarPath: string,
): Promise<RunState> => {
  try {
    const inspectingState: RunState = markInspectingClasses(state)
    const rawPayload: string = await bridge.inspectJarClasses(inputJarPath)
    return setJarInspection(inspectingState, parseJarInspectionPayload(rawPayload))
  } catch (error) {
    return setInspectingClassesFailed(applyBridgeError(state, error, '扫描类树失败'))
  }
}

export const browseInputJar = async (state: RunState, bridge: WailsBridge): Promise<ControllerResult<string | null>> => {
  try {
    const inputJarPath: string = await bridge.selectInputJar()
    if (inputJarPath.trim().length === 0) {
      return successResult(state, null)
    }

    return successResult(setLoadedJar(state, buildLoadedJarInfoFromPath(inputJarPath)), inputJarPath)
  } catch (error) {
    return failureResult(state, error, '选择输入 Jar 失败')
  }
}

export const browseOutputJar = async (state: RunState, bridge: WailsBridge): Promise<ControllerResult<string | null>> => {
  try {
    const defaultInputJarPath: string = state.inputJar?.inputJarPath ?? ''
    const outputJarPath: string = await bridge.selectOutputJar(defaultInputJarPath)
    if (outputJarPath.trim().length === 0) {
      return successResult(state, null)
    }

    return successResult(setOutputJarPath(state, outputJarPath), outputJarPath)
  } catch (error) {
    return failureResult(state, error, '选择输出 Jar 失败')
  }
}

export const importWorkbenchConfig = async (state: RunState, bridge: WailsBridge): Promise<ConfigImportControllerResult> => {
  try {
    const configPath: string = await bridge.selectImportConfig()
    if (configPath.trim().length === 0) {
      return configSuccessResult(state, null, [])
    }

    const rawToml: string = await bridge.readTextFile(configPath)
    const importResult = importWorkbenchTomlConfig(state, rawToml)
    let nextState: RunState = importResult.nextState
    if (importResult.inputJarPath !== null) {
      nextState = await inspectJarClasses(nextState, bridge, importResult.inputJarPath)
    }

    return configSuccessResult(nextState, importResult.warnings.map((warning) => warning.message), importResult.warnings.map((warning) => warning.message))
  } catch (error) {
    return configFailureResult(state, error, '导入配置失败')
  }
}

export const exportWorkbenchConfig = async (state: RunState, bridge: WailsBridge): Promise<ControllerResult<string | null>> => {
  try {
    const configPath: string = await bridge.selectExportConfig()
    if (configPath.trim().length === 0) {
      return successResult(state, null)
    }

    await bridge.writeTextFile(configPath, exportWorkbenchTomlConfig(state))
    return successResult(state, configPath)
  } catch (error) {
    return failureResult(state, error, '导出配置失败')
  }
}

export const startObfuscationRun = async (state: RunState, bridge: WailsBridge): Promise<ControllerResult<boolean>> => {
  let requestState: RunState = state
  try {
    const request = buildObfuscationRequest(state)
    requestState = markRunStarting(state)
    await bridge.startObfuscation(request)
    return successResult(requestState, true)
  } catch (error) {
    return failureResult(requestState, error, '启动混淆失败')
  }
}

export const cancelObfuscationRun = async (state: RunState, bridge: WailsBridge): Promise<ControllerResult<boolean>> => {
  const cancelingState: RunState = markCanceling(state)
  try {
    await bridge.cancelObfuscation()
    return successResult(cancelingState, true)
  } catch (error) {
    return failureResult(cancelingState, error, '取消混淆失败')
  }
}

export const loadWindowMaximiseState = async (bridge: WailsBridge): Promise<boolean> => {
  return bridge.windowIsMaximised()
}

export const runWindowAction = async (
  bridge: WailsBridge,
  actionId: 'minimise' | 'toggle-maximise' | 'quit',
): Promise<void> => {
  if (actionId === 'minimise') {
    await bridge.windowMinimise()
    return
  }

  if (actionId === 'toggle-maximise') {
    await bridge.windowToggleMaximise()
    return
  }

  await bridge.quit()
}

const successResult = <T>(nextState: RunState, value: T | null): ControllerResult<T> => ({
  nextState,
  value,
  failed: false,
})

const configSuccessResult = (nextState: RunState, value: readonly string[] | null, warningMessages: readonly string[]): ConfigImportControllerResult => ({
  nextState,
  value,
  failed: false,
  warningMessages,
})

const failureResult = <T>(state: RunState, error: unknown, context: string): ControllerResult<T> => ({
  nextState: applyBridgeError(state, error, context),
  value: null,
  failed: true,
})

const configFailureResult = (state: RunState, error: unknown, context: string): ConfigImportControllerResult => ({
  nextState: applyBridgeError(state, error, context),
  value: null,
  failed: true,
  warningMessages: [],
})
