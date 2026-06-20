import {
  applyBridgeError,
  buildLoadedJarInfoFromPath,
  setLoadedJar,
} from './state'
import type { RunState } from './types'

interface PathSelectionResult {
  readonly nextState: RunState
  readonly inputJarPath: string | null
  readonly errorMessage: string | null
}

export const applyDroppedJarPath = (state: RunState, inputJarPath: string): PathSelectionResult => {
  if (!isAbsoluteJarPath(inputJarPath)) {
    const nextState: RunState = applyBridgeError(state, new Error('仅支持 .jar 文件的绝对路径。'), '输入校验失败')
    return {
      nextState,
      inputJarPath: null,
      errorMessage: '请拖入 .jar 文件',
    }
  }

  return {
    nextState: setLoadedJar(state, buildLoadedJarInfoFromPath(inputJarPath)),
    inputJarPath,
    errorMessage: null,
  }
}

export const applyDroppedJarPaths = (state: RunState, paths: readonly string[]): PathSelectionResult => {
  const inputJarPath: string | undefined = paths.find((pathValue: string): boolean => isAbsoluteJarPath(pathValue))
  if (inputJarPath === undefined) {
    const nextState: RunState = applyBridgeError(state, new Error('拖拽内容未包含可用的 .jar 绝对路径。'), '输入校验失败')
    return {
      nextState,
      inputJarPath: null,
      errorMessage: '请拖入 .jar 文件',
    }
  }

  return applyDroppedJarPath(state, inputJarPath)
}

export const resolveInspectableJarPath = (state: RunState): string => {
  const inputJarPath: string | undefined = state.inputJar?.inputJarPath
  if (inputJarPath === undefined || inputJarPath.trim().length === 0) {
    throw new Error('输入 Jar 路径为空。')
  }
  if (!isAbsoluteJarPath(inputJarPath)) {
    throw new Error('输入 Jar 必须是 .jar 文件的绝对路径。')
  }

  return inputJarPath
}

export const isAbsoluteJarPath = (inputJarPath: string): boolean => {
  const trimmedPath: string = inputJarPath.trim()
  if (!trimmedPath.toLowerCase().endsWith('.jar')) {
    return false
  }

  return /^[A-Za-z]:(?:\\|\/)/.test(trimmedPath) || trimmedPath.startsWith('\\') || trimmedPath.startsWith('/')
}
