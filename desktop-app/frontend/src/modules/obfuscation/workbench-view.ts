import { buildObfuscationRequest } from './state'
import type { RunState, RunStatus } from './types'
import type { DisplayLanguage } from './pass-localization'

export type WorkbenchPage = 'home' | 'passes' | 'classes' | 'logs' | 'about'
export type RunOutcome = 'done' | 'failed' | 'canceled'
export interface ReadinessIssue {
  readonly message: string
  readonly page: WorkbenchPage
}

export const runIsBusy = (status: RunStatus): boolean => status === 'running' || status === 'canceling'

export const runStatusLabel = (status: RunStatus, language: DisplayLanguage, outcome: RunOutcome | null = null): string => {
  const zh = language === 'zh'
  if (status === 'ready' && outcome === 'canceled') return zh ? '已取消' : 'Canceled'
  const labels: Record<RunStatus, readonly [string, string]> = {
    idle: ['等待输入', 'Awaiting input'],
    ready: ['待运行', 'Ready'],
    running: ['运行中', 'Running'],
    canceling: ['正在取消', 'Canceling'],
    done: ['已完成', 'Completed'],
    failed: ['发生错误', 'Failed'],
  }
  return labels[status][zh ? 0 : 1]
}

export const getReadinessIssue = (state: RunState, language: DisplayLanguage): ReadinessIssue | null => {
  const zh = language === 'zh'
  if (state.schema === null) return { message: zh ? '等待引擎能力加载完成' : 'Waiting for engine capabilities', page: 'home' }
  if (!state.inputJar?.inputJarPath.trim()) return { message: zh ? '选择一个输入 JAR 文件' : 'Choose an input JAR', page: 'home' }
  if (!state.outputJarPath.trim()) return { message: zh ? '设置输出 JAR 路径' : 'Set the output JAR path', page: 'home' }
  if (!state.passes.some((pass) => pass.enabled)) return { message: zh ? '至少启用一个混淆模块' : 'Enable at least one module', page: 'passes' }
  try {
    buildObfuscationRequest(state)
    return null
  } catch (error) {
    return { message: error instanceof Error ? error.message : String(error), page: 'passes' }
  }
}
