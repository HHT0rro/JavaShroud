export interface TerminalLogLine {
  readonly id: string
}

export interface PendingLogSlice<T extends TerminalLogLine> {
  readonly pending: readonly T[]
  readonly nextCursorId: string | null
  readonly replay: boolean
}

export const nextPendingLogs = <T extends TerminalLogLine>(
  logs: readonly T[],
  lastRenderedId: string | null,
): PendingLogSlice<T> => {
  if (logs.length === 0) {
    return { pending: [], nextCursorId: null, replay: lastRenderedId !== null }
  }

  if (lastRenderedId === null) {
    return { pending: logs, nextCursorId: logs[logs.length - 1]?.id ?? null, replay: true }
  }

  const cursorIndex = logs.findIndex((line: T): boolean => line.id === lastRenderedId)
  if (cursorIndex === -1) {
    return { pending: logs, nextCursorId: logs[logs.length - 1]?.id ?? null, replay: true }
  }

  const pending = logs.slice(cursorIndex + 1)
  return {
    pending,
    nextCursorId: pending.length === 0 ? lastRenderedId : pending[pending.length - 1]?.id ?? lastRenderedId,
    replay: false,
  }
}

export const isViewportAtBottom = (viewportY: number, baseY: number): boolean => viewportY >= baseY

export const shouldPauseAutoFollow = (
  autoScroll: boolean,
  ignoringScroll: boolean,
  viewportY: number,
  baseY: number,
): boolean => autoScroll && !ignoringScroll && !isViewportAtBottom(viewportY, baseY)

export const copyTextWithFallback = (
  text: string,
  execCommand: (command: string) => boolean = (command: string): boolean => document.execCommand(command),
): void => {
  const textarea = document.createElement('textarea')
  textarea.value = text
  textarea.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0'
  document.body.appendChild(textarea)
  textarea.select()
  const copied = execCommand('copy')
  textarea.remove()
  if (!copied) {
    throw new Error('copy command failed')
  }
}
