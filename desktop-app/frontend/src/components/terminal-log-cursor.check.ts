import {
  copyTextWithFallback,
  isViewportAtBottom,
  nextPendingLogs,
  shouldPauseAutoFollow,
} from './terminal-log-cursor.ts'

const assert = (condition: boolean, message: string): void => {
  if (!condition) {
    throw new Error(message)
  }
}

const line = (id: string) => ({ id })

assert(nextPendingLogs([], null).pending.length === 0, 'empty logs yield no pending')
assert(nextPendingLogs([], 'x').replay === true, 'missing buffer with stale cursor is replay')

const first = nextPendingLogs([line('a'), line('b')], null)
assert(first.replay === true && first.pending.map((item) => item.id).join(',') === 'a,b', 'null cursor replays all')
assert(first.nextCursorId === 'b', 'null cursor advances to last id')

const append = nextPendingLogs([line('a'), line('b'), line('c')], 'b')
assert(append.replay === false && append.pending.map((item) => item.id).join(',') === 'c', 'append after cursor')
assert(append.nextCursorId === 'c', 'append cursor becomes last pending')

const capped = Array.from({ length: 500 }, (_: unknown, index: number) => line(`id-${index + 50}`))
const afterCap = nextPendingLogs(capped, 'id-49')
assert(afterCap.replay === true && afterCap.pending.length === 500, 'evicted cursor replays window')
assert(afterCap.nextCursorId === 'id-549', 'replay cursor is last remaining id')

const stillPresent = nextPendingLogs(capped, 'id-500')
assert(stillPresent.replay === false && stillPresent.pending[0]?.id === 'id-501', 'present cursor continues after cap')
assert(stillPresent.pending.length === 49, 'pending count after mid-window cursor')

assert(isViewportAtBottom(10, 10) === true, 'viewportY >= baseY is bottom')
assert(isViewportAtBottom(9, 10) === false, 'viewportY < baseY is not bottom')
assert(shouldPauseAutoFollow(true, false, 9, 10) === true, 'scroll up pauses follow')
assert(shouldPauseAutoFollow(true, true, 9, 10) === false, 'programmatic scroll does not pause')
assert(shouldPauseAutoFollow(false, false, 9, 10) === false, 'follow already off')
assert(shouldPauseAutoFollow(true, false, 12, 10) === false, 'at bottom keeps follow')

const created: { removed: boolean } = { removed: false }
const fakeDocument = {
  createElement: (): { value: string; style: { cssText: string }; select: () => void; remove: () => void } => ({
    value: '',
    style: { cssText: '' },
    select: (): void => undefined,
    remove: (): void => {
      created.removed = true
    },
  }),
  body: { appendChild: (): void => undefined },
} as unknown as Document
;(globalThis as { document: Document }).document = fakeDocument

let execCalls = 0
copyTextWithFallback('ok', (): boolean => {
  execCalls += 1
  return true
})
assert(execCalls === 1, 'successful execCommand is used')

let threw = false
try {
  copyTextWithFallback('fail', (): boolean => false)
} catch {
  threw = true
}
assert(threw, 'failed execCommand must throw')
assert(created.removed, 'textarea is removed after copy')

console.log('terminal-log-cursor checks passed')
