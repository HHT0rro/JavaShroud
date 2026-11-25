import { parseEngineEvent } from './event-parser.ts'

const assert = (condition: boolean, message: string): void => {
  if (!condition) {
    throw new Error(message)
  }
}

const expectParseError = (payload: unknown, expectedMessagePart: string): void => {
  try {
    parseEngineEvent(payload)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    assert(message.includes(expectedMessagePart), `expected parse error to include "${expectedMessagePart}", actual=${message}`)
    return
  }

  throw new Error(`expected engine event parse to fail with "${expectedMessagePart}"`)
}

const parsedProgressEvent = parseEngineEvent({
  type: 'progress',
  level: 'info',
  message: 'running',
  progress: 50,
  outPath: null,
})
assert(parsedProgressEvent.progress === 50, 'expected valid progress to be preserved')

const parsedNeedPackEvent = parseEngineEvent({
  type: 'need-pack',
  level: 'info',
  message: 'awaiting packed native',
  progress: 94,
  outPath: 'C:\\tmp\\qp_ffi.dll',
})
assert(parsedNeedPackEvent.type === 'need-pack', 'expected need-pack type')
assert(parsedNeedPackEvent.outPath === 'C:\\tmp\\qp_ffi.dll', 'expected need-pack outPath')
assert(parsedNeedPackEvent.progress === 94, 'expected need-pack progress')

expectParseError(
  {
    type: 'progress',
    level: 'info',
    message: 'bad progress',
    progress: -1,
    outPath: null,
  },
  'progress 超出范围',
)

expectParseError(
  {
    type: 'progress',
    level: 'info',
    message: 'bad progress',
    progress: 101,
    outPath: null,
  },
  'progress 超出范围',
)

console.log('event-parser checks passed')
