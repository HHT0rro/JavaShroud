import { parseTomlDocument } from './toml-parser.ts'
import type { EngineEvent, EngineEventLevel, EngineEventType } from './types'

interface EngineEventShape {
  readonly level?: unknown
  readonly type?: unknown
  readonly message?: unknown
  readonly progress?: unknown
  readonly outPath?: unknown
}

const eventTypes: readonly EngineEventType[] = ['progress', 'log', 'warn', 'error', 'done', 'canceled']
const eventLevels: readonly EngineEventLevel[] = ['info', 'warn', 'error', 'success']

export const parseEngineEvent = (rawEvent: unknown): EngineEvent => {
  const payload: unknown = unwrapTomlEvent(typeof rawEvent === 'string' ? parseSerializedEvent(rawEvent) : rawEvent)

  if (!isRecord(payload)) {
    throw new Error(`engine:event 解析失败：事件不是对象，payload=${JSON.stringify(rawEvent)}`)
  }

  const shape: EngineEventShape = payload
  const type: EngineEventType = parseEventType(shape.type, rawEvent)
  const level: EngineEventLevel = parseEventLevel(shape.level, type)
  const message: string = parseMessage(shape.message, rawEvent)
  const progress: number | null = parseProgress(shape.progress, rawEvent)
  const outPath: string | null = parseNullableString(shape.outPath, 'outPath', rawEvent)

  return {
    level,
    type,
    message,
    progress,
    outPath,
  }
}

const unwrapTomlEvent = (payload: unknown): unknown => {
  if (isRecord(payload) && isRecord(payload.event)) {
    return payload.event
  }
  return payload
}

const parseSerializedEvent = (rawEvent: string): unknown => {
  try {
    if (rawEvent.trimStart().startsWith('{')) {
      return JSON.parse(rawEvent)
    }
    return parseTomlDocument(rawEvent)
  } catch (error) {
    const message: string = error instanceof Error ? error.message : String(error)
    throw new Error(`engine:event 解析失败：${message}，payload=${rawEvent}`)
  }
}

const parseEventType = (value: unknown, rawEvent: unknown): EngineEventType => {
  if (typeof value === 'string' && eventTypes.includes(value as EngineEventType)) {
    return value as EngineEventType
  }

  throw new Error(`engine:event type 无效：type=${String(value)}，payload=${JSON.stringify(rawEvent)}`)
}

const parseEventLevel = (value: unknown, eventType: EngineEventType): EngineEventLevel => {
  if (typeof value === 'string' && eventLevels.includes(value as EngineEventLevel)) {
    return value as EngineEventLevel
  }

  if (eventType === 'warn' || eventType === 'canceled') {
    return 'warn'
  }

  if (eventType === 'error') {
    return 'error'
  }

  if (eventType === 'done') {
    return 'success'
  }

  return 'info'
}

const parseMessage = (value: unknown, rawEvent: unknown): string => {
  if (typeof value === 'string' && value.trim().length > 0) {
    return value
  }

  throw new Error(`engine:event message 无效：message=${String(value)}，payload=${JSON.stringify(rawEvent)}`)
}

const parseProgress = (value: unknown, rawEvent: unknown): number | null => {
  if (value === undefined || value === null) {
    return null
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    if (value < 0 || value > 100) {
      throw new Error(`engine:event progress 超出范围：progress=${String(value)}，payload=${JSON.stringify(rawEvent)}`)
    }
    return value
  }

  throw new Error(`engine:event progress 无效：progress=${String(value)}，payload=${JSON.stringify(rawEvent)}`)
}

const parseNullableString = (value: unknown, fieldName: string, rawEvent: unknown): string | null => {
  if (value === undefined || value === null) {
    return null
  }

  if (typeof value === 'string') {
    return value
  }

  throw new Error(`engine:event ${fieldName} 无效：${fieldName}=${String(value)}，payload=${JSON.stringify(rawEvent)}`)
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value)
