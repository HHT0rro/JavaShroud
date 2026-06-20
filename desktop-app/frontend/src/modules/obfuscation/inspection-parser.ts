import { parseTomlDocument } from './toml-parser.ts'
import type { ClassTreeNode, JarInspectionPayload } from './types'

interface JarInspectionShape {
  readonly jarPath?: unknown
  readonly classCount?: unknown
  readonly packageCount?: unknown
  readonly nodes?: unknown
}

interface ClassTreeNodeShape {
  readonly id?: unknown
  readonly label?: unknown
  readonly qualifiedName?: unknown
  readonly internalName?: unknown
  readonly kind?: unknown
  readonly children?: unknown
}

export const parseJarInspectionPayload = (rawPayload: unknown): JarInspectionPayload => {
  const payload: unknown = typeof rawPayload === 'string' ? parseSerializedInspectionPayload(rawPayload) : rawPayload

  if (!isRecord(payload)) {
    throw new Error(`Jar 类树解析失败：payload 不是对象，summary=${payloadSummary(rawPayload)}`)
  }

  const shape: JarInspectionShape = payload
  return {
    jarPath: parseRequiredText(shape.jarPath, 'jarPath', rawPayload),
    classCount: parseNonNegativeInteger(shape.classCount, 'classCount', rawPayload),
    packageCount: parseNonNegativeInteger(shape.packageCount, 'packageCount', rawPayload),
    nodes: parseClassTreeNodes(shape.nodes, 'nodes', rawPayload),
  }
}

const parseSerializedInspectionPayload = (rawPayload: string): unknown => {
  try {
    if (rawPayload.trimStart().startsWith('{')) {
      return JSON.parse(rawPayload)
    }
    return parseTomlDocument(rawPayload)
  } catch (error) {
    const message: string = error instanceof Error ? error.message : String(error)
    throw new Error(`Jar 类树解析失败：${message}，summary=${payloadSummary(rawPayload)}`)
  }
}

const parseClassTreeNodes = (value: unknown, fieldPath: string, rawPayload: unknown): readonly ClassTreeNode[] => {
  if (!Array.isArray(value)) {
    throw new Error(`Jar 类树解析失败：${fieldPath} 必须是数组，summary=${payloadSummary(rawPayload)}`)
  }

  return value.map((item: unknown, index: number): ClassTreeNode => parseClassTreeNode(item, `${fieldPath}[${index}]`, rawPayload))
}

const parseClassTreeNode = (value: unknown, fieldPath: string, rawPayload: unknown): ClassTreeNode => {
  if (!isRecord(value)) {
    throw new Error(`Jar 类树解析失败：${fieldPath} 必须是对象，summary=${payloadSummary(rawPayload)}`)
  }

  const shape: ClassTreeNodeShape = value
  const kind: ClassTreeNode['kind'] = parseNodeKind(shape.kind, fieldPath, rawPayload)
  return {
    id: parseRequiredText(shape.id, `${fieldPath}.id`, rawPayload),
    label: parseRequiredText(shape.label, `${fieldPath}.label`, rawPayload),
    qualifiedName: parseRequiredText(shape.qualifiedName, `${fieldPath}.qualifiedName`, rawPayload),
    internalName: parseOptionalText(shape.internalName, `${fieldPath}.internalName`, rawPayload),
    kind,
    children: parseClassTreeNodes(shape.children, `${fieldPath}.children`, rawPayload),
  }
}

const parseNodeKind = (value: unknown, fieldPath: string, rawPayload: unknown): ClassTreeNode['kind'] => {
  if (value === 'package' || value === 'class' || value === 'field' || value === 'method') {
    return value
  }

  throw new Error(`Jar 类树解析失败：${fieldPath}.kind 无效，kind=${String(value)}，summary=${payloadSummary(rawPayload)}`)
}

const parseOptionalText = (value: unknown, fieldPath: string, rawPayload: unknown): string => {
  if (typeof value === "string") {
    return value
  }

  throw new Error(`Jar 类树解析失败：${fieldPath} 必须是字符串，summary=${payloadSummary(rawPayload)}`)
}

const parseRequiredText = (value: unknown, fieldPath: string, rawPayload: unknown): string => {
  if (typeof value === 'string' && value.trim().length > 0) {
    return value
  }

  throw new Error(`Jar 类树解析失败：${fieldPath} 必须是非空字符串，summary=${payloadSummary(rawPayload)}`)
}

const parseNonNegativeInteger = (value: unknown, fieldPath: string, rawPayload: unknown): number => {
  if (typeof value === 'number' && Number.isInteger(value) && value >= 0) {
    return value
  }

  throw new Error(`Jar 类树解析失败：${fieldPath} 必须是非负整数，summary=${payloadSummary(rawPayload)}`)
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value)

const payloadSummary = (rawPayload: unknown): string => {
  const text = typeof rawPayload === 'string' ? rawPayload : JSON.stringify(rawPayload)
  if (text === undefined) {
    return 'payload=<unserializable>'
  }

  const compact = text.replace(/\s+/g, ' ').trim()
  if (compact.length <= 240) {
    return compact
  }

  return `${compact.slice(0, 240)}...`
}
