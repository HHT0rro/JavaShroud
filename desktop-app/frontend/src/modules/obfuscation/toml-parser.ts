type TomlValue = string | number | boolean | readonly TomlValue[] | TomlRecord

interface TomlRecord {
  [key: string]: TomlValue
}

export const parseTomlDocument = (rawToml: string): TomlRecord => {
  const root: TomlRecord = {}
  let currentTarget: TomlRecord = root

  rawToml.split(/\r?\n/).forEach((rawLine: string, index: number): void => {
    const lineNumber = index + 1
    const line = stripComment(rawLine).trim()
    if (line.length === 0) {
      return
    }

    if (line.startsWith('[' + '[') && line.endsWith(']' + ']')) {
      currentTarget = openArrayTable(root, line.slice(2, -2).trim(), lineNumber)
      return
    }
    if (line.startsWith('[') && line.endsWith(']')) {
      currentTarget = openTable(root, line.slice(1, -1).trim(), lineNumber)
      return
    }

    const assignment = parseAssignment(line, lineNumber)
    currentTarget[assignment.key] = assignment.value
  })

  return root
}

const openTable = (root: TomlRecord, path: string, lineNumber: number): TomlRecord => {
  const parts = parsePath(path, lineNumber)
  let target: TomlRecord = root
  for (const part of parts) {
    const existing = target[part]
    if (existing === undefined) {
    const next: Record<string, TomlValue> = {}
      target[part] = next
      target = next
      continue
    }
    if (Array.isArray(existing)) {
      const last = existing[existing.length - 1]
      if (isRecord(last)) {
        target = last
        continue
      }
    }
    if (!isRecord(existing)) {
      throw new Error(`TOML 解析失败：第 ${lineNumber} 行 table 路径不是对象：${path}`)
    }
    target = existing
  }
  return target
}

const openArrayTable = (root: TomlRecord, path: string, lineNumber: number): TomlRecord => {
  const parts = parsePath(path, lineNumber)
  const tableName = parts[parts.length - 1]
  const parent = parts.length === 1 ? root : openTable(root, parts.slice(0, -1).join('.'), lineNumber)
  const existing = parent[tableName]
  if (existing !== undefined && !Array.isArray(existing)) {
    throw new Error(`TOML 解析失败：第 ${lineNumber} 行 array table 路径不是数组：${path}`)
  }
  const array = (existing ?? []) as TomlValue[]
  const next: Record<string, TomlValue> = {}
  array.push(next)
  parent[tableName] = array
  return next
}

const parsePath = (path: string, lineNumber: number): readonly string[] => {
  const parts = path.split('.').map((part: string): string => part.trim()).filter(Boolean)
  if (parts.length === 0 || parts.some((part: string): boolean => !isBareKey(part))) {
    throw new Error(`TOML 解析失败：第 ${lineNumber} 行 table 路径非法：${path}`)
  }
  return parts
}

const parseAssignment = (line: string, lineNumber: number): { readonly key: string; readonly value: TomlValue } => {
  const separatorIndex = line.indexOf('=')
  if (separatorIndex <= 0) {
    throw new Error(`TOML 解析失败：第 ${lineNumber} 行不是 key = value。`)
  }
  const key = line.slice(0, separatorIndex).trim()
  if (!isBareKey(key)) {
    throw new Error(`TOML 解析失败：第 ${lineNumber} 行 key 非法：${key}`)
  }
  return { key, value: parseTomlValue(line.slice(separatorIndex + 1).trim(), lineNumber) }
}

const parseTomlValue = (rawValue: string, lineNumber: number): TomlValue => {
  if (rawValue === 'true') return true
  if (rawValue === 'false') return false
  if (/^-?\d+(?:\.\d+)?$/.test(rawValue)) return Number(rawValue)
  if (rawValue.startsWith('"') && rawValue.endsWith('"')) return parseString(rawValue, lineNumber)
  if (rawValue.startsWith("'") && rawValue.endsWith("'")) return rawValue.slice(1, -1)
  if (rawValue.startsWith('[') && rawValue.endsWith(']')) return splitTopLevel(rawValue.slice(1, -1)).filter(Boolean).map((item: string): TomlValue => parseTomlValue(item.trim(), lineNumber))
  if (rawValue.startsWith('{') && rawValue.endsWith('}')) return parseInlineTable(rawValue.slice(1, -1), lineNumber)
  throw new Error(`TOML 解析失败：第 ${lineNumber} 行 value 不受支持：${rawValue}`)
}

const parseInlineTable = (body: string, lineNumber: number): TomlRecord => {
  const record: Record<string, TomlValue> = {}
  for (const item of splitTopLevel(body)) {
    const trimmed = item.trim()
    if (trimmed.length === 0) continue
    const assignment = parseAssignment(trimmed, lineNumber)
    record[assignment.key] = assignment.value
  }
  return record
}

const parseString = (rawValue: string, lineNumber: number): string => {
  try {
    return JSON.parse(rawValue) as string
  } catch (error) {
    throw new Error(`TOML 解析失败：第 ${lineNumber} 行字符串解析失败：${error instanceof Error ? error.message : String(error)}`)
  }
}

const splitTopLevel = (body: string): readonly string[] => {
  const result: string[] = []
  let start = 0
  let depth = 0
  let quoteChar: string | null = null
  let escaped = false
  for (let index = 0; index < body.length; index += 1) {
    const char = body[index]
    if (escaped) {
      escaped = false
      continue
    }
    if (char === '\\') {
      escaped = true
      continue
    }
    if ((char === '"' || char === "'") && (quoteChar === null || quoteChar === char)) {
      quoteChar = quoteChar === null ? char : null
      continue
    }
    if (quoteChar === null && (char === '[' || char === '{')) depth += 1
    if (quoteChar === null && (char === ']' || char === '}')) depth -= 1
    if (char === ',' && quoteChar === null && depth === 0) {
      result.push(body.slice(start, index))
      start = index + 1
    }
  }
  result.push(body.slice(start))
  return result
}

const stripComment = (line: string): string => {
  let quoteChar: string | null = null
  let escaped = false
  for (let index = 0; index < line.length; index += 1) {
    const char = line[index]
    if (escaped) {
      escaped = false
      continue
    }
    if (char === '\\') {
      escaped = true
      continue
    }
    if ((char === '"' || char === "'") && (quoteChar === null || quoteChar === char)) {
      quoteChar = quoteChar === null ? char : null
      continue
    }
    if (char === '#' && quoteChar === null) {
      return line.slice(0, index)
    }
  }
  return line
}

const isBareKey = (key: string): boolean => /^[A-Za-z][A-Za-z0-9_-]*$/.test(key)

const isRecord = (value: TomlValue): value is TomlRecord => typeof value === 'object' && value !== null && !Array.isArray(value)
