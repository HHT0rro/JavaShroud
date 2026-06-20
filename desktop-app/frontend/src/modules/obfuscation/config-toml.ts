import {
  replaceRules,
  setInputJarPath,
  setOutputJarPath,
  setPasses,
  visiblePassParams,
} from './state.ts'
import type {
  ConfigImportResult,
  ConfigImportWarning,
  ParamSchema,
  PassItem,
  PassParamValue,
  RuleAction,
  RuleItem,
  RunState,
  WorkbenchTomlConfig,
  WorkbenchTomlPassConfig,
  WorkbenchTomlRuleConfig,
} from './types.ts'

interface MutableWorkbenchConfig {
  inputJarPath: string
  outputJarPath: string
  passes: WorkbenchTomlPassConfig[]
  rules: RawRuleItem[]
}

type RawRuleItem = WorkbenchTomlRuleConfig

type TomlScalar = string | number | boolean

const formatName = 'javashroud-workbench'
const formatVersion = 1

export const exportWorkbenchTomlConfig = (state: RunState): string => {
  const lines: string[] = [
    '[meta]',
    `format = ${formatString(formatName)}`,
    `version = ${formatVersion}`,
    '',
    '[input]',
    `inputJarPath = ${formatString(state.inputJar?.inputJarPath ?? '')}`,
    `outputJarPath = ${formatString(state.outputJarPath)}`,
    '',
  ]

  for (const passItem of state.passes) {
    lines.push('[[passes]]')
    lines.push(`id = ${formatString(passItem.id)}`)
    lines.push(`enabled = ${passItem.enabled ? 'true' : 'false'}`)
    lines.push('')
    lines.push('[passes.params]')
    for (const [key, value] of Object.entries(visiblePassParams(passItem))) {
      if (value !== null) {
        lines.push(`${key} = ${formatTomlValue(value)}`)
      }
    }
    lines.push('')
  }

  for (const rule of state.rules) {
    lines.push('[[rules]]')
    lines.push(`target = ${formatString(rule.target)}`)
    lines.push(`action = ${formatString(rule.action)}`)
    lines.push('')
  }

  return `${lines.join('\n').trimEnd()}\n`
}

export const importWorkbenchTomlConfig = (state: RunState, rawToml: string): ConfigImportResult => {
  const parsedConfig = parseWorkbenchTomlConfig(rawToml)
  const warnings: ConfigImportWarning[] = []
  let nextState: RunState = state

  if (parsedConfig.inputJarPath.trim().length > 0) {
    nextState = setInputJarPath(nextState, parsedConfig.inputJarPath)
  }
  if (parsedConfig.outputJarPath.trim().length > 0) {
    nextState = setOutputJarPath(nextState, parsedConfig.outputJarPath)
  }

  nextState = setPasses(nextState, mergeImportedPasses(nextState.passes, parsedConfig.passes, warnings))
  nextState = replaceRules(nextState, sanitizeImportedRules(parsedConfig.rules, warnings))

  return {
    nextState,
    inputJarPath: parsedConfig.inputJarPath.trim().length > 0 ? parsedConfig.inputJarPath : null,
    warnings,
  }
}

export const parseWorkbenchTomlConfig = (rawToml: string): WorkbenchTomlConfig => {
  const parsed: MutableWorkbenchConfig = {
    inputJarPath: '',
    outputJarPath: '',
    passes: [],
    rules: [],
  }
  let section: 'none' | 'meta' | 'input' | 'pass' | 'passParams' | 'rule' = 'none'
  let currentPass: WorkbenchTomlPassConfig | null = null
  let currentRule: RawRuleItem | null = null

  rawToml.split(/\r?\n/).forEach((rawLine: string, index: number): void => {
    const lineNumber = index + 1
    const line = stripComment(rawLine).trim()
    if (line.length === 0) {
      return
    }

    if (line === '[meta]') {
      section = 'meta'
      return
    }
    if (line === '[input]') {
      section = 'input'
      return
    }
    if (line === '[[passes]]') {
      currentPass = { id: '', enabled: true, params: {} }
      parsed.passes.push(currentPass)
      section = 'pass'
      return
    }
    if (line === '[passes.params]') {
      if (currentPass === null) {
        throw new Error(`配置导入失败：第 ${lineNumber} 行 [passes.params] 必须位于 [[passes]] 之后。`)
      }
      section = 'passParams'
      return
    }
    if (line === '[[rules]]') {
      currentRule = { id: `rule-config-${parsed.rules.length}`, target: '', action: 'exclude' }
      parsed.rules.push(currentRule)
      section = 'rule'
      return
    }

    const assignment = parseAssignment(line, lineNumber)
    if (section === 'input') {
      if (assignment.key === 'inputJarPath') {
        parsed.inputJarPath = requireString(assignment.value, assignment.key, lineNumber)
      } else if (assignment.key === 'outputJarPath') {
        parsed.outputJarPath = requireString(assignment.value, assignment.key, lineNumber)
      }
      return
    }

    if (section === 'pass') {
      if (currentPass === null) {
        throw new Error(`配置导入失败：第 ${lineNumber} 行 pass 字段缺少 [[passes]]。`)
      }
      if (assignment.key === 'id') {
        currentPass = replaceLastPass(parsed, { ...currentPass, id: requireString(assignment.value, assignment.key, lineNumber).trim() })
      } else if (assignment.key === 'enabled') {
        currentPass = replaceLastPass(parsed, { ...currentPass, enabled: requireBoolean(assignment.value, assignment.key, lineNumber) })
      }
      return
    }

    if (section === 'passParams') {
      if (currentPass === null) {
        throw new Error(`配置导入失败：第 ${lineNumber} 行 pass 参数缺少 [[passes]]。`)
      }
      currentPass = replaceLastPass(parsed, {
        ...currentPass,
        params: {
          ...currentPass.params,
          [assignment.key]: normalizeScalarValue(assignment.value),
        },
      })
      return
    }

    if (section === 'rule') {
      if (currentRule === null) {
        throw new Error(`配置导入失败：第 ${lineNumber} 行 rule 字段缺少 [[rules]]。`)
      }
      if (assignment.key === 'target') {
        currentRule = replaceLastRule(parsed, { ...currentRule, target: requireString(assignment.value, assignment.key, lineNumber).trim() })
      } else if (assignment.key === 'action') {
        currentRule = replaceLastRule(parsed, { ...currentRule, action: requireString(assignment.value, 'action', lineNumber).trim() })
      }
    }
  })

  return {
    inputJarPath: parsed.inputJarPath,
    outputJarPath: parsed.outputJarPath,
    passes: parsed.passes.filter((passConfig: WorkbenchTomlPassConfig): boolean => passConfig.id.trim().length > 0),
    rules: parsed.rules,
  }
}

const mergeImportedPasses = (
  currentPasses: readonly PassItem[],
  importedPasses: readonly WorkbenchTomlPassConfig[],
  warnings: ConfigImportWarning[],
): readonly PassItem[] => {
  const importedById = new Map<string, WorkbenchTomlPassConfig>()
  for (const importedPass of importedPasses) {
    if (importedById.has(importedPass.id)) {
      warnings.push({ message: `重复 pass 已使用最后一项：${importedPass.id}` })
    }
    importedById.set(importedPass.id, importedPass)
  }

  for (const importedPass of importedPasses) {
    if (!currentPasses.some((passItem: PassItem): boolean => passItem.id === importedPass.id)) {
      warnings.push({ message: `已跳过当前引擎不支持的 pass：${importedPass.id}` })
    }
  }

  return currentPasses.map((passItem: PassItem): PassItem => {
    const importedPass = importedById.get(passItem.id)
    if (importedPass === undefined) {
      return passItem
    }

    return {
      ...passItem,
      enabled: importedPass.enabled,
      params: mergeImportedParams(passItem, importedPass.params, warnings),
    }
  })
}

const mergeImportedParams = (
  passItem: PassItem,
  importedParams: Readonly<Record<string, PassParamValue>>,
  warnings: ConfigImportWarning[],
): Readonly<Record<string, PassParamValue>> => {
  const schemasByKey = new Map<string, ParamSchema>(passItem.paramSchemas.map((schema: ParamSchema): [string, ParamSchema] => [schema.key, schema]))
  const nextParams: Record<string, PassParamValue> = { ...passItem.params }

  for (const [key, value] of Object.entries(importedParams)) {
    const schema = schemasByKey.get(key)
    if (schema === undefined) {
      warnings.push({ message: `已跳过 ${passItem.id} 的未知参数：${key}` })
      continue
    }

    const normalizedValue = coerceParamValue(schema, value)
    if (normalizedValue === undefined) {
      warnings.push({ message: `已跳过 ${passItem.id}.${key} 的非法值：${String(value)}` })
      continue
    }
    nextParams[key] = normalizedValue
  }

  return nextParams
}

const sanitizeImportedRules = (
  rules: readonly RawRuleItem[],
  warnings: ConfigImportWarning[],
): readonly RuleItem[] => rules.flatMap((rule: RawRuleItem, index: number): RuleItem[] => {
  if (rule.target.trim().length === 0) {
    warnings.push({ message: `已跳过 target 为空的规则：rules[${index}]` })
    return []
  }
  if (!isRuleAction(rule.action)) {
    warnings.push({ message: `已跳过 action 非法的规则：${rule.target}` })
    return []
  }
  const action: RuleAction = rule.action
  return [{
    id: rule.id.trim().length > 0 ? rule.id : `rule-config-${index}`,
    target: rule.target,
    action,
  }]
})

const coerceParamValue = (schema: ParamSchema, value: PassParamValue): PassParamValue | undefined => {
  if (value === null) {
    return null
  }
  if (schema.type === 'boolean') {
    return typeof value === 'boolean' ? value : undefined
  }
  if (schema.type === 'string') {
    return typeof value === 'string' ? value : undefined
  }
  if (schema.type === 'number') {
    return typeof value === 'number' && Number.isFinite(value) ? value : undefined
  }
  if (schema.type === 'enum') {
    return typeof value === 'string' && (schema.options ?? []).includes(value) ? value : undefined
  }
  return undefined
}

const replaceLastPass = (parsed: MutableWorkbenchConfig, passConfig: WorkbenchTomlPassConfig): WorkbenchTomlPassConfig => {
  parsed.passes[parsed.passes.length - 1] = passConfig
  return passConfig
}

const replaceLastRule = (parsed: MutableWorkbenchConfig, rule: RawRuleItem): RawRuleItem => {
  parsed.rules[parsed.rules.length - 1] = rule
  return rule
}

const parseAssignment = (line: string, lineNumber: number): { readonly key: string; readonly value: TomlScalar } => {
  const separatorIndex = line.indexOf('=')
  if (separatorIndex <= 0) {
    throw new Error(`配置导入失败：第 ${lineNumber} 行不是有效的 key = value。`)
  }

  const key = line.slice(0, separatorIndex).trim()
  const rawValue = line.slice(separatorIndex + 1).trim()
  if (!/^[A-Za-z][A-Za-z0-9_-]*$/.test(key)) {
    throw new Error(`配置导入失败：第 ${lineNumber} 行 key 非法：${key}`)
  }

  return { key, value: parseTomlValue(rawValue, lineNumber) }
}

const parseTomlValue = (rawValue: string, lineNumber: number): TomlScalar => {
  if (rawValue === 'true') {
    return true
  }
  if (rawValue === 'false') {
    return false
  }
  if (/^-?\d+(?:\.\d+)?$/.test(rawValue)) {
    return Number(rawValue)
  }
  if (rawValue.startsWith('"') && rawValue.endsWith('"')) {
    return parseString(rawValue, lineNumber)
  }
  throw new Error(`配置导入失败：第 ${lineNumber} 行 value 只支持字符串、数字或布尔值。`)
}

const parseString = (rawValue: string, lineNumber: number): string => {
  try {
    return JSON.parse(rawValue) as string
  } catch (error) {
    throw new Error(`配置导入失败：第 ${lineNumber} 行字符串解析失败：${error instanceof Error ? error.message : String(error)}`)
  }
}

const stripComment = (line: string): string => {
  let inString = false
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
    if (char === '"') {
      inString = !inString
      continue
    }
    if (char === '#' && !inString) {
      return line.slice(0, index)
    }
  }
  return line
}

const requireString = (value: TomlScalar, key: string, lineNumber: number): string => {
  if (typeof value !== 'string') {
    throw new Error(`配置导入失败：第 ${lineNumber} 行 ${key} 必须是字符串。`)
  }
  return value
}

const requireBoolean = (value: TomlScalar, key: string, lineNumber: number): boolean => {
  if (typeof value !== 'boolean') {
    throw new Error(`配置导入失败：第 ${lineNumber} 行 ${key} 必须是布尔值。`)
  }
  return value
}

const isRuleAction = (action: string): action is RuleAction => action === 'exclude' || action === 'obfuscate'

const normalizeScalarValue = (value: TomlScalar): PassParamValue => value

const formatTomlValue = (value: PassParamValue): string => {
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false'
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) ? String(value) : '0'
  }
  return formatString(value ?? '')
}

const formatString = (value: string): string => JSON.stringify(value)
