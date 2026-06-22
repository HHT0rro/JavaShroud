import { parseTomlDocument } from './toml-parser.ts'
import type { EngineSchemaPayload, ModuleDefinition, ModuleTagDefinition, OrderingConstraint, ParamSchema, PassCompatibilityRule } from './types'

interface EngineSchemaShape {
  readonly schemaVersion?: unknown
  readonly engineVersion?: unknown
  readonly vbcVersion?: unknown
  readonly tags?: unknown
  readonly modules?: unknown
  readonly compatibility?: unknown
  readonly orderingConstraints?: unknown
  readonly defaultPipeline?: unknown
}

interface ModuleTagShape {
  readonly id?: unknown
  readonly name?: unknown
  readonly description?: unknown
}

interface ModuleDefinitionShape {
  readonly id?: unknown
  readonly name?: unknown
  readonly description?: unknown
  readonly tagIds?: unknown
  readonly stability?: unknown
  readonly risk?: unknown
  readonly requiresRuntimeFlags?: unknown
  readonly platformConstraints?: unknown
  readonly compatibilityNotes?: unknown
  readonly requiredPassIds?: unknown
  readonly requiresAnyPassIds?: unknown
  readonly defaultEnabled?: unknown
  readonly requiresOptIn?: unknown
  readonly params?: unknown
}

interface ParamSchemaShape {
  readonly key?: unknown
  readonly type?: unknown
  readonly defaultValue?: unknown
  readonly options?: unknown
  readonly description?: unknown
  readonly hidden?: unknown
}

interface PassCompatibilityRuleShape {
  readonly passIds?: unknown
  readonly severity?: unknown
  readonly description?: unknown
}

interface OrderingConstraintShape {
  readonly before?: unknown
  readonly after?: unknown
  readonly reason?: unknown
  readonly hard?: unknown
}

const compatibilitySeverities = ['hard', 'soft'] as const
const passRisks = ['low', 'medium', 'high'] as const
const paramTypes = ['boolean', 'string', 'enum', 'number'] as const
const supportedSchemaVersion = '2'

export const parseEngineSchema = (rawSchema: unknown): EngineSchemaPayload => {
  const payload: unknown = typeof rawSchema === 'string' ? parseSerializedSchema(rawSchema) : rawSchema

  if (!isRecord(payload)) {
    throw new Error(`引擎 schema 解析失败：payload 不是对象，payload=${JSON.stringify(rawSchema)}`)
  }

  const shape: EngineSchemaShape = payload
  const tags: readonly ModuleTagDefinition[] = parseTags(shape.tags, rawSchema)
  const tagIds: ReadonlySet<string> = new Set<string>(tags.map((tag: ModuleTagDefinition): string => tag.id))
  const modules: readonly ModuleDefinition[] = parseModules(shape.modules, tagIds, rawSchema)
  const moduleIds: ReadonlySet<string> = new Set<string>(modules.map((moduleDefinition: ModuleDefinition): string => moduleDefinition.id))
  validateModuleRequiredPassIds(modules, moduleIds, rawSchema)
  validateModuleRequiresAnyPassIds(modules, moduleIds, rawSchema)
  const schemaVersion: string = parseSupportedSchemaVersion(shape.schemaVersion, rawSchema)

  return {
    schemaVersion,
    engineVersion: parseRequiredText(shape.engineVersion, 'engineVersion', rawSchema),
    vbcVersion: parseRequiredText(shape.vbcVersion, 'vbcVersion', rawSchema),
    tags,
    modules,
    compatibility: parseCompatibilityRules(shape.compatibility, moduleIds, rawSchema),
    orderingConstraints: parseOrderingConstraints(shape.orderingConstraints, moduleIds, rawSchema),
    defaultPipeline: parseDefaultPipeline(shape.defaultPipeline, moduleIds, rawSchema),
  }
}

const parseSerializedSchema = (rawSchema: string): unknown => {
  try {
    if (rawSchema.trimStart().startsWith('{')) {
      return JSON.parse(rawSchema)
    }
    return parseTomlDocument(rawSchema)
  } catch (error) {
    const message: string = error instanceof Error ? error.message : String(error)
    throw new Error(`引擎 schema 解析失败：${message}，payload=${rawSchema}`)
  }
}

const parseSupportedSchemaVersion = (value: unknown, rawSchema: unknown): string => {
  const schemaVersion = parseRequiredText(value, 'schemaVersion', rawSchema)
  if (schemaVersion !== supportedSchemaVersion) {
    throw new Error(`引擎 schema 解析失败：schemaVersion 不受支持，expected=${supportedSchemaVersion}，actual=${schemaVersion}，payload=${JSON.stringify(rawSchema)}`)
  }

  return schemaVersion
}

const parseTags = (tags: unknown, rawSchema: unknown): readonly ModuleTagDefinition[] => {
  if (!Array.isArray(tags)) {
    throw new Error(`引擎 schema 解析失败：tags 必须是数组，payload=${JSON.stringify(rawSchema)}`)
  }

  const seenTagIds = new Set<string>()
  return tags.map((item: unknown, index: number): ModuleTagDefinition => {
    if (!isRecord(item)) {
      throw new Error(`引擎 schema 解析失败：tags[${index}] 不是对象，payload=${JSON.stringify(rawSchema)}`)
    }

    const shape: ModuleTagShape = item
    const id = parseRequiredText(shape.id, `tags[${index}].id`, rawSchema)
    if (seenTagIds.has(id)) {
      throw new Error(`引擎 schema 解析失败：tags[${index}].id 重复，tagId=${id}，payload=${JSON.stringify(rawSchema)}`)
    }
    seenTagIds.add(id)

    return {
      id,
      name: parseRequiredText(shape.name, `tags[${index}].name`, rawSchema),
      description: parseRequiredText(shape.description, `tags[${index}].description`, rawSchema),
    }
  })
}

const parseModules = (modules: unknown, knownTagIds: ReadonlySet<string>, rawSchema: unknown): readonly ModuleDefinition[] => {
  if (!Array.isArray(modules)) {
    throw new Error(`引擎 schema 解析失败：modules 必须是数组，payload=${JSON.stringify(rawSchema)}`)
  }

  const seenModuleIds = new Set<string>()
  return modules.map((item: unknown, index: number): ModuleDefinition => {
    if (!isRecord(item)) {
      throw new Error(`引擎 schema 解析失败：modules[${index}] 不是对象，payload=${JSON.stringify(rawSchema)}`)
    }

    const shape: ModuleDefinitionShape = item
    const id = parseRequiredText(shape.id, `modules[${index}].id`, rawSchema)
    if (seenModuleIds.has(id)) {
      throw new Error(`引擎 schema 解析失败：modules[${index}].id 重复，moduleId=${id}，payload=${JSON.stringify(rawSchema)}`)
    }
    seenModuleIds.add(id)

    return {
      id,
      name: parseRequiredText(shape.name, `modules[${index}].name`, rawSchema),
      description: parseRequiredText(shape.description, `modules[${index}].description`, rawSchema),
      tagIds: parseTagIds(shape.tagIds, knownTagIds, index, rawSchema),
      stability: parseRequiredText(shape.stability, `modules[${index}].stability`, rawSchema),
      risk: parseOptionalPassRisk(shape.risk, index, rawSchema) ?? undefined,
      requiresRuntimeFlags: parseOptionalStringArray(shape.requiresRuntimeFlags, `modules[${index}].requiresRuntimeFlags`, rawSchema) ?? undefined,
      platformConstraints: parseOptionalStringArray(shape.platformConstraints, `modules[${index}].platformConstraints`, rawSchema) ?? undefined,
      compatibilityNotes: parseOptionalText(shape.compatibilityNotes, `modules[${index}].compatibilityNotes`, rawSchema) ?? undefined,
      requiredPassIds: parseOptionalStringArray(shape.requiredPassIds, `modules[${index}].requiredPassIds`, rawSchema) ?? undefined,
      requiresAnyPassIds: parseOptionalStringArray(shape.requiresAnyPassIds, `modules[${index}].requiresAnyPassIds`, rawSchema) ?? undefined,
      defaultEnabled: parseOptionalBoolean(shape.defaultEnabled, `modules[${index}].defaultEnabled`, rawSchema) ?? undefined,
      requiresOptIn: parseOptionalBoolean(shape.requiresOptIn, `modules[${index}].requiresOptIn`, rawSchema) ?? undefined,
      params: parseParamSchemas(shape.params, index, rawSchema),
    }
  })
}


const validateModuleRequiredPassIds = (
  modules: readonly ModuleDefinition[],
  moduleIds: ReadonlySet<string>,
  rawSchema: unknown,
): void => {
  modules.forEach((moduleDefinition: ModuleDefinition, moduleIndex: number): void => {
    const seenRequiredPassIds = new Set<string>()
    for (const [requiredPassIndex, requiredPassId] of (moduleDefinition.requiredPassIds ?? []).entries()) {
      if (!moduleIds.has(requiredPassId)) {
        throw new Error(`引擎 schema 解析失败：modules[${moduleIndex}].requiredPassIds[${requiredPassIndex}] 未声明，passId=${requiredPassId}，payload=${JSON.stringify(rawSchema)}`)
      }
      if (requiredPassId === moduleDefinition.id) {
        throw new Error(`引擎 schema 解析失败：modules[${moduleIndex}].requiredPassIds[${requiredPassIndex}] 不能引用自身，passId=${requiredPassId}，payload=${JSON.stringify(rawSchema)}`)
      }
      if (seenRequiredPassIds.has(requiredPassId)) {
        throw new Error(`引擎 schema 解析失败：modules[${moduleIndex}].requiredPassIds[${requiredPassIndex}] 重复，passId=${requiredPassId}，payload=${JSON.stringify(rawSchema)}`)
      }
      seenRequiredPassIds.add(requiredPassId)
    }
  })
}

const validateModuleRequiresAnyPassIds = (
  modules: readonly ModuleDefinition[],
  moduleIds: ReadonlySet<string>,
  rawSchema: unknown,
): void => {
  modules.forEach((moduleDefinition: ModuleDefinition, moduleIndex: number): void => {
    const seenRequiresAnyPassIds = new Set<string>()
    for (const [requiresAnyPassIndex, requiresAnyPassId] of (moduleDefinition.requiresAnyPassIds ?? []).entries()) {
      if (!moduleIds.has(requiresAnyPassId)) {
        throw new Error(`引擎 schema 解析失败：modules[${moduleIndex}].requiresAnyPassIds[${requiresAnyPassIndex}] 未声明，passId=${requiresAnyPassId}，payload=${JSON.stringify(rawSchema)}`)
      }
      if (requiresAnyPassId === moduleDefinition.id) {
        throw new Error(`引擎 schema 解析失败：modules[${moduleIndex}].requiresAnyPassIds[${requiresAnyPassIndex}] 不能引用自身，passId=${requiresAnyPassId}，payload=${JSON.stringify(rawSchema)}`)
      }
      if (seenRequiresAnyPassIds.has(requiresAnyPassId)) {
        throw new Error(`引擎 schema 解析失败：modules[${moduleIndex}].requiresAnyPassIds[${requiresAnyPassIndex}] 重复，passId=${requiresAnyPassId}，payload=${JSON.stringify(rawSchema)}`)
      }
      seenRequiresAnyPassIds.add(requiresAnyPassId)
    }
  })
}

const parseTagIds = (
  tagIds: unknown,
  knownTagIds: ReadonlySet<string>,
  moduleIndex: number,
  rawSchema: unknown,
): readonly string[] => {
  if (!Array.isArray(tagIds) || tagIds.length === 0) {
    throw new Error(`引擎 schema 解析失败：modules[${moduleIndex}].tagIds 必须是非空数组，payload=${JSON.stringify(rawSchema)}`)
  }

  const seenTagIds = new Set<string>()
  return tagIds.map((value: unknown, index: number): string => {
    const tagId: string = parseRequiredText(value, `modules[${moduleIndex}].tagIds[${index}]`, rawSchema)
    if (!knownTagIds.has(tagId)) {
      throw new Error(`引擎 schema 解析失败：modules[${moduleIndex}].tagIds[${index}] 未声明，tagId=${tagId}，payload=${JSON.stringify(rawSchema)}`)
    }
    if (seenTagIds.has(tagId)) {
      throw new Error(`引擎 schema 解析失败：modules[${moduleIndex}].tagIds[${index}] 重复，tagId=${tagId}，payload=${JSON.stringify(rawSchema)}`)
    }
    seenTagIds.add(tagId)
    return tagId
  })
}

const parseParamSchemas = (params: unknown, moduleIndex: number, rawSchema: unknown): readonly ParamSchema[] => {
  if (!Array.isArray(params)) {
    throw new Error(`引擎 schema 解析失败：modules[${moduleIndex}].params 必须是数组，payload=${JSON.stringify(rawSchema)}`)
  }

  const seenParamKeys = new Set<string>()
  return params.map((item: unknown, index: number): ParamSchema => {
    if (!isRecord(item)) {
      throw new Error(`引擎 schema 解析失败：params item 不是对象，moduleIndex=${moduleIndex}，index=${index}，payload=${JSON.stringify(rawSchema)}`)
    }

    const shape: ParamSchemaShape = item
    const type: ParamSchema['type'] = parseParamType(shape.type, moduleIndex, index, rawSchema)
    const options: readonly string[] | null = parseOptions(shape.options, type, moduleIndex, index, rawSchema)
    const key = parseRequiredText(shape.key, `modules[${moduleIndex}].params[${index}].key`, rawSchema)
    if (seenParamKeys.has(key)) {
      throw new Error(`引擎 schema 解析失败：modules[${moduleIndex}].params[${index}].key 重复，paramKey=${key}，payload=${JSON.stringify(rawSchema)}`)
    }
    seenParamKeys.add(key)
    return {
      key,
      type,
      defaultValue: parseDefaultValue(shape.defaultValue, type, options, moduleIndex, index, rawSchema),
      options,
      description: parseRequiredText(shape.description, `modules[${moduleIndex}].params[${index}].description`, rawSchema),
      hidden: parseOptionalBoolean(shape.hidden, `modules[${moduleIndex}].params[${index}].hidden`, rawSchema) ?? false,
    }
  })
}

const parseParamType = (value: unknown, moduleIndex: number, index: number, rawSchema: unknown): ParamSchema['type'] => {
  if (typeof value === 'string' && paramTypes.includes(value as ParamSchema['type'])) {
    return value as ParamSchema['type']
  }

  throw new Error(`引擎 schema 解析失败：参数类型无效，moduleIndex=${moduleIndex}，index=${index}，type=${String(value)}，payload=${JSON.stringify(rawSchema)}`)
}

const parseDefaultValue = (
  value: unknown,
  type: ParamSchema['type'],
  options: readonly string[] | null,
  moduleIndex: number,
  index: number,
  rawSchema: unknown,
): ParamSchema['defaultValue'] => {
  if (value === undefined || value === null || value === '') {
    return null
  }

  if (type === 'boolean') {
    if (typeof value === 'boolean') {
      return value
    }
    throw new Error(`引擎 schema 解析失败：modules[${moduleIndex}].params[${index}].defaultValue 必须是布尔值，payload=${JSON.stringify(rawSchema)}`)
  }

  if (type === 'number') {
    if (typeof value === 'number' && Number.isFinite(value)) {
      return value
    }
    throw new Error(`引擎 schema 解析失败：modules[${moduleIndex}].params[${index}].defaultValue 必须是数字，payload=${JSON.stringify(rawSchema)}`)
  }

  if (typeof value !== 'string') {
    throw new Error(`引擎 schema 解析失败：modules[${moduleIndex}].params[${index}].defaultValue 必须是字符串，payload=${JSON.stringify(rawSchema)}`)
  }

  if (type === 'enum' && options !== null && !options.includes(value)) {
    throw new Error(`引擎 schema 解析失败：modules[${moduleIndex}].params[${index}].defaultValue 必须包含在 enum options 中，defaultValue=${value}，payload=${JSON.stringify(rawSchema)}`)
  }

  return value
}

const parseCompatibilityRules = (
  compatibility: unknown,
  moduleIds: ReadonlySet<string>,
  rawSchema: unknown,
): readonly PassCompatibilityRule[] => {
  if (compatibility === undefined) {
    return []
  }

  if (!Array.isArray(compatibility)) {
    throw new Error(`引擎 schema 解析失败：compatibility 必须是数组，payload=${JSON.stringify(rawSchema)}`)
  }

  return compatibility.map((item: unknown, index: number): PassCompatibilityRule => {
    if (!isRecord(item)) {
      throw new Error(`引擎 schema 解析失败：compatibility[${index}] 不是对象，payload=${JSON.stringify(rawSchema)}`)
    }

    const shape: PassCompatibilityRuleShape = item
    return {
      passIds: parseCompatibilityPassIds(shape.passIds, moduleIds, index, rawSchema),
      severity: parseCompatibilitySeverity(shape.severity, index, rawSchema),
      description: parseRequiredText(shape.description, `compatibility[${index}].description`, rawSchema),
    }
  })
}

const parseCompatibilityPassIds = (
  passIds: unknown,
  moduleIds: ReadonlySet<string>,
  index: number,
  rawSchema: unknown,
): readonly string[] => {
  if (!Array.isArray(passIds) || passIds.length < 2) {
    throw new Error(`引擎 schema 解析失败：compatibility[${index}].passIds 必须至少包含两个模块，payload=${JSON.stringify(rawSchema)}`)
  }

  const seenPassIds = new Set<string>()
  return passIds.map((value: unknown, passIndex: number): string => {
    const passId: string = parseRequiredText(value, `compatibility[${index}].passIds[${passIndex}]`, rawSchema)
    if (!moduleIds.has(passId)) {
      throw new Error(`引擎 schema 解析失败：compatibility[${index}].passIds[${passIndex}] 未声明，passId=${passId}，payload=${JSON.stringify(rawSchema)}`)
    }
    if (seenPassIds.has(passId)) {
      throw new Error(`引擎 schema 解析失败：compatibility[${index}].passIds[${passIndex}] 重复，passId=${passId}，payload=${JSON.stringify(rawSchema)}`)
    }
    seenPassIds.add(passId)
    return passId
  })
}

const parseCompatibilitySeverity = (severity: unknown, index: number, rawSchema: unknown): PassCompatibilityRule['severity'] => {
  if (typeof severity === 'string' && compatibilitySeverities.includes(severity as PassCompatibilityRule['severity'])) {
    return severity as PassCompatibilityRule['severity']
  }

  throw new Error(`引擎 schema 解析失败：compatibility[${index}].severity 无效，severity=${String(severity)}，payload=${JSON.stringify(rawSchema)}`)
}

const parseDefaultPipeline = (
  defaultPipeline: unknown,
  moduleIds: ReadonlySet<string>,
  rawSchema: unknown,
): readonly string[] => {
  if (defaultPipeline === undefined) {
    return []
  }

  const pipeline = parseOptionalStringArray(defaultPipeline, 'defaultPipeline', rawSchema)
  if (pipeline === null) {
    return []
  }

  pipeline.forEach((passId: string, index: number): void => {
    if (!moduleIds.has(passId)) {
      throw new Error(`引擎 schema 解析失败：defaultPipeline[${index}] 未声明，passId=${passId}，payload=${JSON.stringify(rawSchema)}`)
    }
  })

  return pipeline
}

const parseOptions = (
  value: unknown,
  type: ParamSchema['type'],
  moduleIndex: number,
  index: number,
  rawSchema: unknown,
): readonly string[] | null => {
  if (value === null || value === undefined || value === '') {
    return null
  }

  if (!Array.isArray(value) || !value.every((item: unknown): item is string => typeof item === 'string')) {
    throw new Error(`引擎 schema 解析失败：options 必须是字符串数组，moduleIndex=${moduleIndex}，index=${index}，payload=${JSON.stringify(rawSchema)}`)
  }

  if (type === 'enum' && value.length === 0) {
    throw new Error(`引擎 schema 解析失败：enum options 为空，moduleIndex=${moduleIndex}，index=${index}，payload=${JSON.stringify(rawSchema)}`)
  }

  return value
}

const parseRequiredText = (value: unknown, fieldPath: string, rawSchema: unknown): string => {
  if (typeof value === 'string' && value.trim().length > 0) {
    return value
  }

  throw new Error(`引擎 schema 解析失败：${fieldPath} 必须是非空字符串，payload=${JSON.stringify(rawSchema)}`)
}

const parseOptionalText = (value: unknown, fieldPath: string, rawSchema: unknown): string | null => {
  if (value === undefined || value === null) {
    return null
  }

  if (typeof value === 'string') {
    return value
  }

  throw new Error(`引擎 schema 解析失败：${fieldPath} 必须是字符串，payload=${JSON.stringify(rawSchema)}`)
}

const parseOptionalBoolean = (value: unknown, fieldPath: string, rawSchema: unknown): boolean | null => {
  if (value === undefined || value === null) {
    return null
  }

  if (typeof value === 'boolean') {
    return value
  }

  throw new Error(`引擎 schema 解析失败：${fieldPath} 必须是布尔值，payload=${JSON.stringify(rawSchema)}`)
}

const parseOptionalStringArray = (value: unknown, fieldPath: string, rawSchema: unknown): readonly string[] | null => {
  if (value === undefined || value === null) {
    return null
  }

  if (Array.isArray(value) && value.every((item: unknown): item is string => typeof item === 'string')) {
    return value
  }

  throw new Error(`引擎 schema 解析失败：${fieldPath} 必须是字符串数组，payload=${JSON.stringify(rawSchema)}`)
}

const parseOptionalPassRisk = (value: unknown, moduleIndex: number, rawSchema: unknown): ModuleDefinition['risk'] | null => {
  if (value === undefined || value === null) {
    return null
  }

  if (typeof value === 'string' && passRisks.includes(value as NonNullable<ModuleDefinition['risk']>)) {
    return value as NonNullable<ModuleDefinition['risk']>
  }

  throw new Error(`引擎 schema 解析失败：modules[${moduleIndex}].risk 无效，risk=${String(value)}，payload=${JSON.stringify(rawSchema)}`)
}


const parseOrderingConstraints = (
  orderingConstraints: unknown,
  moduleIds: ReadonlySet<string>,
  rawSchema: unknown,
): readonly OrderingConstraint[] => {
  if (orderingConstraints === undefined) {
    return []
  }

  if (!Array.isArray(orderingConstraints)) {
    throw new Error(`引擎 schema 解析失败：orderingConstraints 必须是数组，payload=${JSON.stringify(rawSchema)}`)
  }

  return orderingConstraints.map((item: unknown, index: number): OrderingConstraint => {
    if (!isRecord(item)) {
      throw new Error(`引擎 schema 解析失败：orderingConstraints[${index}] 不是对象，payload=${JSON.stringify(rawSchema)}`)
    }

    const shape: OrderingConstraintShape = item
    const before: string = parseRequiredText(shape.before, `orderingConstraints[${index}].before`, rawSchema)
    const after: string = parseRequiredText(shape.after, `orderingConstraints[${index}].after`, rawSchema)
    if (!moduleIds.has(before)) {
      throw new Error(`引擎 schema 解析失败：orderingConstraints[${index}].before 未声明，passId=${before}，payload=${JSON.stringify(rawSchema)}`)
    }
    if (!moduleIds.has(after)) {
      throw new Error(`引擎 schema 解析失败：orderingConstraints[${index}].after 未声明，passId=${after}，payload=${JSON.stringify(rawSchema)}`)
    }
    return {
      before,
      after,
      reason: parseRequiredText(shape.reason, `orderingConstraints[${index}].reason`, rawSchema),
      hard: parseOptionalBoolean(shape.hard, `orderingConstraints[${index}].hard`, rawSchema) ?? true,
    }
  })
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value)
