import type { EngineSchemaPayload, ModuleDefinition, PassItem, PassParamValue } from './types'

const legacyPassDependencies: ReadonlyMap<string, readonly string[]> = new Map<string, readonly string[]>([])

const controlFlowPassIds: ReadonlySet<string> = new Set<string>([
  'control-flow-flattening',
  'control-flow-obfuscation',
  'invoke-dynamic-indirection',
  'reference-proxy',
])

const helperLoaderPassIds: ReadonlySet<string> = new Set<string>([
  'class-encryption-loader',
  'method-body-delayed-decryption',
])

const dependencyIdsForPass = (passItem: Pick<PassItem, 'id' | 'requiredPassIds'>): readonly string[] => [
  ...new Set<string>([
    ...(legacyPassDependencies.get(passItem.id) ?? []),
    ...passItem.requiredPassIds,
  ]),
]

const buildDependencyMap = (passes: readonly Pick<PassItem, 'id' | 'requiredPassIds'>[]): ReadonlyMap<string, readonly string[]> => new Map<string, readonly string[]>(
  passes
    .map((passItem): [string, readonly string[]] => [passItem.id, dependencyIdsForPass(passItem)])
    .filter(([, dependencyIds]): boolean => dependencyIds.length > 0),
)

const resolveEnabledDependencyIds = (
  enabledPassIds: readonly string[],
  dependencyMap: ReadonlyMap<string, readonly string[]>,
): readonly string[] => {
  const resolved = new Set<string>(enabledPassIds)
  let changed = true
  while (changed) {
    changed = false
    for (const passId of resolved) {
      const dependencyIds = dependencyMap.get(passId)
      if (!dependencyIds) {
        continue
      }
      for (const dependencyId of dependencyIds) {
        if (!resolved.has(dependencyId)) {
          resolved.add(dependencyId)
          changed = true
        }
      }
    }
  }
  return [...resolved]
}

const buildReverseDependencyMap = (dependencyMap: ReadonlyMap<string, readonly string[]>): ReadonlyMap<string, readonly string[]> => {
  const reverse = new Map<string, string[]>()
  for (const [passId, dependencyIds] of dependencyMap.entries()) {
    for (const dependencyId of dependencyIds) {
      const dependents = reverse.get(dependencyId) ?? []
      dependents.push(passId)
      reverse.set(dependencyId, dependents)
    }
  }
  return reverse
}

export const applyPassDependencies = (passes: readonly PassItem[]): readonly PassItem[] => {
  const enabledPassIds = passes
    .filter((passItem: PassItem): boolean => passItem.enabled)
    .map((passItem: PassItem): string => passItem.id)
  const dependencyMap = buildDependencyMap(passes)
  const resolvedPassIds = new Set<string>(resolveEnabledDependencyIds(enabledPassIds, dependencyMap))

  return passes.map((passItem: PassItem): PassItem => ({
    ...passItem,
    enabled: resolvedPassIds.has(passItem.id),
  }))
}

export const applyPassRequiresAnyConstraints = (passes: readonly PassItem[]): readonly PassItem[] => {
  const enabledPassIds = new Set<string>(passes.filter((passItem: PassItem): boolean => passItem.enabled).map((passItem: PassItem): string => passItem.id))

  return passes.map((passItem: PassItem): PassItem => {
    if (!passItem.enabled || passItem.requiresAnyPassIds.length === 0) {
      return passItem
    }

    const hasCompanionPass = passItem.requiresAnyPassIds.some((requiredPassId: string): boolean => enabledPassIds.has(requiredPassId))
    return hasCompanionPass ? passItem : { ...passItem, enabled: false }
  })
}

export const disablePassAndDependents = (passes: readonly PassItem[], passId: string): readonly PassItem[] => {
  const dependencyMap = buildDependencyMap(passes)
  const reverseDependencyMap = buildReverseDependencyMap(dependencyMap)
  const disabledPassIds = new Set<string>([passId])
  let changed = true

  while (changed) {
    changed = false
    for (const disabledPassId of [...disabledPassIds]) {
      for (const dependentPassId of reverseDependencyMap.get(disabledPassId) ?? []) {
        if (!disabledPassIds.has(dependentPassId)) {
          disabledPassIds.add(dependentPassId)
          changed = true
        }
      }
    }
  }

  return passes.map((passItem: PassItem): PassItem => ({
    ...passItem,
    enabled: disabledPassIds.has(passItem.id) ? false : passItem.enabled,
  }))
}

export const buildPassItemsFromSchema = (schema: EngineSchemaPayload): readonly PassItem[] => {
  const items = schema.modules.map((moduleDefinition: ModuleDefinition): PassItem => createPassItem(moduleDefinition, schema.defaultPipeline))
  return applyPassRequiresAnyConstraints(applyPassDependencies(items))
}

export const clonePassItem = (passItem: PassItem): PassItem => ({
  ...passItem,
  tagIds: [...passItem.tagIds],
  params: { ...passItem.params },
  paramSchemas: passItem.paramSchemas.map((paramSchema) => ({ ...paramSchema })),
  requiredPassIds: [...passItem.requiredPassIds],
  requiresAnyPassIds: [...passItem.requiresAnyPassIds],
})

const createPassItem = (moduleDefinition: ModuleDefinition, defaultPipeline: readonly string[]): PassItem => ({
  id: moduleDefinition.id,
  name: moduleDefinition.name,
  description: moduleDefinition.description,
  tagIds: [...moduleDefinition.tagIds],
  category: deriveDisplayCategory(moduleDefinition),
  enabled: defaultPipeline.length > 0 ? defaultPipeline.includes(moduleDefinition.id) : (moduleDefinition.defaultEnabled ?? true),
  params: buildDefaultParams(moduleDefinition),
  paramSchemas: moduleDefinition.params.filter((paramSchema) => !paramSchema.hidden),
  stability: moduleDefinition.stability,
  risk: moduleDefinition.risk ?? inferRisk(moduleDefinition.id, moduleDefinition.tagIds[0] ?? 'unknown'),
  compatibilityNotes: moduleDefinition.compatibilityNotes,
  requiresOptIn: moduleDefinition.requiresOptIn ?? false,
  requiredPassIds: [...(moduleDefinition.requiredPassIds ?? [])],
  requiresAnyPassIds: [...(moduleDefinition.requiresAnyPassIds ?? [])],
})

const buildDefaultParams = (moduleDefinition: ModuleDefinition): Readonly<Record<string, PassParamValue>> => Object.fromEntries(
  moduleDefinition.params.map((paramSchema): [string, PassParamValue] => [paramSchema.key, parseDefaultParamValue(paramSchema.defaultValue)]),
)

const parseDefaultParamValue = (value: unknown): PassParamValue => {
  if (value === null || value === undefined) {
    return null
  }

  if (typeof value === 'boolean' || typeof value === 'string' || typeof value === 'number') {
    return value
  }

  throw new Error(`不支持的模块参数默认值：value=${JSON.stringify(value)}`)
}

const deriveDisplayCategory = (moduleDefinition: ModuleDefinition): string => {
  const primaryTag: string = moduleDefinition.tagIds[0] ?? 'unknown'

  if (moduleDefinition.id.startsWith('rename-')) {
    return 'symbol-renaming'
  }

  if (moduleDefinition.id === 'member-hide') {
    return 'member-hiding'
  }

  if (primaryTag === 'metadata') {
    return 'metadata-cleanup'
  }

  if (primaryTag === 'hiding') {
    return 'member-hiding'
  }

  if (primaryTag === 'encryption') {
    return 'string-protection'
  }

  if (helperLoaderPassIds.has(moduleDefinition.id) || primaryTag === 'helper-deployment' || primaryTag === 'loader-protection') {
    return 'helper-loader'
  }

  if (primaryTag === 'runtime-defense' || (primaryTag === 'native-kernel' && moduleDefinition.id !== 'jni-microkernel-loader')) {
    return 'runtime-defense'
  }

  if (primaryTag === 'vm-protection') {
    return 'virtualization'
  }

  if (primaryTag === 'native-kernel') {
    return 'native-kernel'
  }


  if (controlFlowPassIds.has(moduleDefinition.id)) {
    return 'control-flow'
  }

  if (primaryTag === 'obfuscation') {
    return 'decompiler-traps'
  }

  return primaryTag
}

const inferRisk = (passId: string, category: string): PassItem['risk'] => {
  if (category === 'metadata-cleanup' || category === 'metadata') {
    return 'low'
  }

  const highRiskPassIds = new Set([
    'anti-dump-protection',
    'anti-instrumentation',
    'class-encryption-loader',
    'environment-bound-keys',
    'jni-microkernel-loader',
    'method-body-delayed-decryption',
    'method-virtualization',
  ])

  if (highRiskPassIds.has(passId) || category === 'native-kernel' || category === 'virtualization') {
    return 'high'
  }

  const mediumRiskCategories = new Set([
    'control-flow',
    'decompiler-traps',
    'helper-loader',
    'member-hiding',
    'runtime-defense',
    'string-protection',
    'symbol-renaming',
  ])

  return mediumRiskCategories.has(category) ? 'medium' : 'low'
}
