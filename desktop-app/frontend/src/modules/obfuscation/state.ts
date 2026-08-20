import { applyPassDependencies, applyPassRequiresAnyConstraints, buildPassItemsFromSchema, clonePassItem, disablePassAndDependents, requiresAnyPassIdsFor } from './pass-catalog'
import { hasEnabledSoftCompatibilityConflict, resolvePassCompatibility } from './pass-compatibility'
import { parsePassSelectionTarget } from './pass-selection-targeting.ts'
import type {
  ClassTreeNode,
  EngineEvent,
  EngineSchemaPayload,
  JarInspectionPayload,
  LoadedJarInfo,
  LogLine,
  ObfuscationRequest,
  OrderingConstraint,
  PassCompatibilityRule,
  PassItem,
  PassParamValue,
  PassSelection,
  PassSelectionMode,
  PassSpec,
  RuleAction,
  RuleItem,
  RulePatch,
  RunState,
  TargetingCapability,
} from './types'


/**
 * Reorder passes according to ordering constraints.
 * Uses a deterministic topological sort: when multiple passes have no unmet prerequisites,
 * the one appearing earliest in the original order wins.
 */
export const reorderByConstraints = (
  passes: readonly PassItem[],
  constraints: readonly OrderingConstraint[],
): readonly PassItem[] => {
  const passIds = passes.map((p: PassItem): string => p.id)
  const passIdSet = new Set<string>(passIds)
  const originalIndex = new Map<string, number>(passIds.map((id: string, i: number): [string, number] => [id, i]))

  // Filter to relevant constraints
  const relevant = constraints.filter((c: OrderingConstraint): boolean => passIdSet.has(c.before) && passIdSet.has(c.after))

  // Build graph
  const adjacency = new Map<string, string[]>()
  const inDegree = new Map<string, number>()
  for (const id of passIds) {
    adjacency.set(id, [])
    inDegree.set(id, 0)
  }
  for (const c of relevant) {
    adjacency.get(c.before)!.push(c.after)
    inDegree.set(c.after, (inDegree.get(c.after) ?? 0) + 1)
  }

  // Kahn's with deterministic tie-breaking (original order)
  const zeroQueue: string[] = []
  for (const [id, degree] of inDegree) {
    if (degree === 0) zeroQueue.push(id)
  }
  zeroQueue.sort((a: string, b: string): number => (originalIndex.get(a) ?? 0) - (originalIndex.get(b) ?? 0))

  const sorted: string[] = []
  while (zeroQueue.length > 0) {
    const current = zeroQueue.shift()!
    sorted.push(current)
    for (const neighbor of adjacency.get(current) ?? []) {
      const newDegree = (inDegree.get(neighbor) ?? 1) - 1
      inDegree.set(neighbor, newDegree)
      if (newDegree === 0) {
        // Insert in sorted position by original index
        const insertIdx = zeroQueue.findIndex((id: string): boolean => (originalIndex.get(id) ?? 0) > (originalIndex.get(neighbor) ?? 0))
        if (insertIdx === -1) {
          zeroQueue.push(neighbor)
        } else {
          zeroQueue.splice(insertIdx, 0, neighbor)
        }
      }
    }
  }

  // If cycle detected, return original order
  if (sorted.length < passIds.length) {
    return passes
  }

  const passMap = new Map<string, PassItem>(passes.map((p: PassItem): [string, PassItem] => [p.id, p]))
  return sorted.map((id: string): PassItem => passMap.get(id)!)
}


export const createInitialRunState = (): RunState => ({
  status: 'idle',
  schema: null,
  inputJar: null,
  outputJarPath: '',
  passes: [],
  rules: [],
  passSelections: [],
  classTree: [],
  classCount: 0,
  packageCount: 0,
  inspectingClasses: false,
  progress: 0,
  currentStep: null,
  outputPath: null,
  logs: [
    {
      id: 'boot-log',
      level: 'info',
      message: 'JavaShroud 工作台已就绪，等待导入 Jar。',
      createdAt: new Date(0).toISOString(),
    },
  ],
  errorMessage: null,
  autoScroll: true,
})

export const buildLoadedJarInfo = (file: File): LoadedJarInfo => ({
  fileName: file.name,
  inputJarPath: '',
  sizeLabel: formatBytes(file.size),
  detectedMainClass: null,
})

export const buildLoadedJarInfoFromPath = (inputJarPath: string): LoadedJarInfo => ({
  fileName: extractFileName(inputJarPath),
  inputJarPath,
  sizeLabel: '系统文件',
  detectedMainClass: null,
})

export const setLoadedJar = (state: RunState, jarInfo: LoadedJarInfo): RunState => ({
  ...state,
  status: 'ready',
  inputJar: jarInfo,
  outputJarPath: jarInfo.inputJarPath.trim().length === 0 ? '' : deriveOutputJarPath(jarInfo.inputJarPath),
  classTree: [],
  classCount: 0,
  packageCount: 0,
  errorMessage: null,
})

export const setInputJarPath = (state: RunState, inputJarPath: string): RunState => {
  const trimmedPath: string = inputJarPath.trim()
  if (trimmedPath.length === 0) {
    return {
      ...state,
      inputJar: null,
      outputJarPath: '',
      classTree: [],
      classCount: 0,
      packageCount: 0,
    }
  }

  const currentInfo: LoadedJarInfo = state.inputJar ?? buildLoadedJarInfoFromPath(trimmedPath)
  return {
    ...state,
    status: 'ready',
    inputJar: {
      ...currentInfo,
      fileName: extractFileName(trimmedPath),
      inputJarPath: trimmedPath,
    },
    outputJarPath: state.outputJarPath.trim().length === 0 ? deriveOutputJarPath(trimmedPath) : state.outputJarPath,
    classTree: [],
    classCount: 0,
    packageCount: 0,
  }
}

export const setOutputJarPath = (state: RunState, outputJarPath: string): RunState => ({
  ...state,
  outputJarPath,
})

export const setPasses = (state: RunState, passes: readonly PassItem[]): RunState => ({
  ...state,
  passes: normalizePasses(
    passes.map((passItem: PassItem): PassItem => clonePassItem(passItem)),
    state.schema?.compatibility ?? [],
    state.schema?.orderingConstraints ?? [],
  ),
})

export const setEngineSchema = (state: RunState, schema: EngineSchemaPayload): RunState => {
  const passes = normalizePasses(buildPassItemsFromSchema(schema), schema.compatibility, schema.orderingConstraints)
  const disabledByCompatibility = schema.modules.length - countEnabledPasses(passes)

  return {
    ...state,
    schema: cloneEngineSchema(schema),
    passes,
    logs: appendLogLine(state.logs, {
      level: 'info',
      message: disabledByCompatibility === 0
        ? `已加载 ${schema.modules.length} 个模块、${schema.tags.length} 个标签。`
        : `已加载 ${schema.modules.length} 个模块、${schema.tags.length} 个标签；已按兼容性规则关闭 ${disabledByCompatibility} 个冲突模块。`,
    }),
  }
}

export const togglePass = (state: RunState, passId: string): RunState => {
  const toggledPass = state.passes.find((passItem: PassItem): boolean => passItem.id === passId)
  const nextPasses = toggledPass?.enabled === true
    ? disablePassAndDependents(state.passes, passId)
    : state.passes.map((passItem: PassItem): PassItem => (
      passItem.id === passId ? { ...passItem, enabled: true, dependencyAutoEnabled: false } : passItem
    ))

  return {
    ...state,
    passes: normalizePasses(
      nextPasses,
      state.schema?.compatibility ?? [],
      state.schema?.orderingConstraints ?? [],
      toggledPass?.enabled === false ? passId : null,
    ),
  }
}

export const setAllPassesEnabled = (state: RunState, enabled: boolean): RunState => ({
  ...state,
  passes: normalizePasses(
    state.passes.map((passItem: PassItem): PassItem => ({
      ...passItem,
      enabled,
      dependencyAutoEnabled: false,
    })),
    state.schema?.compatibility ?? [],
    state.schema?.orderingConstraints ?? [],
  ),
})

export const setPassParam = (state: RunState, passId: string, paramKey: string, value: PassParamValue): RunState => ({
  ...state,
  passes: normalizePasses(
    state.passes.map((passItem: PassItem): PassItem => (
      passItem.id === passId
        ? { ...passItem, params: { ...passItem.params, [paramKey]: value } }
        : passItem
    )),
    state.schema?.compatibility ?? [],
    state.schema?.orderingConstraints ?? [],
  ),
})

export const setAutoScroll = (state: RunState, autoScroll: boolean): RunState => ({
  ...state,
  autoScroll,
})

export const markInspectingClasses = (state: RunState): RunState => ({
  ...state,
  inspectingClasses: true,
  errorMessage: null,
})

export const setJarInspection = (state: RunState, payload: JarInspectionPayload): RunState => {
  const rules = syncRulesWithClassTree(state.rules, payload.nodes)
  const passSelections = syncPassSelectionsWithClassTree(state.passSelections, payload.nodes)
  const removedGlobalRuleCount = state.rules.length - rules.length
  const removedPassRuleCount = countPassSelectionRules(state.passSelections) - countPassSelectionRules(passSelections)
  const removedPassRuleSummary = summarizeRemovedPassRules(state.passSelections, passSelections)
  const pruneSegments: readonly string[] = [
    removedGlobalRuleCount > 0 ? `已清理 ${removedGlobalRuleCount} 条全局规则` : '',
    removedPassRuleSummary.length > 0 ? `Pass 范围：${removedPassRuleSummary}` : '',
  ].filter((segment): segment is string => segment.length > 0)
  const pruneSuffix = pruneSegments.length === 0 ? '' : `；${pruneSegments.join('；')}。`

  return {
    ...state,
    classTree: payload.nodes,
    classCount: payload.classCount,
    packageCount: payload.packageCount,
    inspectingClasses: false,
    rules,
    passSelections,
    logs: appendLogLine(state.logs, {
      level: removedGlobalRuleCount === 0 && removedPassRuleCount === 0 ? 'info' : 'warn',
      message: `已扫描类树：${payload.classCount} 个类、${payload.packageCount} 个包${pruneSuffix}`,
    }),
  }
}

export const setInspectingClassesFailed = (state: RunState): RunState => ({
  ...state,
  inspectingClasses: false,
})

export const setClassTreeRule = (state: RunState, node: ClassTreeNode, action: RuleAction): RunState => {
  const target = buildRuleTarget(node)
  const existingRule = state.rules.find((rule: RuleItem): boolean => rule.target === target)

  if (action === 'obfuscate') {
    if (existingRule?.action === 'exclude') {
      return resolveInheritedRuleAction(state.rules, node) === 'exclude'
        ? updateRule(state, existingRule.id, { target, action: 'obfuscate' })
        : removeRule(state, existingRule.id)
    }
    return existingRule === undefined && resolveInheritedRuleAction(state.rules, node) === 'exclude'
      ? addRule(state, { target, action: 'obfuscate' })
      : state
  }

  return existingRule === undefined
    ? addRule(state, { target, action: 'exclude' })
    : updateRule(state, existingRule.id, { target, action: 'exclude' })
}

/** Missing entries intentionally inherit the live global rule baseline. */
export const passSelectionModeFor = (
  passSelections: readonly PassSelection[],
  passId: string,
): PassSelectionMode => passSelections.find((selection): boolean => selection.passId === passId)?.mode ?? 'inherit-global'

export const passSelectionFor = (
  passSelections: readonly PassSelection[],
  passId: string,
): PassSelection | undefined => passSelections.find((selection): boolean => selection.passId === passId)

export const passSupportsTargeting = (pass: Pick<PassItem, 'targeting'>): boolean => pass.targeting.supported && pass.targeting.targetKinds.length > 0

export const supportsNodeTargeting = (pass: Pick<PassItem, 'targeting'>, node: ClassTreeNode): boolean => (
  (node.kind === 'class' || node.kind === 'method')
  && pass.targeting.supported
  && pass.targeting.targetKinds.includes(node.kind)
)

export const setPassSelectionMode = (
  state: RunState,
  passId: string,
  mode: PassSelectionMode,
): RunState => {
  const pass = requirePassForSelection(state, passId)
  if (!passSupportsTargeting(pass)) {
    throw new Error(`Pass 不支持类/方法范围选择：${passId}`)
  }

  if (mode === 'inherit-global') {
    return {
      ...state,
      passSelections: state.passSelections.filter((selection): boolean => selection.passId !== passId),
    }
  }

  const existing = passSelectionFor(state.passSelections, passId)
  if (existing?.mode === 'selected-only') {
    return state
  }

  return {
    ...state,
    passSelections: [
      ...state.passSelections.filter((selection): boolean => selection.passId !== passId),
      { passId, mode: 'selected-only', rules: [] },
    ],
  }
}

export const setPassSelectionRule = (
  state: RunState,
  passId: string,
  node: ClassTreeNode,
  action: RuleAction,
): RunState => {
  const pass = requirePassForSelection(state, passId)
  if (!supportsNodeTargeting(pass, node)) {
    throw new Error(`Pass ${passId} 不支持选择 ${node.kind}：仅可选择 schema 声明的类或方法。`)
  }

  const selection = passSelectionFor(state.passSelections, passId)
  if (selection?.mode !== 'selected-only') {
    throw new Error(`Pass ${passId} 当前同步全局规则；请先切换为独立范围。`)
  }

  const target = buildRuleTarget(node)
  const existingRule = selection.rules.find((rule): boolean => rule.target === target)
  const inheritedAction = resolveInheritedRuleAction(selection.rules, node) ?? 'obfuscate'
  let nextRules: readonly RuleItem[]

  if (action === 'obfuscate') {
    if (existingRule?.action === 'exclude') {
      nextRules = inheritedAction === 'exclude'
        ? selection.rules.map((rule): RuleItem => rule.id === existingRule.id ? { ...rule, target, action: 'obfuscate' } : rule)
        : selection.rules.filter((rule): boolean => rule.id !== existingRule.id)
    } else if (existingRule === undefined && inheritedAction === 'exclude') {
      nextRules = [...selection.rules, createRule(`pass-rule-${passId}`, selection.rules.length, target, 'obfuscate')]
    } else {
      nextRules = selection.rules
    }
  } else {
    nextRules = existingRule === undefined
      ? [...selection.rules, createRule(`pass-rule-${passId}`, selection.rules.length, target, 'exclude')]
      : selection.rules.map((rule): RuleItem => rule.id === existingRule.id ? { ...rule, target, action: 'exclude' } : rule)
  }

  return {
    ...state,
    passSelections: state.passSelections.map((candidate): PassSelection => (
      candidate.passId === passId ? { ...candidate, rules: normalizeRuleItems(nextRules, `pass-rule-${passId}`) } : candidate
    )),
  }
}

export const replacePassSelections = (state: RunState, passSelections: readonly PassSelection[]): RunState => ({
  ...state,
  passSelections: normalizePassSelections(passSelections),
})

export const clearLogs = (state: RunState): RunState => ({
  ...state,
  logs: [],
})

export const addRule = (state: RunState, patch: RulePatch): RunState => {
  const trimmedTarget: string = patch.target.trim()

  if (trimmedTarget.length === 0) {
    throw new Error('新增规则失败：target 不能为空。')
  }

  const duplicatedRule: RuleItem | undefined = state.rules.find((rule: RuleItem): boolean => rule.target === trimmedTarget)
  if (duplicatedRule !== undefined) {
    return state
  }

  const newRule: RuleItem = createRule('rule', state.rules.length, trimmedTarget, patch.action)

  return {
    ...state,
    rules: [...state.rules, newRule],
  }
}

export const updateRule = (state: RunState, ruleId: string, patch: RulePatch): RunState => {
  const trimmedTarget: string = patch.target.trim()

  if (trimmedTarget.length === 0) {
    throw new Error(`更新规则失败：target 不能为空，ruleId=${ruleId}。`)
  }

  return {
    ...state,
    rules: state.rules.map((rule: RuleItem): RuleItem => (
      rule.id === ruleId ? { ...rule, target: trimmedTarget, action: patch.action } : rule
    )),
  }
}

export const removeRule = (state: RunState, ruleId: string): RunState => ({
  ...state,
  rules: state.rules.filter((rule: RuleItem): boolean => rule.id !== ruleId),
})

export const clearRules = (state: RunState): RunState => ({
  ...state,
  rules: [],
})

export const replaceRules = (state: RunState, rules: readonly RuleItem[]): RunState => ({
  ...state,
  rules: normalizeRuleItems(rules, 'rule-import'),
})

const isKnownRuleAction = (action: string): action is RuleAction => action === 'exclude' || action === 'obfuscate'

export const markRunStarting = (state: RunState): RunState => ({
  ...state,
  status: 'running',
  progress: 0,
  currentStep: null,
  outputPath: null,
  errorMessage: null,
  logs: appendLogLine(state.logs, {
    level: 'info',
    message: '正在启动混淆请求。',
  }),
})

export const markCanceling = (state: RunState): RunState => ({
  ...state,
  status: 'canceling',
  logs: appendLogLine(state.logs, {
    level: 'warn',
    message: '已请求取消当前任务。',
  }),
})

export const applyEngineEvent = (state: RunState, event: EngineEvent): RunState => {
  if (event.type === 'canceled') {
    return {
      ...state,
      status: 'ready',
      currentStep: null,
      logs: appendLogLine(state.logs, { level: event.level, message: event.message }),
      errorMessage: null,
    }
  }

  if (event.type === 'done') {
    return {
      ...state,
      status: 'done',
      progress: 100,
      currentStep: null,
      outputPath: event.outPath,
      logs: appendLogLine(state.logs, { level: event.level, message: event.message }),
      errorMessage: null,
    }
  }

  if (event.type === 'error') {
    return {
      ...state,
      status: 'failed',
      currentStep: null,
      logs: appendLogLine(state.logs, { level: event.level, message: event.message }),
      errorMessage: event.message,
    }
  }

  if (event.type === 'progress') {
    return {
      ...state,
      progress: event.progress === null ? state.progress : clampProgress(event.progress),
      currentStep: event.message || state.currentStep,
    }
  }

  return {
    ...state,
    logs: appendLogLine(state.logs, { level: event.level, message: event.message }),
  }
}

export const applyBridgeError = (state: RunState, error: unknown, context: string): RunState => {
  const message: string = error instanceof Error ? error.message : String(error)
  const contextualMessage: string = `${context}: ${message}`

  return {
    ...state,
    status: context.includes('扫描') ? state.status : 'failed',
    inspectingClasses: false,
    errorMessage: contextualMessage,
    logs: appendLogLine(state.logs, {
      level: 'error',
      message: contextualMessage,
    }),
  }
}

export const buildObfuscationRequest = (state: RunState): ObfuscationRequest => {
  if (state.inputJar === null) {
    throw new Error('无法启动混淆：尚未载入 Jar 文件。')
  }

  if (state.inputJar.inputJarPath.trim().length === 0) {
    throw new Error('无法启动混淆：输入 Jar 路径为空。')
  }

  if (state.outputJarPath.trim().length === 0) {
    throw new Error('无法启动混淆：输出 Jar 路径为空。')
  }

  const enabledPasses: readonly PassSpec[] = state.passes
    .filter((passItem: PassItem): boolean => passItem.enabled)
    .map((passItem: PassItem): PassSpec => ({
      id: passItem.id,
      enabled: passItem.enabled,
      params: visiblePassParams(passItem),
    }))

  if (enabledPasses.length === 0) {
    throw new Error('无法启动混淆：未启用任何可运行模块。')
  }

  const enabledPassIds = new Set<string>(enabledPasses.map((passSpec: PassSpec): string => passSpec.id))
  const unsatisfiedPass = state.passes.find((passItem: PassItem): boolean => (
    passItem.enabled && requiresAnyPassIdsFor(passItem).length > 0 && requiresAnyPassIdsFor(passItem).every((passId: string): boolean => !enabledPassIds.has(passId))
  ))
  if (unsatisfiedPass !== undefined) {
    throw new Error(`无法启动混淆：${unsatisfiedPass.id} 需要同时启用至少一个运行时辅助模块。`)
  }

  const passSelections = state.passSelections
    .filter((selection): boolean => selection.mode === 'selected-only' && enabledPassIds.has(selection.passId))
    .map((selection): PassSelection => {
      const pass = state.passes.find((candidate): boolean => candidate.id === selection.passId)
      if (pass === undefined || !passSupportsTargeting(pass)) {
        throw new Error(`无法启动混淆：${selection.passId} 不支持类/方法范围选择。`)
      }

      const rules = normalizeRuleItems(selection.rules, `pass-rule-${selection.passId}`)

      for (const rule of rules) {
        const parsedTarget = parsePassSelectionTarget(rule.target)
        if (parsedTarget === null) {
          throw new Error(`无法启动混淆：${selection.passId} 包含非 canonical 类/方法的范围规则：${rule.target}`)
        }
        if (!pass.targeting.targetKinds.includes(parsedTarget.kind)) {
          throw new Error(`无法启动混淆：${selection.passId} 不支持 ${parsedTarget.kind} 范围：${rule.target}`)
        }
      }

      return {
        passId: selection.passId,
        mode: 'selected-only',
        rules,
      }
    })

  return {
    inputJarPath: state.inputJar.inputJarPath,
    outputJarPath: state.outputJarPath,
    passes: enabledPasses,
    rules: normalizeRuleItems(state.rules, 'rule'),
    passSelections,
    allowOptInPasses: state.passes.some((passItem: PassItem): boolean => passItem.enabled && passItem.requiresOptIn),
    allowRedundantPasses: hasEnabledSoftCompatibilityConflict(state.passes, state.schema?.compatibility ?? []),
  }
}

export const countEnabledPasses = (passes: readonly PassItem[]): number =>
  passes.filter((passItem: PassItem): boolean => passItem.enabled).length

export const visiblePassParams = (passItem: Pick<PassItem, 'params' | 'paramSchemas'>): Readonly<Record<string, PassParamValue>> => {
  const visibleParamKeys = new Set<string>(passItem.paramSchemas.map((paramSchema): string => paramSchema.key))
  return Object.fromEntries(
    Object.entries(passItem.params).filter(([key]): boolean => visibleParamKeys.has(key)),
  )
}


const normalizePasses = (
  passes: readonly PassItem[],
  compatibility: readonly PassCompatibilityRule[],
  orderingConstraints: readonly OrderingConstraint[],
  preferredPassId: string | null = null,
): readonly PassItem[] => reorderByConstraints(
  applyPassRequiresAnyConstraints(resolvePassCompatibility(applyPassDependencies(passes), compatibility, preferredPassId)),
  orderingConstraints,
)

export const ruleActionLabel = (action: RuleAction): string => {
  if (action === 'obfuscate') {
    return '混淆'
  }

  return '跳过'
}

export const ruleActionTone = (action: RuleAction): 'success' | 'error' => {
  if (action === 'obfuscate') {
    return 'success'
  }

  return 'error'
}

export const nodeRuleAction = (rules: readonly RuleItem[], node: ClassTreeNode): RuleAction => resolveRuleAction(rules, node, 'obfuscate')

/** selected-only is an independent range with an implicit all-obfuscate baseline. */
export const nodePassSelectionAction = (rules: readonly RuleItem[], node: ClassTreeNode): RuleAction => resolveRuleAction(rules, node, 'obfuscate')

const cloneEngineSchema = (schema: EngineSchemaPayload): EngineSchemaPayload => ({
  schemaVersion: schema.schemaVersion,
  engineVersion: schema.engineVersion,
  vbcVersion: schema.vbcVersion,
  tags: schema.tags.map((tag) => ({ ...tag })),
  modules: schema.modules.map((moduleDefinition) => ({
    ...moduleDefinition,
    tagIds: [...moduleDefinition.tagIds],
    requiredPassIds: [...(moduleDefinition.requiredPassIds ?? [])],
    requiresAnyPassIds: [...(moduleDefinition.requiresAnyPassIds ?? [])],
    targeting: cloneTargeting(moduleDefinition.targeting),
    variantRequirements: (moduleDefinition.variantRequirements ?? []).map((requirement) => ({
      ...requirement,
      requiredPassIds: [...(requirement.requiredPassIds ?? [])],
      requiresAnyPassIds: [...(requirement.requiresAnyPassIds ?? [])],
    })),
    params: moduleDefinition.params.map((paramSchema) => ({ ...paramSchema })),
  })),
  compatibility: schema.compatibility.map((rule) => ({
    ...rule,
    passIds: [...rule.passIds],
  })),
  orderingConstraints: schema.orderingConstraints.map((constraint) => ({ ...constraint })),
  defaultPipeline: [...schema.defaultPipeline],
})

const appendLogLine = (
  logs: readonly LogLine[],
  input: Pick<LogLine, 'level' | 'message'>,
): readonly LogLine[] => [
  ...logs,
  {
    id: `${Date.now()}-${logs.length}`,
    level: input.level,
    message: input.message,
    createdAt: new Date().toISOString(),
  },
].slice(-500)

const clampProgress = (progress: number): number => Math.max(0, Math.min(100, progress))

const formatBytes = (bytes: number): string => {
  if (bytes <= 0) {
    return '0 B'
  }

  const units: readonly string[] = ['B', 'KB', 'MB', 'GB']
  const exponent: number = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const value: number = bytes / (1024 ** exponent)
  return `${value.toFixed(value >= 10 || exponent === 0 ? 0 : 1)} ${units[exponent]}`
}

const extractFileName = (inputJarPath: string): string => {
  const normalizedPath: string = inputJarPath.replace(/\\/g, '/')
  const segments: readonly string[] = normalizedPath.split('/')
  return segments[segments.length - 1] ?? inputJarPath
}

const deriveOutputJarPath = (inputJarPath: string): string => {
  const trimmedPath: string = inputJarPath.trim()
  if (trimmedPath.length === 0) {
    return ''
  }

  const jarSuffix = '.jar'
  if (trimmedPath.toLowerCase().endsWith(jarSuffix)) {
    return `${trimmedPath.slice(0, -jarSuffix.length)}-shrouded.jar`
  }

  return `${trimmedPath}-shrouded.jar`
}

const buildRuleTarget = (node: ClassTreeNode): string => {
  if (typeof node.selector === 'string' && node.selector.trim().length > 0) {
    return node.selector
  }
  if (node.kind === 'package') {
    return node.internalName.length === 0 ? '*' : `${node.internalName}/*`
  }
  return node.internalName
}

const syncRulesWithClassTree = (rules: readonly RuleItem[], nodes: readonly ClassTreeNode[]): readonly RuleItem[] => {
  const validTargets = new Set<string>(collectClassTreeTargets(nodes))
  return normalizeRuleItems(rules.filter((rule): boolean => validTargets.has(rule.target)), 'rule')
}

const syncPassSelectionsWithClassTree = (
  passSelections: readonly PassSelection[],
  nodes: readonly ClassTreeNode[],
): readonly PassSelection[] => {
  const validTargets = new Set<string>(collectClassTreeTargets(nodes, true))
  return passSelections.map((selection): PassSelection => ({
    ...selection,
    rules: normalizeRuleItems(selection.rules.filter((rule): boolean => validTargets.has(rule.target)), `pass-rule-${selection.passId}`),
  }))
}

const collectClassTreeTargets = (nodes: readonly ClassTreeNode[], classAndMethodOnly = false): readonly string[] => {
  const targets: string[] = []
  const visitNode = (node: ClassTreeNode): void => {
    if (!classAndMethodOnly || node.kind === 'class' || node.kind === 'method') {
      targets.push(buildRuleTarget(node))
    }
    node.children.forEach(visitNode)
  }
  nodes.forEach(visitNode)
  return targets
}

const countPassSelectionRules = (passSelections: readonly PassSelection[]): number => passSelections.reduce(
  (count, selection): number => count + selection.rules.length,
  0,
)

const summarizeRemovedPassRules = (
  before: readonly PassSelection[],
  after: readonly PassSelection[],
): string => {
  const afterRuleCounts = new Map<string, number>(after.map((selection): [string, number] => [selection.passId, selection.rules.length]))
  return before
    .map((selection): readonly [string, number] => [selection.passId, Math.max(0, selection.rules.length - (afterRuleCounts.get(selection.passId) ?? 0))])
    .filter(([, removedCount]): boolean => removedCount > 0)
    .sort(([leftPassId], [rightPassId]): number => leftPassId.localeCompare(rightPassId))
    .map(([passId, removedCount]): string => `${passId} -${removedCount}`)
    .join('，')
}

const resolveRuleAction = (
  rules: readonly RuleItem[],
  node: ClassTreeNode,
  defaultAction: RuleAction,
): RuleAction => {
  const target = buildRuleTarget(node)
  const exact = rules.find((rule): boolean => rule.target === target)
  if (exact !== undefined) {
    return exact.action
  }
  return resolveInheritedRuleAction(rules, node) ?? defaultAction
}

const resolveInheritedRuleAction = (rules: readonly RuleItem[], node: ClassTreeNode): RuleAction | undefined => {
  const target = buildRuleTarget(node)
  let best: RuleItem | undefined
  for (const rule of rules) {
    if (rule.target === target || !ruleMatchesNode(rule.target, node)) {
      continue
    }
    if (best === undefined || ruleSpecificity(rule.target) > ruleSpecificity(best.target)) {
      best = rule
    }
  }
  return best?.action
}

const ruleSpecificity = (target: string): number => target === '*' ? 0 : target.endsWith('/*') ? target.length - 2 : target.length + 1000

const ruleMatchesNode = (ruleTarget: string, node: ClassTreeNode): boolean => {
  if (ruleTarget === '*') {
    return true
  }
  const target = buildRuleTarget(node)
  const classTarget = target.split('#', 1)[0] ?? target
  if (ruleTarget.endsWith('/*')) {
    const packagePrefix = ruleTarget.slice(0, -1)
    return classTarget.startsWith(packagePrefix)
  }
  if (target.includes('#')) {
    return target.startsWith(`${ruleTarget}#`)
  }
  return target === ruleTarget
}

const normalizeRuleItems = (rules: readonly RuleItem[], idPrefix: string): readonly RuleItem[] => {
  const byTarget = new Map<string, RuleItem>()
  rules.forEach((rule, index): void => {
    const target = rule.target.trim()
    if (target.length === 0 || !isKnownRuleAction(rule.action)) {
      return
    }
    byTarget.set(target, {
      id: rule.id.trim().length > 0 ? rule.id : `${idPrefix}-${index}-${target}`,
      target,
      action: rule.action,
    })
  })
  return [...byTarget.values()]
}

const normalizePassSelections = (passSelections: readonly PassSelection[]): readonly PassSelection[] => {
  const byPassId = new Map<string, PassSelection>()
  passSelections.forEach((selection): void => {
    const passId = selection.passId.trim()
    if (passId.length === 0 || selection.mode !== 'selected-only') {
      return
    }
    byPassId.set(passId, {
      passId,
      mode: 'selected-only',
      rules: normalizeRuleItems(selection.rules, `pass-rule-${passId}`),
    })
  })
  return [...byPassId.values()]
}

const createRule = (prefix: string, index: number, target: string, action: RuleAction): RuleItem => ({
  id: `${prefix}-${Date.now()}-${index}`,
  target,
  action,
})

const requirePassForSelection = (state: RunState, passId: string): PassItem => {
  const pass = state.passes.find((candidate): boolean => candidate.id === passId)
  if (pass === undefined) {
    throw new Error(`未知 Pass：${passId}`)
  }
  return pass
}

const cloneTargeting = (targeting: TargetingCapability): TargetingCapability => ({
  supported: targeting.supported,
  targetKinds: [...targeting.targetKinds],
})
