import { applyPassDependencies, applyPassRequiresAnyConstraints, buildPassItemsFromSchema, clonePassItem, disablePassAndDependents } from './pass-catalog'
import { hasEnabledSoftCompatibilityConflict, resolvePassCompatibility } from './pass-compatibility'
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
  PassSpec,
  RuleAction,
  RuleItem,
  RulePatch,
  RunState,
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
      passItem.id === passId ? { ...passItem, enabled: true } : passItem
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
    })),
    state.schema?.compatibility ?? [],
    state.schema?.orderingConstraints ?? [],
  ),
})

export const setPassParam = (state: RunState, passId: string, paramKey: string, value: PassParamValue): RunState => ({
  ...state,
  passes: state.passes.map((passItem: PassItem): PassItem => (
    passItem.id === passId
      ? { ...passItem, params: { ...passItem.params, [paramKey]: value } }
      : passItem
  )),
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

export const setJarInspection = (state: RunState, payload: JarInspectionPayload): RunState => ({
  ...state,
  classTree: payload.nodes,
  classCount: payload.classCount,
  packageCount: payload.packageCount,
  inspectingClasses: false,
  rules: syncRulesWithClassTree(state.rules, payload.nodes),
  logs: appendLogLine(state.logs, {
    level: 'info',
    message: `已扫描类树：${payload.classCount} 个类、${payload.packageCount} 个包。`,
  }),
})

export const setInspectingClassesFailed = (state: RunState): RunState => ({
  ...state,
  inspectingClasses: false,
})

export const setClassTreeRule = (state: RunState, node: ClassTreeNode, action: RuleAction): RunState => {
  const target: string = buildRuleTarget(node)
  const existingRule: RuleItem | undefined = state.rules.find((rule: RuleItem): boolean => rule.target === target)

  if (action === 'obfuscate') {
    if (existingRule?.action === 'exclude') {
      return hasInheritedExcludeRule(state.rules, node) ? updateRule(state, existingRule.id, { target, action: 'obfuscate' }) : removeRule(state, existingRule.id)
    }
    return existingRule === undefined && hasInheritedExcludeRule(state.rules, node) ? addRule(state, { target, action: 'obfuscate' }) : state
  }

  if (existingRule !== undefined) {
    return updateRule(state, existingRule.id, { target, action: 'exclude' })
  }

  return addRule(state, { target, action: 'exclude' })
}

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

  const newRule: RuleItem = {
    id: `rule-${Date.now()}-${state.rules.length}`,
    target: trimmedTarget,
    action: 'exclude',
  }

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
  rules: rules.map((rule: RuleItem, index: number): RuleItem => ({
    id: rule.id.trim().length > 0 ? rule.id : `rule-import-${Date.now()}-${index}`,
    target: rule.target.trim(),
    action: rule.action,
  })).filter((rule: RuleItem): boolean => rule.target.length > 0 && isKnownRuleAction(rule.action)),
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
    passItem.enabled && passItem.requiresAnyPassIds.length > 0 && passItem.requiresAnyPassIds.every((passId: string): boolean => !enabledPassIds.has(passId))
  ))
  if (unsatisfiedPass !== undefined) {
    throw new Error(`无法启动混淆：${unsatisfiedPass.id} 需要同时启用至少一个运行时辅助模块。`)
  }

  return {
    inputJarPath: state.inputJar.inputJarPath,
    outputJarPath: state.outputJarPath,
    passes: enabledPasses,
    rules: [...state.rules],
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

export const nodeRuleAction = (rules: readonly RuleItem[], node: ClassTreeNode): RuleAction => {
  const target: string = buildRuleTarget(node)
  const matchedRule: RuleItem | undefined = rules.find((rule: RuleItem): boolean => rule.target === target)
  if (matchedRule !== undefined) {
    return matchedRule.action
  }
  return hasInheritedExcludeRule(rules, node) ? 'exclude' : 'obfuscate'
}

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
  if (node.kind === 'package') {
    return node.internalName.length === 0 ? '*' : `${node.internalName}/*`
  }

  return node.internalName
}

const syncRulesWithClassTree = (rules: readonly RuleItem[], nodes: readonly ClassTreeNode[]): readonly RuleItem[] => {
  const validTargets: ReadonlySet<string> = new Set<string>(collectClassTreeTargets(nodes))
  return rules.filter((rule: RuleItem): boolean => validTargets.has(rule.target))
}

const collectClassTreeTargets = (nodes: readonly ClassTreeNode[]): readonly string[] => {
  const targets: string[] = []

  const visitNode = (node: ClassTreeNode): void => {
    targets.push(buildRuleTarget(node))
    node.children.forEach(visitNode)
  }

  nodes.forEach(visitNode)
  return targets
}

const hasInheritedExcludeRule = (rules: readonly RuleItem[], node: ClassTreeNode): boolean => {
  const target: string = buildRuleTarget(node)
  return rules.some((rule: RuleItem): boolean => rule.action === 'exclude' && rule.target !== target && ruleMatchesNode(rule.target, node))
}

const ruleMatchesNode = (ruleTarget: string, node: ClassTreeNode): boolean => {
  if (ruleTarget === '*') {
    return true
  }
  if (ruleTarget.endsWith('/*')) {
    const packagePrefix: string = ruleTarget.slice(0, -1)
    return node.internalName.startsWith(packagePrefix)
  }
  if (node.kind === 'field' || node.kind === 'method') {
    return node.internalName.startsWith(`${ruleTarget}#`)
  }
  return node.internalName === ruleTarget
}
