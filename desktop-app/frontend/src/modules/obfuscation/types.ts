export type RunStatus = 'idle' | 'ready' | 'running' | 'canceling' | 'done' | 'failed'

export type EngineEventType = 'progress' | 'log' | 'warn' | 'error' | 'done' | 'canceled'

export type EngineEventLevel = 'info' | 'warn' | 'error' | 'success'

export type RuleAction = 'obfuscate' | 'exclude'

export type PassSelectionMode = 'inherit-global' | 'selected-only'

export type TargetKind = 'class' | 'method'

export interface TargetingCapability {
  readonly supported: boolean
  readonly targetKinds: readonly TargetKind[]
}

export interface ParamSchema {
  readonly key: string
  readonly type: 'boolean' | 'string' | 'enum' | 'number'
  readonly defaultValue: unknown
  readonly options: readonly string[] | null
  readonly description: string
  readonly hidden: boolean
}

export interface ModuleTagDefinition {
  readonly id: string
  readonly name: string
  readonly description: string
}

export interface VariantRequirement {
  readonly whenParam: string
  readonly equals: string
  readonly requiredPassIds?: readonly string[]
  readonly requiresAnyPassIds?: readonly string[]
}

export interface ModuleDefinition {
  readonly id: string
  readonly name: string
  readonly description: string
  readonly tagIds: readonly string[]
  readonly stability: string
  readonly risk?: PassRisk
  readonly requiresRuntimeFlags?: readonly string[]
  readonly platformConstraints?: readonly string[]
  readonly compatibilityNotes?: string
  readonly requiredPassIds?: readonly string[]
  readonly requiresAnyPassIds?: readonly string[]
  readonly variantRequirements?: readonly VariantRequirement[]
  readonly defaultEnabled?: boolean
  readonly requiresOptIn?: boolean
  readonly targeting: TargetingCapability
  readonly params: readonly ParamSchema[]
}

export interface PassCompatibilityRule {
  readonly passIds: readonly string[]
  readonly severity: 'hard' | 'soft'
  readonly description: string
}

export interface OrderingConstraint {
  readonly before: string
  readonly after: string
  readonly reason: string
  readonly hard: boolean
}

export interface PlanningDiagnostic {
  readonly level: 'info' | 'warn' | 'error'
  readonly passes: readonly string[]
  readonly message: string
  readonly causeId: string | null
}

export interface EngineSchemaPayload {
  readonly schemaVersion: string
  readonly engineVersion: string
  readonly tags: readonly ModuleTagDefinition[]
  readonly modules: readonly ModuleDefinition[]
  readonly compatibility: readonly PassCompatibilityRule[]
  readonly orderingConstraints: readonly OrderingConstraint[]
  readonly defaultPipeline: readonly string[]
}

export type PassParamValue = boolean | string | number | null

export type PassRisk = 'low' | 'medium' | 'high'

export interface PassItem {
  readonly id: string
  readonly name: string
  readonly description: string
  readonly tagIds: readonly string[]
  readonly category: string
  readonly enabled: boolean
  readonly params: Readonly<Record<string, PassParamValue>>
  readonly paramSchemas: readonly ParamSchema[]
  readonly stability: string
  readonly risk: PassRisk
  readonly compatibilityNotes?: string
  readonly requiresOptIn: boolean
  readonly requiredPassIds: readonly string[]
  readonly requiresAnyPassIds: readonly string[]
  readonly variantRequirements: readonly VariantRequirement[]
  readonly targeting: TargetingCapability
  readonly dependencyAutoEnabled?: boolean
}

export interface PassSpec {
  readonly id: string
  readonly enabled: boolean
  readonly params: Readonly<Record<string, PassParamValue>>
}

export interface RuleItem {
  readonly id: string
  readonly target: string
  readonly action: RuleAction
}

export interface RulePatch {
  readonly target: string
  readonly action: RuleAction
}

export interface PassSelection {
  readonly passId: string
  readonly mode: PassSelectionMode
  readonly rules: readonly RuleItem[]
}

export interface ObfuscationRequest {
  readonly inputJarPath: string
  readonly outputJarPath: string
  readonly passes: readonly PassSpec[]
  readonly rules: readonly RuleItem[]
  readonly passSelections: readonly PassSelection[]
  readonly allowOptInPasses: boolean
  readonly allowRedundantPasses: boolean
  readonly allowAnnotationPasses?: boolean
}

export interface WorkbenchTomlPassConfig {
  readonly id: string
  readonly enabled: boolean
  readonly params: Readonly<Record<string, PassParamValue>>
}

export interface WorkbenchTomlRuleConfig {
  readonly id: string
  readonly target: string
  readonly action: string
}

export interface WorkbenchTomlPassSelectionConfig {
  readonly passId: string
  readonly mode: string
  readonly rules: readonly WorkbenchTomlRuleConfig[]
}

export interface WorkbenchTomlConfig {
  readonly version: number
  readonly inputJarPath: string
  readonly outputJarPath: string
  readonly passes: readonly WorkbenchTomlPassConfig[]
  readonly rules: readonly WorkbenchTomlRuleConfig[]
  readonly passSelections: readonly WorkbenchTomlPassSelectionConfig[]
}

export interface ConfigImportWarning {
  readonly message: string
}

export interface ConfigImportResult {
  readonly nextState: RunState
  readonly inputJarPath: string | null
  readonly warnings: readonly ConfigImportWarning[]
}

export interface EngineEvent {
  readonly level: EngineEventLevel
  readonly type: EngineEventType
  readonly message: string
  readonly progress: number | null
  readonly outPath: string | null
}

export interface LogLine {
  readonly id: string
  readonly level: EngineEventLevel
  readonly message: string
  readonly createdAt: string
}

export interface LoadedJarInfo {
  readonly fileName: string
  readonly inputJarPath: string
  readonly sizeLabel: string
  readonly detectedMainClass: string | null
}

export interface ClassTreeNode {
  readonly id: string
  readonly label: string
  readonly qualifiedName: string
  readonly internalName: string
  /** Engine-provided canonical selector. */
  readonly selector: string
  readonly kind: 'package' | 'class' | 'field' | 'method'
  readonly children: readonly ClassTreeNode[]
}

export interface JarInspectionPayload {
  readonly jarPath: string
  readonly classCount: number
  readonly packageCount: number
  readonly nodes: readonly ClassTreeNode[]
}

export interface RunState {
  readonly status: RunStatus
  readonly schema: EngineSchemaPayload | null
  readonly inputJar: LoadedJarInfo | null
  readonly outputJarPath: string
  readonly passes: readonly PassItem[]
  readonly rules: readonly RuleItem[]
  /** Only selected-only entries are stored; missing entries inherit the global rule baseline. */
  readonly passSelections: readonly PassSelection[]
  readonly classTree: readonly ClassTreeNode[]
  readonly classCount: number
  readonly packageCount: number
  readonly inspectingClasses: boolean
  readonly progress: number
  readonly currentStep: string | null
  readonly outputPath: string | null
  readonly logs: readonly LogLine[]
  readonly errorMessage: string | null
  readonly autoScroll: boolean
}
