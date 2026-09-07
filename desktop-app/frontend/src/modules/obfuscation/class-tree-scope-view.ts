import type { PassItem, PassSelection, PassSelectionMode, RuleItem } from './types.ts'
import { localizePassNameById, type DisplayLanguage } from './pass-localization.ts'

const passSelectionFor = (
  passSelections: readonly PassSelection[],
  passId: string,
): PassSelection | undefined => passSelections.find((selection): boolean => selection.passId === passId)

const passSelectionModeFor = (
  passSelections: readonly PassSelection[],
  passId: string,
): PassSelectionMode => passSelectionFor(passSelections, passId)?.mode ?? 'inherit-global'

const passSupportsTargeting = (pass: Pick<PassItem, 'targeting'>): boolean => (
  pass.targeting.supported && pass.targeting.targetKinds.length > 0
)

export const GLOBAL_CLASS_TREE_SCOPE_ID = 'global'

export type ClassTreeScopeId = typeof GLOBAL_CLASS_TREE_SCOPE_ID | string

export interface ClassTreeScopeItem {
  readonly id: ClassTreeScopeId
  readonly kind: 'global' | 'pass'
  readonly title: string
  readonly subtitle: string
  readonly modeLabel: string
  readonly targeting: boolean
  readonly independent: boolean
}

export const resolveClassTreeScopeIds = (enabledPassIds: readonly string[]): readonly ClassTreeScopeId[] => [
  GLOBAL_CLASS_TREE_SCOPE_ID,
  ...enabledPassIds,
]

export const resolveActiveClassTreeScopeId = (
  enabledPassIds: readonly string[],
  currentScopeId: ClassTreeScopeId | null,
): ClassTreeScopeId => {
  const ids = resolveClassTreeScopeIds(enabledPassIds)
  return currentScopeId !== null && ids.includes(currentScopeId)
    ? currentScopeId
    : GLOBAL_CLASS_TREE_SCOPE_ID
}

export const resolveClassTreeScopeIdForKey = (
  enabledPassIds: readonly string[],
  currentScopeId: ClassTreeScopeId,
  key: string,
): ClassTreeScopeId | null => {
  const ids = resolveClassTreeScopeIds(enabledPassIds)
  const currentIndex = ids.indexOf(currentScopeId)
  if (currentIndex < 0 || ids.length === 0) return null

  const last = ids.at(-1) ?? GLOBAL_CLASS_TREE_SCOPE_ID
  if (key === 'Home') return ids[0] ?? GLOBAL_CLASS_TREE_SCOPE_ID
  if (key === 'End') return last
  if (key === 'ArrowRight' || key === 'ArrowDown') return ids[(currentIndex + 1) % ids.length] ?? null
  if (key === 'ArrowLeft' || key === 'ArrowUp') return ids[(currentIndex - 1 + ids.length) % ids.length] ?? null
  return null
}

export const classTreeScopeModeLabel = (
  mode: PassSelectionMode,
  language: DisplayLanguage,
): string => mode === 'selected-only'
  ? (language === 'zh' ? '独立范围 · 默认全混淆' : 'Independent · all by default')
  : (language === 'zh' ? '同步全局 · 实时继承' : 'Inherit global · live')

export const buildClassTreeScopeItems = (
  enabledPasses: readonly Pick<PassItem, 'id' | 'name' | 'targeting'>[],
  passSelections: readonly PassSelection[],
  language: DisplayLanguage,
): readonly ClassTreeScopeItem[] => {
  const global: ClassTreeScopeItem = {
    id: GLOBAL_CLASS_TREE_SCOPE_ID,
    kind: 'global',
    title: language === 'zh' ? '全局基线' : 'Global baseline',
    subtitle: language === 'zh' ? '包 / 类 / 字段 / 方法' : 'Package / class / field / method',
    modeLabel: language === 'zh' ? '排除基线' : 'Exclusion baseline',
    targeting: true,
    independent: false,
  }
  return [
    global,
    ...enabledPasses.map((pass): ClassTreeScopeItem => {
      const independent = passSelectionModeFor(passSelections, pass.id) === 'selected-only'
      const targeting = passSupportsTargeting(pass)
      return {
        id: pass.id,
        kind: 'pass',
        title: localizePassNameById(pass.id, language),
        subtitle: pass.id,
        modeLabel: targeting
          ? classTreeScopeModeLabel(independent ? 'selected-only' : 'inherit-global', language)
          : (language === 'zh' ? '工件级 · 无类树' : 'Artifact-level · no tree'),
        targeting,
        independent,
      }
    }),
  ]
}

export const independentExcludeCount = (selection: PassSelection | undefined): number => (
  selection?.rules.filter((rule: RuleItem): boolean => rule.action === 'exclude').length ?? 0
)

export const excludeRuleCount = (rules: readonly RuleItem[]): number => (
  rules.filter((rule: RuleItem): boolean => rule.action === 'exclude').length
)

export const passRulesForScope = (
  passId: string,
  mode: PassSelectionMode,
  passSelections: readonly PassSelection[],
  globalRules: readonly RuleItem[],
): readonly RuleItem[] => (
  mode === 'selected-only'
    ? (passSelectionFor(passSelections, passId)?.rules ?? [])
    : globalRules
)

export type ClassTreeRuleSource = 'global' | 'inherited-global' | 'independent'

export const classTreeRuleSource = (
  isGlobalScope: boolean,
  mode: PassSelectionMode,
): ClassTreeRuleSource => {
  if (isGlobalScope) return 'global'
  return mode === 'selected-only' ? 'independent' : 'inherited-global'
}

export const classTreeRuleSourceLabel = (
  source: ClassTreeRuleSource,
  language: DisplayLanguage,
): string => {
  if (source === 'independent') return language === 'zh' ? '独立规则' : 'Independent rules'
  if (source === 'inherited-global') return language === 'zh' ? '实时全局规则' : 'Live global rules'
  return language === 'zh' ? '全局规则' : 'Global rules'
}

export const canChangePassSelectionMode = (
  locked: boolean,
  hasScannedJar: boolean,
  pass: Pick<PassItem, 'targeting'> | null,
): boolean => !locked && hasScannedJar && pass !== null && passSupportsTargeting(pass)

export const canEmitClassTreeRuleChange = (
  locked: boolean,
  isGlobalScope: boolean,
  mode: PassSelectionMode,
  pass: Pick<PassItem, 'targeting'> | null,
  node: { readonly kind: string },
): boolean => {
  if (locked) return false
  if (isGlobalScope) return true
  if (pass === null || !passSupportsTargeting(pass) || mode !== 'selected-only') return false
  return node.kind === 'class' || node.kind === 'method'
    ? pass.targeting.targetKinds.includes(node.kind)
    : false
}
