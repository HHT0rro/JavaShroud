import {
  GLOBAL_CLASS_TREE_SCOPE_ID,
  buildClassTreeScopeItems,
  classTreeScopeModeLabel,
  independentExcludeCount,
  canChangePassSelectionMode,
  canEmitClassTreeRuleChange,
  classTreeRuleSource,
  excludeRuleCount,
  passRulesForScope,
  resolveActiveClassTreeScopeId,
  resolveClassTreeScopeIdForKey,
  resolveClassTreeScopeIds,
} from './class-tree-scope-view.ts'
import type { PassItem, PassSelection, RuleItem } from './types.ts'

const assert = (condition: boolean, message: string): void => {
  if (!condition) throw new Error(message)
}

const passIds = ['rename-classes', 'method-virtualization'] as const

assert(
  resolveClassTreeScopeIds(passIds).join(',') === 'global,rename-classes,method-virtualization',
  'expected global first then enabled passes',
)
assert(resolveActiveClassTreeScopeId(passIds, null) === GLOBAL_CLASS_TREE_SCOPE_ID, 'expected missing selection to fall back to global')
assert(resolveActiveClassTreeScopeId(passIds, 'method-virtualization') === 'method-virtualization', 'expected existing pass scope to stay selected')
assert(resolveActiveClassTreeScopeId(passIds, 'removed-pass') === GLOBAL_CLASS_TREE_SCOPE_ID, 'expected removed pass to fall back to global')
assert(resolveActiveClassTreeScopeId([], 'method-virtualization') === GLOBAL_CLASS_TREE_SCOPE_ID, 'expected empty pipeline to keep global')
assert(resolveClassTreeScopeIdForKey(passIds, GLOBAL_CLASS_TREE_SCOPE_ID, 'ArrowDown') === 'rename-classes', 'expected ArrowDown from global')
assert(resolveClassTreeScopeIdForKey(passIds, 'method-virtualization', 'ArrowDown') === GLOBAL_CLASS_TREE_SCOPE_ID, 'expected wrap to global')
assert(resolveClassTreeScopeIdForKey(passIds, 'rename-classes', 'ArrowUp') === GLOBAL_CLASS_TREE_SCOPE_ID, 'expected ArrowUp to global')
assert(resolveClassTreeScopeIdForKey(passIds, 'rename-classes', 'Home') === GLOBAL_CLASS_TREE_SCOPE_ID, 'expected Home to global')
assert(resolveClassTreeScopeIdForKey(passIds, GLOBAL_CLASS_TREE_SCOPE_ID, 'End') === 'method-virtualization', 'expected End to last pass')
assert(resolveClassTreeScopeIdForKey(passIds, 'rename-classes', 'Enter') === null, 'expected native activation keys to remain native')

assert(classTreeScopeModeLabel('inherit-global', 'zh').includes('实时继承'), 'expected inherit-global to be live global')
assert(classTreeScopeModeLabel('selected-only', 'en').includes('all by default'), 'expected selected-only to be independent all-obfuscate')

const globalRule: RuleItem = { id: 'g', target: 'sample/Target', action: 'exclude' }
const independentRule: RuleItem = { id: 'p', target: 'sample/Target#find:(I)Ljava/lang/String;', action: 'exclude' }
const selections: readonly PassSelection[] = [
  { passId: 'rename-classes', mode: 'inherit-global', rules: [] },
  { passId: 'method-virtualization', mode: 'selected-only', rules: [independentRule] },
]
assert(passRulesForScope('rename-classes', 'inherit-global', selections, [globalRule])[0]?.id === 'g', 'inherit-global must reuse live global rules')
assert(passRulesForScope('method-virtualization', 'selected-only', selections, [globalRule])[0]?.id === 'p', 'selected-only must use independent rules')
assert(passRulesForScope('missing', 'selected-only', selections, [globalRule]).length === 0, 'missing independent scope defaults to empty rules')
assert(independentExcludeCount(selections[1]) === 1, 'expected independent exclude count')
assert(independentExcludeCount(selections[0]) === 0, 'empty independent rules are not a whitelist')

const inheritRules = passRulesForScope('rename-classes', 'inherit-global', selections, [globalRule])
assert(excludeRuleCount(inheritRules) === 1, 'inherit-global effective exclusions come from live global rules')
assert(classTreeRuleSource(false, 'inherit-global') === 'inherited-global', 'inherit-global source is live global')
assert(classTreeRuleSource(false, 'selected-only') === 'independent', 'selected-only source is independent')
assert(excludeRuleCount(inheritRules) === 1, 'inherited summary must not stay at 0 when global exclusions exist')
assert(excludeRuleCount([]) === 0, 'empty independent rules still mean all-obfuscate')

const passes: readonly Pick<PassItem, 'id' | 'name' | 'targeting'>[] = [
  {
    id: 'rename-classes',
    name: 'Rename',
    targeting: { supported: true, targetKinds: ['class'] },
  },
  {
    id: 'artifact-pass',
    name: 'Artifact',
    targeting: { supported: false, targetKinds: [] },
  },
]
const items = buildClassTreeScopeItems(passes, selections, 'en')
assert(items[0]?.id === GLOBAL_CLASS_TREE_SCOPE_ID && items[0]?.kind === 'global', 'sidebar starts with global')
assert(items[1]?.independent === false && items[1]?.targeting === true, 'inherit-global pass is not independent')
assert(items[2]?.targeting === false, 'artifact-level pass has no class tree')
assert(canChangePassSelectionMode(false, true, passes[0]!) === true, 'targeting pass can switch mode')
assert(canChangePassSelectionMode(false, true, passes[1]!) === false, 'artifact-level pass cannot switch mode')
assert(canChangePassSelectionMode(true, true, passes[0]!) === false, 'locked status cannot switch mode')
assert(canEmitClassTreeRuleChange(false, true, 'inherit-global', null, { kind: 'field' }) === true, 'global scope can edit any node')
assert(canEmitClassTreeRuleChange(false, false, 'inherit-global', passes[0]!, { kind: 'class' }) === false, 'inherit-global tree is read-only')
assert(canEmitClassTreeRuleChange(false, false, 'selected-only', passes[0]!, { kind: 'class' }) === true, 'independent class targeting can emit')
assert(canEmitClassTreeRuleChange(false, false, 'selected-only', passes[0]!, { kind: 'method' }) === false, 'class-only pass cannot emit method rules')
assert(canEmitClassTreeRuleChange(false, false, 'selected-only', passes[1]!, { kind: 'class' }) === false, 'unsupported pass cannot emit')
assert(canEmitClassTreeRuleChange(true, false, 'selected-only', passes[0]!, { kind: 'class' }) === false, 'locked cannot emit')

console.log('class-tree-scope-view checks passed')
