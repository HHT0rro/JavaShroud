<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { GitBranch, ScanLine } from 'lucide-vue-next'
import { NButton, NInput, NSelect, NTag } from 'naive-ui'
import ClassTreeScopeNav from './ClassTreeScopeNav.vue'
import ClassTreeVirtualList from './ClassTreeVirtualList.vue'
import LiquidGlass from './LiquidGlass.vue'
import type { ClassTreeNode, PassItem, PassSelection, PassSelectionMode, RuleAction, RuleItem, RunStatus } from '../modules/obfuscation/types'
import { nodePassSelectionAction, nodeRuleAction, passSelectionModeFor, passSupportsTargeting } from '../modules/obfuscation/state'
import {
  GLOBAL_CLASS_TREE_SCOPE_ID,
  buildClassTreeScopeItems,
  canChangePassSelectionMode,
  canEmitClassTreeRuleChange,
  classTreeRuleSource,
  classTreeRuleSourceLabel,
  classTreeScopeModeLabel,
  excludeRuleCount,
  passRulesForScope,
  resolveActiveClassTreeScopeId,
  resolveClassTreeScopeIdForKey,
  type ClassTreeScopeId,
} from '../modules/obfuscation/class-tree-scope-view'
import { localizePassName, type DisplayLanguage } from '../modules/obfuscation/pass-localization'

const props = defineProps<{
  readonly nodes: readonly ClassTreeNode[]
  readonly rules: readonly RuleItem[]
  readonly passSelections: readonly PassSelection[]
  readonly passes: readonly PassItem[]
  readonly classCount: number
  readonly inspecting: boolean
  readonly status: RunStatus
  readonly displayLanguage: DisplayLanguage
}>()

const emit = defineEmits<{
  readonly inspect: []
  readonly nodeRuleChanged: [node: ClassTreeNode, action: RuleAction]
  readonly passSelectionModeChanged: [passId: string, mode: PassSelectionMode]
  readonly passSelectionRuleChanged: [passId: string, node: ClassTreeNode, action: RuleAction]
}>()

const query = ref<string>('')
const activeScopeId = ref<ClassTreeScopeId>(GLOBAL_CLASS_TREE_SCOPE_ID)
const locked = computed((): boolean => props.status === 'running' || props.status === 'canceling')
const enabledPasses = computed((): readonly PassItem[] => props.passes.filter((pass): boolean => pass.enabled))
const isGlobalScope = computed((): boolean => activeScopeId.value === GLOBAL_CLASS_TREE_SCOPE_ID)
const activePass = computed((): PassItem | null => (
  isGlobalScope.value ? null : enabledPasses.value.find((pass): boolean => pass.id === activeScopeId.value) ?? null
))
const activeMode = computed((): PassSelectionMode => activePass.value === null ? 'inherit-global' : passSelectionModeFor(props.passSelections, activePass.value.id))
const activeRules = computed((): readonly RuleItem[] => (
  isGlobalScope.value || activePass.value === null
    ? props.rules
    : passRulesForScope(activePass.value.id, activeMode.value, props.passSelections, props.rules)
))
const hasScannedJar = computed((): boolean => props.nodes.length > 0)
const activeRuleSource = computed(() => classTreeRuleSource(isGlobalScope.value, activeMode.value))
const activeExcludedTargetCount = computed((): number => excludeRuleCount(activeRules.value))
const canSwitchMode = computed((): boolean => canChangePassSelectionMode(locked.value, hasScannedJar.value, activePass.value))
const scopeItems = computed(() => buildClassTreeScopeItems(enabledPasses.value, props.passSelections, props.displayLanguage))
const scopeSelectOptions = computed(() => scopeItems.value.map((item) => ({
  value: item.id,
  label: item.title,
})))
const onScopeSelect = (value: string): void => {
  void selectScope(value)
}

interface ScopeImpact {
  readonly classes: number
  readonly methods: number
}

const scopeImpactFor = (pass: PassItem, mode: PassSelectionMode, rules: readonly RuleItem[]): ScopeImpact => {
  let classes = 0
  let methods = 0
  const visit = (node: ClassTreeNode): void => {
    const action = mode === 'selected-only' ? nodePassSelectionAction(rules, node) : nodeRuleAction(rules, node)
    if (node.kind === 'class' && pass.targeting.targetKinds.includes('class') && action === 'obfuscate') classes += 1
    if (node.kind === 'method' && pass.targeting.targetKinds.includes('method') && action === 'obfuscate') methods += 1
    node.children.forEach(visit)
  }
  props.nodes.forEach(visit)
  return { classes, methods }
}

const scopeImpactByPass = computed((): ReadonlyMap<string, ScopeImpact> => new Map<string, ScopeImpact>(
  enabledPasses.value
    .filter(passSupportsTargeting)
    .map((pass): [string, ScopeImpact] => {
      const mode = passSelectionModeFor(props.passSelections, pass.id)
      const rules = passRulesForScope(pass.id, mode, props.passSelections, props.rules)
      return [pass.id, scopeImpactFor(pass, mode, rules)]
    }),
))
const activeScopeImpact = computed((): ScopeImpact | null => (
  activePass.value === null || !passSupportsTargeting(activePass.value)
    ? null
    : scopeImpactByPass.value.get(activePass.value.id) ?? { classes: 0, methods: 0 }
))

const scopeTabId = (scopeId: ClassTreeScopeId): string => `class-tree-scope-${scopeId}`

watch(enabledPasses, (passes): void => {
  activeScopeId.value = resolveActiveClassTreeScopeId(
    passes.map((pass): string => pass.id),
    activeScopeId.value,
  )
}, { immediate: true })

const selectScope = async (scopeId: ClassTreeScopeId, focus = false): Promise<void> => {
  const nextId = resolveActiveClassTreeScopeId(
    enabledPasses.value.map((pass): string => pass.id),
    scopeId,
  )
  activeScopeId.value = nextId
  if (!focus) return
  await nextTick()
  const tab = document.getElementById(scopeTabId(nextId))
  if (tab instanceof HTMLButtonElement) tab.focus()
}

const handleTabKeydown = (event: KeyboardEvent, scopeId: ClassTreeScopeId): void => {
  const nextScopeId = resolveClassTreeScopeIdForKey(
    enabledPasses.value.map((pass): string => pass.id),
    scopeId,
    event.key,
  )
  if (nextScopeId === null) return
  event.preventDefault()
  void selectScope(nextScopeId, true)
}

const targetingSummary = (pass: PassItem): string => {
  if (!passSupportsTargeting(pass)) return props.displayLanguage === 'zh' ? '不支持类/方法范围选择' : 'No class/method targeting'
  const kinds = pass.targeting.targetKinds.map((kind): string => kind === 'class' ? (props.displayLanguage === 'zh' ? '类' : 'class') : (props.displayLanguage === 'zh' ? '方法' : 'method'))
  return `${props.displayLanguage === 'zh' ? '可选：' : 'Targets: '}${kinds.join(' / ')}`
}

const passScopeImpactSummary = (pass: PassItem): string => {
  if (!passSupportsTargeting(pass)) return ''
  const impact = scopeImpactByPass.value.get(pass.id) ?? { classes: 0, methods: 0 }
  return props.displayLanguage === 'zh'
    ? `${impact.classes} 类 / ${impact.methods} 方法`
    : `${impact.classes} classes / ${impact.methods} methods`
}

const selectMode = (mode: PassSelectionMode): void => {
  if (!canChangePassSelectionMode(locked.value, hasScannedJar.value, activePass.value)) return
  if (activePass.value !== null) emit('passSelectionModeChanged', activePass.value.id, mode)
}
const forwardNodeRuleChanged = (node: ClassTreeNode, action: RuleAction): void => emit('nodeRuleChanged', node, action)
const forwardPassRuleChanged = (node: ClassTreeNode, action: RuleAction): void => {
  if (activePass.value !== null) emit('passSelectionRuleChanged', activePass.value.id, node, action)
}
const onTreeRuleChanged = (node: ClassTreeNode, action: RuleAction): void => {
  if (!canEmitClassTreeRuleChange(locked.value, isGlobalScope.value, activeMode.value, activePass.value, node)) return
  if (isGlobalScope.value) forwardNodeRuleChanged(node, action)
  else forwardPassRuleChanged(node, action)
}

const treeDisabled = computed((): boolean => {
  if (locked.value) return true
  if (isGlobalScope.value) return false
  return activeMode.value !== 'selected-only'
})

const showTree = computed((): boolean => (
  hasScannedJar.value && (isGlobalScope.value || (activePass.value !== null && passSupportsTargeting(activePass.value)))
))

const currentSummaryTitle = computed((): string => {
  if (isGlobalScope.value) return props.displayLanguage === 'zh' ? '全局排除基线' : 'Global exclusion baseline'
  return activePass.value === null
    ? (props.displayLanguage === 'zh' ? 'Pass 范围' : 'Pass scope')
    : localizePassName(activePass.value, props.displayLanguage)
})

const currentSummaryNote = computed((): string => {
  if (isGlobalScope.value) {
    return props.displayLanguage === 'zh'
      ? '包、类、字段和方法均可设置跳过或恢复混淆。默认 Pass 会实时继承这份基线。'
      : 'Packages, classes, fields, and methods can be skipped or restored. Default passes live-inherit this baseline.'
  }
  if (activePass.value === null) return ''
  if (!passSupportsTargeting(activePass.value)) {
    return props.displayLanguage === 'zh'
      ? '引擎 schema 将该 Pass 标记为工件级处理，因此没有可编辑的类或方法范围。'
      : 'The engine schema marks this as artifact-level processing, so no class or method scope is editable.'
  }
  if (activeMode.value === 'inherit-global') {
    return props.displayLanguage === 'zh'
      ? '当前实时继承全局排除基线；全局规则的任何变化都会立即反映在此 Pass。树只读，切换到独立范围后才能编辑。'
      : 'This pass live-inherits the global baseline; global rule changes apply immediately. The tree is read-only until you switch to an independent scope.'
  }
  return props.displayLanguage === 'zh'
    ? '独立范围不继承全局规则。空规则表示默认混淆该 Pass 支持的全部目标，不是选择白名单。点击类或方法将其设为跳过；更具体的方法混淆规则可在已跳过的类下恢复该方法。'
    : 'Independent scope does not inherit global rules. Empty rules obfuscate every target this pass supports by default — not a selection whitelist. Click a class or method to skip it; a more-specific method obfuscate rule restores it beneath a skipped class.'
})
</script>

<template>
  <LiquidGlass as="section" level="surface" class="panel tree-panel class-tree-panel">
    <div class="panel-head">
      <div>
        <p class="eyebrow">{{ displayLanguage === 'zh' ? '类树与规则' : 'Class tree and rules' }}</p>
        <h2>{{ displayLanguage === 'zh' ? '混淆范围' : 'Obfuscation scope' }}</h2>
      </div>
      <div class="scope-header-actions"><NTag size="small" round>{{ classCount }} {{ displayLanguage === 'zh' ? '类' : 'classes' }}</NTag><NButton tertiary :disabled="locked" :loading="inspecting" @click="emit('inspect')"><template #icon><ScanLine :size="16" /></template>{{ displayLanguage === 'zh' ? '扫描 Jar' : 'Scan Jar' }}</NButton></div>
    </div>

    <div class="panel-toolbar tree-panel-toolbar">
      <p class="panel-note">{{ displayLanguage === 'zh' ? '先选择全局规则或模块，再调整类与方法的处理范围。' : 'Choose global rules or a module first, then adjust how classes and methods are treated.' }}</p>
    </div>

    <div class="class-tree-layout">
      <aside class="class-tree-layout__scope">
        <p class="eyebrow">{{ displayLanguage === 'zh' ? '范围' : 'Scope' }}</p>
        <NSelect
          class="class-tree-scope-select"
          size="small"
          :value="activeScopeId"
          :options="scopeSelectOptions"
          :consistent-menu-width="false"
          :aria-label="displayLanguage === 'zh' ? '选择作用范围' : 'Choose scope'"
          @update:value="onScopeSelect"
        />
        <ClassTreeScopeNav
          :items="scopeItems"
          :active-id="activeScopeId"
          :display-language="displayLanguage"
          @select="void selectScope($event)"
          @key-navigate="handleTabKeydown"
        />
      </aside>

      <div class="class-tree-layout__main">
        <header class="class-tree-summary">
          <div class="class-tree-summary__copy">
            <p class="eyebrow">{{ currentSummaryTitle }}</p>
            <p v-if="!isGlobalScope && activePass !== null" class="class-tree-summary__id">{{ activePass.id }}</p>
            <div class="class-tree-summary__metrics">
              <NTag v-if="isGlobalScope" size="small" round>{{ classTreeRuleSourceLabel(activeRuleSource, displayLanguage) }} · {{ activeExcludedTargetCount }}</NTag>
              <template v-else-if="activePass !== null">
                <NTag size="small" round>{{ classTreeScopeModeLabel(activeMode, displayLanguage) }}</NTag>
                <NTag size="small" round>{{ classTreeRuleSourceLabel(activeRuleSource, displayLanguage) }} · {{ activeExcludedTargetCount }}</NTag>
                <NTag v-if="activeScopeImpact !== null" size="small" type="default">{{ passScopeImpactSummary(activePass) }}</NTag>
              </template>
            </div>
            <details class="class-tree-summary__help">
              <summary>{{ displayLanguage === 'zh' ? '范围说明' : 'Scope help' }}</summary>
              <p class="panel-note">{{ currentSummaryNote }}</p>
            </details>
          </div>
        </header>

        <div v-if="!isGlobalScope && activePass !== null && passSupportsTargeting(activePass)" class="pass-scope-actions">
          <NButton :type="activeMode === 'inherit-global' ? 'primary' : 'default'" :disabled="!canSwitchMode" @click="selectMode('inherit-global')">
            {{ displayLanguage === 'zh' ? '恢复同步全局' : 'Inherit global' }}
          </NButton>
          <NButton :type="activeMode === 'selected-only' ? 'primary' : 'default'" :disabled="!canSwitchMode" @click="selectMode('selected-only')">
            {{ displayLanguage === 'zh' ? '使用独立范围' : 'Use independent scope' }}
          </NButton>
        </div>

        <p v-else-if="!isGlobalScope && activePass !== null" class="panel-note">{{ targetingSummary(activePass) }}</p>

        <div class="tree-filter">
          <NInput v-model:value="query" clearable :placeholder="displayLanguage === 'zh' ? '搜索类名、方法名或 descriptor' : 'Search class, method, or descriptor'" />
        </div>

        <div class="class-tree-layout__viewport">
          <ClassTreeVirtualList
            v-if="showTree"
            :key="activeScopeId"
            :nodes="nodes"
            :rules="activeRules"
            :query="query"
            :display-language="displayLanguage"
            :selection-mode="isGlobalScope ? 'global' : (activeMode === 'selected-only' ? 'selected-only' : 'global')"
            :selectable-kinds="isGlobalScope ? undefined : activePass?.targeting.targetKinds"
            :allowed-kinds="isGlobalScope ? undefined : ['package', 'class', 'method']"
            :disabled="treeDisabled"
            :aria-label="isGlobalScope
              ? (displayLanguage === 'zh' ? '全局排除基线类树' : 'Global exclusion baseline class tree')
              : (displayLanguage === 'zh' ? `${activePass === null ? '' : localizePassName(activePass, displayLanguage)} 范围类树` : `${activePass === null ? '' : localizePassName(activePass, displayLanguage)} scope class tree`)"
            @node-rule-changed="onTreeRuleChanged"
          />
          <div v-else-if="!hasScannedJar" class="empty-state scope-empty scope-empty--inline">
            <strong>{{ displayLanguage === 'zh' ? '还没有类树' : 'No class tree yet' }}</strong>
            <span>{{ displayLanguage === 'zh' ? '选择输入 Jar 后扫描类树；已导入的独立范围会保留，并会在下次扫描后同步清理。' : 'Choose an input Jar and scan it. Imported independent scopes are kept and pruned on the next scan.' }}</span>
          </div>
          <div v-else class="empty-state scope-empty scope-empty--inline">
            <GitBranch :size="18" />
            <strong>{{ displayLanguage === 'zh' ? '此 Pass 无类树' : 'No class tree for this pass' }}</strong>
            <span v-if="activePass !== null">{{ targetingSummary(activePass) }}</span>
          </div>
        </div>
      </div>
    </div>
  </LiquidGlass>
</template>

<style scoped>
.class-tree-panel {
  display: flex;
  flex-direction: column;
  min-width: 0;
  width: 100%;
  max-width: 100%;
  min-height: 0;
  flex: 1 1 auto;
  height: 100%;
  overflow: hidden;
}

.tree-panel-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  min-width: 0;
  width: 100%;
}

.tree-panel-toolbar .panel-note {
  min-width: 0;
  flex: 1 1 auto;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.class-tree-layout {
  display: grid;
  grid-template-columns: minmax(0, 204px) minmax(0, 1fr);
  gap: 12px;
  min-width: 0;
  width: 100%;
  min-height: 0;
  flex: 1 1 auto;
}

.class-tree-layout__scope,
.class-tree-layout__main,
.class-tree-layout__viewport,
.class-tree-summary,
.class-tree-summary__copy {
  min-width: 0;
  width: 100%;
}

.class-tree-layout__scope {
  display: flex;
  flex-direction: column;
  gap: 8px;
  min-height: 0;
  padding: 10px;
  border-radius: 16px;
  background: rgba(237, 237, 237, 0.04);
  border: 1px solid rgba(237, 237, 237, 0.08);
}

.class-tree-scope-select {
  display: none;
  width: 100%;
}

.class-tree-layout__main {
  display: flex;
  flex-direction: column;
  gap: 8px;
  min-height: 0;
}

.class-tree-layout__viewport {
  min-height: 180px;
  flex: 1 1 auto;
  display: flex;
  flex-direction: column;
}

.class-tree-summary {
  display: flex;
  gap: 8px;
  align-items: flex-start;
}

.class-tree-summary__id {
  margin: 0;
  font-size: 12px;
  opacity: 0.62;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.class-tree-summary__metrics {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.class-tree-summary__help {
  min-width: 0;
}

.class-tree-summary__help summary {
  cursor: pointer;
  font-size: 12px;
  opacity: 0.78;
}

.class-tree-summary__help .panel-note {
  margin-top: 6px;
}

.pass-scope-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.tree-filter {
  flex: 0 0 auto;
  min-width: 0;
  width: 100%;
}

@media (max-width: 1100px) {
  .class-tree-layout {
    grid-template-columns: minmax(0, 1fr);
    grid-template-rows: auto minmax(180px, 1fr);
  }

  .class-tree-layout__scope {
    min-height: unset;
    max-height: 72px;
    padding: 6px 8px;
  }

  .class-tree-layout__scope .eyebrow {
    display: none;
  }

  .class-tree-scope-select {
    display: block;
  }

  .class-tree-layout__scope :deep(.class-tree-scope-nav) {
    display: none;
  }
}
.scope-header-actions { display: flex; align-items: center; gap: 10px; }
.tree-panel-toolbar { flex: 0 0 auto; padding: 12px 20px; }
.class-tree-layout { padding: 0 16px 16px; }
.class-tree-layout__main { overflow-y: auto; }
.class-tree-summary__copy { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 12px; }
.class-tree-summary__copy > .eyebrow { color: var(--text-soft); font-size: 13px; }
.class-tree-summary__help { flex-basis: 100%; }
.class-tree-summary__help[open] { padding-bottom: 6px; }
@media (max-width: 1100px) {
  .class-tree-panel > .panel-head { min-height: 60px; padding: 10px 16px; }
  .tree-panel-toolbar { display: none; }
  .class-tree-layout { padding: 10px; gap: 8px; grid-template-rows: 42px minmax(0, 1fr); }
  .class-tree-layout__scope { padding: 4px 8px; }
  .class-tree-layout__main { gap: 6px; }
  .class-tree-summary__copy { gap: 5px 10px; }
  .class-tree-summary__id { display: none; }
  .class-tree-summary__help { flex-basis: auto; }
  .class-tree-layout__viewport { min-height: 150px; }
}
</style>
