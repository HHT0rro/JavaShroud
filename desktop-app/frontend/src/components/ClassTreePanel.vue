<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { ScanLine } from 'lucide-vue-next'
import { NButton, NInput, NTag } from 'naive-ui'
import ClassTreeVirtualList from './ClassTreeVirtualList.vue'
import LiquidGlass from './LiquidGlass.vue'
import type { ClassTreeNode, PassItem, PassSelection, PassSelectionMode, RuleAction, RuleItem, RunStatus } from '../modules/obfuscation/types'
import { nodePassSelectionAction, nodeRuleAction, passSelectionFor, passSelectionModeFor, passSupportsTargeting } from '../modules/obfuscation/state'
import { resolveActivePassScopeTabId, resolvePassScopeTabIdForKey } from '../modules/obfuscation/pass-scope-tabs'
import type { DisplayLanguage } from '../modules/obfuscation/pass-localization'

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
const activePassId = ref<string | null>(null)
const locked = computed((): boolean => props.status === 'running' || props.status === 'canceling')
const enabledPasses = computed((): readonly PassItem[] => props.passes.filter((pass): boolean => pass.enabled))
const activePass = computed((): PassItem | null => enabledPasses.value.find((pass): boolean => pass.id === activePassId.value) ?? null)
const activeSelection = computed((): PassSelection | undefined => activePass.value === null ? undefined : passSelectionFor(props.passSelections, activePass.value.id))
const activeMode = computed((): PassSelectionMode => activePass.value === null ? 'inherit-global' : passSelectionModeFor(props.passSelections, activePass.value.id))
const activeRules = computed((): readonly RuleItem[] => activeMode.value === 'selected-only' ? (activeSelection.value?.rules ?? []) : props.rules)
const activeExcludedTargetCount = computed((): number => activeSelection.value?.rules.filter((rule): boolean => rule.action === 'exclude').length ?? 0)
const hasScannedJar = computed((): boolean => props.nodes.length > 0)

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

// Keep scope-impact work independent from query/scroll updates. Large-Jar
// filtering should only rebuild virtual visible rows, not rescan every Pass.
const scopeImpactByPass = computed((): ReadonlyMap<string, ScopeImpact> => new Map<string, ScopeImpact>(
  enabledPasses.value
    .filter(passSupportsTargeting)
    .map((pass): [string, ScopeImpact] => {
      const mode = passSelectionModeFor(props.passSelections, pass.id)
      const rules = mode === 'selected-only' ? (passSelectionFor(props.passSelections, pass.id)?.rules ?? []) : props.rules
      return [pass.id, scopeImpactFor(pass, mode, rules)]
    }),
))
const activeScopeImpact = computed((): ScopeImpact | null => (
  activePass.value === null || !passSupportsTargeting(activePass.value)
    ? null
    : scopeImpactByPass.value.get(activePass.value.id) ?? { classes: 0, methods: 0 }
))

const passScopeTabId = (passId: string): string => `pass-scope-tab-${passId}`
const passScopePanelId = (passId: string): string => `pass-scope-panel-${passId}`

watch(enabledPasses, (passes): void => {
  activePassId.value = resolveActivePassScopeTabId(
    passes.map((pass): string => pass.id),
    activePassId.value,
  )
}, { immediate: true })

const selectPass = async (passId: string, focus = false): Promise<void> => {
  if (!enabledPasses.value.some((pass): boolean => pass.id === passId)) return
  activePassId.value = passId
  if (!focus) return
  await nextTick()
  const tab = document.getElementById(passScopeTabId(passId))
  if (tab instanceof HTMLButtonElement) tab.focus()
}

const handleTabKeydown = (event: KeyboardEvent, passId: string): void => {
  const nextPassId = resolvePassScopeTabIdForKey(
    enabledPasses.value.map((pass): string => pass.id),
    passId,
    event.key,
  )
  if (nextPassId === null) return
  event.preventDefault()
  void selectPass(nextPassId, true)
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
const scopeModeLabel = (passId: string): string => passSelectionModeFor(props.passSelections, passId) === 'selected-only'
  ? (props.displayLanguage === 'zh' ? '独立范围（默认全混淆）' : 'Independent scope (all by default)')
  : (props.displayLanguage === 'zh' ? '同步全局' : 'Inherit global')
const selectMode = (mode: PassSelectionMode): void => {
  if (activePass.value !== null) emit('passSelectionModeChanged', activePass.value.id, mode)
}
const forwardNodeRuleChanged = (node: ClassTreeNode, action: RuleAction): void => emit('nodeRuleChanged', node, action)
const forwardPassRuleChanged = (node: ClassTreeNode, action: RuleAction): void => {
  if (activePass.value !== null) emit('passSelectionRuleChanged', activePass.value.id, node, action)
}
</script>

<template>
  <LiquidGlass as="section" level="surface" class="panel tree-panel">
    <div class="panel-head">
      <div>
        <p class="eyebrow">{{ displayLanguage === 'zh' ? '类树与规则' : 'Class tree and rules' }}</p>
        <h2>{{ displayLanguage === 'zh' ? '混淆范围' : 'Obfuscation scope' }}</h2>
      </div>
      <NTag size="small" round>{{ classCount }} {{ displayLanguage === 'zh' ? '类' : 'classes' }}</NTag>
    </div>

    <div class="panel-toolbar tree-panel-toolbar">
      <p class="panel-note">{{ displayLanguage === 'zh' ? '全局排除基线会被默认 Pass 实时继承；独立范围不会继承全局规则，默认混淆该 Pass 支持的全部目标。' : 'The global exclusion baseline is live-inherited by default. Independent scopes do not inherit it and obfuscate every target supported by the pass by default.' }}</p>
      <NButton tertiary :disabled="locked" :loading="inspecting" @click="emit('inspect')">
        <template #icon><ScanLine :size="16" /></template>
        {{ displayLanguage === 'zh' ? '扫描 Jar' : 'Scan Jar' }}
      </NButton>
    </div>

    <div class="tree-filter">
      <NInput v-model:value="query" clearable :disabled="locked" :placeholder="displayLanguage === 'zh' ? '搜索类名、方法名或 descriptor' : 'Search class, method, or descriptor'" />
    </div>

    <section class="scope-section">
      <div class="scope-section__head">
        <div>
          <p class="eyebrow">{{ displayLanguage === 'zh' ? '全局排除基线' : 'Global exclusion baseline' }}</p>
          <p class="panel-note">{{ displayLanguage === 'zh' ? '包、类、字段和方法均可设置跳过或恢复混淆。' : 'Packages, classes, fields, and methods can be skipped or restored.' }}</p>
        </div>
        <NTag size="small" round>{{ rules.length }}</NTag>
      </div>
      <ClassTreeVirtualList
        v-if="hasScannedJar"
        :nodes="nodes"
        :rules="rules"
        :query="query"
        :display-language="displayLanguage"
        :disabled="locked"
        :aria-label="displayLanguage === 'zh' ? '全局排除基线类树' : 'Global exclusion baseline class tree'"
        @node-rule-changed="forwardNodeRuleChanged"
      />
      <div v-else class="empty-state scope-empty scope-empty--inline">
        <strong>{{ displayLanguage === 'zh' ? '还没有类树' : 'No class tree yet' }}</strong>
        <span>{{ displayLanguage === 'zh' ? '选择输入 Jar 后扫描类树；已导入的独立范围会保留，并会在下次扫描后同步清理。' : 'Choose an input Jar and scan it. Imported independent scopes are kept and pruned on the next scan.' }}</span>
      </div>
    </section>

    <section class="scope-section scope-section--passes">
      <div class="scope-section__head">
        <div>
          <p class="eyebrow">{{ displayLanguage === 'zh' ? '已启用 Pass 范围' : 'Enabled pass scopes' }}</p>
          <p class="panel-note">{{ displayLanguage === 'zh' ? '按实际 pipeline 顺序横向浏览；禁用后独立范围仍保留，但不会下发运行请求。' : 'Browse in pipeline order horizontally. Disabled passes keep their scope, but it is not sent with a run request.' }}</p>
        </div>
        <NTag size="small" round>{{ enabledPasses.length }}</NTag>
      </div>

      <div v-if="enabledPasses.length === 0" class="empty-state scope-empty">
        <strong>{{ displayLanguage === 'zh' ? '尚未启用 Pass' : 'No enabled passes' }}</strong>
      </div>
      <template v-else>
        <div class="pass-scope-tabs" role="tablist" :aria-label="displayLanguage === 'zh' ? '已启用 Pass 范围标签' : 'Enabled pass scope tabs'">
          <button
            v-for="pass in enabledPasses"
            :id="passScopeTabId(pass.id)"
            :key="pass.id"
            class="pass-scope-tab"
            :class="{ 'pass-scope-tab--unsupported': !passSupportsTargeting(pass) }"
            type="button"
            role="tab"
            :aria-selected="activePassId === pass.id"
            :aria-controls="passScopePanelId(pass.id)"
            :tabindex="activePassId === pass.id ? 0 : -1"
            @click="void selectPass(pass.id)"
            @keydown="handleTabKeydown($event, pass.id)"
          >
            <span class="pass-scope-tab__title">{{ pass.name }}</span>
            <span class="pass-scope-tab__id">{{ pass.id }}</span>
            <span class="pass-scope-tab__mode" :class="{ 'pass-scope-tab__mode--independent': passSelectionModeFor(passSelections, pass.id) === 'selected-only' }">{{ scopeModeLabel(pass.id) }}</span>
            <span class="pass-scope-tab__targeting">{{ targetingSummary(pass) }}</span>
            <span v-if="passSupportsTargeting(pass)" class="pass-scope-tab__impact">{{ passScopeImpactSummary(pass) }}</span>
          </button>
        </div>

        <article
          v-if="activePass !== null"
          :id="passScopePanelId(activePass.id)"
          class="active-pass-editor"
          role="tabpanel"
          :aria-labelledby="passScopeTabId(activePass.id)"
        >
          <div class="active-pass-editor__head">
            <div>
              <p class="eyebrow">{{ activePass.name }}</p>
              <h3>{{ displayLanguage === 'zh' ? '此 Pass 的混淆范围' : 'This pass scope' }}</h3>
            </div>
            <div v-if="activeScopeImpact !== null" class="active-pass-editor__metrics">
              <NTag size="small" type="default">{{ displayLanguage === 'zh' ? `${activeScopeImpact.classes} 类 / ${activeScopeImpact.methods} 方法` : `${activeScopeImpact.classes} classes / ${activeScopeImpact.methods} methods` }}</NTag>
              <NTag v-if="activeMode === 'selected-only'" size="small" type="success">{{ activeExcludedTargetCount }} {{ displayLanguage === 'zh' ? '个排除规则' : 'exclude rules' }}</NTag>
            </div>
          </div>

          <template v-if="!passSupportsTargeting(activePass)">
            <p class="panel-note">{{ displayLanguage === 'zh' ? '引擎 schema 将该 Pass 标记为工件级处理，因此没有可编辑的类或方法范围。' : 'The engine schema marks this as artifact-level processing, so no class or method scope is editable.' }}</p>
          </template>
          <template v-else>
            <div class="pass-scope-actions">
              <NButton :type="activeMode === 'inherit-global' ? 'primary' : 'default'" :disabled="locked || !hasScannedJar" @click="selectMode('inherit-global')">
                {{ displayLanguage === 'zh' ? '恢复同步全局' : 'Inherit global' }}
              </NButton>
              <NButton :type="activeMode === 'selected-only' ? 'primary' : 'default'" :disabled="locked || !hasScannedJar" @click="selectMode('selected-only')">
                {{ displayLanguage === 'zh' ? '使用独立范围' : 'Use independent scope' }}
              </NButton>
            </div>
            <p class="panel-note">
              {{ activeMode === 'inherit-global'
                ? (displayLanguage === 'zh' ? '当前实时继承全局排除基线；全局规则的任何变化都会立即反映在此 Pass。' : 'This pass currently live-inherits the global baseline; global rule changes apply immediately.')
                : (displayLanguage === 'zh' ? '默认会混淆该 Pass 支持的全部类和方法；点击类或方法将其设为跳过。若父级类被跳过，给更具体的方法设为混淆即可恢复该方法。' : 'This pass obfuscates every supported class and method by default. Click a class or method to skip it. A more-specific method obfuscate rule restores it beneath a skipped class.') }}
            </p>
            <ClassTreeVirtualList
              v-if="hasScannedJar"
              :key="activePass.id"
              :nodes="nodes"
              :rules="activeRules"
              :query="query"
              :display-language="displayLanguage"
              :selection-mode="activeMode === 'selected-only' ? 'selected-only' : 'global'"
              :selectable-kinds="activePass.targeting.targetKinds"
              :allowed-kinds="['package', 'class', 'method']"
              :disabled="locked || activeMode !== 'selected-only'"
              :aria-label="displayLanguage === 'zh' ? `${activePass.name} 范围类树` : `${activePass.name} scope class tree`"
              @node-rule-changed="forwardPassRuleChanged"
            />
            <div v-else class="empty-state scope-empty scope-empty--inline">
              <strong>{{ displayLanguage === 'zh' ? '请先扫描 Jar' : 'Scan the Jar first' }}</strong>
              <span>{{ displayLanguage === 'zh' ? '范围配置会保留；扫描后即可查看并编辑类与方法。' : 'Scope configuration is preserved; scan to inspect and edit classes and methods.' }}</span>
            </div>
          </template>
        </article>
      </template>
    </section>
  </LiquidGlass>
</template>
