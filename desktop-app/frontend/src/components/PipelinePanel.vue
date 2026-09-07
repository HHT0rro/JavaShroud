<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { NAlert, NButton, NCheckbox, NInput, NInputNumber, NSelect, NSwitch, NTag } from 'naive-ui'
import { AlertTriangle, ArrowDown, ArrowUp, GripVertical, Search } from 'lucide-vue-next'
import draggable from 'vuedraggable'
import LiquidGlass from './LiquidGlass.vue'
import { clonePassItem } from '../modules/obfuscation/pass-catalog'
import {
  localizeCategoryLabel,
  localizeOptionLabel,
  localizeParamDescription,
  localizePassDescription,
  localizePassName,
  localizeRiskLabel,
  type DisplayLanguage,
} from '../modules/obfuscation/pass-localization'
import { conflictingPassIdsFor } from '../modules/obfuscation/pass-compatibility'
import {
  applyVisibleReorder,
  canMoveAmongVisible,
  filterPipelinePasses,
  movePassAmongVisible,
  pipelineFilterChips,
  resolveSelectedPassId,
  type PipelineFilterId,
} from '../modules/obfuscation/pipeline-workbench'
import type { PassCompatibilityRule, PassItem, PassParamValue, RunStatus } from '../modules/obfuscation/types'

const props = defineProps<{
  readonly passes: readonly PassItem[]
  readonly status: RunStatus
  readonly displayLanguage: DisplayLanguage
  readonly schemaCompatibility: readonly PassCompatibilityRule[]
}>()

const emit = defineEmits<{
  readonly passesChanged: [passes: readonly PassItem[]]
  readonly passToggled: [passId: string]
  readonly passParamChanged: [passId: string, paramKey: string, value: PassParamValue]
  readonly browseNativeShroudCli: [passId: string, paramKey: string]
}>()

const activeFilter = ref<PipelineFilterId>('all')
const searchQuery = ref<string>('')
const selectedPassId = ref<string | null>(null)
const narrowDetailOpen = ref<boolean>(false)

const filterChips = computed(() => pipelineFilterChips(props.passes))
const visiblePasses = computed((): PassItem[] => [...filterPipelinePasses(props.passes, activeFilter.value, searchQuery.value, props.displayLanguage)])

watch(
  [(): readonly PassItem[] => props.passes, activeFilter, searchQuery, (): DisplayLanguage => props.displayLanguage],
  (): void => {
    selectedPassId.value = resolveSelectedPassId(selectedPassId.value, visiblePasses.value)
  },
  { immediate: true },
)

const selectedPass = computed((): PassItem | null => {
  const id = selectedPassId.value
  if (id === null) {
    return null
  }
  return props.passes.find((passItem: PassItem): boolean => passItem.id === id) ?? null
})

const selectedFullIndex = computed((): number => {
  const id = selectedPassId.value
  if (id === null) {
    return -1
  }
  return props.passes.findIndex((passItem: PassItem): boolean => passItem.id === id)
})

const canMoveSelectedUp = computed((): boolean => canMoveAmongVisible(visiblePasses.value, selectedPassId.value, -1))
const canMoveSelectedDown = computed((): boolean => canMoveAmongVisible(visiblePasses.value, selectedPassId.value, 1))

const enabledCount = computed((): number => props.passes.filter((passItem: PassItem): boolean => passItem.enabled).length)
const hasEnabledAggressive = computed((): boolean => props.passes.some((p: PassItem): boolean => p.enabled && p.tagIds.includes('aggressive')))
const isLocked = (): boolean => props.status === 'running' || props.status === 'canceling'
const isPassInteractionDisabled = (): boolean => isLocked()
const canMovePass = (): boolean => true

const onDragUpdate = (value: PassItem[]): void => {
  const merged = applyVisibleReorder(props.passes, value).map(clonePassItem)
  emit('passesChanged', merged)
}

const onToggle = (passId: string): void => {
  const passItem = props.passes.find((candidate: PassItem): boolean => candidate.id === passId)
  if (passItem === undefined || isPassInteractionDisabled()) {
    return
  }
  emit('passToggled', passId)
}

const onSelectPass = (passId: string): void => {
  selectedPassId.value = passId
  narrowDetailOpen.value = true
}

const closeNarrowDetail = (): void => {
  narrowDetailOpen.value = false
}

const paramControlAria = (paramKey: string): string => {
  const passItem = selectedPass.value
  const name = passItem === null ? paramKey : localizePassName(passItem, props.displayLanguage)
  return props.displayLanguage === 'zh' ? `${name} 参数 ${paramKey}` : `${name} parameter ${paramKey}`
}

const isPathParam = (paramKey: string): boolean => paramKey === 'cliPath'

const paramPlaceholder = (paramSchema: { readonly type: string; readonly key: string }): string => {
  if (paramSchema.key === 'cliPath') {
    return props.displayLanguage === 'zh' ? '选择 nativeshroud.exe' : 'Choose nativeshroud.exe'
  }
  if (paramSchema.type === 'number') {
    return props.displayLanguage === 'zh' ? '输入数值' : 'Enter a number'
  }
  return props.displayLanguage === 'zh' ? '输入文本' : 'Enter text'
}

const onParamChanged = (passId: string, paramKey: string, value: PassParamValue): void => {
  emit('passParamChanged', passId, paramKey, value)
}

const onToggleSelected = (): void => {
  const passId = selectedPassId.value
  if (passId === null) {
    return
  }
  onToggle(passId)
}

const onSelectedParamChanged = (paramKey: string, value: PassParamValue): void => {
  const passId = selectedPassId.value
  if (passId === null) {
    return
  }
  onParamChanged(passId, paramKey, value)
}

const onBrowsePathParam = (paramKey: string): void => {
  const passId = selectedPassId.value
  if (passId === null || isLocked()) {
    return
  }
  emit('browseNativeShroudCli', passId, paramKey)
}

const moveSelected = (direction: -1 | 1): void => {
  if (selectedPassId.value === null || isLocked() || !canMoveAmongVisible(visiblePasses.value, selectedPassId.value, direction)) {
    return
  }
  emit('passesChanged', movePassAmongVisible(props.passes, visiblePasses.value, selectedPassId.value, direction).map(clonePassItem))
}

const onListKeydown = (event: KeyboardEvent): void => {
  if (selectedPassId.value === null || isLocked() || !event.altKey) {
    return
  }
  if (event.key === 'ArrowUp') {
    event.preventDefault()
    moveSelected(-1)
    return
  }
  if (event.key === 'ArrowDown') {
    event.preventDefault()
    moveSelected(1)
  }
}

const riskType = (risk: PassItem['risk']): 'success' | 'warning' | 'error' => {
  if (risk === 'low') {
    return 'success'
  }
  if (risk === 'medium') {
    return 'warning'
  }
  return 'error'
}

const riskLabel = (risk: PassItem['risk']): string => localizeRiskLabel(risk, props.displayLanguage)

const compatibilityNoteLabel = (passItem: PassItem): string => {
  if (passItem.compatibilityNotes === undefined || passItem.compatibilityNotes.length === 0) {
    return ''
  }
  return props.displayLanguage === 'zh'
    ? `兼容性说明：${passItem.compatibilityNotes}`
    : `Compatibility notes: ${passItem.compatibilityNotes}`
}

const passCategoryLabel = (category: string): string => {
  if (category === 'enabled') {
    return props.displayLanguage === 'zh' ? '已启用' : 'Enabled'
  }
  return localizeCategoryLabel(category, props.displayLanguage)
}

const selectOptions = (options: readonly string[] | null): { readonly label: string; readonly value: string }[] => (
  options ?? []
).map((option: string): { readonly label: string; readonly value: string } => ({
  label: localizeOptionLabel(option, props.displayLanguage),
  value: option,
}))

const stringValue = (value: PassParamValue): string => (typeof value === 'string' ? value : '')
const numberValue = (value: PassParamValue): number | null => (typeof value === 'number' ? value : null)
const booleanValue = (value: PassParamValue): boolean => (typeof value === 'boolean' ? value : false)

const conflictLabels = (passItem: PassItem): string => conflictingPassIdsFor(passItem.id, props.passes, props.schemaCompatibility)
  .map((passId: string): string => {
    const matchedPass = props.passes.find((candidate: PassItem): boolean => candidate.id === passId)
    return matchedPass === undefined ? passId : localizePassName(matchedPass, props.displayLanguage)
  })
  .join('、')

const dependencyLabels = (passItem: PassItem): string => {
  const ids = [...passItem.requiredPassIds, ...passItem.requiresAnyPassIds]
  if (ids.length === 0) {
    return ''
  }
  return ids.map((passId: string): string => {
    const matchedPass = props.passes.find((candidate: PassItem): boolean => candidate.id === passId)
    return matchedPass === undefined ? passId : localizePassName(matchedPass, props.displayLanguage)
  }).join('、')
}

const fullOrderLabel = (passId: string): number => props.passes.findIndex((passItem: PassItem): boolean => passItem.id === passId) + 1
</script>

<template>
  <LiquidGlass as="section" level="surface" class="panel pipeline-panel pipeline-workbench">
    <div class="panel-head">
      <div>
        <p class="eyebrow">{{ displayLanguage === 'zh' ? '引擎能力' : 'Engine capabilities' }}</p>
        <h2>{{ displayLanguage === 'zh' ? '混淆功能' : 'Obfuscation features' }}</h2>
      </div>
      <NTag size="small" round>{{ enabledCount }} / {{ passes.length }}</NTag>
    </div>

    <div class="workbench-toolbar">
      <div class="search-wrap">
        <Search class="search-icon" :size="14" />
        <NInput
          v-model:value="searchQuery"
          size="small"
          clearable
          :disabled="false"
          :aria-label="displayLanguage === 'zh' ? '搜索模块名称或说明' : 'Search modules'"
          :placeholder="displayLanguage === 'zh' ? '搜索模块名称或说明' : 'Search modules'"
        />
      </div>
      <div class="category-chips" :aria-label="displayLanguage === 'zh' ? 'Pass 分类筛选' : 'Pass category filters'">
        <button
          v-for="chip in filterChips"
          :key="chip.id"
          type="button"
          class="category-chip"
          :class="{ active: activeFilter === chip.id }"
          :disabled="isLocked()"
          :aria-pressed="activeFilter === chip.id"
          :aria-label="displayLanguage === 'zh' ? `筛选 ${passCategoryLabel(chip.id)}，${chip.count} 项` : `Filter ${passCategoryLabel(chip.id)}, ${chip.count} items`"
          @click="activeFilter = chip.id"
        >
          {{ passCategoryLabel(chip.id) }}
          <span class="chip-count">{{ chip.count }}</span>
        </button>
      </div>
    </div>

    <NAlert v-if="hasEnabledAggressive" type="warning" :bordered="false" class="aggressive-warning">
      <template #icon><AlertTriangle /></template>
      <strong>{{ displayLanguage === 'zh' ? '已启用高影响混淆功能' : 'High-impact obfuscation is enabled' }}</strong>
      <p>{{ displayLanguage === 'zh' ? '这类功能可能增加兼容性、体积或启动参数要求；最终可执行性以引擎校验和运行日志为准。' : 'These passes may affect compatibility, output size, or launch requirements. Final executability is determined by engine validation and run logs.' }}</p>
    </NAlert>

    <div v-if="passes.length === 0" class="empty-state">
      <strong>{{ displayLanguage === 'zh' ? '暂未获取到引擎能力' : 'Engine capabilities not loaded yet' }}</strong>
      <span>{{ displayLanguage === 'zh' ? 'Pass 列表会从引擎 -schema 输出加载。' : 'The pass list is loaded from the engine -schema output.' }}</span>
    </div>

    <div v-else class="workbench-body" :class="{ 'workbench-body--detail': narrowDetailOpen }">
      <div class="module-pane" tabindex="0" @keydown="onListKeydown" :aria-keyshortcuts="'Alt+ArrowUp Alt+ArrowDown'">
        <draggable
          class="pass-list"
          :model-value="visiblePasses"
          item-key="id"
          handle=".drag-handle"
          :disabled="isLocked()"
          :move="canMovePass"
          @update:model-value="onDragUpdate"
        >
          <template #item="{ element }">
            <article
              class="pass-item"
              :class="{
                disabled: !element.enabled,
                aggressive: element.tagIds.includes('aggressive'),
                locked: isLocked(),
                selected: selectedPassId === element.id,
              }"
              @click="onSelectPass(element.id)"
            >
              <div class="pass-row">
                <span
                  class="drag-handle pass-index"
                  :aria-label="`${displayLanguage === 'zh' ? '拖拽排序' : 'Drag to reorder'} ${fullOrderLabel(element.id)}`"
                  @click.stop
                >
                  <GripVertical :size="14" />{{ fullOrderLabel(element.id) }}
                </span>
                <NCheckbox
                  class="pass-enable-checkbox"
                  :checked="element.enabled"
                  :disabled="isPassInteractionDisabled()"
                  :aria-label="`${element.enabled ? (displayLanguage === 'zh' ? '停用' : 'Disable') : (displayLanguage === 'zh' ? '启用' : 'Enable')} ${localizePassName(element, displayLanguage)}`"
                  @click.stop
                  @update:checked="() => onToggle(element.id)"
                />
                <div class="pass-copy">
                  <strong>{{ localizePassName(element, displayLanguage) }}</strong>
                  <small class="pass-cat">{{ passCategoryLabel(element.category) }}</small>
                </div>
                <NTag :type="riskType(element.risk)" size="small" round>{{ riskLabel(element.risk) }}</NTag>
              </div>
            </article>
          </template>
        </draggable>
        <div v-if="visiblePasses.length === 0" class="empty-state search-empty">
          <strong>{{ displayLanguage === 'zh' ? '没有匹配的模块' : 'No matching modules' }}</strong>
          <span>{{ displayLanguage === 'zh' ? '调整搜索词或筛选条件。' : 'Try a different search or filter.' }}</span>
        </div>
      </div>

      <aside class="detail-pane">
        <template v-if="selectedPass">
          <header class="detail-head">
            <div>
              <button type="button" class="back-to-list" @click="closeNarrowDetail">{{ displayLanguage === 'zh' ? '返回列表' : 'Back to list' }}</button>
              <p class="eyebrow">{{ passCategoryLabel(selectedPass.category) }}</p>
              <h3>{{ localizePassName(selectedPass, displayLanguage) }}</h3>
            </div>
            <div class="detail-actions">
              <button type="button" class="reorder-btn" :disabled="isLocked() || !canMoveSelectedUp" :title="displayLanguage === 'zh' ? '上移当前筛选列表中的相邻项（Alt+↑）。最终顺序仍受引擎约束。' : 'Move among visible neighbors (Alt+↑). Engine constraints still apply.'" :aria-label="displayLanguage === 'zh' ? '上移' : 'Move up'" @click="moveSelected(-1)">
                <ArrowUp :size="14" />
              </button>
              <button type="button" class="reorder-btn" :disabled="isLocked() || !canMoveSelectedDown" :title="displayLanguage === 'zh' ? '下移当前筛选列表中的相邻项（Alt+↓）。最终顺序仍受引擎约束。' : 'Move among visible neighbors (Alt+↓). Engine constraints still apply.'" :aria-label="displayLanguage === 'zh' ? '下移' : 'Move down'" @click="moveSelected(1)">
                <ArrowDown :size="14" />
              </button>
              <NSwitch
                :value="selectedPass.enabled"
                :disabled="isPassInteractionDisabled()"
                :aria-label="`${selectedPass.enabled ? (displayLanguage === 'zh' ? '停用当前模块' : 'Disable current module') : (displayLanguage === 'zh' ? '启用当前模块' : 'Enable current module')} ${localizePassName(selectedPass, displayLanguage)}`"
                @update:value="onToggleSelected"
              />
            </div>
          </header>
          <p class="detail-desc">{{ localizePassDescription(selectedPass, displayLanguage) }}</p>
          <div class="detail-meta">
            <NTag :type="riskType(selectedPass.risk)" size="small" round>{{ riskLabel(selectedPass.risk) }}</NTag>
            <NTag v-if="selectedPass.requiresOptIn" size="small" round>{{ displayLanguage === 'zh' ? '需确认启用' : 'Opt-in' }}</NTag>
            <NTag v-if="selectedPass.dependencyAutoEnabled" size="small" round>{{ displayLanguage === 'zh' ? '依赖自动开启' : 'Auto-enabled dep' }}</NTag>
            <span class="order-hint">{{ displayLanguage === 'zh' ? `全列表顺序 ${selectedFullIndex + 1}；筛选内上/下移不会丢掉隐藏项，最终顺序由引擎约束校正。快捷键 Alt+↑ / Alt+↓` : `Full-list order ${selectedFullIndex + 1}. Visible up/down keeps hidden slots; engine constraints still apply. Shortcut Alt+↑ / Alt+↓` }}</span>
          </div>
          <p v-if="compatibilityNoteLabel(selectedPass).length > 0" class="pass-compatibility-note">{{ compatibilityNoteLabel(selectedPass) }}</p>
          <p v-if="!selectedPass.enabled && conflictLabels(selectedPass).length > 0" class="pass-conflict-note">{{ displayLanguage === 'zh' ? `与 ${conflictLabels(selectedPass)} 冲突，已自动关闭` : `Conflicts with ${conflictLabels(selectedPass)} and was disabled automatically` }}</p>
          <p v-if="dependencyLabels(selectedPass).length > 0" class="pass-dep-note">{{ displayLanguage === 'zh' ? `依赖：${dependencyLabels(selectedPass)}` : `Depends on: ${dependencyLabels(selectedPass)}` }}</p>

          <div v-if="selectedPass.paramSchemas.length > 0" class="param-list" @click.stop>
            <label v-for="paramSchema in selectedPass.paramSchemas" :key="paramSchema.key" class="param-row">
              <span class="param-copy">
                <code class="param-key">{{ paramSchema.key }}</code>
                <small class="param-help">{{ localizeParamDescription(selectedPass, paramSchema, displayLanguage) }}</small>
              </span>
              <NSwitch v-if="paramSchema.type === 'boolean'" :value="booleanValue(selectedPass.params[paramSchema.key] ?? null)" :disabled="isLocked()" :aria-label="paramControlAria(paramSchema.key)" @update:value="(value: boolean) => onSelectedParamChanged(paramSchema.key, value)" />
              <div v-else-if="paramSchema.type === 'string' && isPathParam(paramSchema.key)" class="param-path-controls">
                <NInput :value="stringValue(selectedPass.params[paramSchema.key] ?? null)" :disabled="isLocked()" :aria-label="paramControlAria(paramSchema.key)" :placeholder="paramPlaceholder(paramSchema)" @update:value="(value: string) => onSelectedParamChanged(paramSchema.key, value)" />
                <NButton secondary :disabled="isLocked()" :aria-label="displayLanguage === 'zh' ? `浏览 ${paramSchema.key}` : `Browse ${paramSchema.key}`" @click.stop="onBrowsePathParam(paramSchema.key)">{{ displayLanguage === 'zh' ? '浏览' : 'Browse' }}</NButton>
              </div>
              <NInput v-else-if="paramSchema.type === 'string'" :value="stringValue(selectedPass.params[paramSchema.key] ?? null)" :disabled="isLocked()" :aria-label="paramControlAria(paramSchema.key)" :placeholder="paramPlaceholder(paramSchema)" @update:value="(value: string) => onSelectedParamChanged(paramSchema.key, value)" />
              <NInputNumber v-else-if="paramSchema.type === 'number'" :value="numberValue(selectedPass.params[paramSchema.key] ?? null)" :disabled="isLocked()" :aria-label="paramControlAria(paramSchema.key)" :placeholder="paramPlaceholder(paramSchema)" @update:value="(value: number | null) => onSelectedParamChanged(paramSchema.key, value)" />
              <NSelect v-else :value="stringValue(selectedPass.params[paramSchema.key] ?? null)" :options="selectOptions(paramSchema.options)" :disabled="isLocked()" :aria-label="paramControlAria(paramSchema.key)" :placeholder="displayLanguage === 'zh' ? '选择选项' : 'Select an option'" @update:value="(value: string) => onSelectedParamChanged(paramSchema.key, value)" />
            </label>
          </div>
          <p v-else class="empty-params">{{ displayLanguage === 'zh' ? '该模块没有可调参数。' : 'This module has no parameters.' }}</p>
        </template>
        <div v-else class="empty-state">
          <strong>{{ displayLanguage === 'zh' ? '未选择模块' : 'No module selected' }}</strong>
          <span>{{ displayLanguage === 'zh' ? '从左侧列表选择一项查看说明与参数。' : 'Select a module from the list to inspect details and parameters.' }}</span>
        </div>
      </aside>
    </div>
  </LiquidGlass>
</template>

<style scoped>
.pipeline-workbench {
  display: flex;
  flex-direction: column;
  min-height: 0;
  height: 100%;
  max-height: 100%;
  gap: 8px;
  padding-bottom: 8px;
  overflow: hidden;
}

.workbench-toolbar {
  display: flex;
  flex-direction: column;
  gap: 6px;
  flex: 0 0 auto;
}

.search-wrap {
  position: relative;
}

.search-icon {
  position: absolute;
  left: 10px;
  top: 50%;
  transform: translateY(-50%);
  color: #737373;
  pointer-events: none;
  z-index: 1;
}

.search-wrap :deep(.n-input) {
  padding-left: 18px;
}

.search-wrap :deep(.n-input .n-input-wrapper) {
  padding-left: 22px;
}

.category-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  padding: 0;
  overflow-x: auto;
}

.category-chip {
  appearance: none;
  min-height: 28px;
  border: 1px solid rgba(237, 237, 237, 0.12);
  background: #111111;
  color: #a3a3a3;
  border-radius: 999px;
  padding: 4px 10px;
  font-size: 12px;
  font-weight: 560;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  transition: color 160ms ease, background 160ms ease, border-color 160ms ease, transform 160ms ease;
}

.category-chip:hover {
  color: #ededed;
  border-color: rgba(237, 237, 237, 0.28);
  transform: translateY(-1px);
}

.category-chip:active {
  transform: translateY(0) scale(0.97);
}

.category-chip.active {
  color: #0a0a0a;
  background: #ededed;
  border-color: #ededed;
}

.category-chip:disabled {
  opacity: 0.45;
  cursor: not-allowed;
  transform: none;
}

.chip-count {
  font-variant-numeric: tabular-nums;
  opacity: 0.75;
}

.aggressive-warning {
  flex: 0 0 auto;
  margin: 0;
}

.workbench-body {
  display: grid;
  grid-template-columns: minmax(240px, 0.95fr) minmax(280px, 1.15fr);
  gap: 10px;
  min-height: 0;
  flex: 1 1 auto;
  overflow: hidden;
}

.module-pane,
.detail-pane {
  min-height: 0;
  overflow: auto;
  background: #0a0a0a;
  border: 1px solid rgba(237, 237, 237, 0.08);
  border-radius: 10px;
}

.module-pane {
  outline: none;
}

.pass-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
  margin: 0;
  padding: 6px;
  list-style: none;
}

.pass-item {
  display: block;
  min-height: 54px;
  max-height: 64px;
  border: 1px solid transparent;
  border-radius: 8px;
  background: #111111;
  cursor: pointer;
  transition: border-color 160ms ease, background 160ms ease, transform 160ms ease;
}

.pass-item:not(.locked):hover {
  border-color: rgba(237, 237, 237, 0.22);
  background: #161616;
  transform: translateY(-1px);
}

.pass-item.selected {
  border-color: rgba(237, 237, 237, 0.35);
  background: #161616;
}

.pass-item.disabled {
  opacity: 0.72;
}

.pass-item.locked {
  cursor: default;
  transform: none;
}

.pass-row {
  display: grid;
  grid-template-columns: auto auto minmax(0, 1fr) auto;
  align-items: center;
  gap: 8px;
  min-height: 54px;
  padding: 6px 8px;
}

.drag-handle {
  cursor: grab;
}

.pass-index {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 2px;
  min-width: 42px;
  height: 28px;
  padding: 0 6px;
  border: 1px solid rgba(237, 237, 237, 0.12);
  border-radius: 6px;
  color: #737373;
  background: #0f0f0f;
  font-variant-numeric: tabular-nums;
  font-size: 11px;
  cursor: grab;
}

.pass-item:not(.disabled) .pass-index {
  color: #0a0a0a;
  border-color: transparent;
  background: #ededed;
}

.pass-copy {
  min-width: 0;
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 2px;
  padding: 0;
  border: 0;
  color: inherit;
  background: transparent;
  text-align: left;
}

.pass-copy strong {
  color: #ededed;
  font-size: 13px;
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.pass-cat {
  color: #737373;
  font-size: 12px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.detail-pane {
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.detail-head {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  align-items: flex-start;
}

.detail-head h3 {
  margin: 0;
  color: #ededed;
  font-size: 16px;
}

.detail-actions {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
}

.reorder-btn {
  appearance: none;
  width: 28px;
  height: 28px;
  border-radius: 6px;
  border: 1px solid rgba(237, 237, 237, 0.12);
  background: #111111;
  color: #ededed;
  display: grid;
  place-items: center;
  cursor: pointer;
}

.reorder-btn:hover:not(:disabled) {
  border-color: rgba(237, 237, 237, 0.28);
}

.reorder-btn:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}

.detail-desc,
.pass-compatibility-note,
.pass-dep-note,
.empty-params,
.order-hint {
  margin: 0;
  color: #a3a3a3;
  font-size: 12px;
  line-height: 1.5;
}

.pass-conflict-note {
  margin: 0;
  color: #f5a524;
  font-size: 12px;
  font-weight: 560;
  line-height: 1.4;
}

.detail-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
}

.param-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 10px;
  border: 1px solid rgba(237, 237, 237, 0.08);
  border-radius: 8px;
  background: rgba(0, 0, 0, 0.28);
}

.param-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(120px, 220px);
  gap: 8px;
  align-items: start;
  color: #a3a3a3;
  font-size: 12px;
}

.param-path-controls {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 8px;
  min-width: 0;
}

.param-copy {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}

.param-key {
  color: #ededed;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
}

.param-help {
  color: #a3a3a3;
  font-size: 12px;
  line-height: 1.45;
}

.back-to-list {
  display: none;
  appearance: none;
  margin: 0 0 6px;
  padding: 0;
  border: 0;
  background: transparent;
  color: #ededed;
  font-size: 12px;
  cursor: pointer;
}

@media (min-width: 1001px) {
  .pipeline-workbench {
    overflow: hidden;
  }
}

.empty-state {
  display: flex;
  flex-direction: column;
  gap: 4px;
  margin: 0;
  padding: 16px;
  color: #a3a3a3;
  border: 0;
  background: transparent;
}

.empty-state strong {
  color: #ededed;
  font-size: 14px;
}

.empty-state span {
  color: #a3a3a3;
  font-size: 12px;
  line-height: 1.5;
}

.search-empty {
  padding: 12px;
}

@media (max-width: 1000px) {
  .pipeline-workbench {
    overflow-y: auto;
  }

  .workbench-toolbar {
    gap: 4px;
  }

  .category-chips {
    flex-wrap: nowrap;
  }

  .category-chip {
    flex: 0 0 auto;
  }

  .workbench-body {
    grid-template-columns: 1fr;
    grid-template-rows: minmax(180px, 1fr);
    min-height: 180px;
  }

  .module-pane,
  .detail-pane {
    min-height: 180px;
  }

  .detail-pane {
    display: none;
  }

  .workbench-body--detail .module-pane {
    display: none;
  }

  .workbench-body--detail .detail-pane {
    display: flex;
  }

  .back-to-list {
    display: inline-flex;
  }

  .param-row {
    grid-template-columns: 1fr;
  }

  .detail-head {
    display: grid;
    grid-template-columns: 1fr;
  }
}
</style>
