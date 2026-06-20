<script setup lang="ts">
import { computed, ref } from 'vue'
import { NAlert, NCheckbox, NInput, NInputNumber, NSelect, NSwitch, NTag } from 'naive-ui'
import { AlertTriangle, ChevronDown, GripVertical } from 'lucide-vue-next'
import draggable from 'vuedraggable'
import LiquidGlass from './LiquidGlass.vue'
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
}>()

const activeCategory = ref<string>('all')
const collapsedPasses = ref<Set<string>>(new Set<string>())
const draggablePasses = computed<PassItem[]>((): PassItem[] => props.passes.map(clonePassItem))
const categories = computed((): readonly string[] => {
  const seen: Set<string> = new Set<string>()
  const ordered: string[] = []

  props.passes.forEach((passItem: PassItem): void => {
    if (!seen.has(passItem.category)) {
      seen.add(passItem.category)
      ordered.push(passItem.category)
    }
  })

  return ['all', ...ordered]
})

const filteredPasses = computed<PassItem[]>((): PassItem[] => {
  if (activeCategory.value === 'all') {
    return draggablePasses.value
  }

  return draggablePasses.value.filter((passItem: PassItem): boolean => passItem.category === activeCategory.value)
})

const enabledCount = computed((): number => props.passes.filter((passItem: PassItem): boolean => passItem.enabled).length)
const hasEnabledAggressive = computed((): boolean => props.passes.some((p: PassItem): boolean => p.enabled && p.tagIds.includes('aggressive')))
const isLocked = (): boolean => props.status === 'running' || props.status === 'canceling'
const isPassInteractionDisabled = (): boolean => isLocked()
const canMovePass = (): boolean => true

const toggleCollapse = (passId: string): void => {
  const next = new Set(collapsedPasses.value)
  if (next.has(passId)) {
    next.delete(passId)
  } else {
    next.add(passId)
  }
  collapsedPasses.value = next
}

const isCollapsed = (passId: string): boolean => collapsedPasses.value.has(passId)
const isParamPanelOpen = (passItem: PassItem): boolean => passItem.enabled && !isCollapsed(passItem.id)

const onDragUpdate = (value: PassItem[]): void => {
  const byId: Readonly<Record<string, PassItem>> = Object.fromEntries(props.passes.map((passItem: PassItem): [string, PassItem] => [passItem.id, passItem]))
  const rest: PassItem[] = props.passes
    .filter((passItem: PassItem): boolean => !value.some((item: PassItem): boolean => item.id === passItem.id))
    .map(clonePassItem)

  const merged: PassItem[] = [...value.map((item: PassItem): PassItem => clonePassItem({ ...byId[item.id], ...item })), ...rest]
  emit('passesChanged', merged)
}

const onToggle = (passId: string): void => {
  const passItem = props.passes.find((candidate: PassItem): boolean => candidate.id === passId)
  if (passItem === undefined || isPassInteractionDisabled()) {
    return
  }

  emit('passToggled', passId)
}

const onPassItemClicked = (passId: string): void => {
  const passItem = props.passes.find((candidate: PassItem): boolean => candidate.id === passId)
  if (passItem === undefined || isPassInteractionDisabled()) {
    return
  }

  emit('passToggled', passId)
}

const onParamChanged = (passId: string, paramKey: string, value: PassParamValue): void => {
  emit('passParamChanged', passId, paramKey, value)
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

const passCategoryLabel = (category: string): string => localizeCategoryLabel(category, props.displayLanguage)

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

const clonePassItem = (passItem: PassItem): PassItem => ({
  ...passItem,
  params: { ...passItem.params },
  paramSchemas: passItem.paramSchemas.map((paramSchema) => ({ ...paramSchema })),
})

</script>

<template>
  <LiquidGlass as="section" level="surface" class="panel pipeline-panel">
    <div class="panel-head">
      <div>
        <p class="eyebrow">{{ displayLanguage === 'zh' ? '引擎能力' : 'Engine capabilities' }}</p>
        <h2>{{ displayLanguage === 'zh' ? '混淆功能' : 'Obfuscation features' }}</h2>
      </div>
      <NTag size="small" round>{{ enabledCount }} / {{ passes.length }}</NTag>
    </div>

    <div class="category-chips" :aria-label="displayLanguage === 'zh' ? 'Pass 分类筛选' : 'Pass category filters'">
      <button v-for="cat in categories" :key="cat" type="button" class="category-chip" :class="{ active: activeCategory === cat }" :disabled="isLocked()" @click="activeCategory = cat">{{ passCategoryLabel(cat) }}</button>
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

    <draggable v-else class="pass-list" :model-value="filteredPasses" item-key="id" handle=".drag-handle" :disabled="isLocked()" :move="canMovePass" @update:model-value="onDragUpdate">
      <template #item="{ element, index }">
        <article class="pass-item" :class="{ disabled: !element.enabled, aggressive: element.tagIds.includes('aggressive'), locked: isLocked() }" @click="onPassItemClicked(element.id)">
          <div class="pass-row">
            <span class="drag-handle pass-index" :aria-label="`${displayLanguage === 'zh' ? '拖拽排序' : 'Drag to reorder'} ${index + 1}`" @click.stop><GripVertical :size="14" />{{ index + 1 }}</span>
            <NCheckbox class="pass-enable-checkbox" :checked="element.enabled" :disabled="isPassInteractionDisabled()" :aria-label="`${element.enabled ? (displayLanguage === 'zh' ? '停用' : 'Disable') : (displayLanguage === 'zh' ? '启用' : 'Enable')} ${localizePassName(element, displayLanguage)}`" @click.stop @update:checked="() => onToggle(element.id)" />
            <button type="button" class="pass-copy" @click.stop="toggleCollapse(element.id)">
              <strong>{{ localizePassName(element, displayLanguage) }}</strong>
              <span>{{ localizePassDescription(element, displayLanguage) }}</span>
              <small v-if="compatibilityNoteLabel(element).length > 0" class="pass-compatibility-note">{{ compatibilityNoteLabel(element) }}</small>
              <small v-if="!element.enabled && conflictLabels(element).length > 0" class="pass-conflict-note">{{ displayLanguage === 'zh' ? `与 ${conflictLabels(element)} 冲突，已自动关闭` : `Conflicts with ${conflictLabels(element)} and was disabled automatically` }}</small>
            </button>
            <div class="pass-meta">
              <NTag :type="riskType(element.risk)" size="small" round>{{ riskLabel(element.risk) }}</NTag>
              <button v-if="element.paramSchemas.length > 0" type="button" class="collapse-button" :aria-expanded="isParamPanelOpen(element)" @click.stop="toggleCollapse(element.id)">
                <ChevronDown class="pass-collapse-icon" :class="{ rotated: isParamPanelOpen(element) }" :stroke-width="2" />
              </button>
            </div>
          </div>

          <Transition name="params-slide">
            <div v-if="element.paramSchemas.length > 0 && isParamPanelOpen(element)" class="param-list" @click.stop>
              <label v-for="paramSchema in element.paramSchemas" :key="paramSchema.key" class="param-row">
                <span>{{ localizeParamDescription(element, paramSchema, displayLanguage) }}</span>
                <NSwitch v-if="paramSchema.type === 'boolean'" :value="booleanValue(element.params[paramSchema.key] ?? null)" :disabled="isLocked()" @update:value="(value: boolean) => onParamChanged(element.id, paramSchema.key, value)" />
                <NInput v-else-if="paramSchema.type === 'string'" :value="stringValue(element.params[paramSchema.key] ?? null)" :disabled="isLocked()" @update:value="(value: string) => onParamChanged(element.id, paramSchema.key, value)" />
                <NInputNumber v-else-if="paramSchema.type === 'number'" :value="numberValue(element.params[paramSchema.key] ?? null)" :disabled="isLocked()" @update:value="(value: number | null) => onParamChanged(element.id, paramSchema.key, value)" />
                <NSelect v-else :value="stringValue(element.params[paramSchema.key] ?? null)" :options="selectOptions(paramSchema.options)" :disabled="isLocked()" @update:value="(value: string) => onParamChanged(element.id, paramSchema.key, value)" />
              </label>
            </div>
          </Transition>
        </article>
      </template>
    </draggable>
  </LiquidGlass>
</template>
