<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { ChevronRight, Variable, Wrench } from 'lucide-vue-next'
import { NButton, NTag, NTooltip } from 'naive-ui'
import type { ClassTreeNode, RuleAction, RuleItem } from '../modules/obfuscation/types'
import { nodePassSelectionAction, nodeRuleAction, ruleActionTone } from '../modules/obfuscation/state'
import type { DisplayLanguage } from '../modules/obfuscation/pass-localization'
import {
  buildClassTreeVisibleRows,
  CLASS_TREE_VIRTUAL_ROW_HEIGHT,
  type ClassTreeVisibleRow,
  virtualizeClassTreeRows,
} from '../modules/obfuscation/class-tree-view'

const props = defineProps<{
  readonly nodes: readonly ClassTreeNode[]
  readonly rules: readonly RuleItem[]
  readonly displayLanguage: DisplayLanguage
  readonly query: string
  readonly selectionMode?: 'global' | 'selected-only'
  readonly selectableKinds?: readonly ('class' | 'method')[]
  readonly allowedKinds?: readonly ClassTreeNode['kind'][]
  readonly disabled?: boolean
  readonly ariaLabel?: string
}>()

const emit = defineEmits<{
  readonly nodeRuleChanged: [node: ClassTreeNode, action: RuleAction]
}>()

const host = ref<HTMLElement | null>(null)
const scrollTop = ref<number>(0)
const viewportHeight = ref<number>(520)
const expandedNodeIds = ref<ReadonlySet<string>>(new Set<string>())
let resizeObserver: ResizeObserver | null = null

const visibleRows = computed((): readonly ClassTreeVisibleRow[] => buildClassTreeVisibleRows(props.nodes, {
  query: props.query,
  allowedKinds: props.allowedKinds,
  expandedNodeIds: expandedNodeIds.value,
}))
const virtualSlice = computed(() => virtualizeClassTreeRows(
  visibleRows.value,
  scrollTop.value,
  viewportHeight.value,
))

const kindLabel = (kind: ClassTreeNode['kind'], language: DisplayLanguage): string => {
  if (kind === 'package') return language === 'zh' ? '包' : 'Package'
  if (kind === 'class') return language === 'zh' ? '类' : 'Class'
  if (kind === 'field') return language === 'zh' ? '字段' : 'Field'
  return language === 'zh' ? '方法' : 'Method'
}

const actionLabel = (action: RuleAction, language: DisplayLanguage): string => action === 'obfuscate'
  ? (language === 'zh' ? '混淆' : 'Obfuscate')
  : (language === 'zh' ? '跳过' : 'Skip')

const isLeaf = (node: ClassTreeNode): boolean => node.kind === 'field' || node.kind === 'method'
const isPassSelectable = (node: ClassTreeNode): boolean => (
  props.selectionMode === 'selected-only'
  && (node.kind === 'class' || node.kind === 'method')
  && (props.selectableKinds ?? []).includes(node.kind)
)
const searchForcesExpansion = computed((): boolean => props.query.trim().length > 0)
const currentAction = (node: ClassTreeNode): RuleAction => props.selectionMode === 'selected-only'
  ? nodePassSelectionAction(props.rules, node)
  : nodeRuleAction(props.rules, node)
const nextAction = (node: ClassTreeNode): RuleAction => currentAction(node) === 'exclude' ? 'obfuscate' : 'exclude'
const isExpanded = (node: ClassTreeNode): boolean => searchForcesExpansion.value || expandedNodeIds.value.has(node.id)

const toggleExpanded = (node: ClassTreeNode): void => {
  if (node.children.length === 0) return
  const next = new Set(expandedNodeIds.value)
  if (next.has(node.id)) next.delete(node.id)
  else next.add(node.id)
  expandedNodeIds.value = next
}

const updateViewport = (): void => {
  viewportHeight.value = Math.max(CLASS_TREE_VIRTUAL_ROW_HEIGHT, host.value?.clientHeight ?? 520)
}
const handleScroll = (event: Event): void => {
  scrollTop.value = (event.currentTarget as HTMLElement).scrollTop
}
const rowIndent = (row: ClassTreeVisibleRow): string => `${row.depth * 24}px`

watch(() => props.query, async (): Promise<void> => {
  await nextTick()
  if (host.value !== null) {
    host.value.scrollTop = 0
    scrollTop.value = 0
  }
})

watch(() => props.nodes, (): void => {
  expandedNodeIds.value = new Set<string>()
  if (host.value !== null) {
    host.value.scrollTop = 0
    scrollTop.value = 0
  }
})

onMounted((): void => {
  updateViewport()
  if (host.value !== null && typeof ResizeObserver !== 'undefined') {
    resizeObserver = new ResizeObserver(updateViewport)
    resizeObserver.observe(host.value)
  }
})

onBeforeUnmount((): void => resizeObserver?.disconnect())
</script>

<template>
  <div ref="host" class="class-tree-virtual" :aria-label="ariaLabel" role="tree" @scroll="handleScroll">
    <div :style="{ height: `${virtualSlice.topPadding}px` }" aria-hidden="true" />
    <div
      v-for="row in virtualSlice.rows"
      :key="row.node.id"
      class="tree-row class-tree-virtual__row"
      :class="{
        leaf: isLeaf(row.node),
        member: isLeaf(row.node),
        'tree-row--unavailable': selectionMode === 'selected-only' && !isPassSelectable(row.node),
      }"
      :style="{ paddingInlineStart: `calc(var(--space-2) + ${rowIndent(row)})` }"
      role="treeitem"
      :aria-level="row.depth + 1"
      :aria-expanded="row.hasChildren ? isExpanded(row.node) : undefined"
    >
      <NButton
        v-if="row.hasChildren"
        quaternary
        circle
        size="tiny"
        class="tree-expand"
        :class="{ open: isExpanded(row.node) }"
        :aria-label="`${isExpanded(row.node) ? (displayLanguage === 'zh' ? '折叠' : 'Collapse') : (displayLanguage === 'zh' ? '展开' : 'Expand')} ${row.node.label}`"
        :disabled="searchForcesExpansion"
        @click="toggleExpanded(row.node)"
      >
        <ChevronRight :size="14" />
      </NButton>
      <span v-else class="tree-spacer" />
      <NTag size="small">{{ kindLabel(row.node.kind, displayLanguage) }}</NTag>
      <span class="tree-label" :title="row.node.qualifiedName">{{ row.node.label }}</span>
      <NTooltip v-if="row.node.kind === 'field'" trigger="hover">
        <template #trigger><Variable :size="15" class="tree-kind-icon" /></template>
        {{ displayLanguage === 'zh' ? '字段' : 'Field' }}: {{ row.node.qualifiedName }}
      </NTooltip>
      <NTooltip v-else-if="row.node.kind === 'method'" trigger="hover">
        <template #trigger><Wrench :size="15" class="tree-kind-icon" /></template>
        {{ displayLanguage === 'zh' ? '方法' : 'Method' }}: {{ row.node.qualifiedName }}
      </NTooltip>
      <span v-else class="tree-spacer" />
      <NButton
        v-if="selectionMode !== 'selected-only' || isPassSelectable(row.node)"
        quaternary
        round
        size="small"
        :type="ruleActionTone(currentAction(row.node))"
        :disabled="disabled"
        @click="emit('nodeRuleChanged', row.node, nextAction(row.node))"
      >
        {{ actionLabel(currentAction(row.node), displayLanguage) }}
      </NButton>
      <NTag v-else-if="selectionMode === 'selected-only'" size="small" type="default">
        {{ displayLanguage === 'zh' ? '不适用' : 'N/A' }}
      </NTag>
    </div>
    <div :style="{ height: `${virtualSlice.bottomPadding}px` }" aria-hidden="true" />
  </div>
</template>
