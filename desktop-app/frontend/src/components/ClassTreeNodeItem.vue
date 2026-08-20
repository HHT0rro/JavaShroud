<script setup lang="ts">
import { ref } from 'vue'
import { ChevronRight, Variable, Wrench } from 'lucide-vue-next'
import { NButton, NTag, NTooltip } from 'naive-ui'
import type { ClassTreeNode, RuleAction, RuleItem } from '../modules/obfuscation/types'
import { nodePassSelectionAction, nodeRuleAction, ruleActionTone } from '../modules/obfuscation/state'
import type { DisplayLanguage } from '../modules/obfuscation/pass-localization'

const props = defineProps<{
  readonly node: ClassTreeNode
  readonly rules: readonly RuleItem[]
  readonly displayLanguage: DisplayLanguage
  readonly selectionMode?: 'global' | 'selected-only'
  readonly selectableKinds?: readonly ('class' | 'method')[]
  readonly disabled?: boolean
}>()

const emit = defineEmits<{
  readonly nodeRuleChanged: [node: ClassTreeNode, action: RuleAction]
}>()

const expanded = ref<boolean>(false)

const kindLabel = (kind: ClassTreeNode['kind'], language: DisplayLanguage): string => {
  if (kind === 'package') return language === 'zh' ? '包' : 'Package'
  if (kind === 'class') return language === 'zh' ? '类' : 'Class'
  if (kind === 'field') return language === 'zh' ? '字段' : 'Field'
  return language === 'zh' ? '方法' : 'Method'
}

const actionLabel = (action: RuleAction, language: DisplayLanguage): string => action === 'obfuscate'
  ? (language === 'zh' ? '混淆' : 'Obfuscate')
  : (language === 'zh' ? '跳过' : 'Skip')

const canExpand = (node: ClassTreeNode): boolean => node.children.length > 0
const isLeaf = (node: ClassTreeNode): boolean => node.kind === 'field' || node.kind === 'method'
const isPassSelectable = (node: ClassTreeNode): boolean => (
  props.selectionMode === 'selected-only'
  && (node.kind === 'class' || node.kind === 'method')
  && (props.selectableKinds ?? []).includes(node.kind)
)
const currentAction = (node: ClassTreeNode): RuleAction => props.selectionMode === 'selected-only'
  ? nodePassSelectionAction(props.rules, node)
  : nodeRuleAction(props.rules, node)
const nextAction = (node: ClassTreeNode): RuleAction => currentAction(node) === 'exclude' ? 'obfuscate' : 'exclude'
const toggleExpanded = (): void => { expanded.value = !expanded.value }
const forwardNodeRuleChanged = (node: ClassTreeNode, action: RuleAction): void => emit('nodeRuleChanged', node, action)
</script>

<template>
  <li>
    <div class="tree-row" :class="{ leaf: isLeaf(node), member: isLeaf(node), 'tree-row--unavailable': selectionMode === 'selected-only' && !isPassSelectable(node) }">
      <NButton v-if="canExpand(node)" quaternary circle size="tiny" class="tree-expand" :class="{ open: expanded }" :aria-label="`${expanded ? (displayLanguage === 'zh' ? '折叠' : 'Collapse') : (displayLanguage === 'zh' ? '展开' : 'Expand')} ${node.label}`" @click="toggleExpanded">
        <ChevronRight :size="14" />
      </NButton>
      <span v-else class="tree-spacer" />
      <NTag size="small">{{ kindLabel(node.kind, displayLanguage) }}</NTag>
      <span class="tree-label" :title="node.qualifiedName">{{ node.label }}</span>
      <NTooltip v-if="node.kind === 'field'" trigger="hover">
        <template #trigger><Variable :size="15" class="tree-kind-icon" /></template>
        {{ displayLanguage === 'zh' ? '字段' : 'Field' }}: {{ node.qualifiedName }}
      </NTooltip>
      <NTooltip v-else-if="node.kind === 'method'" trigger="hover">
        <template #trigger><Wrench :size="15" class="tree-kind-icon" /></template>
        {{ displayLanguage === 'zh' ? '方法' : 'Method' }}: {{ node.qualifiedName }}
      </NTooltip>
      <span v-else class="tree-spacer" />
      <NButton
        v-if="selectionMode !== 'selected-only' || isPassSelectable(node)"
        quaternary
        round
        size="small"
        :type="ruleActionTone(currentAction(node))"
        :disabled="disabled"
        @click="emit('nodeRuleChanged', node, nextAction(node))"
      >
        {{ actionLabel(currentAction(node), displayLanguage) }}
      </NButton>
      <NTag v-else-if="selectionMode === 'selected-only'" size="small" type="default">
        {{ displayLanguage === 'zh' ? '不适用' : 'N/A' }}
      </NTag>
    </div>
    <ul v-if="expanded && node.children.length > 0">
      <ClassTreeNodeItem
        v-for="child in node.children"
        :key="child.id"
        :node="child"
        :rules="rules"
        :display-language="displayLanguage"
        :selection-mode="selectionMode"
        :selectable-kinds="selectableKinds"
        :disabled="disabled"
        @node-rule-changed="forwardNodeRuleChanged"
      />
    </ul>
  </li>
</template>
