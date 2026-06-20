<script setup lang="ts">
import { ref } from 'vue'
import { ChevronRight, Variable, Wrench } from 'lucide-vue-next'
import { NButton, NTag, NTooltip } from 'naive-ui'
import type { ClassTreeNode, RuleAction, RuleItem } from '../modules/obfuscation/types'
import { nodeRuleAction, ruleActionTone } from '../modules/obfuscation/state'
import type { DisplayLanguage } from '../modules/obfuscation/pass-localization'

defineProps<{
  readonly node: ClassTreeNode
  readonly rules: readonly RuleItem[]
  readonly displayLanguage: DisplayLanguage
}>()

const emit = defineEmits<{
  readonly nodeRuleChanged: [node: ClassTreeNode, action: RuleAction]
}>()

const expanded = ref<boolean>(false)

const kindLabel = (kind: ClassTreeNode['kind'], language: DisplayLanguage): string => {
  if (kind === 'package') {
    return language === 'zh' ? '包' : 'Package'
  }
  if (kind === 'class') {
    return language === 'zh' ? '类' : 'Class'
  }
  if (kind === 'field') {
    return language === 'zh' ? '字段' : 'Field'
  }
  return language === 'zh' ? '方法' : 'Method'
}

const actionLabel = (action: RuleAction, language: DisplayLanguage): string => {
  if (action === 'obfuscate') {
    return language === 'zh' ? '混淆' : 'Obfuscate'
  }

  return language === 'zh' ? '跳过' : 'Skip'
}

const nextAction = (currentAction: RuleAction): RuleAction => currentAction === 'exclude' ? 'obfuscate' : 'exclude'
const canExpand = (node: ClassTreeNode): boolean => node.children.length > 0
const isLeaf = (node: ClassTreeNode): boolean => node.kind === 'field' || node.kind === 'method'

const toggleExpanded = (): void => {
  expanded.value = !expanded.value
}

const forwardNodeRuleChanged = (node: ClassTreeNode, action: RuleAction): void => {
  emit('nodeRuleChanged', node, action)
}
</script>

<template>
  <li>
    <div class="tree-row" :class="{ leaf: isLeaf(node), member: isLeaf(node) }">
      <NButton v-if="canExpand(node)" quaternary circle size="tiny" class="tree-expand" :class="{ open: expanded }" :aria-label="`${expanded ? (displayLanguage === 'zh' ? '折叠' : 'Collapse') : (displayLanguage === 'zh' ? '展开' : 'Expand')} ${node.label}`" @click="toggleExpanded">
        <ChevronRight :size="14" />
      </NButton>
      <span v-else class="tree-spacer" />
      <NTag size="small">{{ kindLabel(node.kind, displayLanguage) }}</NTag>
      <span class="tree-label" :title="node.qualifiedName">{{ node.label }}</span>
      <NTooltip v-if="node.kind === 'field'" trigger="hover">
        <template #trigger>
          <Variable :size="15" class="tree-kind-icon" />
        </template>
        {{ displayLanguage === 'zh' ? '字段' : 'Field' }}: {{ node.qualifiedName }}
      </NTooltip>
      <NTooltip v-else-if="node.kind === 'method'" trigger="hover">
        <template #trigger>
          <Wrench :size="15" class="tree-kind-icon" />
        </template>
        {{ displayLanguage === 'zh' ? '方法' : 'Method' }}: {{ node.qualifiedName }}
      </NTooltip>
      <span v-else class="tree-spacer" />
      <NButton quaternary round size="small" :type="ruleActionTone(nodeRuleAction(rules, node))" @click="emit('nodeRuleChanged', node, nextAction(nodeRuleAction(rules, node)))">
        {{ actionLabel(nodeRuleAction(rules, node), displayLanguage) }}
      </NButton>
    </div>
    <ul v-if="expanded && node.children.length > 0">
      <ClassTreeNodeItem v-for="child in node.children" :key="child.id" :node="child" :rules="rules" :display-language="displayLanguage" @node-rule-changed="forwardNodeRuleChanged" />
    </ul>
  </li>
</template>
