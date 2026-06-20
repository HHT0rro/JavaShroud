<script setup lang="ts">
import { ScanLine } from 'lucide-vue-next'
import { NButton, NTag } from 'naive-ui'
import ClassTreeNodeItem from './ClassTreeNodeItem.vue'
import LiquidGlass from './LiquidGlass.vue'
import type { ClassTreeNode, RuleAction, RuleItem } from '../modules/obfuscation/types'
import type { DisplayLanguage } from '../modules/obfuscation/pass-localization'

defineProps<{
  readonly nodes: readonly ClassTreeNode[]
  readonly rules: readonly RuleItem[]
  readonly classCount: number
  readonly inspecting: boolean
  readonly displayLanguage: DisplayLanguage
}>()

const emit = defineEmits<{
  readonly inspect: []
  readonly nodeRuleChanged: [node: ClassTreeNode, action: RuleAction]
}>()

const forwardNodeRuleChanged = (node: ClassTreeNode, action: RuleAction): void => {
  emit('nodeRuleChanged', node, action)
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

    <div class="panel-toolbar">
      <p class="panel-note">{{ displayLanguage === 'zh' ? '未添加规则时默认参与混淆；可选择包、类、字段或方法设置跳过或恢复混淆。' : 'Without rules, items are included by default. Select packages, classes, fields, or methods to skip or restore obfuscation.' }}</p>
      <NButton tertiary :loading="inspecting" @click="emit('inspect')">
        <template #icon><ScanLine :size="16" /></template>
        {{ displayLanguage === 'zh' ? '扫描 Jar' : 'Scan Jar' }}
      </NButton>
    </div>

    <div v-if="nodes.length === 0" class="empty-state">
      <strong>{{ displayLanguage === 'zh' ? '还没有类树' : 'No class tree yet' }}</strong>
      <span>{{ displayLanguage === 'zh' ? '选择输入 Jar 后扫描类树，扫描结果会包含包、类、字段和方法。' : 'Choose an input Jar and scan it. Results include packages, classes, fields, and methods.' }}</span>
    </div>

    <ul v-else class="class-tree">
      <ClassTreeNodeItem v-for="node in nodes" :key="node.id" :node="node" :rules="rules" :display-language="displayLanguage" @node-rule-changed="forwardNodeRuleChanged" />
    </ul>
  </LiquidGlass>
</template>
