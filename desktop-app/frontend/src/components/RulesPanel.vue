<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Download, Trash2, Upload } from 'lucide-vue-next'
import { NButton, NInput, NTag } from 'naive-ui'
import LiquidGlass from './LiquidGlass.vue'
import type { RuleItem, RunStatus } from '../modules/obfuscation/types'

const props = defineProps<{
  readonly rules: readonly RuleItem[]
  readonly status: RunStatus
}>()

const emit = defineEmits<{
  readonly importRules: [rules: readonly RuleItem[]]
  readonly clearRules: []
}>()

interface RuleConfigItem {
  readonly target: string
  readonly action: RuleItem['action']
}

const configText = ref<string>('')
const errorMessage = ref<string | null>(null)
const isLocked = (): boolean => props.status === 'running' || props.status === 'canceling'
const exportedRules = computed((): readonly RuleConfigItem[] => props.rules.map((rule: RuleItem): RuleConfigItem => ({
  target: rule.target,
  action: rule.action,
})))

const formatRuleConfig = (rules: readonly RuleConfigItem[]): string => JSON.stringify({ rules }, null, 2)

watch(
  () => props.rules,
  (): void => {
    configText.value = formatRuleConfig(exportedRules.value)
    errorMessage.value = null
  },
  { immediate: true, deep: true },
)

const onImportRules = (): void => {
  try {
    const parsedRules: readonly RuleItem[] = parseRuleConfig(configText.value)
    emit('importRules', parsedRules)
    errorMessage.value = null
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : String(error)
  }
}

const onExportRules = (): void => {
  configText.value = formatRuleConfig(exportedRules.value)
  errorMessage.value = null
}

const parseRuleConfig = (rawConfig: string): readonly RuleItem[] => {
  const parsed: unknown = JSON.parse(rawConfig)
  if (!isRecord(parsed)) {
    throw new Error('配置导入失败：根节点必须是对象。')
  }

  const rawRules: unknown = parsed.rules
  if (!Array.isArray(rawRules)) {
    throw new Error('配置导入失败：rules 必须是数组。')
  }

  return rawRules.map((rawRule: unknown, index: number): RuleItem => {
    if (!isRecord(rawRule)) {
      throw new Error(`配置导入失败：rules[${index}] 必须是对象。`)
    }

    const target: unknown = rawRule.target
    if (typeof target !== 'string' || target.trim().length === 0) {
      throw new Error(`配置导入失败：rules[${index}].target 必须是非空字符串。`)
    }

    const action: unknown = rawRule.action
    if (action !== undefined && action !== 'exclude' && action !== 'obfuscate') {
      throw new Error(`配置导入失败：rules[${index}].action 只能是 exclude 或 obfuscate。`)
    }

    return {
      id: `rule-config-${index}-${target.trim()}`,
      target: target.trim(),
      action: action === 'obfuscate' ? 'obfuscate' : 'exclude',
    }
  })
}

const isRecord = (value: unknown): value is Record<string, unknown> => (
  typeof value === 'object' && value !== null && !Array.isArray(value)
)
</script>

<template>
  <LiquidGlass as="section" level="surface" class="panel rules-panel">
    <div class="panel-head">
      <div>
        <p class="eyebrow">Rule document</p>
        <h2>排除规则 JSON</h2>
      </div>
      <NTag size="small" round>{{ rules.length }} 条</NTag>
    </div>

    <p class="panel-note">这里编辑的 JSON 与“类树”页选中的排除项同步；导入会替换当前排除规则。</p>

    <div class="rule-config-editor">
      <NInput v-model:value="configText" type="textarea" :autosize="{ minRows: 14, maxRows: 24 }" :disabled="isLocked()" placeholder='{ "rules": [{ "target": "com.example", "action": "exclude" }] }' />
      <p v-if="errorMessage !== null" class="rule-config-error">{{ errorMessage }}</p>
    </div>

    <div class="rules-footer">
      <NButton secondary :disabled="isLocked()" @click="onExportRules">
        <template #icon><Download :size="16" /></template>
        导出配置
      </NButton>
      <NButton type="primary" :disabled="isLocked()" @click="onImportRules">
        <template #icon><Upload :size="16" /></template>
        导入配置
      </NButton>
      <NButton quaternary :disabled="isLocked() || rules.length === 0" @click="emit('clearRules')">
        <template #icon><Trash2 :size="16" /></template>
        清空排除项
      </NButton>
    </div>
  </LiquidGlass>
</template>
