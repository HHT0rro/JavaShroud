<script setup lang="ts">
import { computed } from 'vue'
import { Download, Languages, Maximize2, Minimize2, Minus, Play, Square, Upload, X } from 'lucide-vue-next'
import { NButton, NTooltip } from 'naive-ui'
import LiquidGlass from './LiquidGlass.vue'
import { t, type DisplayLanguage } from '../modules/obfuscation/pass-localization'
import type { RunStatus } from '../modules/obfuscation/types'
const props = defineProps<{
  title: string
  fileName: string | null
  displayLanguage: DisplayLanguage
  status: RunStatus
  canStart: boolean
  busy: boolean
  maximised: boolean
  startHint: string
  informational?: boolean
}>()
const emit = defineEmits<{
  import: []
  export: []
  start: []
  cancel: []
  language: []
  window: [action: 'minimise' | 'toggle-maximise' | 'quit']
}>()
const running = computed(() => props.status === 'running' || props.status === 'canceling')
const windowActions = computed(() => [
  { id: 'minimise' as const, label: t('minimize', props.displayLanguage), icon: Minus },
  { id: 'toggle-maximise' as const, label: t(props.maximised ? 'restore' : 'maximize', props.displayLanguage), icon: props.maximised ? Minimize2 : Maximize2 },
  { id: 'quit' as const, label: t('close', props.displayLanguage), icon: X },
])
</script>

<template>
  <LiquidGlass as="header" level="surface" class="command-bar">
    <div class="command-context window-drag-region" @dblclick.self="emit('window', 'toggle-maximise')">
      <strong>{{ title }}</strong>
      <span v-if="!informational" :title="fileName ?? ''">{{ fileName ?? (displayLanguage === 'zh' ? '新建混淆任务' : 'New obfuscation task') }}</span>
    </div>
    <div class="command-actions">
      <NButton v-if="!informational" secondary :disabled="busy || running" :aria-label="t('importConfig', displayLanguage)" @click="emit('import')"><template #icon><Upload :size="16" /></template>{{ displayLanguage === 'zh' ? '导入' : 'Import' }}</NButton>
      <NButton v-if="!informational" secondary :disabled="busy" :aria-label="t('exportConfig', displayLanguage)" @click="emit('export')"><template #icon><Download :size="16" /></template>{{ displayLanguage === 'zh' ? '导出' : 'Export' }}</NButton>
      <span v-if="!informational" class="action-divider" aria-hidden="true"></span>
      <NButton v-if="running" class="run-action" :disabled="status === 'canceling'" :loading="status === 'canceling'" @click="emit('cancel')"><template #icon><Square :size="15" /></template>{{ displayLanguage === 'zh' ? (status === 'canceling' ? '正在取消' : '取消任务') : (status === 'canceling' ? 'Canceling' : 'Cancel run') }}</NButton>
      <NTooltip v-else-if="!informational" trigger="hover"><template #trigger><span class="run-action-wrap"><NButton type="primary" class="run-action" :disabled="!canStart" :loading="busy" @click="emit('start')"><template #icon><Play :size="16" /></template>{{ displayLanguage === 'zh' ? '开始混淆' : 'Start run' }}</NButton></span></template>{{ startHint }}</NTooltip>
      <button type="button" class="utility-button language-action" :aria-label="displayLanguage === 'zh' ? 'Switch to English' : '切换为中文'" @click="emit('language')"><Languages :size="16" /><span>{{ displayLanguage === 'zh' ? 'EN' : '中文' }}</span></button>
    </div>
    <div class="window-actions" :aria-label="t('windowControls', displayLanguage)">
      <button v-for="action in windowActions" :key="action.id" type="button" class="utility-button" :class="{ danger: action.id === 'quit' }" :aria-label="action.label" :title="action.label" @click="emit('window', action.id)"><component :is="action.icon" :size="15" aria-hidden="true" /></button>
    </div>
  </LiquidGlass>
</template>
