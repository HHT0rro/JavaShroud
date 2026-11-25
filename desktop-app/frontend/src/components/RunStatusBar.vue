<script setup lang="ts">
import { computed } from 'vue'
import { ArrowUpRight, CheckCircle2, Circle, CircleAlert, LoaderCircle, Square } from 'lucide-vue-next'
import { runIsBusy, runStatusLabel, type RunOutcome } from '../modules/obfuscation/workbench-view'
import type { RunStatus } from '../modules/obfuscation/types'
import type { DisplayLanguage } from '../modules/obfuscation/pass-localization'
const props = defineProps<{
  status: RunStatus
  progress: number
  step: string | null
  error: string | null
  outcome: RunOutcome | null
  busyLabel: string | null
  displayLanguage: DisplayLanguage
  passCount: number
}>()
const emit = defineEmits<{ logs: [] }>()
const label = computed(() => props.busyLabel ?? runStatusLabel(props.status, props.displayLanguage, props.outcome))
const busy = computed(() => runIsBusy(props.status) || props.busyLabel !== null)
const icon = computed(() => busy.value ? LoaderCircle : props.status === 'failed' ? CircleAlert : props.status === 'done' ? CheckCircle2 : props.outcome === 'canceled' ? Square : Circle)
const detail = computed(() => props.error ?? props.step ?? (props.displayLanguage === 'zh' ? `${props.passCount} 个模块已启用` : `${props.passCount} modules enabled`))
</script>

<template>
  <footer class="run-status-bar" :data-status="status">
    <div v-if="runIsBusy(status)" class="status-progress" role="progressbar" :aria-valuenow="progress" aria-valuemin="0" aria-valuemax="100" :aria-label="displayLanguage === 'zh' ? '任务进度' : 'Run progress'"><span :style="{ width: `${progress}%` }"></span></div>
    <span class="status-label" role="status"><component :is="icon" :size="15" :class="{ spinning: busy }" aria-hidden="true" />{{ label }}</span>
    <span class="status-detail" :title="detail">{{ detail }}</span>
    <span v-if="runIsBusy(status) || status === 'done'" class="status-percent">{{ Math.round(progress) }}%</span>
    <button type="button" class="status-log-link" @click="emit('logs')">{{ displayLanguage === 'zh' ? '查看日志' : 'View logs' }}<ArrowUpRight :size="14" /></button>
  </footer>
</template>
