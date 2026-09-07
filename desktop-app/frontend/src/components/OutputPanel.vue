<script setup lang="ts">
import { computed, ref } from 'vue'
import { ArrowUpRight, CheckCircle2, CircleAlert, Copy, Package, Square } from 'lucide-vue-next'
import { NButton } from 'naive-ui'
import LiquidGlass from './LiquidGlass.vue'
import type { RunStatus } from '../modules/obfuscation/types'
import type { DisplayLanguage } from '../modules/obfuscation/pass-localization'
import { runIsBusy, type RunOutcome } from '../modules/obfuscation/workbench-view'
const props = defineProps<{
  outputPath: string | null
  outputJarPath: string
  status: RunStatus
  displayLanguage: DisplayLanguage
  outcome: RunOutcome | null
  error: string | null
}>()
const emit = defineEmits<{ logs: [] }>()
const copied = ref(false)
const copyError = ref(false)
const completed = computed(() => props.status === 'done' && !!props.outputPath)
const label = computed(() => {
  const zh = props.displayLanguage === 'zh'
  if (runIsBusy(props.status)) return zh ? '任务正在运行' : 'Run in progress'
  if (props.status === 'failed') return zh ? '任务未完成' : 'Task not completed'
  if (props.outcome === 'canceled') return zh ? '任务已取消' : 'Run canceled'
  if (completed.value) return zh ? '产物已生成' : 'Output generated'
  return zh ? '完成后在这里查看结果' : 'Your result will appear here'
})
const copyOutput = async (): Promise<void> => {
  if (!completed.value || !props.outputPath) return
  try { await navigator.clipboard.writeText(props.outputPath); copied.value = true; copyError.value = false }
  catch { copyError.value = true }
}
</script>

<template>
  <LiquidGlass as="section" level="surface" class="panel result-panel">
    <div class="result-heading"><span class="eyebrow">{{ displayLanguage === 'zh' ? '03 / 执行结果' : '03 / RESULT' }}</span><button type="button" class="text-link" @click="emit('logs')">{{ displayLanguage === 'zh' ? '运行日志' : 'Run logs' }}<ArrowUpRight :size="14" /></button></div>
    <div class="result-content"><span class="result-icon" :class="{ success: completed, error: status === 'failed' }"><CheckCircle2 v-if="completed" :size="24" /><CircleAlert v-else-if="status === 'failed'" :size="24" /><Square v-else-if="outcome === 'canceled'" :size="22" /><Package v-else :size="24" /></span><div class="result-copy"><h3>{{ label }}</h3><p v-if="status === 'failed' && error" class="result-error">{{ error }}</p><p v-else-if="completed" class="result-path">{{ outputPath }}</p><p v-else>{{ displayLanguage === 'zh' ? '只在引擎确认成功后展示输出产物。详细过程可随时查看日志。' : 'Output is shown only after the engine confirms success. Check the logs for details.' }}</p></div><NButton v-if="completed" secondary @click="copyOutput"><template #icon><Copy :size="14" /></template>{{ displayLanguage === 'zh' ? (copied ? '已复制路径' : '复制路径') : (copied ? 'Path copied' : 'Copy path') }}</NButton></div>
    <p v-if="copyError" role="status" class="field-hint copy-error">{{ displayLanguage === 'zh' ? '剪贴板不可用，请选中上方完整路径手动复制。' : 'Clipboard unavailable. Select the full path above to copy it.' }}</p>
  </LiquidGlass>
</template>

<style scoped>
.result-panel { padding: 20px; }
.result-heading { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 20px; }
.result-content { display: flex; align-items: center; gap: 16px; }
.result-icon { display: grid; place-items: center; width: 48px; height: 48px; flex: 0 0 auto; border: 1px solid var(--line); border-radius: var(--radius-sm); color: var(--text-muted); background: var(--panel-strong); }
.result-icon.success { color: var(--success); }
.result-icon.error { color: var(--danger); }
.result-copy { flex: 1; min-width: 0; display: grid; gap: 7px; }
.result-copy h3 { font-size: 14px; font-weight: 600; }
.result-copy p { color: var(--text-muted); font-size: 13px; line-height: 1.6; overflow-wrap: anywhere; }
.result-copy .result-path { font: 12px/1.6 var(--font-mono); color: var(--text-soft); user-select: text; }
.result-copy .result-error { color: var(--danger); }
.copy-error { margin-top: 12px; }
@media (max-width: 700px) { .result-content { flex-wrap: wrap; } .result-copy { flex-basis: calc(100% - 64px); } }
</style>
