<script setup lang="ts">
import { computed } from 'vue'
import { ArrowRight, CheckCircle2, Circle, FolderTree, Layers, LoaderCircle, RefreshCw } from 'lucide-vue-next'
import { NButton } from 'naive-ui'
import LiquidGlass from './LiquidGlass.vue'
import type { RunState } from '../modules/obfuscation/types'
import type { DisplayLanguage } from '../modules/obfuscation/pass-localization'
import { getReadinessIssue, type WorkbenchPage } from '../modules/obfuscation/workbench-view'
const props = defineProps<{ state: RunState; displayLanguage: DisplayLanguage; busy: boolean }>()
const emit = defineEmits<{ navigate: [page: WorkbenchPage]; inspect: []; retry: [] }>()
const enabledCount = computed(() => props.state.passes.filter((pass) => pass.enabled).length)
const issue = computed(() => getReadinessIssue(props.state, props.displayLanguage))
const independentCount = computed(() => props.state.passSelections.filter((selection) => props.state.passes.some((pass) => pass.id === selection.passId && pass.enabled)).length)
</script>

<template>
  <LiquidGlass as="section" level="surface" class="panel overview-panel">
    <div class="panel-head"><div><p class="eyebrow">{{ displayLanguage === 'zh' ? '02 / 配置' : '02 / CONFIGURATION' }}</p><h2>{{ displayLanguage === 'zh' ? '运行准备' : 'Run preparation' }}</h2></div><Layers :size="18" class="muted-icon" /></div>
    <div class="overview-body">
      <div class="readiness" :class="{ 'readiness--ready': !issue && !busy }" role="status"><LoaderCircle v-if="busy" :size="18" class="spinning" /><Circle v-else-if="issue" :size="18" /><CheckCircle2 v-else :size="18" /><div><strong>{{ busy ? (displayLanguage === 'zh' ? '正在处理，请稍候' : 'Working, please wait') : issue ? (displayLanguage === 'zh' ? '还差一步' : 'One more step') : (displayLanguage === 'zh' ? '配置已就绪' : 'Ready to run') }}</strong><span>{{ busy ? (displayLanguage === 'zh' ? '文件与配置操作完成后即可继续' : 'Continue once the file operation completes') : issue?.message ?? (displayLanguage === 'zh' ? '使用顶部「开始混淆」执行任务' : 'Use Start run in the toolbar') }}</span></div></div>
      <NButton v-if="!state.schema && !busy" secondary @click="emit('retry')"><template #icon><RefreshCw :size="14" /></template>{{ displayLanguage === 'zh' ? '重新加载引擎' : 'Reload engine' }}</NButton>
      <div class="preparation-links">
        <button type="button" @click="emit('navigate', 'passes')"><Layers :size="18" /><span><strong>{{ displayLanguage === 'zh' ? '混淆流水线' : 'Obfuscation pipeline' }}</strong><small>{{ displayLanguage === 'zh' ? '调整模块、参数和顺序' : 'Modules, parameters & order' }}</small></span><b>{{ enabledCount }}<small> / {{ state.passes.length }}</small></b><ArrowRight :size="15" /></button>
        <button type="button" @click="emit('navigate', 'classes')"><FolderTree :size="18" /><span><strong>{{ displayLanguage === 'zh' ? '作用范围' : 'Target scope' }}</strong><small>{{ displayLanguage === 'zh' ? `${state.rules.length} 条全局规则 · ${independentCount} 个独立范围` : `${state.rules.length} global rules · ${independentCount} custom scopes` }}</small></span><ArrowRight :size="15" /></button>
      </div>
      <div class="inspection-summary"><div><span class="field-label">{{ displayLanguage === 'zh' ? 'JAR 结构' : 'JAR structure' }}</span><strong>{{ state.inspectingClasses ? (displayLanguage === 'zh' ? '扫描中…' : 'Scanning…') : state.classTree.length ? (displayLanguage === 'zh' ? `${state.classCount} 个类 · ${state.packageCount} 个包` : `${state.classCount} classes · ${state.packageCount} packages`) : (displayLanguage === 'zh' ? '尚无扫描结果' : 'No inspection results') }}</strong></div><NButton size="small" secondary :disabled="busy || !state.inputJar || state.status === 'running' || state.status === 'canceling'" :loading="state.inspectingClasses" @click="emit('inspect')"><template #icon><RefreshCw :size="14" /></template>{{ displayLanguage === 'zh' ? '扫描' : 'Inspect' }}</NButton></div>
      <p class="field-hint">{{ displayLanguage === 'zh' ? '全局规则是默认范围；模块可以独立配置。未设置规则时默认处理全部。' : 'Global rules are the default scope. Modules can have independent rules; an empty rule set processes everything.' }}</p>
    </div>
  </LiquidGlass>
</template>

<style scoped>
.overview-body { display: grid; gap: 18px; padding: 20px; }
.readiness { display: flex; align-items: flex-start; gap: 10px; padding: 13px; background: var(--accent-soft); border: 1px solid var(--line); border-radius: var(--radius-sm); }
.readiness > svg { flex-shrink: 0; margin-top: 2px; color: var(--text-muted); }
.readiness--ready > svg { color: var(--success); }
.readiness > div { display: grid; gap: 5px; }
.readiness strong { font-size: 13px; }
.readiness span { font-size: 12px; color: var(--text-muted); line-height: 1.55; overflow-wrap: anywhere; }
.preparation-links { display: grid; }
.preparation-links button { display: flex; align-items: center; gap: 12px; padding: 15px 0; border: 0; border-bottom: 1px solid var(--line); background: none; color: var(--text-muted); text-align: left; cursor: pointer; }
.preparation-links button:hover { color: var(--text); }
.preparation-links button > span { display: grid; gap: 5px; flex: 1; min-width: 0; }
.preparation-links strong { font-size: 13px; color: var(--text); font-weight: 550; }
.preparation-links small { font-size: 12px; color: var(--text-muted); line-height: 1.45; }
.preparation-links b { font: 18px var(--font-mono); white-space: nowrap; color: var(--text); }
.inspection-summary { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.inspection-summary > div { display: grid; gap: 5px; }
.inspection-summary strong { font-size: 13px; font-weight: 500; }
</style>
