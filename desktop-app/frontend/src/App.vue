<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { CircleAlert, ScrollText } from 'lucide-vue-next'
import { NConfigProvider, createDiscreteApi, darkTheme } from 'naive-ui'
import { BrowserOpenURL } from '../wailsjs/runtime/runtime'
import AboutPanel from './components/AboutPanel.vue'
import ClassTreePanel from './components/ClassTreePanel.vue'
import DropZonePanel from './components/DropZonePanel.vue'
import OutputPanel from './components/OutputPanel.vue'
import PipelinePanel from './components/PipelinePanel.vue'
import RunStatusBar from './components/RunStatusBar.vue'
import TerminalPanel from './components/TerminalPanel.vue'
import WorkbenchCommandBar from './components/WorkbenchCommandBar.vue'
import WorkbenchNavigation from './components/WorkbenchNavigation.vue'
import WorkbenchOverview from './components/WorkbenchOverview.vue'
import { applyBridgeError, applyEngineEvent, countEnabledPasses, createInitialRunState } from './modules/obfuscation/state'
import { attachFrontendLifecycle, detachFrontendLifecycle, type FrontendLifecycleBindings } from './modules/obfuscation/lifecycle-controller'
import { parseEngineEvent } from './modules/obfuscation/event-parser'
import { loadWorkbenchState } from './modules/obfuscation/page-controller'
import { createWorkbenchHandlers } from './modules/obfuscation/workbench-handlers'
import { toggleLanguage, type DisplayLanguage } from './modules/obfuscation/pass-localization'
import { getReadinessIssue, runIsBusy, type RunOutcome, type WorkbenchPage } from './modules/obfuscation/workbench-view'
import type { RunState, RunStatus } from './modules/obfuscation/types'
import { createWailsBridge } from './modules/obfuscation/wails-bridge'

const themeOverrides = {
  common: {
    primaryColor: '#ededed', primaryColorHover: '#ffffff', primaryColorPressed: '#cfcfcf', primaryColorSuppl: '#ededed',
    borderRadius: '8px', fontFamily: 'var(--font-ui)', textColorBase: '#ededed',
  },
}
const state = ref<RunState>(createInitialRunState())
const activePage = ref<WorkbenchPage>('home')
const displayLanguage = ref<DisplayLanguage>('zh')
const isWindowMaximised = ref(false)
const pending = ref<string | null>(null)
const loadingCapabilities = ref(true)
const lastOutcome = ref<RunOutcome | null>(null)
const pageHost = ref<HTMLElement | null>(null)
const { message } = createDiscreteApi(['message'], { configProviderProps: { theme: darkTheme, themeOverrides } })
const bridge = createWailsBridge(window)
let lifecycleBindings: FrontendLifecycleBindings | null = null
let disposed = false

const activePassCount = computed(() => countEnabledPasses(state.value.passes))
const busy = computed(() => loadingCapabilities.value || pending.value !== null || state.value.inspectingClasses)
const editingStatus = computed<RunStatus>(() => busy.value ? 'running' : state.value.status)
const readinessIssue = computed(() => getReadinessIssue(state.value, displayLanguage.value))
const canStart = computed(() => !busy.value && !runIsBusy(state.value.status) && readinessIssue.value === null)
const version = computed(() => state.value.schema?.engineVersion ?? (displayLanguage.value === 'zh' ? '等待引擎' : 'Waiting for engine'))
const pageTitle = computed(() => ({
  home: ['工作台', 'Workbench'], passes: ['流水线', 'Pipeline'], classes: ['作用范围', 'Scope'], logs: ['运行日志', 'Run logs'], about: ['关于', 'About'],
})[activePage.value][displayLanguage.value === 'zh' ? 0 : 1] ?? '')
const busyLabel = computed(() => loadingCapabilities.value
  ? (displayLanguage.value === 'zh' ? '加载引擎中' : 'Loading engine')
  : pending.value !== null || state.value.inspectingClasses ? (displayLanguage.value === 'zh' ? '正在处理文件与配置' : 'Processing files & configuration') : null)
const startHint = computed(() => busyLabel.value ?? readinessIssue.value?.message ?? (displayLanguage.value === 'zh' ? '使用当前配置开始混淆' : 'Start with the current configuration'))
const handlers = createWorkbenchHandlers({ state, bridge, message, activePage, isWindowMaximised })

const navigate = (page: WorkbenchPage): void => { activePage.value = page }
watch(() => state.value.inputJar?.inputJarPath, () => { lastOutcome.value = null })
watch(activePage, async () => {
  await nextTick()
  const heading = pageHost.value?.querySelector<HTMLElement>(`[data-page="${activePage.value}"] h2`)
  heading?.setAttribute('tabindex', '-1')
  heading?.focus({ preventScroll: true })
})

const withFileAction = async (name: string, action: () => Promise<void>): Promise<void> => {
  if (busy.value || runIsBusy(state.value.status)) return
  pending.value = name
  try { await action() }
  finally { pending.value = null }
}
const handleNativeFileDrop = (x: number, y: number, paths: string[]): Promise<void> => withFileAction('drop', () => handlers.handleNativeFileDrop(x, y, paths))
const handleBrowseInput = (): Promise<void> => withFileAction('input', handlers.handleBrowseInput)
const handleBrowseOutput = (): Promise<void> => withFileAction('output', handlers.handleBrowseOutput)
const handleImport = (): Promise<void> => withFileAction('import', handlers.handleImportConfig)
const handleExport = async (): Promise<void> => {
  if (busy.value) return
  pending.value = 'export'
  try { await handlers.handleExportConfig() }
  finally { pending.value = null }
}
const handleInspect = (): Promise<void> => withFileAction('inspect', handlers.inspectCurrentJar)
const handleStart = async (): Promise<void> => {
  if (!canStart.value) return
  lastOutcome.value = null
  await handlers.handleStart()
}
const handleEnginePayload = (payload: unknown): void => {
  try {
    const event = parseEngineEvent(payload)
    state.value = applyEngineEvent(state.value, event)
    if (event.type === 'done') lastOutcome.value = 'done'
    else if (event.type === 'error') lastOutcome.value = 'failed'
    else if (event.type === 'canceled') lastOutcome.value = 'canceled'
  } catch (error) { state.value = applyBridgeError(state.value, error, '处理引擎事件失败') }
}
const loadCapabilities = async (): Promise<void> => {
  if (runIsBusy(state.value.status)) return
  loadingCapabilities.value = true
  try {
    const result = await loadWorkbenchState(state.value, bridge)
    if (disposed) return
    state.value = result.nextState
    if (result.isWindowMaximised !== null) isWindowMaximised.value = result.isWindowMaximised
  } finally { loadingCapabilities.value = false }
}
onMounted(() => {
  try { lifecycleBindings = attachFrontendLifecycle(bridge, handleEnginePayload, handleNativeFileDrop) }
  catch (error) { state.value = applyBridgeError(state.value, error, '绑定前端生命周期失败') }
  void loadCapabilities()
})
onBeforeUnmount(() => {
  disposed = true
  if (lifecycleBindings) detachFrontendLifecycle(lifecycleBindings)
})
</script>

<template>
  <NConfigProvider :theme="darkTheme" :theme-overrides="themeOverrides">
    <main class="app-shell">
      <WorkbenchNavigation :active-page="activePage" :display-language="displayLanguage" :version="version" :pass-count="`${activePassCount}/${state.passes.length}`" :rule-count="state.rules.length" @navigate="navigate" />
      <section class="workbench-shell">
        <WorkbenchCommandBar :informational="activePage === 'about'" :title="pageTitle" :file-name="state.inputJar?.fileName ?? null" :display-language="displayLanguage" :status="state.status" :can-start="canStart" :busy="busy" :maximised="isWindowMaximised" :start-hint="startHint" @import="handleImport" @export="handleExport" @start="handleStart" @cancel="handlers.handleCancel" @language="displayLanguage = toggleLanguage(displayLanguage)" @window="handlers.handleWindowAction" />
        <div v-if="state.errorMessage && activePage !== 'logs'" class="workbench-error" role="alert"><CircleAlert :size="17" /><span>{{ state.errorMessage }}</span><button type="button" class="text-link" @click="navigate('logs')"><ScrollText :size="15" />{{ displayLanguage === 'zh' ? '查看详情' : 'Details' }}</button></div>
        <div ref="pageHost" class="page-host">
          <section v-show="activePage === 'home'" data-page="home" class="page-panel page-panel--home">
            <div class="home-heading"><div><p class="eyebrow">{{ displayLanguage === 'zh' ? '任务总览' : 'TASK OVERVIEW' }}</p><h1>{{ displayLanguage === 'zh' ? '配置混淆任务' : 'Configure your run' }}</h1><p>{{ displayLanguage === 'zh' ? '选择文件，安排流水线，确认范围；运行状态始终可见。' : 'Choose a file, arrange the pipeline, and review scope. Keep every run in view.' }}</p></div><span class="workbench-kicker">JAR / {{ displayLanguage === 'zh' ? '字节码保护' : 'BYTECODE PROTECTION' }}</span></div>
            <div class="home-grid"><DropZonePanel :input-jar="state.inputJar" :output-jar-path="state.outputJarPath" :status="editingStatus" :display-language="displayLanguage" @input-path-changed="handlers.handleInputPathChanged" @output-changed="handlers.handleOutputChanged" @browse-input="handleBrowseInput" @browse-output="handleBrowseOutput" /><WorkbenchOverview :state="state" :display-language="displayLanguage" :busy="busy" @navigate="navigate" @inspect="handleInspect" @retry="loadCapabilities" /></div>
            <OutputPanel :output-path="state.outputPath" :output-jar-path="state.outputJarPath" :status="state.status" :display-language="displayLanguage" :outcome="lastOutcome" :error="state.errorMessage" @logs="navigate('logs')" />
          </section>
          <section v-show="activePage === 'passes'" data-page="passes" class="page-panel"><PipelinePanel :passes="state.passes" :status="editingStatus" :display-language="displayLanguage" :schema-compatibility="state.schema?.compatibility ?? []" @passes-changed="handlers.handlePassesChanged" @pass-toggled="handlers.handlePassToggled" @pass-param-changed="handlers.handlePassParamChanged" @browse-native-shroud-cli="handlers.handleBrowseNativeShroudCli" /></section>
          <section v-show="activePage === 'classes'" data-page="classes" class="page-panel"><ClassTreePanel :nodes="state.classTree" :rules="state.rules" :pass-selections="state.passSelections" :passes="state.passes" :class-count="state.classCount" :inspecting="state.inspectingClasses" :status="editingStatus" :display-language="displayLanguage" @inspect="handleInspect" @node-rule-changed="handlers.handleNodeRuleChanged" @pass-selection-mode-changed="handlers.handlePassSelectionModeChanged" @pass-selection-rule-changed="handlers.handlePassSelectionRuleChanged" /></section>
          <section v-show="activePage === 'logs'" data-page="logs" class="page-panel"><TerminalPanel :active="activePage === 'logs'" :error-message="state.errorMessage" :last-outcome="lastOutcome" :logs="state.logs" :auto-scroll="state.autoScroll" :status="state.status" :progress="state.progress" :current-step="state.currentStep" :display-language="displayLanguage" @auto-scroll-changed="handlers.handleAutoScrollChanged" @clear-logs="handlers.handleClearLogs" /></section>
          <section v-show="activePage === 'about'" data-page="about" class="page-panel"><AboutPanel :display-language="displayLanguage" :version="version" @open="BrowserOpenURL" /></section>
        </div>
        <RunStatusBar :status="state.status" :progress="state.progress" :step="state.currentStep" :error="state.errorMessage" :outcome="lastOutcome" :busy-label="busyLabel" :display-language="displayLanguage" :pass-count="activePassCount" @logs="navigate('logs')" />
      </section>
    </main>
  </NConfigProvider>
</template>
