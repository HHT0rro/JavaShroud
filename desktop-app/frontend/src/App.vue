<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, type Component } from 'vue'
import { BookOpen, Download, FileInput, Info, Languages, Maximize2, Minimize2, Minus, Play, ScrollText, Settings2, Square, Upload, X } from 'lucide-vue-next'
import { NButton, NConfigProvider, NTooltip, createDiscreteApi, darkTheme } from 'naive-ui'
import { BrowserOpenURL } from '../wailsjs/runtime/runtime'
import ClassTreePanel from './components/ClassTreePanel.vue'
import DropZonePanel from './components/DropZonePanel.vue'
import LiquidGlass from './components/LiquidGlass.vue'
import PipelinePanel from './components/PipelinePanel.vue'
import TerminalPanel from './components/TerminalPanel.vue'
import { applyBridgeError, countEnabledPasses, createInitialRunState } from './modules/obfuscation/state'
import { attachFrontendLifecycle, detachFrontendLifecycle, type FrontendLifecycleBindings } from './modules/obfuscation/lifecycle-controller'
import { applyEnginePayload } from './modules/obfuscation/frontend-controller'
import { loadWorkbenchState } from './modules/obfuscation/page-controller'
import { createWorkbenchHandlers } from './modules/obfuscation/workbench-handlers'
import { languageToggleLabel, nextLanguageLabel, t, toggleLanguage, type DisplayLanguage } from './modules/obfuscation/pass-localization'
import type { RunState } from './modules/obfuscation/types'
import { createWailsBridge, type WailsBridge } from './modules/obfuscation/wails-bridge'
import javashroudLogo from './assets/logo.png'

type PageId = 'home' | 'passes' | 'classes' | 'logs' | 'about'

interface NavItem {
  readonly id: PageId
  readonly icon: Component
  readonly labelKey: Parameters<typeof t>[0]
  readonly descriptionKey: Parameters<typeof t>[0]
}

interface WindowActionItem {
  readonly id: 'minimise' | 'toggle-maximise' | 'quit'
  readonly label: string
  readonly icon: Component
}

const themeOverrides = {
  common: {
    primaryColor: '#ededed',
    primaryColorHover: '#ffffff',
    primaryColorPressed: '#cfcfcf',
    primaryColorSuppl: '#ededed',
    borderRadius: '8px',
    fontFamily: 'var(--font-ui)',
    textColorBase: '#ededed',
  },
}

const navItems: readonly NavItem[] = [
  { id: 'home', icon: FileInput, labelKey: 'home', descriptionKey: 'inputOutput' },
  { id: 'passes', icon: Settings2, labelKey: 'passes', descriptionKey: 'passFeatures' },
  { id: 'classes', icon: BookOpen, labelKey: 'rules', descriptionKey: 'classScope' },
  { id: 'logs', icon: ScrollText, labelKey: 'logs', descriptionKey: 'eventStream' },
  { id: 'about', icon: Info, labelKey: 'about', descriptionKey: 'projectLicense' },
]

const state = ref<RunState>(createInitialRunState())
const activePage = ref<PageId>('home')
const displayLanguage = ref<DisplayLanguage>('zh')
const isWindowMaximised = ref<boolean>(false)
const { message } = createDiscreteApi(['message'])
const bridge: WailsBridge = createWailsBridge(window)
let lifecycleBindings: FrontendLifecycleBindings | null = null

const activePassCount = computed((): number => countEnabledPasses(state.value.passes))
const passCountLabel = computed((): string => `${activePassCount.value}/${state.value.passes.length}`)
const canStart = computed((): boolean => (
  state.value.inputJar !== null
  && state.value.inputJar.inputJarPath.trim().length > 0
  && state.value.outputJarPath.trim().length > 0
  && activePassCount.value > 0
  && state.value.status !== 'running'
  && state.value.status !== 'canceling'
))
const canCancel = computed((): boolean => state.value.status === 'running')
const canImportConfig = computed((): boolean => state.value.status !== 'running' && state.value.status !== 'canceling')
const maximiseIcon = computed((): Component => (isWindowMaximised.value ? Minimize2 : Maximize2))
const currentLanguageLabel = computed((): string => languageToggleLabel(displayLanguage.value))
const languageTooltipLabel = computed((): string => `${t('switchTo', displayLanguage.value)} ${nextLanguageLabel(displayLanguage.value)}`)
const engineVersionLabel = computed((): string => state.value.schema?.engineVersion ?? 'loading')
const vbcVersionLabel = computed((): string => state.value.schema?.vbcVersion ?? 'loading')
const windowActions = computed((): readonly WindowActionItem[] => [
  { id: 'minimise', label: t('minimize', displayLanguage.value), icon: Minus },
  { id: 'toggle-maximise', label: isWindowMaximised.value ? t('restore', displayLanguage.value) : t('maximize', displayLanguage.value), icon: maximiseIcon.value },
  { id: 'quit', label: t('close', displayLanguage.value), icon: X },
])

const handleLanguageToggled = (): void => {
  displayLanguage.value = toggleLanguage(displayLanguage.value)
}

const handlePageChanged = (pageId: PageId): void => {
  activePage.value = pageId
}

const handleAboutPageChanged = (): void => {
  activePage.value = 'about'
}

const handleExternalLinkOpened = (url: string): void => {
  BrowserOpenURL(url)
}

const handlers = createWorkbenchHandlers({
  state,
  bridge,
  message,
  activePage,
  isWindowMaximised,
})

const handleWindowAction = handlers.handleWindowAction
const handleNativeFileDrop = handlers.handleNativeFileDrop
const handleInputPathChanged = handlers.handleInputPathChanged
const handleOutputChanged = handlers.handleOutputChanged
const handleBrowseInput = handlers.handleBrowseInput
const handleBrowseOutput = handlers.handleBrowseOutput
const handleImportConfig = handlers.handleImportConfig
const handleExportConfig = handlers.handleExportConfig
const inspectCurrentJar = handlers.inspectCurrentJar
const handlePassesChanged = handlers.handlePassesChanged
const handlePassToggled = handlers.handlePassToggled
const handlePassParamChanged = handlers.handlePassParamChanged
const handleAutoScrollChanged = handlers.handleAutoScrollChanged
const handleNodeRuleChanged = handlers.handleNodeRuleChanged
const handleClearLogs = handlers.handleClearLogs
const handleStart = handlers.handleStart
const handleCancel = handlers.handleCancel

const handleEnginePayload = (payload: unknown): void => {
  state.value = applyEnginePayload(state.value, payload)
}

const loadCapabilities = async (): Promise<void> => {
  const result = await loadWorkbenchState(state.value, bridge)
  state.value = result.nextState
  if (result.isWindowMaximised !== null) {
    isWindowMaximised.value = result.isWindowMaximised
  }
}

onMounted((): void => {
  try {
    lifecycleBindings = attachFrontendLifecycle(bridge, handleEnginePayload, handleNativeFileDrop)
  } catch (error) {
    state.value = applyBridgeError(state.value, error, '绑定前端生命周期失败')
  }

  void loadCapabilities()
})

onBeforeUnmount((): void => {
  if (lifecycleBindings !== null) {
    detachFrontendLifecycle(lifecycleBindings)
    lifecycleBindings = null
  }
})
</script>

<template>
  <NConfigProvider :theme="darkTheme" :theme-overrides="themeOverrides">
    <main class="app-shell">
      <LiquidGlass as="aside" level="background" class="side-rail" :aria-label="t('appNav', displayLanguage)">
        <div class="brand-lockup">
          <img class="brand-logo" :src="javashroudLogo" alt="JavaShroud" />
          <div class="brand-copy">
            <span class="brand-name">JavaShroud</span>
            <span class="brand-tagline">{{ displayLanguage === 'zh' ? '字节码混淆工作台' : 'Bytecode obfuscation workbench' }}</span>
            <span class="version-pills" aria-label="JavaShroud and VBC versions">
              <span class="version-pill" :title="`JavaShroud ${engineVersionLabel}`" :aria-label="`JavaShroud ${engineVersionLabel}`">
                <span class="version-pill-key">JS</span>
                <span class="version-pill-value">{{ engineVersionLabel }}</span>
              </span>
              <span class="version-pill" :title="`VBC ${vbcVersionLabel}`" :aria-label="`VBC ${vbcVersionLabel}`">
                <span class="version-pill-key">VBC</span>
                <span class="version-pill-value">{{ vbcVersionLabel }}</span>
              </span>
            </span>
          </div>
        </div>

        <nav class="rail-nav" :aria-label="t('workbenchSections', displayLanguage)">
          <button
            v-for="(item, index) in navItems"
            :key="item.id"
            v-motion
            :initial="{ opacity: 0, x: -10 }"
            :enter="{ opacity: 1, x: 0, transition: { delay: 80 + index * 55, duration: 320 } }"
            type="button"
            class="rail-link"
            :class="{ active: activePage === item.id }"
            @click="handlePageChanged(item.id)"
          >
            <component :is="item.icon" class="nav-icon" :stroke-width="1.9" aria-hidden="true" />
            <span class="rail-link-main">{{ t(item.labelKey, displayLanguage) }}</span>
            <span class="rail-link-sub">{{ t(item.descriptionKey, displayLanguage) }}</span>
          </button>
        </nav>

        <section class="rail-meter" :aria-label="t('configSummary', displayLanguage)">
          <div>
            <span class="metric-value">{{ passCountLabel }}</span>
            <span class="metric-label">{{ t('enabledPasses', displayLanguage) }}</span>
          </div>
          <div>
            <span class="metric-value">{{ state.rules.length }}</span>
            <span class="metric-label">{{ t('excludedRules', displayLanguage) }}</span>
          </div>
        </section>

        <div class="rail-footer" :aria-label="t('projectInfo', displayLanguage)">
          <button type="button" class="text-link strong" @click="handleAboutPageChanged">JavaShroud</button>
          <button type="button" class="text-link" @click="handleExternalLinkOpened('https://www.gnu.org/licenses/gpl-3.0.html')">GPL-3.0</button>
          <button type="button" class="text-link muted" @click="handleExternalLinkOpened('https://github.com/HHT0rro/JavaShroud')">GitHub</button>
        </div>
      </LiquidGlass>

      <section class="workbench-shell">
        <LiquidGlass as="header" level="surface" class="command-bar command-bar--actions-only">
          <div class="window-drag-region" aria-hidden="true"></div>

          <div class="hero-actions">
            <NButton secondary size="large" :disabled="!canImportConfig" @click="handleImportConfig">
              <template #icon><Upload :size="16" /></template>
              {{ t('importConfig', displayLanguage) }}
            </NButton>
            <NButton secondary size="large" @click="handleExportConfig">
              <template #icon><Download :size="16" /></template>
              {{ t('exportConfig', displayLanguage) }}
            </NButton>
            <NButton type="primary" size="large" :disabled="!canStart" :loading="state.status === 'running'" @click="handleStart">
              <template #icon><Play :size="16" /></template>
              {{ t('start', displayLanguage) }}
            </NButton>
            <NButton tertiary size="large" :disabled="!canCancel" @click="handleCancel">
              <template #icon><Square :size="15" /></template>
              {{ t('cancel', displayLanguage) }}
            </NButton>
            <NButton secondary size="large" class="language-action" :aria-label="languageTooltipLabel" @click="handleLanguageToggled">
              <template #icon><Languages :size="16" /></template>
              {{ currentLanguageLabel }}
            </NButton>
          </div>

          <div class="utility-actions" :aria-label="t('windowControls', displayLanguage)">
            <NTooltip v-for="action in windowActions" :key="action.id" trigger="hover">
              <template #trigger>
                <button
                  type="button"
                  class="utility-button"
                  :class="{ danger: action.id === 'quit' }"
                  :aria-label="action.label"
                  @click="handleWindowAction(action.id)"
                >
                  <component :is="action.icon" :stroke-width="2" aria-hidden="true" />
                </button>
              </template>
              <span>{{ action.label }}</span>
            </NTooltip>
          </div>
        </LiquidGlass>

        <section v-if="activePage === 'home'" v-motion :initial="{ opacity: 0, y: 8 }" :enter="{ opacity: 1, y: 0 }" class="page-panel page-panel--home">
          <DropZonePanel
            :input-jar="state.inputJar"
            :output-jar-path="state.outputJarPath"
            :status="state.status"
            :display-language="displayLanguage"
            @input-path-changed="handleInputPathChanged"
            @output-changed="handleOutputChanged"
            @browse-input="handleBrowseInput"
            @browse-output="handleBrowseOutput"
          />
        </section>

        <section v-else-if="activePage === 'passes'" v-motion :initial="{ opacity: 0, y: 10 }" :enter="{ opacity: 1, y: 0 }" class="page-panel">
          <PipelinePanel
            :passes="state.passes"
            :status="state.status"
            :display-language="displayLanguage"
            :schema-compatibility="state.schema?.compatibility ?? []"
            @passes-changed="handlePassesChanged"
            @pass-toggled="handlePassToggled"
            @pass-param-changed="handlePassParamChanged"
          />
        </section>

        <section v-else-if="activePage === 'classes'" v-motion :initial="{ opacity: 0, y: 10 }" :enter="{ opacity: 1, y: 0 }" class="page-panel">
          <ClassTreePanel
            :nodes="state.classTree"
            :rules="state.rules"
            :class-count="state.classCount"
            :inspecting="state.inspectingClasses"
            :display-language="displayLanguage"
            @inspect="inspectCurrentJar"
            @node-rule-changed="handleNodeRuleChanged"
          />
        </section>

        <section v-else-if="activePage === 'logs'" v-motion :initial="{ opacity: 0, y: 10 }" :enter="{ opacity: 1, y: 0 }" class="page-panel">
          <TerminalPanel
            :logs="state.logs"
            :auto-scroll="state.autoScroll"
            :status="state.status"
            :progress="state.progress"
            :current-step="state.currentStep"
            :display-language="displayLanguage"
            @auto-scroll-changed="handleAutoScrollChanged"
            @clear-logs="handleClearLogs"
          />
        </section>

        <section v-else v-motion :initial="{ opacity: 0, y: 10 }" :enter="{ opacity: 1, y: 0 }" class="about-page">
          <LiquidGlass as="article" level="surface" class="panel about-card">
            <img class="about-brand-logo" :src="javashroudLogo" alt="JavaShroud" />
            <div class="about-copy">
              <p class="eyebrow">{{ t('aboutApp', displayLanguage) }}</p>
              <h2>JavaShroud</h2>
              <p>{{ t('aboutDescription', displayLanguage) }}</p>
              <p>{{ t('aboutStack', displayLanguage) }}</p>
            </div>
          </LiquidGlass>

          <LiquidGlass as="article" level="surface" class="panel about-card about-card--license">
            <div class="about-license-mark" aria-hidden="true">GPL</div>
            <div class="about-copy">
              <p class="eyebrow">{{ t('openSourceLicense', displayLanguage) }}</p>
              <h2>GPL-3.0</h2>
              <p>{{ t('licenseDescription', displayLanguage) }}</p>
              <p>{{ t('licenseObligation', displayLanguage) }}</p>
              <NButton secondary round @click="handleExternalLinkOpened('https://www.gnu.org/licenses/gpl-3.0.html')">{{ t('viewGpl', displayLanguage) }}</NButton>
            </div>
          </LiquidGlass>
        </section>
      </section>
    </main>
  </NConfigProvider>
</template>
