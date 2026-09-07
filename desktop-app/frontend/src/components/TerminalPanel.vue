<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { ArrowDownToLine, Copy, Trash2 } from 'lucide-vue-next'
import { Terminal } from 'xterm'
import 'xterm/css/xterm.css'
import { NButton, NProgress, NSwitch } from 'naive-ui'
import LiquidGlass from './LiquidGlass.vue'
import type { LogLine, RunStatus } from '../modules/obfuscation/types'
import type { DisplayLanguage } from '../modules/obfuscation/pass-localization'
import { localizePassNameById } from '../modules/obfuscation/pass-localization'
import {
  copyTextWithFallback,
  nextPendingLogs,
  shouldPauseAutoFollow,
} from './terminal-log-cursor'

const props = withDefaults(defineProps<{
  readonly logs: readonly LogLine[]
  readonly autoScroll: boolean
  readonly status: RunStatus
  readonly progress: number
  readonly currentStep: string | null
  readonly displayLanguage: DisplayLanguage
  /** Optional: true when the logs page is shown (v-show). Triggers a fit after activation. */
  readonly active?: boolean
  readonly errorMessage?: string | null
  /** View-only last run result; canceled maps to ready in RunStatus. */
  readonly lastOutcome?: 'done' | 'failed' | 'canceled' | null
}>(), {
  active: true,
  errorMessage: null,
  lastOutcome: null,
})

const emit = defineEmits<{
  readonly autoScrollChanged: [autoScroll: boolean]
  readonly clearLogs: []
}>()

const isRunning = computed((): boolean => props.status === 'running' || props.status === 'canceling')

const displayStatus = computed((): RunStatus | 'canceled' => {
  if (props.status === 'failed' || props.status === 'done' || isRunning.value) {
    return props.status
  }
  if (props.status === 'ready' && props.lastOutcome === 'canceled') {
    return 'canceled'
  }
  return props.status
})

const statusLabel = computed((): string => {
  const zh = props.displayLanguage === 'zh'
  switch (displayStatus.value) {
    case 'running':
      return zh ? '运行中' : 'Running'
    case 'canceling':
      return zh ? '正在取消' : 'Canceling'
    case 'canceled':
      return zh ? '已取消' : 'Canceled'
    case 'done':
      return zh ? '已完成' : 'Done'
    case 'failed':
      return zh ? '失败' : 'Failed'
    case 'ready':
      return zh ? '就绪' : 'Ready'
    default:
      return zh ? '空闲' : 'Idle'
  }
})

const currentStepLabel = computed((): string | null => {
  if (props.currentStep === null || !isRunning.value) {
    return null
  }
  const localizedName = localizePassNameById(props.currentStep, props.displayLanguage)
  return props.displayLanguage === 'zh' ? `步骤：${localizedName}` : `Step: ${localizedName}`
})

const lastErrorText = computed((): string | null => {
  if (props.errorMessage !== null && props.errorMessage.trim().length > 0) {
    return props.errorMessage
  }
  if (displayStatus.value !== 'failed') {
    return null
  }
  const errorLine = [...props.logs].reverse().find((line: LogLine): boolean => line.level === 'error')
  return errorLine?.message ?? null
})

const copyFeedback = ref<string | null>(null)
let copyFeedbackTimer: number | null = null

const terminalElement = ref<HTMLDivElement | null>(null)
let terminal: Terminal | null = null
let resizeObserver: ResizeObserver | null = null
let lastRenderedId: string | null = null
let pendingWriteFrame: number | null = null
let ignoreScrollUntil = 0
let windowResizeHandler: (() => void) | null = null
let languageRenderToken = 0

const terminalFontSize = 13
const terminalLineHeight = 1.38

const levelPrefix = (level: LogLine['level'], language: DisplayLanguage): string => {
  if (level === 'warn') {
    return language === 'zh' ? '[警告]' : '[WARN]'
  }

  if (level === 'error') {
    return language === 'zh' ? '[错误]' : '[ERROR]'
  }

  if (level === 'success') {
    return language === 'zh' ? '[完成]' : '[DONE]'
  }

  return language === 'zh' ? '[信息]' : '[INFO]'
}

const formatLogLine = (line: LogLine, language: DisplayLanguage = props.displayLanguage): string => `${levelPrefix(line.level, language)} ${line.message}`

const beginProgrammaticScroll = (): void => {
  ignoreScrollUntil += 1
}

const endProgrammaticScroll = (): void => {
  ignoreScrollUntil = Math.max(0, ignoreScrollUntil - 1)
}

const schedulePendingLogWrite = (): void => {
  if (pendingWriteFrame !== null) {
    return
  }

  pendingWriteFrame = window.requestAnimationFrame((): void => {
    pendingWriteFrame = null
    writePendingLogs()
  })
}

const writePendingLogs = (): void => {
  if (terminal === null) {
    return
  }

  const slice = nextPendingLogs(props.logs, lastRenderedId)
  if (slice.replay) {
    terminal.clear()
    lastRenderedId = null
  }
  if (slice.pending.length === 0) {
    lastRenderedId = slice.nextCursorId
    return
  }

  const payload = slice.pending.map((line: LogLine): string => `${formatLogLine(line)}\r\n`).join('')
  const follow = props.autoScroll
  if (follow) {
    beginProgrammaticScroll()
  }
  terminal.write(payload, (): void => {
    lastRenderedId = slice.nextCursorId
    if (follow) {
      terminal?.scrollToBottom()
    }
    if (follow) {
      endProgrammaticScroll()
    }
  })
}

const replayAllLogs = (): void => {
  lastRenderedId = null
  terminal?.clear()
  schedulePendingLogWrite()
}

const clearTerminal = (): void => {
  lastRenderedId = null
  terminal?.clear()
  emit('clearLogs')
}

const onAutoScrollChange = (value: boolean): void => {
  emit('autoScrollChanged', value)
  if (value) {
    jumpToBottom()
  }
}

const jumpToBottom = (): void => {
  if (terminal === null) {
    return
  }
  beginProgrammaticScroll()
  terminal.scrollToBottom()
  endProgrammaticScroll()
}

const pauseFollowFromScroll = (): void => {
  if (terminal === null) {
    return
  }
  const buffer = terminal.buffer.active
  if (shouldPauseAutoFollow(props.autoScroll, ignoreScrollUntil > 0, buffer.viewportY, buffer.baseY)) {
    emit('autoScrollChanged', false)
  }
}

const measureTerminalCell = (host: HTMLElement): { readonly width: number; readonly height: number } => {
  const probe = document.createElement('span')
  probe.textContent = 'W'
  probe.setAttribute('aria-hidden', 'true')
  probe.style.cssText = `position:absolute;visibility:hidden;font-family:${terminal?.options.fontFamily ?? 'monospace'};font-size:${terminalFontSize}px;line-height:${terminalLineHeight}`
  host.appendChild(probe)
  const rect = probe.getBoundingClientRect()
  probe.remove()

  return {
    width: Math.max(rect.width, 1),
    height: terminalFontSize * terminalLineHeight,
  }
}

const hostIsUsable = (host: HTMLElement): boolean => {
  if (host.clientWidth <= 0 || host.clientHeight <= 0) {
    return false
  }
  const style = getComputedStyle(host)
  return style.display !== 'none' && style.visibility !== 'hidden'
}

const resizeTerminalToHost = (): void => {
  if (terminal === null || terminalElement.value === null) {
    return
  }

  const host = terminalElement.value
  if (!hostIsUsable(host)) {
    return
  }

  const style = getComputedStyle(host)
  const horizontalPadding = Number.parseFloat(style.paddingLeft) + Number.parseFloat(style.paddingRight)
  const verticalPadding = Number.parseFloat(style.paddingTop) + Number.parseFloat(style.paddingBottom)
  const usableWidth = host.clientWidth - (Number.isFinite(horizontalPadding) ? horizontalPadding : 0)
  const usableHeight = host.clientHeight - (Number.isFinite(verticalPadding) ? verticalPadding : 0)
  if (usableWidth <= 0 || usableHeight <= 0) {
    return
  }

  const cell = measureTerminalCell(host)
  const cols = Math.max(Math.floor(usableWidth / cell.width), 2)
  const rows = Math.max(Math.floor(usableHeight / cell.height), 2)
  if (terminal.cols === cols && terminal.rows === rows) {
    return
  }
  terminal.resize(cols, rows)
}

const showCopyFeedback = (message: string): void => {
  copyFeedback.value = message
  if (copyFeedbackTimer !== null) {
    window.clearTimeout(copyFeedbackTimer)
  }
  copyFeedbackTimer = window.setTimeout((): void => {
    copyFeedback.value = null
    copyFeedbackTimer = null
  }, 1800)
}

const copySelectedText = async (): Promise<void> => {
  const selection = terminal?.getSelection() ?? ''
  if (selection.length === 0) {
    return
  }

  try {
    await navigator.clipboard.writeText(selection)
  } catch {
    copyTextWithFallback(selection)
  }
}

const copyAllOriginalLogs = async (): Promise<void> => {
  const text = props.logs.map((line: LogLine): string => formatLogLine(line)).join('\n')
  if (text.length === 0) {
    showCopyFeedback(props.displayLanguage === 'zh' ? '暂无日志' : 'No logs')
    return
  }

  try {
    await navigator.clipboard.writeText(text)
    showCopyFeedback(props.displayLanguage === 'zh' ? '已复制全部日志' : 'Copied all logs')
  } catch {
    try {
      copyTextWithFallback(text)
      showCopyFeedback(props.displayLanguage === 'zh' ? '已复制全部日志' : 'Copied all logs')
    } catch {
      showCopyFeedback(props.displayLanguage === 'zh' ? '复制失败' : 'Copy failed')
    }
  }
}

const disposeTerminal = (): void => {
  if (pendingWriteFrame !== null) {
    window.cancelAnimationFrame(pendingWriteFrame)
    pendingWriteFrame = null
  }
  if (windowResizeHandler !== null) {
    window.removeEventListener('resize', windowResizeHandler)
    windowResizeHandler = null
  }
  resizeObserver?.disconnect()
  resizeObserver = null
  terminal?.dispose()
  terminal = null
}

const initializeTerminal = (): void => {
  if (terminal !== null || terminalElement.value === null) {
    return
  }

  terminal = new Terminal({
    allowProposedApi: false,
    convertEol: true,
    cursorBlink: false,
    disableStdin: true,
    screenReaderMode: true,
    fontFamily: '"Cascadia Code", "JetBrains Mono", Consolas, monospace',
    fontSize: terminalFontSize,
    lineHeight: terminalLineHeight,
    cols: 80,
    rows: 16,
    scrollback: 5000,
    theme: {
      background: '#050505',
      foreground: '#ededed',
      cursor: '#ededed',
      black: '#050505',
      green: '#46d369',
      red: '#f75f5f',
      yellow: '#f5a623',
      white: '#ffffff',
    },
  })

  terminal.open(terminalElement.value)
  resizeTerminalToHost()
  resizeObserver = new ResizeObserver((): void => {
    resizeTerminalToHost()
  })
  resizeObserver.observe(terminalElement.value)

  windowResizeHandler = (): void => {
    resizeTerminalToHost()
  }
  window.addEventListener('resize', windowResizeHandler)

  terminal.onScroll((): void => {
    pauseFollowFromScroll()
  })

  terminal.attachCustomKeyEventHandler((event: KeyboardEvent): boolean => {
    const isCopyShortcut = (event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'c'
    if (isCopyShortcut && terminal?.hasSelection()) {
      event.preventDefault()
      void copySelectedText()
      return false
    }

    return true
  })

  schedulePendingLogWrite()
}

onMounted((): void => {
  if (props.active) {
    initializeTerminal()
  }
})

watch(
  (): readonly LogLine[] => props.logs,
  async (): Promise<void> => {
    await nextTick()
    schedulePendingLogWrite()
  },
  { deep: false },
)

watch(
  (): DisplayLanguage => props.displayLanguage,
  (): void => {
    languageRenderToken += 1
    replayAllLogs()
  },
)

watch(
  (): boolean => props.active,
  async (isActive: boolean): Promise<void> => {
    if (!isActive) {
      return
    }
    await nextTick()
    if (terminal === null) {
      initializeTerminal()
      return
    }
    resizeTerminalToHost()
    if (props.autoScroll) {
      jumpToBottom()
    }
  },
)

onBeforeUnmount((): void => {
  if (copyFeedbackTimer !== null) {
    window.clearTimeout(copyFeedbackTimer)
    copyFeedbackTimer = null
  }
  disposeTerminal()
})
</script>

<template>
  <LiquidGlass as="section" level="surface" class="panel terminal-panel" :aria-label="displayLanguage === 'zh' ? '运行日志' : 'Run logs'">
    <div class="panel-head terminal-head">
      <div class="terminal-status">
        <p class="eyebrow">{{ displayLanguage === 'zh' ? '引擎事件' : 'Engine events' }}</p>
        <h2>{{ displayLanguage === 'zh' ? '运行日志' : 'Run logs' }}</h2>
        <div class="status-row">
          <span class="status-badge" :data-status="displayStatus">{{ statusLabel }}</span>
          <span class="progress-percent">{{ progress }}%</span>
          <span v-if="currentStepLabel" class="current-step-label">{{ currentStepLabel }}</span>
        </div>
        <NProgress
          type="line"
          :percentage="progress"
          :show-indicator="false"
          :status="displayStatus === 'failed' ? 'error' : displayStatus === 'done' ? 'success' : 'default'"
          :border-radius="4"
          :height="4"
          class="run-progress-bar"
        />
        <p v-if="lastErrorText" class="error-line">{{ lastErrorText }}</p>
      </div>
      <div class="terminal-actions">
        <label class="switch-row">
          <span>{{ displayLanguage === 'zh' ? '自动跟随' : 'Auto-follow' }}</span>
          <NSwitch
            :value="autoScroll"
            size="small"
            :aria-label="displayLanguage === 'zh' ? '自动跟随' : 'Auto-follow'"
            @update:value="onAutoScrollChange"
          />
        </label>
        <NButton quaternary size="small" @click="jumpToBottom">
          <template #icon><ArrowDownToLine :size="15" /></template>
          {{ displayLanguage === 'zh' ? '跳到底部' : 'Jump to bottom' }}
        </NButton>
        <NButton quaternary size="small" @click="copyAllOriginalLogs">
          <template #icon><Copy :size="15" /></template>
          {{ displayLanguage === 'zh' ? '复制全部' : 'Copy all' }}
        </NButton>
        <NButton quaternary size="small" @click="clearTerminal">
          <template #icon><Trash2 :size="15" /></template>
          {{ displayLanguage === 'zh' ? '清空' : 'Clear' }}
        </NButton>
        <span v-if="copyFeedback" class="copy-feedback">{{ copyFeedback }}</span>
      </div>
    </div>
    <div
      ref="terminalElement"
      class="terminal-host"
      role="log"
      :aria-label="displayLanguage === 'zh' ? '终端输出' : 'Terminal output'"
    />
  </LiquidGlass>
</template>

<style scoped>
.terminal-panel {
  display: flex;
  flex-direction: column;
  min-height: 0;
  height: 100%;
}

.terminal-head.panel-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-3, 12px);
  flex: 0 0 auto;
  padding-bottom: var(--space-2, 8px);
}

.terminal-status {
  min-width: 0;
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: var(--space-1, 4px);
}

.terminal-status h2 {
  margin: 0;
  font-size: var(--text-lg, 1.05rem);
  color: var(--text, #ededed);
}

.status-row {
  display: flex;
  align-items: center;
  gap: var(--space-2, 8px);
  min-width: 0;
}

.status-badge {
  font-size: var(--text-xs, 12px);
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--text, #ededed);
  border: 1px solid color-mix(in srgb, var(--text, #ededed) 28%, transparent);
  border-radius: var(--radius-sm, 4px);
  padding: 1px 6px;
  background: color-mix(in srgb, var(--bg, #050505) 45%, transparent);
}

.status-badge[data-status='running'],
.status-badge[data-status='canceling'] {
  border-color: color-mix(in srgb, var(--text, #ededed) 55%, transparent);
}

.status-badge[data-status='done'] {
  color: var(--ok, #46d369);
  border-color: color-mix(in srgb, var(--ok, #46d369) 45%, transparent);
}

.status-badge[data-status='failed'] {
  color: var(--danger, #f75f5f);
  border-color: color-mix(in srgb, var(--danger, #f75f5f) 50%, transparent);
}

.status-badge[data-status='canceled'] {
  color: var(--warn, #f5a623);
  border-color: color-mix(in srgb, var(--warn, #f5a623) 45%, transparent);
}

.terminal-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-2, 6px);
  flex: 0 0 auto;
}

.run-progress-bar {
  width: min(280px, 100%);
}

.run-progress-bar :deep(.n-progress-graph) {
  transition: all 0.3s ease;
}

.current-step-label {
  font-size: var(--text-sm, 12px);
  color: var(--muted, #aaa);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  min-width: 0;
}

.progress-percent {
  font-size: var(--text-sm, 12px);
  color: var(--muted, #888);
  white-space: nowrap;
}

.error-line {
  margin: 0;
  font-size: var(--text-sm, 13px);
  line-height: 1.45;
  color: var(--danger, #f75f5f);
  white-space: normal;
  overflow-wrap: anywhere;
  max-width: 100%;
}

.copy-feedback {
  font-size: var(--text-sm, 12px);
  color: var(--muted, #aaa);
}

.terminal-host {
  flex: 1 1 auto;
  min-height: 0;
  width: 100%;
  overflow: hidden;
}

.terminal-host :deep(.xterm) {
  height: 100%;
}

.switch-row {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2, 6px);
  font-size: var(--text-sm, 12px);
  color: var(--muted, #aaa);
}
</style>
