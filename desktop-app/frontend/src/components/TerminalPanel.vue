<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { Trash2 } from 'lucide-vue-next'
import { Terminal } from 'xterm'
import 'xterm/css/xterm.css'
import { NButton, NProgress, NSwitch } from 'naive-ui'
import LiquidGlass from './LiquidGlass.vue'
import type { LogLine, RunStatus } from '../modules/obfuscation/types'
import type { DisplayLanguage } from '../modules/obfuscation/pass-localization'
import { localizePassNameById } from '../modules/obfuscation/pass-localization'

const props = defineProps<{
  readonly logs: readonly LogLine[]
  readonly autoScroll: boolean
  readonly status: RunStatus
  readonly progress: number
  readonly currentStep: string | null
  readonly displayLanguage: DisplayLanguage
}>()

const emit = defineEmits<{
  readonly autoScrollChanged: [autoScroll: boolean]
  readonly clearLogs: []
}>()

const isRunning = computed((): boolean => props.status === 'running' || props.status === 'canceling')

const currentStepLabel = computed((): string | null => {
  if (props.currentStep === null || !isRunning.value) {
    return null
  }
  const localizedName = localizePassNameById(props.currentStep, props.displayLanguage)
  return props.displayLanguage === 'zh' ? `正在执行：${localizedName}` : `Running: ${localizedName}`
})

const terminalElement = ref<HTMLDivElement | null>(null)
let terminal: Terminal | null = null
let resizeObserver: ResizeObserver | null = null
let renderedLogCount = 0
let pendingWriteFrame: number | null = null

const terminalFontSize = 13
const terminalLineHeight = 1.38

const levelPrefix = (level: LogLine['level']): string => {
  if (level === 'warn') {
    return props.displayLanguage === 'zh' ? '[警告]' : '[WARN]'
  }

  if (level === 'error') {
    return props.displayLanguage === 'zh' ? '[错误]' : '[ERROR]'
  }

  if (level === 'success') {
    return props.displayLanguage === 'zh' ? '[完成]' : '[DONE]'
  }

  return props.displayLanguage === 'zh' ? '[信息]' : '[INFO]'
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

  const pendingLogs: readonly LogLine[] = props.logs.slice(renderedLogCount)
  if (pendingLogs.length === 0) {
    return
  }

  terminal.write(pendingLogs.map((line: LogLine): string => `${levelPrefix(line.level)} ${line.message}\r\n`).join(''))
  renderedLogCount = props.logs.length

  if (props.autoScroll) {
    terminal.scrollToBottom()
  }
}

const clearTerminal = (): void => {
  renderedLogCount = 0
  terminal?.clear()
  emit('clearLogs')
}

const onAutoScrollChange = (value: boolean): void => {
  emit('autoScrollChanged', value)
}

const measureTerminalCell = (host: HTMLElement): { readonly width: number; readonly height: number } => {
  const probe = document.createElement('span')
  probe.textContent = 'W'
  probe.style.cssText = `position:absolute;visibility:hidden;font-family:${terminal?.options.fontFamily ?? 'monospace'};font-size:${terminalFontSize}px;line-height:${terminalLineHeight}`
  host.appendChild(probe)
  const rect = probe.getBoundingClientRect()
  probe.remove()

  return {
    width: Math.max(rect.width, 1),
    height: terminalFontSize * terminalLineHeight,
  }
}

const resizeTerminalToHost = (): void => {
  if (terminal === null || terminalElement.value === null) {
    return
  }

  const host = terminalElement.value
  const style = getComputedStyle(host)
  const horizontalPadding = Number.parseFloat(style.paddingLeft) + Number.parseFloat(style.paddingRight)
  const verticalPadding = Number.parseFloat(style.paddingTop) + Number.parseFloat(style.paddingBottom)
  const cell = measureTerminalCell(host)
  const cols = Math.max(Math.floor((host.clientWidth - horizontalPadding) / cell.width), 20)
  const rows = Math.max(Math.floor((host.clientHeight - verticalPadding) / cell.height), 6)
  terminal.resize(cols, rows)
}

const copyWithFallback = (selection: string): void => {
  const textarea = document.createElement('textarea')
  textarea.value = selection
  textarea.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0'
  document.body.appendChild(textarea)
  textarea.select()
  document.execCommand('copy')
  textarea.remove()
}

const copySelectedText = async (): Promise<void> => {
  const selection = terminal?.getSelection() ?? ''
  if (selection.length === 0) {
    return
  }

  try {
    await navigator.clipboard.writeText(selection)
  } catch {
    copyWithFallback(selection)
  }
}

onMounted((): void => {
  terminal = new Terminal({
    allowProposedApi: false,
    convertEol: true,
    cursorBlink: false,
    disableStdin: true,
    fontFamily: '"Cascadia Code", "JetBrains Mono", Consolas, monospace',
    fontSize: terminalFontSize,
    lineHeight: terminalLineHeight,
    cols: 120,
    rows: 16,
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

  if (terminalElement.value !== null) {
    terminal.open(terminalElement.value)
    resizeTerminalToHost()
    resizeObserver = new ResizeObserver(resizeTerminalToHost)
    resizeObserver.observe(terminalElement.value)
  }

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
})

watch(
  (): readonly LogLine[] => props.logs,
  async (): Promise<void> => {
    await nextTick()
    schedulePendingLogWrite()
  },
  { deep: false },
)

onBeforeUnmount((): void => {
  if (pendingWriteFrame !== null) {
    window.cancelAnimationFrame(pendingWriteFrame)
    pendingWriteFrame = null
  }
  resizeObserver?.disconnect()
  resizeObserver = null
  terminal?.dispose()
  terminal = null
})
</script>

<template>
  <LiquidGlass as="section" level="surface" class="panel terminal-panel">
    <div class="panel-head">
      <div>
        <p class="eyebrow">{{ displayLanguage === 'zh' ? '引擎事件' : 'Engine events' }}</p>
        <h2>{{ displayLanguage === 'zh' ? '运行事件流' : 'Run event stream' }}</h2>
      </div>
      <div class="terminal-actions">
        <div class="progress-area">
          <NProgress
            type="line"
            :percentage="progress"
            :show-indicator="false"
            :status="status === 'failed' ? 'error' : status === 'done' ? 'success' : 'default'"
            :border-radius="4"
            :height="6"
            class="run-progress-bar"
          />
          <span v-if="currentStepLabel" class="current-step-label">{{ currentStepLabel }}</span>
          <span v-else class="progress-percent">{{ progress }}%</span>
        </div>
        <label class="switch-row">
          <span>{{ displayLanguage === 'zh' ? '自动滚动' : 'Auto scroll' }}</span>
          <NSwitch :value="autoScroll" size="small" @update:value="onAutoScrollChange" />
        </label>
        <NButton quaternary size="small" @click="clearTerminal">
          <template #icon><Trash2 :size="15" /></template>
          {{ displayLanguage === 'zh' ? '清空' : 'Clear' }}
        </NButton>
      </div>
    </div>
    <div class="terminal-summary">
      <span>{{ logs.length }} {{ displayLanguage === 'zh' ? '条事件' : 'events' }}</span>
      <span>{{ displayLanguage === 'zh' ? 'Ctrl/Cmd + C 可复制选中日志' : 'Ctrl/Cmd + C copies selected logs' }}</span>
    </div>
    <div ref="terminalElement" class="terminal-host" />
  </LiquidGlass>
</template>

<style scoped>
.progress-area {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 160px;
}

.run-progress-bar {
  flex: 1;
  min-width: 80px;
}

.run-progress-bar :deep(.n-progress-graph) {
  transition: all 0.3s ease;
}

.current-step-label {
  font-size: 11px;
  color: var(--n-text-color-2, #aaa);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 180px;
}

.progress-percent {
  font-size: 11px;
  color: var(--n-text-color-3, #888);
  white-space: nowrap;
}
</style>
