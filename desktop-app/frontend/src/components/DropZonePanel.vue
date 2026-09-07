<script setup lang="ts">
import { computed, ref } from 'vue'
import { Check, Copy, FileArchive, FolderOpen, Upload } from 'lucide-vue-next'
import { NButton, NInput } from 'naive-ui'
import LiquidGlass from './LiquidGlass.vue'
import type { LoadedJarInfo, RunStatus } from '../modules/obfuscation/types'
import type { DisplayLanguage } from '../modules/obfuscation/pass-localization'

const props = defineProps<{
  readonly inputJar: LoadedJarInfo | null
  readonly outputJarPath: string
  readonly status: RunStatus
  readonly displayLanguage: DisplayLanguage
}>()
const emit = defineEmits<{
  readonly inputPathChanged: [inputJarPath: string]
  readonly outputChanged: [outputJarPath: string]
  readonly browseInput: []
  readonly browseOutput: []
}>()
const isLocked = computed(() => props.status === 'running' || props.status === 'canceling')
const inputPath = computed(() => props.inputJar?.inputJarPath ?? '')
const feedback = ref('')
const copyPath = async (value: string): Promise<void> => {
  try {
    await navigator.clipboard.writeText(value)
    feedback.value = props.displayLanguage === 'zh' ? '路径已复制' : 'Path copied'
  } catch {
    feedback.value = props.displayLanguage === 'zh' ? '无法复制，请在路径输入框中选择并复制' : 'Copy unavailable. Select and copy the path in its field.'
  }
}
</script>

<template>
  <LiquidGlass as="section" level="surface" class="panel file-panel" @dragover.prevent>
    <div class="panel-head"><div><p class="eyebrow">{{ displayLanguage === 'zh' ? '01 / 文件' : '01 / FILES' }}</p><h2>{{ displayLanguage === 'zh' ? '输入与输出' : 'Input & output' }}</h2></div><span v-if="inputJar" class="inline-status"><Check :size="14" />{{ displayLanguage === 'zh' ? '已选择' : 'Selected' }}</span></div>
    <div class="file-panel-body">
      <button type="button" class="file-drop" :class="{ 'file-drop--loaded': inputJar }" :disabled="isLocked" :aria-label="displayLanguage === 'zh' ? '选择 JAR 文件' : 'Choose JAR file'" @click="emit('browseInput')">
        <span class="file-drop-mark"><FileArchive v-if="inputJar" :size="25" /><Upload v-else :size="25" /></span>
        <span class="file-drop-copy"><strong>{{ inputJar?.fileName ?? (displayLanguage === 'zh' ? '拖入 JAR，开始配置' : 'Drop a JAR to get started') }}</strong><small>{{ inputJar ? (displayLanguage === 'zh' ? '点击更换文件，或拖入新的 JAR' : 'Click to replace, or drop another JAR') : (displayLanguage === 'zh' ? '也可以点击这里，通过系统对话框选择文件' : 'Or click here to choose a file from your computer') }}</small></span>
        <FolderOpen :size="18" class="file-drop-arrow" aria-hidden="true" />
      </button>
      <div class="file-field">
        <label for="input-jar-path">{{ displayLanguage === 'zh' ? '输入 JAR 路径' : 'Input JAR path' }}</label>
        <div class="file-field-controls"><NInput :value="inputPath" :disabled="isLocked" :input-props="{ id: 'input-jar-path', 'aria-label': displayLanguage === 'zh' ? '输入 JAR 路径' : 'Input JAR path' }" placeholder="D:\build\app.jar" @update:value="emit('inputPathChanged', $event)" /><button class="utility-button" type="button" :disabled="!inputPath" :aria-label="displayLanguage === 'zh' ? '复制输入路径' : 'Copy input path'" @click="copyPath(inputPath)"><Copy :size="15" /></button><NButton secondary :disabled="isLocked" @click="emit('browseInput')">{{ displayLanguage === 'zh' ? '浏览' : 'Browse' }}</NButton></div>
      </div>
      <div class="file-field">
        <label for="output-jar-path">{{ displayLanguage === 'zh' ? '输出 JAR 路径' : 'Output JAR path' }}</label>
        <div class="file-field-controls"><NInput :value="outputJarPath" :disabled="isLocked" :input-props="{ id: 'output-jar-path', 'aria-label': displayLanguage === 'zh' ? '输出 JAR 路径' : 'Output JAR path' }" placeholder="D:\build\app-shrouded.jar" @update:value="emit('outputChanged', $event)" /><button class="utility-button" type="button" :disabled="!outputJarPath" :aria-label="displayLanguage === 'zh' ? '复制输出路径' : 'Copy output path'" @click="copyPath(outputJarPath)"><Copy :size="15" /></button><NButton secondary :disabled="isLocked || !inputJar" @click="emit('browseOutput')">{{ displayLanguage === 'zh' ? '另存为' : 'Save as' }}</NButton></div>
        <p class="field-hint">{{ displayLanguage === 'zh' ? '使用不同的输出文件，保留原始 JAR。路径可直接编辑。' : 'Use a separate output file to keep the original JAR. Paths are editable.' }}</p>
      </div>
      <p v-if="feedback" class="field-hint" role="status">{{ feedback }}</p>
    </div>
  </LiquidGlass>
</template>

<style scoped>
.file-panel { align-self: start; }
.file-panel-body { display: grid; gap: 22px; padding: 20px; }
.file-drop { display: flex; align-items: center; gap: 18px; width: 100%; min-width: 0; min-height: 154px; padding: 24px; border: 1px dashed var(--line-strong); border-radius: var(--radius-md); color: var(--text); background: var(--accent-soft); cursor: pointer; text-align: left; transition: background var(--motion-fast), border-color var(--motion-fast); }
.file-drop:hover:not(:disabled) { background: var(--control-hover); border-color: var(--accent-line); }
.file-drop:disabled { cursor: not-allowed; opacity: .6; }
.file-drop--loaded { min-height: 104px; border-style: solid; }
.file-drop-mark { display: grid; place-items: center; width: 48px; height: 48px; flex: 0 0 auto; background: var(--accent); color: var(--accent-ink); border-radius: var(--radius-sm); }
.file-drop-copy { display: grid; gap: 7px; min-width: 0; }
.file-drop-copy strong { font-size: 16px; font-weight: 600; overflow-wrap: anywhere; }
.file-drop-copy small { color: var(--text-muted); font-size: 13px; line-height: 1.5; }
.file-drop-arrow { flex: 0 0 auto; margin-left: auto; color: var(--text-muted); }
.file-field { display: grid; gap: 9px; min-width: 0; }
.file-field label { color: var(--text-soft); font-size: 13px; font-weight: 550; }
.file-field-controls { display: grid; align-items: center; gap: 8px; grid-template-columns: minmax(0, 1fr) 36px auto; }
.file-field-controls :deep(input) { font-family: var(--font-mono); font-size: 12px; }
@media (max-width: 700px) { .file-panel-body { padding: 16px; } .file-drop { padding: 18px; gap: 12px; } .file-drop-arrow { display: none; } }
</style>
