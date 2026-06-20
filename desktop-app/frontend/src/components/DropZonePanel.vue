<script setup lang="ts">
import { computed } from 'vue'
import { FolderOpen, Upload } from 'lucide-vue-next'
import { NButton, NInput, NTag } from 'naive-ui'
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

const isLocked = computed((): boolean => props.status === 'running' || props.status === 'canceling')
const inputPath = computed((): string => props.inputJar?.inputJarPath ?? '')
const readinessLabel = computed((): string => props.inputJar === null
  ? (props.displayLanguage === 'zh' ? '等待 JAR' : 'Waiting for JAR')
  : (props.displayLanguage === 'zh' ? 'JAR 已选择' : 'JAR selected'))

const onInputPathChange = (value: string): void => {
  emit('inputPathChanged', value)
}

const onOutputChange = (value: string): void => {
  emit('outputChanged', value)
}

const onBrowseInput = (): void => {
  if (isLocked.value) {
    return
  }

  emit('browseInput')
}
</script>

<template>
  <LiquidGlass as="section" level="surface" class="panel drop-panel" @dragover.prevent>
    <div class="panel-head">
      <div>
        <p class="eyebrow">{{ displayLanguage === 'zh' ? '首页' : 'Home' }}</p>
        <h2>{{ displayLanguage === 'zh' ? '输入与输出' : 'Input and output' }}</h2>
      </div>
      <NTag :type="inputJar === null ? 'default' : 'success'" size="small" round>{{ readinessLabel }}</NTag>
    </div>

    <button type="button" class="drop-zone" :class="{ locked: isLocked }" :disabled="isLocked" :aria-label="displayLanguage === 'zh' ? '选择 Jar 文件' : 'Select Jar file'" @click="onBrowseInput">
      <span class="drop-mark"><Upload :stroke-width="2" aria-hidden="true" /></span>
      <span class="drop-copy">
        <strong>{{ displayLanguage === 'zh' ? '拖入 .jar 文件，或通过系统对话框选择' : 'Drop a .jar file, or choose one from the system dialog' }}</strong>
      </span>
    </button>

    <div class="path-stack">
      <label class="path-field">
        <span>{{ displayLanguage === 'zh' ? '输入 JAR 路径' : 'Input JAR path' }}</span>
        <NInput :value="inputPath" :disabled="isLocked" placeholder="D:\build\app\target.jar" @update:value="onInputPathChange" />
      </label>
      <NButton tertiary :disabled="isLocked" @click="emit('browseInput')">
        <template #icon><FolderOpen :size="16" /></template>
        {{ displayLanguage === 'zh' ? '选择输入' : 'Choose input' }}
      </NButton>
    </div>

    <div class="path-stack">
      <label class="path-field">
        <span>{{ displayLanguage === 'zh' ? '输出 JAR 路径' : 'Output JAR path' }}</span>
        <NInput :value="outputJarPath" :disabled="isLocked" placeholder="D:\build\app\target-shrouded.jar" @update:value="onOutputChange" />
      </label>
      <NButton tertiary :disabled="isLocked || inputJar === null" @click="emit('browseOutput')">
        <template #icon><FolderOpen :size="16" /></template>
        {{ displayLanguage === 'zh' ? '选择输出' : 'Choose output' }}
      </NButton>
    </div>
  </LiquidGlass>
</template>
