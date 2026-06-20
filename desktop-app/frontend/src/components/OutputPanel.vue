<script setup lang="ts">
import { computed } from 'vue'
import { Box, FileJson, FolderOpen, RotateCcw } from 'lucide-vue-next'
import { NButton, NTag } from 'naive-ui'
import LiquidGlass from './LiquidGlass.vue'
import type { RunStatus } from '../modules/obfuscation/types'

const props = defineProps<{
  readonly outputPath: string | null
  readonly outputJarPath: string
  readonly status: RunStatus
}>()

const displayedOutputPath = computed((): string => props.outputPath ?? (props.outputJarPath || '尚未配置输出路径'))
const isReady = computed((): boolean => props.status === 'done' && props.outputPath !== null)
</script>

<template>
  <LiquidGlass as="section" level="surface" class="panel output-panel">
    <div class="panel-head">
      <div>
        <p class="eyebrow">Artifact shelf</p>
        <h2>输出产物</h2>
      </div>
      <NTag :type="isReady ? 'success' : 'default'" size="small" round>{{ isReady ? '已就绪' : '等待中' }}</NTag>
    </div>

    <div class="artifact-path">
      <span class="artifact-icon"><Box :size="18" /></span>
      <div>
        <span class="field-label">输出路径</span>
        <strong>{{ displayedOutputPath }}</strong>
      </div>
    </div>

    <div class="artifact-grid">
      <NButton tertiary :disabled="outputPath === null">
        <template #icon><FolderOpen :size="16" /></template>
        打开文件夹
      </NButton>
      <NButton tertiary :disabled="outputPath === null">
        <template #icon><FileJson :size="16" /></template>
        映射文件
      </NButton>
      <NButton tertiary :disabled="outputPath === null">
        <template #icon><RotateCcw :size="16" /></template>
        反混淆
      </NButton>
    </div>
  </LiquidGlass>
</template>
