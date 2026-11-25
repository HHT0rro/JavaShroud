<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Copy, FolderOpen, Package, ShieldAlert } from 'lucide-vue-next'
import { NButton } from 'naive-ui'
import LiquidGlass from './LiquidGlass.vue'
import type { DisplayLanguage } from '../modules/obfuscation/pass-localization'
import type { RunStatus } from '../modules/obfuscation/types'

const props = defineProps<{
  readonly unpackedPath: string | null
  readonly status: RunStatus
  readonly displayLanguage: DisplayLanguage
}>()

const emit = defineEmits<{
  readonly reveal: []
  readonly browse: []
  readonly continue: [packedPath: string]
  readonly skip: []
  readonly logs: []
}>()

const packedPath = ref('')
const copied = ref(false)
const copyError = ref(false)
const continuing = ref(false)

const zh = computed(() => props.displayLanguage === 'zh')
const awaiting = computed(() => props.status === 'awaiting-pack')
const canSkip = computed(() => (props.unpackedPath ?? '').toLowerCase().endsWith('.so'))
const canContinue = computed(() => awaiting.value && packedPath.value.trim().length > 0 && !continuing.value)

watch(
  () => props.unpackedPath,
  (): void => {
    packedPath.value = ''
    copied.value = false
    copyError.value = false
    continuing.value = false
  },
)

const copyUnpackedPath = async (): Promise<void> => {
  if (!props.unpackedPath) {
    return
  }
  try {
    await navigator.clipboard.writeText(props.unpackedPath)
    copied.value = true
    copyError.value = false
  } catch {
    copyError.value = true
  }
}

const onBrowse = (): void => {
  if (!awaiting.value) {
    return
  }
  emit('browse')
}

const onContinue = (): void => {
  if (!canContinue.value) {
    return
  }
  continuing.value = true
  emit('continue', packedPath.value.trim())
}

const onSkip = (): void => {
  if (!awaiting.value || !canSkip.value || continuing.value) {
    return
  }
  continuing.value = true
  emit('skip')
}

const setPackedPath = (path: string): void => {
  packedPath.value = path
  continuing.value = false
}
defineExpose({ setPackedPath })
</script>

<template>
  <LiquidGlass as="section" level="surface" class="panel packing-panel">
    <div class="packing-heading">
      <div>
        <p class="eyebrow">{{ zh ? '自定义加壳交接' : 'CUSTOM PACK HANDOFF' }}</p>
        <h2>{{ zh ? '请自行加壳后再继续' : 'Pack the native image, then continue' }}</h2>
      </div>
      <button type="button" class="text-link" @click="emit('logs')">{{ zh ? '查看日志' : 'View logs' }}</button>
    </div>

    <div class="packing-alert">
      <ShieldAlert :size="18" aria-hidden="true" />
      <p>
        {{ zh
          ? '引擎已编译未加壳镜像。请用 Xenolith、VMP 或其他工具自行加壳，并保留 JNI_OnLoad / qp_r1 导出与 .jsms/.jsmk 段；抹掉它们会被引擎拒绝。想免手动交接，可在“混淆管线”的自定义加壳模块开启 Xenolith 自动加壳。'
          : 'The engine built an unpacked image. Pack it yourself with Xenolith, VMP, or another tool, and keep JNI_OnLoad / qp_r1 exports and the .jsms/.jsmk sections — stripping them will be rejected. To skip the manual round-trip, enable Xenolith auto packing on the Custom packing module in the pipeline.' }}
      </p>
    </div>

    <div class="packing-card">
      <span class="packing-icon"><Package :size="22" aria-hidden="true" /></span>
      <div class="packing-copy">
        <h3>{{ zh ? '未加壳镜像' : 'Unpacked image' }}</h3>
        <p v-if="unpackedPath" class="packing-path">{{ unpackedPath }}</p>
        <p v-else>{{ zh ? '等待引擎给出镜像路径…' : 'Waiting for the engine path…' }}</p>
      </div>
      <div class="packing-actions">
        <NButton secondary :disabled="!unpackedPath" @click="emit('reveal')">
          <template #icon><FolderOpen :size="14" /></template>
          {{ zh ? '打开所在目录' : 'Reveal in folder' }}
        </NButton>
        <NButton secondary :disabled="!unpackedPath" @click="copyUnpackedPath">
          <template #icon><Copy :size="14" /></template>
          {{ zh ? (copied ? '已复制' : '复制路径') : (copied ? 'Copied' : 'Copy path') }}
        </NButton>
      </div>
    </div>
    <p v-if="copyError" role="status" class="field-hint copy-error">
      {{ zh ? '剪贴板不可用，请选中上方完整路径手动复制。' : 'Clipboard unavailable. Select the full path above to copy it.' }}
    </p>

    <div class="packing-resume">
      <label class="resume-label">
        <span>{{ zh ? '加壳后的文件' : 'Packed file' }}</span>
        <input
          class="resume-input"
          type="text"
          :value="packedPath"
          :disabled="!awaiting"
          :placeholder="zh ? '浏览选择 *.dll / *.so' : 'Browse for *.dll / *.so'"
          readonly
          @click="onBrowse"
        />
      </label>
      <div class="resume-actions">
        <NButton secondary :disabled="!awaiting" @click="onBrowse">{{ zh ? '浏览加壳文件' : 'Browse packed file' }}</NButton>
        <NButton type="primary" :disabled="!canContinue" :loading="continuing" @click="onContinue">
          {{ zh ? '继续混淆' : 'Continue run' }}
        </NButton>
        <NButton v-if="canSkip" secondary :disabled="!awaiting || continuing" @click="onSkip">
          {{ zh ? '跳过加壳（Linux）' : 'Skip packing (Linux)' }}
        </NButton>
      </div>
    </div>
  </LiquidGlass>
</template>

<style scoped>
.packing-panel {
  display: grid;
  gap: 18px;
  padding: 22px;
  max-width: 920px;
}
.packing-heading {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
}
.packing-heading h2 {
  margin-top: 6px;
  font-size: 22px;
  font-weight: 650;
}
.packing-alert {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  padding: 14px 16px;
  border: 1px solid color-mix(in srgb, var(--warning, #d4a017) 35%, var(--line));
  border-radius: var(--radius-sm);
  background: color-mix(in srgb, var(--warning, #d4a017) 10%, transparent);
  color: var(--text-soft);
  font-size: 13px;
  line-height: 1.55;
}
.packing-alert :deep(svg) {
  flex: 0 0 auto;
  margin-top: 2px;
  color: var(--warning, #d4a017);
}
.packing-card {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 16px;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
  background: var(--panel-strong);
}
.packing-icon {
  display: grid;
  place-items: center;
  width: 44px;
  height: 44px;
  flex: 0 0 auto;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
  color: var(--text-muted);
}
.packing-copy {
  flex: 1;
  min-width: 0;
  display: grid;
  gap: 6px;
}
.packing-copy h3 {
  font-size: 14px;
  font-weight: 600;
}
.packing-copy p {
  color: var(--text-muted);
  font-size: 13px;
  line-height: 1.55;
}
.packing-path {
  font: 12px/1.6 var(--font-mono);
  color: var(--text-soft);
  overflow-wrap: anywhere;
  user-select: text;
}
.packing-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.packing-resume {
  display: grid;
  gap: 12px;
}
.resume-label {
  display: grid;
  gap: 8px;
  font-size: 13px;
  color: var(--text-muted);
}
.resume-input {
  width: 100%;
  min-height: 40px;
  padding: 0 12px;
  border: 1px solid var(--line);
  border-radius: var(--radius-sm);
  background: var(--panel-strong);
  color: var(--text-soft);
  font: 12px/1.4 var(--font-mono);
  cursor: pointer;
}
.resume-input:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}
.resume-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}
.copy-error {
  margin-top: -6px;
}
@media (max-width: 760px) {
  .packing-card {
    flex-wrap: wrap;
  }
  .packing-actions {
    width: 100%;
  }
}
</style>
