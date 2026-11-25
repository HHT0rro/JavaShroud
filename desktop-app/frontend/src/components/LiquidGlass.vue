<script setup lang="ts">
import { computed } from 'vue'

export type LiquidGlassLevel = 'background' | 'surface' | 'raised' | 'control'

const props = withDefaults(
  defineProps<{
    readonly as: string
    readonly level?: LiquidGlassLevel
  }>(),
  {
    level: 'background',
  },
)

const surfaceStyle = computed((): Readonly<Record<string, string>> => ({
  '--surface-fg': `var(--surface-${props.level}-fg)`,
  '--surface-muted': `var(--surface-${props.level}-muted)`,
}))
</script>

<template>
  <component :is="props.as" class="surface" :class="[`surface--${props.level}`]" :style="surfaceStyle">
    <slot />
  </component>
</template>
