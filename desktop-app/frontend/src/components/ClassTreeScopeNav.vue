<script setup lang="ts">
import { Globe, Layers } from 'lucide-vue-next'
import type { ClassTreeScopeId, ClassTreeScopeItem } from '../modules/obfuscation/class-tree-scope-view'
import type { DisplayLanguage } from '../modules/obfuscation/pass-localization'

defineProps<{
  readonly items: readonly ClassTreeScopeItem[]
  readonly activeId: ClassTreeScopeId
  readonly displayLanguage: DisplayLanguage
}>()

const emit = defineEmits<{
  readonly select: [id: ClassTreeScopeId]
  readonly keyNavigate: [event: KeyboardEvent, id: ClassTreeScopeId]
}>()

const scopeTabId = (id: ClassTreeScopeId): string => `class-tree-scope-${id}`
</script>

<template>
  <nav class="class-tree-scope-nav" role="tablist" :aria-label="displayLanguage === 'zh' ? '混淆范围' : 'Obfuscation scopes'">
    <button
      v-for="item in items"
      :id="scopeTabId(item.id)"
      :key="item.id"
      class="class-tree-scope-nav__item"
      :class="{
        'class-tree-scope-nav__item--active': activeId === item.id,
        'class-tree-scope-nav__item--independent': item.independent,
        'class-tree-scope-nav__item--unsupported': !item.targeting,
      }"
      type="button"
      role="tab"
      :aria-selected="activeId === item.id"
      :tabindex="activeId === item.id ? 0 : -1"
      @click="emit('select', item.id)"
      @keydown="emit('keyNavigate', $event, item.id)"
    >
      <span class="class-tree-scope-nav__icon" aria-hidden="true">
        <Globe v-if="item.kind === 'global'" :size="16" />
        <Layers v-else :size="16" />
      </span>
      <span class="class-tree-scope-nav__copy">
        <span class="class-tree-scope-nav__title">{{ item.title }}</span>
        <span class="class-tree-scope-nav__mode">{{ item.modeLabel }}</span>
      </span>
    </button>
  </nav>
</template>

<style scoped>
.class-tree-scope-nav {
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-width: 0;
  width: 100%;
  min-height: 0;
  overflow: auto;
}

.class-tree-scope-nav__item {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  min-width: 0;
  width: 100%;
  margin: 0;
  padding: 8px 10px;
  border: 1px solid rgba(237, 237, 237, 0.08);
  border-radius: 12px;
  background: rgba(237, 237, 237, 0.03);
  color: #ededed;
  text-align: left;
  cursor: pointer;
}

.class-tree-scope-nav__item:focus-visible {
  outline: 2px solid #ededed;
  outline-offset: 2px;
}

.class-tree-scope-nav__item--active {
  background: rgba(237, 237, 237, 0.12);
  border-color: rgba(237, 237, 237, 0.28);
}

.class-tree-scope-nav__item--independent .class-tree-scope-nav__mode {
  color: rgba(126, 196, 143, 0.95);
}

.class-tree-scope-nav__item--unsupported {
  opacity: 0.62;
}

.class-tree-scope-nav__icon {
  display: flex;
  margin-top: 1px;
  opacity: 0.8;
}

.class-tree-scope-nav__copy {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.class-tree-scope-nav__title,
.class-tree-scope-nav__mode {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.class-tree-scope-nav__title {
  font-size: 13px;
  font-weight: 600;
}

.class-tree-scope-nav__mode {
  font-size: 11px;
  opacity: 0.7;
}

@media (max-width: 1100px) {
  .class-tree-scope-nav {
    flex-direction: row;
    flex-wrap: nowrap;
    max-height: 72px;
    overflow-x: auto;
    overflow-y: hidden;
  }

  .class-tree-scope-nav__item {
    min-width: 0;
    flex: 0 0 auto;
    max-width: 160px;
    padding: 6px 8px;
  }

  .class-tree-scope-nav__mode {
    display: none;
  }
}
</style>
