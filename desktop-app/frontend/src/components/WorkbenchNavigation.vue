<script setup lang="ts">
import { computed } from 'vue'
import { Blocks, FileInput, FolderTree, Info, ScrollText } from 'lucide-vue-next'
import LiquidGlass from './LiquidGlass.vue'
import type { DisplayLanguage } from '../modules/obfuscation/pass-localization'
import type { WorkbenchPage } from '../modules/obfuscation/workbench-view'
import javashroudLogo from '../assets/logo.png'

const props = defineProps<{
  activePage: WorkbenchPage
  displayLanguage: DisplayLanguage
  version: string
  passCount: string
  ruleCount: number
}>()
const emit = defineEmits<{ navigate: [page: WorkbenchPage] }>()
const navItems = computed(() => [
  { id: 'home' as const, icon: FileInput, label: props.displayLanguage === 'zh' ? '工作台' : 'Workbench', detail: props.displayLanguage === 'zh' ? '文件与任务总览' : 'Files & overview' },
  { id: 'passes' as const, icon: Blocks, label: props.displayLanguage === 'zh' ? '流水线' : 'Pipeline', detail: props.displayLanguage === 'zh' ? '模块与参数' : 'Modules & parameters' },
  { id: 'classes' as const, icon: FolderTree, label: props.displayLanguage === 'zh' ? '作用范围' : 'Scope', detail: props.displayLanguage === 'zh' ? '类、方法与规则' : 'Classes & rules' },
  { id: 'logs' as const, icon: ScrollText, label: props.displayLanguage === 'zh' ? '运行日志' : 'Run logs', detail: props.displayLanguage === 'zh' ? '进度与执行记录' : 'Progress & events' },
  { id: 'about' as const, icon: Info, label: props.displayLanguage === 'zh' ? '关于' : 'About', detail: props.displayLanguage === 'zh' ? '项目与许可证' : 'Project & license' },
])
</script>

<template>
  <LiquidGlass as="aside" level="background" class="side-rail">
    <div class="brand-lockup">
      <img class="brand-logo" :src="javashroudLogo" alt="JavaShroud" />
      <div class="brand-copy">
        <span class="brand-name">JavaShroud</span>
        <span class="brand-tagline">{{ displayLanguage === 'zh' ? '字节码混淆工作台' : 'Bytecode workbench' }}</span>
      </div>
    </div>
    <nav class="rail-nav" :aria-label="displayLanguage === 'zh' ? '工作台导航' : 'Workbench navigation'">
      <button v-for="item in navItems" :key="item.id" type="button" class="rail-link" :class="{ active: activePage === item.id }" :aria-current="activePage === item.id ? 'page' : undefined" :aria-label="item.label" :data-testid="`nav-${item.id}`" @click="emit('navigate', item.id)">
        <component :is="item.icon" class="nav-icon" :stroke-width="1.8" aria-hidden="true" />
        <span class="rail-link-main">{{ item.label }}</span>
        <span class="rail-link-sub">{{ item.detail }}</span>
      </button>
    </nav>
    <section class="rail-summary" :aria-label="displayLanguage === 'zh' ? '配置摘要' : 'Configuration summary'">
      <div><span>{{ displayLanguage === 'zh' ? '已启用模块' : 'Enabled modules' }}</span><strong>{{ passCount }}</strong></div>
      <div><span>{{ displayLanguage === 'zh' ? '全局规则' : 'Global rules' }}</span><strong>{{ ruleCount }}</strong></div>
    </section>
    <div class="rail-footer"><span class="engine-version" :title="version">JS <span>{{ version }}</span></span><span>GPL-3.0</span></div>
  </LiquidGlass>
</template>
