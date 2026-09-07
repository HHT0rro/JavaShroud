<script setup lang="ts">
import { ArrowUpRight, Code2, Github, Scale } from 'lucide-vue-next'
import { NButton } from 'naive-ui'
import LiquidGlass from './LiquidGlass.vue'
import { t, type DisplayLanguage } from '../modules/obfuscation/pass-localization'
import javashroudLogo from '../assets/logo.png'
defineProps<{ displayLanguage: DisplayLanguage; version: string }>()
const emit = defineEmits<{ open: [url: string] }>()
</script>

<template>
  <div class="about-layout">
    <LiquidGlass as="article" level="surface" class="panel about-intro">
      <img class="about-logo" :src="javashroudLogo" alt="JavaShroud" />
      <div class="about-intro-copy">
        <p class="eyebrow">{{ displayLanguage === 'zh' ? 'JVM 字节码保护' : 'JVM BYTECODE PROTECTION' }}</p>
        <h2>JavaShroud</h2>
        <p class="about-description">{{ displayLanguage === 'zh' ? '面向 Java 应用的开源字节码混淆工具。配置处理流水线，控制类与方法的作用范围，并查看每次任务的执行过程。' : 'An open-source bytecode obfuscator for Java applications. Configure the processing pipeline, control class and method scope, and follow each run.' }}</p>
      </div>
      <NButton secondary class="project-link" @click="emit('open', 'https://github.com/HHT0rro/JavaShroud')">
        <template #icon><Github :size="16" /></template>
        {{ displayLanguage === 'zh' ? '项目源码' : 'Source code' }}<ArrowUpRight :size="14" class="external-icon" />
      </NButton>
    </LiquidGlass>

    <div class="about-details">
      <LiquidGlass as="section" level="surface" class="panel about-section" aria-labelledby="about-build-heading">
        <div class="about-section-heading"><Code2 :size="19" /><h3 id="about-build-heading">{{ displayLanguage === 'zh' ? '版本与技术信息' : 'Version & technology' }}</h3></div>
        <dl class="about-facts">
          <div><dt>{{ displayLanguage === 'zh' ? '引擎版本' : 'Engine version' }}</dt><dd class="version-value">{{ version }}</dd></div>
          <div><dt>{{ displayLanguage === 'zh' ? '界面框架' : 'Interface' }}</dt><dd>Vue 3 / Naive UI</dd></div>
          <div><dt>{{ displayLanguage === 'zh' ? '桌面运行时' : 'Desktop runtime' }}</dt><dd>Wails</dd></div>
          <div><dt>{{ displayLanguage === 'zh' ? '处理对象' : 'Input format' }}</dt><dd>Java Archive (.jar)</dd></div>
        </dl>
      </LiquidGlass>

      <LiquidGlass as="section" level="surface" class="panel about-section license-section" aria-labelledby="about-license-heading">
        <div class="about-section-heading"><Scale :size="19" /><h3 id="about-license-heading">{{ displayLanguage === 'zh' ? '开源许可证' : 'Open-source license' }}</h3><span class="license-badge">GPL-3.0</span></div>
        <p>{{ t('licenseDescription', displayLanguage) }}</p>
        <p>{{ t('licenseObligation', displayLanguage) }}</p>
        <button type="button" class="text-link license-link" @click="emit('open', 'https://www.gnu.org/licenses/gpl-3.0.html')">{{ t('viewGpl', displayLanguage) }}<ArrowUpRight :size="14" /></button>
      </LiquidGlass>
    </div>
  </div>
</template>

<style scoped>
.about-layout { display: grid; gap: 16px; width: 100%; min-width: 0; align-content: start; }
.about-intro { display: flex; align-items: center; gap: 24px; padding: 28px; }
.about-logo { width: 68px; height: 68px; flex: 0 0 auto; object-fit: contain; }
.about-intro-copy { display: grid; gap: 9px; min-width: 0; flex: 1; }
.about-intro-copy h2 { font-size: 26px; line-height: 1.2; }
.about-description { max-width: 690px; color: var(--text-muted); font-size: 13px; line-height: 1.8; }
.project-link { flex: 0 0 auto; align-self: flex-start; }
.external-icon { margin-left: 12px; }
.about-details { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1.15fr); gap: 16px; align-items: stretch; }
.about-section { min-width: 0; padding: 24px; }
.about-section-heading { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; min-height: 26px; margin-bottom: 20px; }
.about-section-heading > svg { color: var(--text-muted); }
.about-section-heading h3 { font-size: 15px; font-weight: 600; }
.about-facts { display: grid; margin: 0; }
.about-facts > div { display: flex; justify-content: space-between; gap: 20px; padding: 13px 0; border-top: 1px solid var(--line); }
.about-facts dt { flex-shrink: 0; color: var(--text-muted); font-size: 13px; }
.about-facts dd { margin: 0; text-align: right; color: var(--text-soft); font-size: 13px; overflow-wrap: anywhere; }
.about-facts .version-value { font-family: var(--font-mono); font-size: 12px; }
.license-section { display: flex; flex-direction: column; gap: 16px; }
.license-section .about-section-heading { margin-bottom: 4px; }
.license-badge { margin-left: auto; border: 1px solid var(--line-strong); padding: 3px 8px; border-radius: var(--radius-xs); font: 11px var(--font-mono); color: var(--text-soft); }
.license-section p { color: var(--text-muted); font-size: 13px; line-height: 1.8; }
.license-link { margin-top: auto; padding-top: 10px; align-self: flex-start; }
@media (max-width: 1000px) {
  .about-intro { flex-wrap: wrap; gap: 18px; padding: 22px; }
  .about-intro-copy { flex-basis: calc(100% - 86px); }
  .project-link { margin-left: 86px; }
  .about-details { grid-template-columns: minmax(0, 1fr); }
}
@media (max-width: 550px) {
  .about-intro { padding: 20px; }
  .about-logo { width: 48px; height: 48px; }
  .about-intro-copy { flex-basis: calc(100% - 66px); }
  .about-intro-copy h2 { font-size: 23px; }
  .project-link { margin-left: 66px; }
  .about-section { padding: 20px; }
}
</style>
