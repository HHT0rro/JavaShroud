/// <reference types="node" />
import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'
import * as vue from 'vue'
import { compileScript, compileTemplate, parse } from 'vue/compiler-sfc'
import ts from 'typescript'
import * as passCatalog from '../modules/obfuscation/pass-catalog.ts'
import * as passLocalization from '../modules/obfuscation/pass-localization.ts'
import * as passCompatibility from '../modules/obfuscation/pass-compatibility.ts'
import * as pipelineWorkbench from '../modules/obfuscation/pipeline-workbench.ts'
import type { DisplayLanguage } from '../modules/obfuscation/pass-localization.ts'
import type { PipelineFilterId } from '../modules/obfuscation/pipeline-workbench.ts'
import type { PassItem, RunStatus } from '../modules/obfuscation/types.ts'

const assert = (condition: boolean, message: string): void => {
  if (!condition) throw new Error(message)
}

// Exercise the actual SFC setup with Vue reactivity; presentation imports need no DOM.
const filename = 'PipelinePanel.vue'
const { descriptor, errors } = parse(readFileSync(new URL(`./${filename}`, import.meta.url), 'utf8'), { filename })
assert(errors.length === 0, 'expected valid pipeline SFC')
const script = compileScript(descriptor, { id: 'pipeline-panel-check' })
const template = descriptor.template!.content
const compiledTemplate = compileTemplate({ source: template, filename, id: 'pipeline-panel-check', compilerOptions: { bindingMetadata: script.bindings } })
assert(compiledTemplate.errors.length === 0, 'expected valid pipeline template')
const compiled = ts.transpileModule(script.content, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } })
const imports: Readonly<Record<string, unknown>> = {
  vue,
  'naive-ui': {},
  'lucide-vue-next': {},
  vuedraggable: {},
  './LiquidGlass.vue': {},
  '../modules/obfuscation/pass-catalog': passCatalog,
  '../modules/obfuscation/pass-localization': passLocalization,
  '../modules/obfuscation/pass-compatibility': passCompatibility,
  '../modules/obfuscation/pipeline-workbench': pipelineWorkbench,
}
const componentExports: { default?: unknown } = {}
runInNewContext(compiled.outputText, {
  exports: componentExports,
  require: (specifier: string): unknown => {
    if (!(specifier in imports)) throw new Error(`Unexpected SFC import: ${specifier}`)
    return imports[specifier]
  },
})

type PanelProps = {
  passes: readonly PassItem[]
  status: RunStatus
  displayLanguage: DisplayLanguage
  schemaCompatibility: []
  xenolithCli: null
}
type PanelSetup = {
  activeFilter: vue.Ref<PipelineFilterId>
  searchQuery: vue.Ref<string>
  allPassesEnabled: vue.ComputedRef<boolean>
  allPassesToggleDisabled: vue.ComputedRef<boolean>
  allPassesToggleLabel: vue.ComputedRef<string>
  allPassesToggleTitle: vue.ComputedRef<string>
  onToggleAll: () => void
}
const component = componentExports.default as {
  emits: readonly string[]
  setup: (props: PanelProps, context: { emit: (event: string, enabled: boolean) => void; expose: () => void }) => PanelSetup
}
assert(component.emits.includes('allPassesToggled'), 'expected a declared bulk toggle event')
const pass = (id: string, enabled: boolean): PassItem => ({
  id, name: id, description: '', category: id, enabled,
  tagIds: [], params: {}, paramSchemas: [], stability: 'stable', risk: 'low', requiresOptIn: false,
  requiredPassIds: [], requiresAnyPassIds: [], variantRequirements: [], targeting: { supported: false, targetKinds: [] },
})
const props = vue.reactive<PanelProps>({
  passes: [pass('rename', true), pass('flow', false)],
  status: 'ready', displayLanguage: 'zh', schemaCompatibility: [], xenolithCli: null,
})
const emitted: Array<{ event: string; enabled: boolean }> = []
const scope = vue.effectScope()
const panel = scope.run(() => component.setup(props, {
  emit: (event, enabled): void => { emitted.push({ event, enabled }) },
  expose: (): void => undefined,
}))!
try {
  panel.activeFilter.value = 'enabled'
  panel.searchQuery.value = 'rename'
  assert(!panel.allPassesEnabled.value && !panel.allPassesToggleDisabled.value, 'expected mixed enabled state to allow select all')
  assert(panel.allPassesToggleLabel.value === '全选', 'expected Chinese select-all label')
  assert(panel.allPassesToggleTitle.value.includes('兼容性'), 'expected Chinese constraint explanation')
  panel.onToggleAll()
  assert(emitted.length === 1 && emitted[0]?.event === 'allPassesToggled' && emitted[0].enabled === true, 'expected enable-all event even with a filtered list')
  assert(props.passes[1]?.enabled === false, 'expected the component not to mutate passes')
  assert(panel.activeFilter.value === 'enabled' && panel.searchQuery.value === 'rename', 'expected bulk toggle to retain filters and search')

  props.passes = props.passes.map((item) => ({ ...item, enabled: true }))
  assert(panel.allPassesEnabled.value && panel.allPassesToggleLabel.value === '取消全选', 'expected Chinese deselect-all label when every pass is enabled')
  assert(panel.allPassesToggleTitle.value === '停用全部模块', 'expected Chinese disable-all title')
  panel.onToggleAll()
  assert(emitted.length === 2 && emitted[1]?.enabled === false, 'expected disable-all event')
  props.displayLanguage = 'en'
  assert(panel.allPassesToggleLabel.value === 'Deselect all' && panel.allPassesToggleTitle.value === 'Disable all modules', 'expected English deselect-all text')
  props.passes = props.passes.map((item) => ({ ...item, enabled: false }))
  assert(panel.allPassesToggleLabel.value === 'Select all' && panel.allPassesToggleTitle.value.includes('compatibility'), 'expected English select-all text')

  for (const status of ['running', 'awaiting-pack', 'canceling'] as const) {
    props.status = status
    assert(panel.allPassesToggleDisabled.value, `expected disabled bulk button during ${status}`)
    panel.onToggleAll()
    assert(emitted.length === 2, `expected no bulk event during ${status}`)
  }
  for (const status of ['idle', 'ready', 'done', 'failed'] as const) {
    props.status = status
    assert(!panel.allPassesToggleDisabled.value, `expected bulk button available during ${status}`)
  }
  props.passes = []
  assert(panel.allPassesToggleDisabled.value && !panel.allPassesEnabled.value, 'expected empty list to disable bulk toggle without claiming all enabled')
  assert(panel.allPassesToggleLabel.value === 'Select all', 'expected select-all label for empty list')
  panel.onToggleAll()
  assert(emitted.length === 2, 'expected no bulk event for empty list')
} finally {
  scope.stop()
}

const chipBar = template.match(/<div class="category-chips"[^>]*>([\s\S]*?)<\/div>/)?.[1] ?? ''
const button = chipBar.match(/<button\b[^>]*class="category-chip category-chip--bulk"[\s\S]*?<\/button>/)?.[0] ?? ''
for (const binding of [':disabled="allPassesToggleDisabled"', ':aria-label="allPassesToggleLabel"', ':title="allPassesToggleTitle"', '@click="onToggleAll"', '{{ allPassesToggleLabel }}']) {
  assert(button.includes(binding), `expected category-bar bulk button binding: ${binding}`)
}
const app = readFileSync(new URL('../App.vue', import.meta.url), 'utf8')
assert(app.includes('@all-passes-toggled="handlers.handleAllPassesToggled"'), 'expected App to route the bulk event to the workbench handler')
console.log('PipelinePanel checks passed')
