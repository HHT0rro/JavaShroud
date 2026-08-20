import { exportWorkbenchTomlConfig, importWorkbenchTomlConfig } from './config-toml.ts'
import type { EngineSchemaPayload, RunState } from './types.ts'
import { buildObfuscationRequest, createInitialRunState, setEngineSchema, setInputJarPath, setOutputJarPath, setPassParam } from './state.ts'

const assert = (condition: boolean, message: string): void => {
  if (!condition) {
    throw new Error(message)
  }
}

const schema: EngineSchemaPayload = {
  schemaVersion: '2',
  engineVersion: 'check-engine',
  vbcVersion: 'VBC4-dev',
  tags: [
    { id: 'obfuscation', name: 'Obfuscation', description: 'Obfuscation passes' },
  ],
  modules: [
    {
      id: 'rename-classes',
      name: 'Rename classes',
      description: 'Rename class symbols.',
      tagIds: ['obfuscation'],
      stability: 'stable',
      defaultEnabled: false,
      targeting: { supported: true, targetKinds: ['class'] },
      params: [
        {
          key: 'dictionary',
          type: 'enum',
          defaultValue: 'ascii',
          options: ['ascii', 'compact'],
          description: 'Dictionary',
          hidden: false,
        },
        {
          key: 'seed',
          type: 'number',
          defaultValue: 7,
          options: null,
          description: 'Seed',
          hidden: false,
        },
        {
          key: 'backendOnlySeed',
          type: 'number',
          defaultValue: 13,
          options: null,
          description: 'Backend only seed',
          hidden: true,
        },
      ],
    },
    {
      id: 'rename-methods',
      name: 'Rename methods',
      description: 'Rename method symbols.',
      tagIds: ['obfuscation'],
      stability: 'stable',
      defaultEnabled: false,
      targeting: { supported: true, targetKinds: ['class', 'method'] },
      params: [],
    },
    {
      id: 'strip-compile-debug-info',
      name: 'Strip compile debug info',
      description: 'Strip compile debug metadata.',
      tagIds: ['obfuscation'],
      stability: 'stable',
      defaultEnabled: false,
      targeting: { supported: false, targetKinds: [] },
      params: [],
    },
  ],
  compatibility: [],
  orderingConstraints: [],
  defaultPipeline: ['strip-compile-debug-info'],
}

let state: RunState = setEngineSchema(createInitialRunState(), schema)
state = setInputJarPath(state, 'C:\\debug\\demo-app.jar')
state = setOutputJarPath(state, 'C:\\debug\\demo-app-shrouded.jar')
state = setPassParam(state, 'rename-classes', 'dictionary', 'compact')
state = setPassParam(state, 'rename-classes', 'backendOnlySeed', 21)

state = {
  ...state,
  passSelections: [{
    passId: 'rename-methods',
    mode: 'selected-only',
    rules: [
      { id: 'selection-class', target: 'com/example/Target', action: 'obfuscate' },
      { id: 'selection-method', target: 'com/example/Target#value:()I', action: 'exclude' },
    ],
  }],
}

const exportedToml = exportWorkbenchTomlConfig(state)
assert(exportedToml.includes('version = 3'), 'expected exported config to use version 3')
assert(exportedToml.includes('[[passSelections]]'), 'expected exported config to include pass selections')
assert(exportedToml.includes('passId = "rename-methods"'), 'expected exported config to include rename-methods selection pass id')
assert(exportedToml.includes('[[passSelections.rules]]'), 'expected exported config to include pass selection rules')
const emptyScopeToml = exportWorkbenchTomlConfig({
  ...state,
  passSelections: [{ passId: 'rename-methods', mode: 'selected-only', rules: [] }],
})
assert(emptyScopeToml.includes('[[passSelections]]'), 'expected empty independent scope table to be exported')
assert(!emptyScopeToml.includes('[[passSelections.rules]]'), 'expected empty independent scope to omit nested rule tables')
assert(exportedToml.includes('[input]'), 'expected exported config to include input section')
assert(exportedToml.includes('inputJarPath = "C:\\\\debug\\\\demo-app.jar"'), 'expected exported config to include escaped input path')
assert(exportedToml.includes('[[passes]]'), 'expected exported config to include pass entries')
assert(exportedToml.includes('id = "rename-classes"'), 'expected exported config to include rename-classes pass')
assert(!exportedToml.includes('backendOnlySeed'), 'expected exported config to omit hidden params')

const importToml = [
  '[meta]',
  'format = "javashroud-workbench"',
  'version = 2',
  '',
  '[input]',
  'inputJarPath = "C:\\\\debug\\\\imported.jar"',
  'outputJarPath = "C:\\\\debug\\\\imported-shrouded.jar"',
  '',
  '[[passes]]',
  'id = "rename-classes"',
  'enabled = true',
  '',
  '[passes.params]',
  'dictionary = "compact"',
  'backendOnlySeed = 99',
  'unknownParam = "ignored"',
  'seed = "wrong-type"',
  '',
  '[[passes]]',
  'id = "rename-methods"',
  'enabled = true',
  '',
  '[[passes]]',
  'id = "missing-pass"',
  'enabled = true',
  '',
  '[passes.params]',
  '',
  '[[rules]]',
  'target = "com/example/api/*"',
  'action = "exclude"',
  '',
  '[[rules]]',
  'target = "com/example/bad/*"',
  'action = "delete"',
  '',
  '[[passSelections]]',
  'passId = "rename-methods"',
  'mode = "selected-only"',
  '',
  '[[passSelections.rules]]',
  'target = "com/example/Target"',
  'action = "obfuscate"',
  '',
  '[[passSelections.rules]]',
  'target = "com/example/Target#value:()I"',
  'action = "exclude"',
  '',
  '[[passSelections.rules]]',
  'target = "com/example/*/Target"',
  'action = "obfuscate"',
  '',
  '[[passSelections.rules]]',
  'target = "com/example/Target#field:I"',
  'action = "obfuscate"',
  '',
  '[[passSelections]]',
  'passId = "strip-compile-debug-info"',
  'mode = "selected-only"',
  '',
  '[[passSelections.rules]]',
  'target = "com/example/Bad"',
  'action = "obfuscate"',
  '',
].join('\n')

const result = importWorkbenchTomlConfig(state, importToml)
assert(importWorkbenchTomlConfig(state, importToml).warnings.filter((warning) => warning.message.includes('v2 selected-only')).length === 1, 'expected one v2 selected-only migration warning')
const renamedClassesPass = result.nextState.passes.find((passItem) => passItem.id === 'rename-classes')
const request = buildObfuscationRequest(result.nextState)
const requestRenameClassesPass = request.passes.find((passItem) => passItem.id === 'rename-classes')
const requestRenameMethodsPass = request.passes.find((passItem) => passItem.id === 'rename-methods')
const requestRenameMethodsSelection = request.passSelections.find((selection) => selection.passId === 'rename-methods')
assert(result.nextState.inputJar?.inputJarPath === 'C:\\debug\\imported.jar', 'expected imported input path to be applied')
assert(result.nextState.outputJarPath === 'C:\\debug\\imported-shrouded.jar', 'expected imported output path to be applied')
assert(renamedClassesPass?.enabled === true, 'expected imported rename-classes pass enabled flag to be applied')
assert(renamedClassesPass?.params.dictionary === 'compact', 'expected imported enum param to be applied')
assert(renamedClassesPass?.params.backendOnlySeed === 21, 'expected hidden param imports to be ignored')
assert(requestRenameClassesPass?.params.backendOnlySeed === undefined, 'expected obfuscation request to omit hidden params')
assert(requestRenameMethodsPass !== undefined, 'expected imported rename-methods pass to be included in request')
assert(result.nextState.rules.length === 1, 'expected invalid rule action to be skipped')
assert(result.nextState.rules[0]?.target === 'com/example/api/*', 'expected valid rule to be imported')
assert(result.nextState.passSelections.length === 1, 'expected unsupported pass selection to be skipped')
assert(result.nextState.passSelections[0]?.passId === 'rename-methods', 'expected method-targeting pass selection to be imported')
assert(result.nextState.passSelections[0]?.rules.length === 2, 'expected class and descriptor-specific method rules to round trip')
assert(result.nextState.passSelections[0]?.rules[1]?.target === 'com/example/Target#value:()I', 'expected canonical overloaded method selector to be preserved')
assert(requestRenameMethodsSelection?.rules.length === 2, 'expected method-targeting selection rules to be included in request')
assert(requestRenameMethodsSelection?.rules[1]?.target === 'com/example/Target#value:()I', 'expected request to preserve canonical overloaded method selector')
assert(result.warnings.some((warning) => warning.message.includes('missing-pass')), 'expected unknown pass warning')
assert(result.warnings.some((warning) => warning.message.includes('unknownParam')), 'expected unknown param warning')
assert(result.warnings.some((warning) => warning.message.includes('backendOnlySeed')), 'expected hidden param warning')
assert(result.warnings.some((warning) => warning.message.includes('seed')), 'expected invalid param type warning')
assert(result.warnings.some((warning) => warning.message.includes('action 非法')), 'expected invalid rule action warning')
assert(result.warnings.some((warning) => warning.message.includes('不支持类/方法选择')), 'expected unsupported pass targeting warning')
assert(result.warnings.filter((warning) => warning.message.includes('非 canonical 类/方法范围')).length === 2, 'expected wildcard and field selector warnings')

const v3Import = importWorkbenchTomlConfig(state, importToml.replace('version = 2', 'version = 3'))
assert(!v3Import.warnings.some((warning) => warning.message.includes('v2 selected-only')), 'expected v3 import to avoid v2 migration warning')

console.log('config-toml checks passed')
