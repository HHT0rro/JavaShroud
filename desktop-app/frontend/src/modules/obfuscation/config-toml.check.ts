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
      id: 'strip-compile-debug-info',
      name: 'Strip compile debug info',
      description: 'Strip compile debug metadata.',
      tagIds: ['obfuscation'],
      stability: 'stable',
      defaultEnabled: false,
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

const exportedToml = exportWorkbenchTomlConfig(state)
assert(exportedToml.includes('[input]'), 'expected exported config to include input section')
assert(exportedToml.includes('inputJarPath = "C:\\\\debug\\\\demo-app.jar"'), 'expected exported config to include escaped input path')
assert(exportedToml.includes('[[passes]]'), 'expected exported config to include pass entries')
assert(exportedToml.includes('id = "rename-classes"'), 'expected exported config to include rename-classes pass')
assert(!exportedToml.includes('backendOnlySeed'), 'expected exported config to omit hidden params')

const importToml = [
  '[meta]',
  'format = "javashroud-workbench"',
  'version = 1',
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
].join('\n')

const result = importWorkbenchTomlConfig(state, importToml)
const renamedPass = result.nextState.passes.find((passItem) => passItem.id === 'rename-classes')
const request = buildObfuscationRequest(result.nextState)
const requestRenamePass = request.passes.find((passItem) => passItem.id === 'rename-classes')
assert(result.nextState.inputJar?.inputJarPath === 'C:\\debug\\imported.jar', 'expected imported input path to be applied')
assert(result.nextState.outputJarPath === 'C:\\debug\\imported-shrouded.jar', 'expected imported output path to be applied')
assert(renamedPass?.enabled === true, 'expected imported pass enabled flag to be applied')
assert(renamedPass?.params.dictionary === 'compact', 'expected imported enum param to be applied')
assert(renamedPass?.params.backendOnlySeed === 21, 'expected hidden param imports to be ignored')
assert(requestRenamePass?.params.backendOnlySeed === undefined, 'expected obfuscation request to omit hidden params')
assert(result.nextState.rules.length === 1, 'expected invalid rule action to be skipped')
assert(result.nextState.rules[0]?.target === 'com/example/api/*', 'expected valid rule to be imported')
assert(result.warnings.some((warning) => warning.message.includes('missing-pass')), 'expected unknown pass warning')
assert(result.warnings.some((warning) => warning.message.includes('unknownParam')), 'expected unknown param warning')
assert(result.warnings.some((warning) => warning.message.includes('backendOnlySeed')), 'expected hidden param warning')
assert(result.warnings.some((warning) => warning.message.includes('seed')), 'expected invalid param type warning')
assert(result.warnings.some((warning) => warning.message.includes('action 非法')), 'expected invalid rule action warning')

console.log('config-toml checks passed')
