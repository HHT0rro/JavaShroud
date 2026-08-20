import {
  buildObfuscationRequest,
  createInitialRunState,
  nodePassSelectionAction,
  nodeRuleAction,
  passSelectionModeFor,
  setClassTreeRule,
  setJarInspection,
  setPassSelectionMode,
  setPassSelectionRule,
  togglePass,
} from './state.ts'
import type { ClassTreeNode, EngineSchemaPayload, PassItem, RunState } from './types.ts'

const assert = (condition: boolean, message: string): void => {
  if (!condition) throw new Error(message)
}

const expectError = (operation: () => unknown, expectedMessagePart: string): void => {
  try {
    operation()
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    assert(message.includes(expectedMessagePart), `expected error containing "${expectedMessagePart}", actual=${message}`)
    return
  }
  throw new Error(`expected operation to fail with "${expectedMessagePart}"`)
}

const method = (id: string, label: string, selector: string): ClassTreeNode => ({
  id,
  label,
  qualifiedName: selector,
  internalName: selector,
  selector,
  kind: 'method',
  children: [],
})

const classNode = (id: string, internalName: string, children: readonly ClassTreeNode[]): ClassTreeNode => ({
  id,
  label: internalName.slice(internalName.lastIndexOf('/') + 1),
  qualifiedName: internalName.replaceAll('/', '.'),
  internalName,
  selector: internalName,
  kind: 'class',
  children,
})

const packageNode = (id: string, internalName: string, children: readonly ClassTreeNode[]): ClassTreeNode => ({
  id,
  label: internalName.slice(internalName.lastIndexOf('/') + 1),
  qualifiedName: internalName.replaceAll('/', '.'),
  internalName,
  selector: `${internalName}/*`,
  kind: 'package',
  children,
})

const findNodeOrUndefined = (nodes: readonly ClassTreeNode[], id: string): ClassTreeNode | undefined => {
  for (const node of nodes) {
    if (node.id === id) return node
    const found = findNodeOrUndefined(node.children, id)
    if (found !== undefined) return found
  }
  return undefined
}

const findNode = (nodes: readonly ClassTreeNode[], id: string): ClassTreeNode => {
  const found = findNodeOrUndefined(nodes, id)
  if (found !== undefined) return found
  throw new Error(`node not found: ${id}`)
}

const schema: EngineSchemaPayload = {
  schemaVersion: '2',
  engineVersion: 'state-check',
  vbcVersion: 'VBC4-state-check',
  tags: [{ id: 'obfuscation', name: 'Obfuscation', description: 'checks' }],
  modules: [],
  compatibility: [],
  orderingConstraints: [],
  defaultPipeline: [],
}

const supportedPass = (id: string, enabled = true): PassItem => ({
  id,
  name: id,
  description: id,
  tagIds: ['obfuscation'],
  category: 'checks',
  enabled,
  params: {},
  paramSchemas: [],
  stability: 'stable',
  risk: 'low',
  requiresOptIn: false,
  requiredPassIds: [],
  requiresAnyPassIds: [],
  variantRequirements: [],
  targeting: { supported: true, targetKinds: ['class', 'method'] },
})

const tree = packageNode('package:sample', 'sample', [
  classNode('class:Target', 'sample/Target', [
    method('method:find:string', 'find', 'sample/Target#find:(Ljava/lang/String;)Ljava/lang/String;'),
    method('method:find:int', 'find', 'sample/Target#find:(I)Ljava/lang/String;'),
    method('method:other', 'other', 'sample/Target#other:()V'),
  ]),
  classNode('class:Other', 'sample/Other', [
    method('method:other:value', 'value', 'sample/Other#value:()I'),
  ]),
])

const initialState = (): RunState => ({
  ...createInitialRunState(),
  schema,
  inputJar: { fileName: 'fixture.jar', inputJarPath: 'C:\\fixture.jar', sizeLabel: 'fixture', detectedMainClass: null },
  outputJarPath: 'C:\\fixture-shrouded.jar',
  passes: [supportedPass('pass-a'), supportedPass('pass-b'), supportedPass('pass-c')],
})

const targetClass = findNode([tree], 'class:Target')
const findString = findNode([tree], 'method:find:string')
const findInt = findNode([tree], 'method:find:int')
const otherMethod = findNode([tree], 'method:other')

// inherit-global is a live view of global rules, not a copied snapshot.
let state = setJarInspection(initialState(), {
  jarPath: 'C:\\fixture.jar',
  classCount: 2,
  packageCount: 1,
  nodes: [tree],
})
state = setClassTreeRule(state, targetClass, 'exclude')
assert(passSelectionModeFor(state.passSelections, 'pass-a') === 'inherit-global', 'expected missing selection to mean live inherit-global')
assert(nodeRuleAction(state.rules, targetClass) === 'exclude', 'expected global class exclusion')
assert(nodeRuleAction(state.rules, findString) === 'exclude', 'expected global class exclusion inherited by method')
state = setClassTreeRule(state, findString, 'obfuscate')
assert(nodeRuleAction(state.rules, findString) === 'obfuscate', 'expected exact method override of global class exclude')
assert(nodeRuleAction(state.rules, findInt) === 'exclude', 'expected overload without exact rule to retain class exclusion')
state = setClassTreeRule(state, findInt, 'obfuscate')
assert(nodeRuleAction(state.rules, findInt) === 'obfuscate', 'expected global overload rule before rescan pruning')

// Independent scopes keep separate rules and start from an all-obfuscate baseline.
state = setPassSelectionMode(state, 'pass-a', 'selected-only')
const emptyPassA = state.passSelections.find((selection) => selection.passId === 'pass-a')
if (emptyPassA === undefined) throw new Error('expected pass-a independent scope')
assert(emptyPassA.rules.length === 0, 'expected independent scope to start without explicit rules')
assert(nodePassSelectionAction(emptyPassA.rules, targetClass) === 'obfuscate', 'expected independent scope class default to obfuscate')
assert(nodePassSelectionAction(emptyPassA.rules, findString) === 'obfuscate', 'expected independent scope method default to obfuscate')
state = setPassSelectionRule(state, 'pass-a', targetClass, 'exclude')
state = setPassSelectionRule(state, 'pass-a', findString, 'obfuscate')
state = setPassSelectionMode(state, 'pass-b', 'selected-only')
state = setPassSelectionRule(state, 'pass-b', findString, 'exclude')
state = setPassSelectionMode(state, 'pass-c', 'selected-only')
state = setPassSelectionRule(state, 'pass-c', otherMethod, 'exclude')
const passA = state.passSelections.find((selection) => selection.passId === 'pass-a')
const passB = state.passSelections.find((selection) => selection.passId === 'pass-b')
const passC = state.passSelections.find((selection) => selection.passId === 'pass-c')
if (passA === undefined || passB === undefined || passC === undefined) {
  throw new Error('expected all independent pass selections')
}
assert(nodePassSelectionAction(passA.rules, targetClass) === 'exclude', 'expected class exclusion in pass-a')
assert(nodePassSelectionAction(passA.rules, findString) === 'obfuscate', 'expected exact method recovery from pass-a class exclusion')
assert(nodePassSelectionAction(passA.rules, findInt) === 'exclude', 'expected overload without recovery to retain class exclusion')
assert(nodePassSelectionAction(passB.rules, targetClass) === 'obfuscate', 'expected independent pass-b class baseline')
assert(nodePassSelectionAction(passB.rules, findString) === 'exclude', 'expected pass-b method exclusion to remain independent')
assert(nodePassSelectionAction(passB.rules, otherMethod) === 'obfuscate', 'expected pass-b default scope to remain independent')
assert(passA.rules.some((rule) => rule.target === targetClass.selector && rule.action === 'exclude'), 'expected pass-a class exclusion stored exactly')
assert(passA.rules.some((rule) => rule.target === findString.selector && rule.action === 'obfuscate'), 'expected restored overload selector stored exactly')
assert(passB.rules.some((rule) => rule.target === findString.selector && rule.action === 'exclude'), 'expected excluded overload selector stored exactly')

// Disabled custom selections stay in state but never leave in a run request.
const disabled = togglePass(state, 'pass-a')
assert(disabled.passSelections.some((selection) => selection.passId === 'pass-a'), 'expected disabled pass selection retained in state')
const request = buildObfuscationRequest(disabled)
assert(!request.passSelections.some((selection) => selection.passId === 'pass-a'), 'expected disabled pass selection omitted from run request')
assert(request.passSelections.some((selection) => selection.passId === 'pass-b'), 'expected independent enabled pass selection sent')
const reenabled = togglePass(disabled, 'pass-a')
assert(reenabled.passSelections.some((selection) => selection.passId === 'pass-a'), 'expected re-enabled pass selection to be restored from retained state')
assert(buildObfuscationRequest(reenabled).passSelections.some((selection) => selection.passId === 'pass-a'), 'expected re-enabled pass selection to rejoin the run request')

const malformedSelectorState: RunState = {
  ...state,
  passSelections: [{ passId: 'pass-a', mode: 'selected-only', rules: [{ id: 'bad', target: 'sample/*/Target', action: 'exclude' }] }],
}
expectError(() => buildObfuscationRequest(malformedSelectorState), '非 canonical 类/方法')
const classOnlyPass = { ...supportedPass('pass-a'), targeting: { supported: true, targetKinds: ['class'] as const } }
const capabilityMismatchState: RunState = {
  ...state,
  passes: [classOnlyPass, supportedPass('pass-b'), supportedPass('pass-c')],
  passSelections: [{ passId: 'pass-a', mode: 'selected-only', rules: [{ id: 'method-only', target: 'sample/Target#other:()V', action: 'exclude' }] }],
}
expectError(() => buildObfuscationRequest(capabilityMismatchState), '不支持 method 范围')

// Rescanning prunes global and selected-only targets using the same canonical selector source.
const pruned = setJarInspection(state, {
  jarPath: 'C:\\fixture.jar',
  classCount: 1,
  packageCount: 1,
  nodes: [packageNode('package:sample', 'sample', [classNode('class:Target', 'sample/Target', [findString])])],
})
const prunedPassA = pruned.passSelections.find((selection) => selection.passId === 'pass-a')
const prunedPassB = pruned.passSelections.find((selection) => selection.passId === 'pass-b')
const prunedPassC = pruned.passSelections.find((selection) => selection.passId === 'pass-c')
assert(pruned.rules.every((rule) => rule.target !== findInt.selector), 'expected stale global overload rule to be pruned')
assert(prunedPassA?.rules.length === 2, 'expected surviving class exclusion and method recovery in pass-a')
assert(prunedPassB?.rules.length === 1, 'expected surviving pass-b method exclusion to remain')
assert(prunedPassC?.rules.length === 0, 'expected cleared pass-c independent scope to preserve an empty rule list')
assert(prunedPassC?.mode === 'selected-only', 'expected cleared independent scope mode to remain selected-only')
assert(pruned.logs.at(-1)?.message.includes('pass-c -1') === true, 'expected rescan log to identify cleared pass-c scope')
assert(pruned.logs.at(-1)?.message.includes('pass-a -') !== true, 'expected unchanged pass-a scope to avoid a false prune report')
assert(pruned.logs.at(-1)?.message.includes('pass-b -') !== true, 'expected unchanged pass-b scope to avoid a false prune report')
const prunedRequest = buildObfuscationRequest(pruned)
assert(prunedRequest.passSelections.find((selection) => selection.passId === 'pass-c')?.rules.length === 0, 'expected empty independent scope to remain in the execution request')

console.log('state-pass-selection checks passed')
