import {
  applyVisibleReorder,
  canMoveAmongVisible,
  filterPipelinePasses,
  movePassAmongVisible,
  pipelineFilterChips,
  resolveSelectedPassId,
} from './pipeline-workbench.ts'
import type { PassItem } from './types.ts'

const assert = (condition: boolean, message: string): void => {
  if (!condition) {
    throw new Error(message)
  }
}

const pass = (id: string, category: string, enabled: boolean, name = id): PassItem => ({
  id,
  name,
  description: `${name} desc`,
  tagIds: [],
  category,
  enabled,
  params: {},
  paramSchemas: [],
  stability: 'stable',
  risk: 'low',
  requiresOptIn: false,
  requiredPassIds: [],
  requiresAnyPassIds: [],
  variantRequirements: [],
  targeting: { supported: false, targetKinds: [] },
})

const full = [pass('a', 'rename', true), pass('b', 'flow', false), pass('c', 'rename', true), pass('d', 'flow', true)]
const renameCatalog = [
  pass('rename-classes', 'rename', true, 'Rename classes'),
  pass('rename-packages', 'rename', true, 'Rename packages'),
  pass('rename-methods', 'rename', true, 'Rename methods'),
  pass('rename-fields', 'rename', true, 'Rename fields'),
  pass('string-encryption', 'protect', true, 'String encryption'),
]

const chips = pipelineFilterChips(full)
assert(chips[0]?.id === 'all' && chips[0].count === 4, 'all chip count')
assert(chips[1]?.id === 'enabled' && chips[1].count === 3, 'enabled chip count')
assert(chips.some((chip) => chip.id === 'rename' && chip.count === 2), 'rename category count')

const enabledOnly = filterPipelinePasses(full, 'enabled', '')
assert(enabledOnly.map((item) => item.id).join(',') === 'a,c,d', 'enabled filter order')

const searched = filterPipelinePasses(full, 'all', 'FLOW')
assert(searched.map((item) => item.id).join(',') === 'b,d', 'search is case-insensitive')

const zhRename = filterPipelinePasses(renameCatalog, 'all', '重命名', 'zh')
assert(zhRename.map((item) => item.id).join(',') === 'rename-classes,rename-packages,rename-methods,rename-fields', 'zh displayed labels are searchable')
const enRename = filterPipelinePasses(renameCatalog, 'all', 'Rename classes', 'en')
assert(enRename.map((item) => item.id).join(',') === 'rename-classes', 'en displayed labels are searchable')
const idSearch = filterPipelinePasses(renameCatalog, 'all', 'rename-fields', 'zh')
assert(idSearch.map((item) => item.id).join(',') === 'rename-fields', 'raw ids remain searchable')
const crossLocale = filterPipelinePasses(renameCatalog, 'all', 'Rename packages', 'zh')
assert(crossLocale.map((item) => item.id).join(',') === 'rename-packages', 'opposite-locale labels remain searchable')

const visible = filterPipelinePasses(full, 'rename', '')
const reorderedVisible = [visible[1]!, visible[0]!]
const merged = applyVisibleReorder(full, reorderedVisible)
assert(merged.map((item) => item.id).join(',') === 'c,b,a,d', 'hidden passes stay in relative slots')

const movedDown = movePassAmongVisible(full, visible, 'a', 1)
assert(movedDown.map((item) => item.id).join(',') === 'c,b,a,d', 'up/down swaps visible neighbors and keeps hidden slots')
assert(movePassAmongVisible(full, visible, 'a', -1) === full, 'cannot move first visible item up')
assert(canMoveAmongVisible(visible, 'a', 1) === true, 'can move first visible down')
assert(canMoveAmongVisible(visible, 'a', -1) === false, 'cannot move first visible up')

assert(resolveSelectedPassId('c', enabledOnly) === 'c', 'keep visible selection')
assert(resolveSelectedPassId('b', enabledOnly) === 'a', 'drop selection that left the visible list')
assert(resolveSelectedPassId(null, []) === null, 'empty selection')

console.log('pipeline-workbench checks passed')
