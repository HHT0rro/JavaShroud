import {
  buildClassTreeVisibleRows,
  filterClassTreeNodes,
  virtualizeClassTreeRows,
} from './class-tree-view.ts'
import type { ClassTreeNode } from './types.ts'

const assert = (condition: boolean, message: string): void => {
  if (!condition) throw new Error(message)
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

const tree: readonly ClassTreeNode[] = [{
  id: 'package:sample',
  label: 'sample',
  qualifiedName: 'sample',
  internalName: 'sample',
  selector: 'sample/*',
  kind: 'package',
  children: [{
    id: 'class:Target',
    label: 'Target',
    qualifiedName: 'sample.Target',
    internalName: 'sample/Target',
    selector: 'sample/Target',
    kind: 'class',
    children: [
      method('method:find:string', 'find', 'sample/Target#find:(Ljava/lang/String;)Ljava/lang/String;'),
      method('method:find:int', 'find', 'sample/Target#find:(I)Ljava/lang/String;'),
    ],
  }],
}]

const filtered = filterClassTreeNodes(tree, '(I)Ljava/lang/String;', ['package', 'class', 'method'])
assert(filtered.length === 1, 'expected matching package path')
assert(filtered[0]?.children.length === 1, 'expected matching class path')
assert(filtered[0]?.children[0]?.children.length === 1, 'expected only descriptor-matched overload')
assert((filtered[0]?.children[0]?.children[0]?.selector ?? '').endsWith('(I)Ljava/lang/String;'), 'expected canonical selector matching')

const collapsedRows = buildClassTreeVisibleRows(tree)
assert(collapsedRows.length === 1 && collapsedRows[0]?.node.kind === 'package', 'expected collapsed tree to mount only root rows')
const expandedRows = buildClassTreeVisibleRows(tree, { expandedNodeIds: new Set(['package:sample', 'class:Target']) })
assert(expandedRows.length === 4, 'expected expanded flat view to include package, class, and overloads')
assert(expandedRows[3]?.depth === 2, 'expected method indentation preserved in flat rows')
const passRows = buildClassTreeVisibleRows([
  {
    ...tree[0]!,
    children: [{
      ...tree[0]!.children[0]!,
      children: [
        ...tree[0]!.children[0]!.children,
        {
          id: 'field:Target:value',
          label: 'value',
          qualifiedName: 'sample.Target.value',
          internalName: 'sample/Target#value:I',
          selector: 'sample/Target#value:I',
          kind: 'field',
          children: [],
        },
      ],
    }],
  },
], {
  allowedKinds: ['package', 'class', 'method'],
  expandedNodeIds: new Set(['package:sample', 'class:Target']),
})
assert(passRows.every((row) => row.node.kind !== 'field'), 'expected pass-scope rows to hide global-only fields without filtering package navigation')
const searchedRows = buildClassTreeVisibleRows(tree, { query: '(I)Ljava/lang/String;' })
assert(searchedRows.map((row) => row.node.id).join(',') === 'package:sample,class:Target,method:find:int', 'expected search to reveal retained parent path')

const slice = virtualizeClassTreeRows(expandedRows, 48, 48, 48, 0)
assert(slice.startIndex === 1 && slice.endIndex === 2, 'expected one-row virtual viewport window')
assert(slice.rows[0]?.node.id === 'class:Target', 'expected virtual window to select row at scroll offset')
assert(slice.topPadding === 48 && slice.bottomPadding === 96, 'expected exact spacer geometry')

console.log('class-tree-view checks passed')
