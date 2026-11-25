import type { ClassTreeNode } from './types'

/** Fixed virtual-row height shared with .class-tree--virtual in style.css. */
export const CLASS_TREE_VIRTUAL_ROW_HEIGHT = 48

export interface ClassTreeVisibleRow {
  readonly node: ClassTreeNode
  readonly depth: number
  readonly hasChildren: boolean
}

export interface ClassTreeVirtualSlice {
  readonly rows: readonly ClassTreeVisibleRow[]
  readonly startIndex: number
  readonly endIndex: number
  readonly topPadding: number
  readonly bottomPadding: number
}

export interface ClassTreeViewOptions {
  readonly query?: string
  readonly allowedKinds?: readonly ClassTreeNode['kind'][]
  readonly expandedNodeIds?: ReadonlySet<string>
}

/**
 * Filters a protocol tree without losing the package/class path to a matching
 * descendant. Scope-specific views can hide unsupported field nodes while still
 * retaining package navigation nodes.
 */
export const filterClassTreeNodes = (
  nodes: readonly ClassTreeNode[],
  rawQuery: string,
  allowedKinds?: readonly ClassTreeNode['kind'][],
): readonly ClassTreeNode[] => {
  const normalizedQuery = rawQuery.trim().toLowerCase()
  const allowedKindSet = allowedKinds === undefined ? undefined : new Set(allowedKinds)

  const visit = (node: ClassTreeNode): ClassTreeNode | null => {
    const children = node.children
      .map(visit)
      .filter((child): child is ClassTreeNode => child !== null)
    const selector = node.selector ?? node.internalName
    const matchesQuery = normalizedQuery.length === 0 || `${node.label} ${node.qualifiedName} ${selector}`
      .toLowerCase()
      .includes(normalizedQuery)
    const isAllowed = allowedKindSet === undefined || allowedKindSet.has(node.kind)

    if (isAllowed && (matchesQuery || children.length > 0)) {
      return { ...node, children }
    }

    // Packages are structural navigation nodes. Keep them when a retained
    // descendant needs a visible path, even if a caller excludes package rules.
    return node.kind === 'package' && children.length > 0 ? { ...node, children } : null
  }

  return nodes.map(visit).filter((node): node is ClassTreeNode => node !== null)
}

/**
 * Converts the nested protocol tree to the small set of rows currently visible
 * to the user. Searches automatically reveal the retained parent path; clearing
 * a search returns to the caller-owned expansion state.
 */
export const buildClassTreeVisibleRows = (
  nodes: readonly ClassTreeNode[],
  options: ClassTreeViewOptions = {},
): readonly ClassTreeVisibleRow[] => {
  const query = options.query ?? ''
  const hasQuery = query.trim().length > 0
  const allowedKindSet = options.allowedKinds === undefined ? undefined : new Set(options.allowedKinds)
  // Empty searches are the normal large-Jar path. Do not clone/filter the
  // complete tree here: walk only branches the user expanded. Search still
  // filters every node so it can preserve all matching parent paths.
  const filteredNodes = hasQuery ? filterClassTreeNodes(nodes, query, options.allowedKinds) : nodes
  const expandedNodeIds = options.expandedNodeIds ?? new Set<string>()
  const forceExpand = hasQuery
  const rows: ClassTreeVisibleRow[] = []

  const visit = (items: readonly ClassTreeNode[], depth: number): void => {
    for (const node of items) {
      if (!hasQuery && allowedKindSet !== undefined && !allowedKindSet.has(node.kind)) {
        continue
      }
      const visibleChildren = !hasQuery && allowedKindSet !== undefined
        ? node.children.filter((child): boolean => allowedKindSet.has(child.kind))
        : node.children
      const hasChildren = visibleChildren.length > 0
      rows.push({ node, depth, hasChildren })
      if (hasChildren && (forceExpand || expandedNodeIds.has(node.id))) {
        visit(visibleChildren, depth + 1)
      }
    }
  }

  visit(filteredNodes, 0)
  return rows
}

/**
 * Returns only the viewport plus overscan rows. The spacer values preserve the
 * browser's native scroll geometry without recursively mounting an entire Jar.
 */
export const virtualizeClassTreeRows = (
  rows: readonly ClassTreeVisibleRow[],
  scrollTop: number,
  viewportHeight: number,
  rowHeight = CLASS_TREE_VIRTUAL_ROW_HEIGHT,
  overscan = 8,
): ClassTreeVirtualSlice => {
  const safeRowHeight = Math.max(1, rowHeight)
  const safeScrollTop = Math.max(0, scrollTop)
  const safeViewportHeight = Math.max(safeRowHeight, viewportHeight)
  const firstVisibleIndex = Math.floor(safeScrollTop / safeRowHeight)
  const lastVisibleExclusive = Math.ceil((safeScrollTop + safeViewportHeight) / safeRowHeight)
  const startIndex = Math.max(0, firstVisibleIndex - overscan)
  const endIndex = Math.min(rows.length, Math.max(startIndex, lastVisibleExclusive + overscan))

  return {
    rows: rows.slice(startIndex, endIndex),
    startIndex,
    endIndex,
    topPadding: startIndex * safeRowHeight,
    bottomPadding: Math.max(0, rows.length - endIndex) * safeRowHeight,
  }
}
