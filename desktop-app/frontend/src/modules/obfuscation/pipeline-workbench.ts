import {
  localizeCategoryLabel,
  localizePassDescription,
  localizePassName,
  type DisplayLanguage,
} from './pass-localization'
import type { PassItem } from './types'

export type PipelineFilterId = 'all' | 'enabled' | string

export interface PipelineFilterChip {
  readonly id: PipelineFilterId
  readonly count: number
}

export const pipelineFilterChips = (passes: readonly PassItem[]): readonly PipelineFilterChip[] => {
  const enabledCount = passes.filter((passItem: PassItem): boolean => passItem.enabled).length
  const seen: Set<string> = new Set<string>()
  const chips: PipelineFilterChip[] = [
    { id: 'all', count: passes.length },
    { id: 'enabled', count: enabledCount },
  ]

  for (const passItem of passes) {
    if (seen.has(passItem.category)) {
      continue
    }
    seen.add(passItem.category)
    chips.push({
      id: passItem.category,
      count: passes.filter((candidate: PassItem): boolean => candidate.category === passItem.category).length,
    })
  }

  return chips
}

const searchablePassText = (passItem: PassItem, language: DisplayLanguage): string => {
  const languages: readonly DisplayLanguage[] = language === 'zh' ? ['zh', 'en'] : ['en', 'zh']
  const localized = languages.flatMap((locale: DisplayLanguage): string[] => [
    localizePassName(passItem, locale),
    localizePassDescription(passItem, locale),
    localizeCategoryLabel(passItem.category, locale),
  ])
  return [
    passItem.id,
    passItem.name,
    passItem.description,
    passItem.category,
    ...localized,
  ].join(' ').toLowerCase()
}

export const filterPipelinePasses = (
  passes: readonly PassItem[],
  filterId: PipelineFilterId,
  query: string,
  language: DisplayLanguage = 'zh',
): readonly PassItem[] => {
  const normalized = query.trim().toLowerCase()
  return passes.filter((passItem: PassItem): boolean => {
    if (filterId === 'enabled' && !passItem.enabled) {
      return false
    }
    if (filterId !== 'all' && filterId !== 'enabled' && passItem.category !== filterId) {
      return false
    }
    if (normalized.length === 0) {
      return true
    }
    return searchablePassText(passItem, language).includes(normalized)
  })
}

export const applyVisibleReorder = <T extends { readonly id: string }>(
  full: readonly T[],
  visibleNewOrder: readonly T[],
): readonly T[] => {
  const nextVisibleIds = visibleNewOrder.map((item: T): string => item.id)
  const visibleSet = new Set(nextVisibleIds)
  const byId: Readonly<Record<string, T>> = Object.fromEntries(full.map((item: T): [string, T] => [item.id, item]))
  let visibleIndex = 0

  return full.map((item: T): T => {
    if (!visibleSet.has(item.id)) {
      return item
    }
    const nextId = nextVisibleIds[visibleIndex]
    visibleIndex += 1
    return nextId === undefined ? item : byId[nextId] ?? item
  })
}

export const movePassAmongVisible = <T extends { readonly id: string }>(
  full: readonly T[],
  visible: readonly T[],
  passId: string,
  direction: -1 | 1,
): readonly T[] => {
  const visibleIndex = visible.findIndex((item: T): boolean => item.id === passId)
  const neighborIndex = visibleIndex + direction
  if (visibleIndex < 0 || neighborIndex < 0 || neighborIndex >= visible.length) {
    return full
  }

  const nextVisible = [...visible]
  const current = nextVisible[visibleIndex]
  const neighbor = nextVisible[neighborIndex]
  if (current === undefined || neighbor === undefined) {
    return full
  }
  nextVisible[visibleIndex] = neighbor
  nextVisible[neighborIndex] = current
  return applyVisibleReorder(full, nextVisible)
}

export const canMoveAmongVisible = (
  visible: readonly { readonly id: string }[],
  passId: string | null,
  direction: -1 | 1,
): boolean => {
  if (passId === null) {
    return false
  }
  const visibleIndex = visible.findIndex((item): boolean => item.id === passId)
  const neighborIndex = visibleIndex + direction
  return visibleIndex >= 0 && neighborIndex >= 0 && neighborIndex < visible.length
}

export const resolveSelectedPassId = (
  selectedPassId: string | null,
  visible: readonly PassItem[],
): string | null => {
  if (selectedPassId !== null && visible.some((passItem: PassItem): boolean => passItem.id === selectedPassId)) {
    return selectedPassId
  }
  return visible[0]?.id ?? null
}
