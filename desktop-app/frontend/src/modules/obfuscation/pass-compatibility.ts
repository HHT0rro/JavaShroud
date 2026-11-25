import type { PassCompatibilityRule, PassItem } from './types'

const conflictGroups = (
  rules: readonly PassCompatibilityRule[],
  severity: PassCompatibilityRule['severity'],
): readonly ReadonlySet<string>[] => rules
  .filter((rule: PassCompatibilityRule): boolean => rule.severity === severity && rule.passIds.length > 1)
  .map((rule: PassCompatibilityRule): ReadonlySet<string> => new Set<string>(rule.passIds))

export const resolvePassCompatibility = (
  passes: readonly PassItem[],
  rules: readonly PassCompatibilityRule[],
  preferredPassId: string | null = null,
): readonly PassItem[] => {
  const enabledIds = new Set<string>(passes.filter((passItem: PassItem): boolean => passItem.enabled).map((passItem: PassItem): string => passItem.id))

  for (const group of conflictGroups(rules, 'hard')) {
    const enabledInGroup = passes
      .filter((passItem: PassItem): boolean => enabledIds.has(passItem.id) && group.has(passItem.id))
      .map((passItem: PassItem): string => passItem.id)

    if (enabledInGroup.length <= 1) {
      continue
    }

    const winner = preferredPassId !== null && group.has(preferredPassId) && enabledIds.has(preferredPassId)
      ? preferredPassId
      : enabledInGroup[0]

    enabledInGroup
      .filter((passId: string): boolean => passId !== winner)
      .forEach((passId: string): void => {
        enabledIds.delete(passId)
      })
  }

  return passes.map((passItem: PassItem): PassItem => ({
    ...passItem,
    enabled: enabledIds.has(passItem.id),
  }))
}

export const hasEnabledSoftCompatibilityConflict = (
  passes: readonly PassItem[],
  rules: readonly PassCompatibilityRule[],
): boolean => {
  const enabledIds = new Set<string>(passes.filter((passItem: PassItem): boolean => passItem.enabled).map((passItem: PassItem): string => passItem.id))

  return conflictGroups(rules, 'soft').some((group: ReadonlySet<string>): boolean => (
    [...group].filter((passId: string): boolean => enabledIds.has(passId)).length > 1
  ))
}

export const conflictingPassIdsFor = (
  passId: string,
  passes: readonly PassItem[],
  rules: readonly PassCompatibilityRule[],
): readonly string[] => {
  const enabledIds = new Set<string>(passes.filter((passItem: PassItem): boolean => passItem.enabled).map((passItem: PassItem): string => passItem.id))
  const conflicts = new Set<string>()

  for (const group of conflictGroups(rules, 'hard')) {
    if (!group.has(passId)) {
      continue
    }

    group.forEach((candidate: string): void => {
      if (candidate !== passId && enabledIds.has(candidate)) {
        conflicts.add(candidate)
      }
    })
  }

  return [...conflicts]
}