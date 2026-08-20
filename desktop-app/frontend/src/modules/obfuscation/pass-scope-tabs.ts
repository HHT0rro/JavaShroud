export const resolveActivePassScopeTabId = (
  enabledPassIds: readonly string[],
  currentPassId: string | null,
): string | null => {
  if (enabledPassIds.length === 0) return null
  return currentPassId !== null && enabledPassIds.includes(currentPassId)
    ? currentPassId
    : enabledPassIds[0] ?? null
}

export const resolvePassScopeTabIdForKey = (
  enabledPassIds: readonly string[],
  currentPassId: string,
  key: string,
): string | null => {
  const currentIndex = enabledPassIds.indexOf(currentPassId)
  if (currentIndex < 0 || enabledPassIds.length === 0) return null

  if (key === 'Home') return enabledPassIds[0] ?? null
  if (key === 'End') return enabledPassIds.at(-1) ?? null
  if (key === 'ArrowRight') return enabledPassIds[(currentIndex + 1) % enabledPassIds.length] ?? null
  if (key === 'ArrowLeft') return enabledPassIds[(currentIndex - 1 + enabledPassIds.length) % enabledPassIds.length] ?? null
  return null
}
