import { requiredPassIdsFor, requiresAnyPassIdsFor } from './pass-catalog'
import type { ArtifactFormat, PassItem } from './types'

// Keep in sync with ConfigModels.kt APK_FORBIDDEN_PASS_IDS. The policy check
// verifies parity against the engine source and covers transitive dependencies.
export const APK_FORBIDDEN_PASS_IDS: ReadonlySet<string> = new Set([
  'jni-microkernel-loader',
  'nativeshroud',
  'method-virtualization',
  'os-anti-debug',
  'os-anti-vm',
])

export const unavailableApkPassIds = (passes: readonly PassItem[]): ReadonlySet<string> => {
  const unavailable = new Set(APK_FORBIDDEN_PASS_IDS)
  let changed = true
  while (changed) {
    changed = false
    for (const pass of passes) {
      const required = requiredPassIdsFor(pass)
      const alternatives = requiresAnyPassIdsFor(pass)
      if (!unavailable.has(pass.id) && (
        required.some((id) => unavailable.has(id))
        || (alternatives.length > 0 && alternatives.every((id) => unavailable.has(id)))
      )) {
        unavailable.add(pass.id)
        changed = true
      }
    }
  }
  return unavailable
}

export const passesForArtifactFormat = (passes: readonly PassItem[], format: ArtifactFormat): readonly PassItem[] => {
  if (format === 'jar') return passes
  const unavailable = unavailableApkPassIds(passes)
  return passes.filter((pass) => !unavailable.has(pass.id))
}

export const artifactFormatForPath = (path: string): ArtifactFormat | null => {
  const lower = path.trim().toLowerCase()
  if (lower.endsWith('.apk')) return 'apk'
  if (lower.endsWith('.jar')) return 'jar'
  return null
}
