import { access } from 'node:fs/promises'
import { extname } from 'node:path'
import { fileURLToPath } from 'node:url'

const sourceExtensions = ['.ts', '.tsx']

/**
 * The frontend intentionally uses Vite-style extensionless TypeScript imports.
 * Node's native TypeScript runner does not resolve those specifiers, so local
 * standalone checks use this narrow resolver instead of changing production
 * import conventions or adding a test runtime dependency.
 */
export async function resolve(specifier, context, nextResolve) {
  try {
    return await nextResolve(specifier, context)
  } catch (error) {
    if (
      error?.code !== 'ERR_MODULE_NOT_FOUND'
      || !specifier.startsWith('.')
      || extname(specifier) !== ''
    ) {
      throw error
    }

    for (const extension of sourceExtensions) {
      const candidate = new URL(`${specifier}${extension}`, context.parentURL)
      try {
        await access(fileURLToPath(candidate))
        return { url: candidate.href, shortCircuit: true }
      } catch {
        // Try the next source extension.
      }
    }

    throw error
  }
}
