import { spawnSync } from 'node:child_process'
import { readdirSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const frontendRoot = dirname(fileURLToPath(import.meta.url))
const registerLoader = pathToFileURL(join(frontendRoot, 'scripts', 'register-ts-loader.mjs')).href
const srcRoot = join(frontendRoot, 'src')

const explicitChecks = [
  { name: 'check:capabilities', args: ['src/modules/obfuscation/capability-parser.check.ts'] },
  { name: 'check:events', args: ['src/modules/obfuscation/event-parser.check.ts'] },
  { name: 'check:pass-selections', args: ['src/modules/obfuscation/pass-selection-targeting.check.ts'] },
  { name: 'check:pass-selections-state', args: ['src/modules/obfuscation/state-pass-selection.check.ts'] },
  { name: 'check:class-tree-view', args: ['src/modules/obfuscation/class-tree-view.check.ts'] },
  { name: 'check:pass-scope-tabs', args: ['src/modules/obfuscation/pass-scope-tabs.check.ts'] },
  { name: 'check:config', args: ['src/modules/obfuscation/config-toml.check.ts'] },
  { name: 'check:input-flow', args: ['src/modules/obfuscation/input-flow-controller.check.ts'] },
  { name: 'check:state-dependencies', args: ['src/modules/obfuscation/state-dependencies.check.ts'] },
]

const walkCheckFiles = (dir) => {
  const entries = readdirSync(dir, { withFileTypes: true })
  const files = []
  for (const entry of entries) {
    const fullPath = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist') {
        continue
      }
      files.push(...walkCheckFiles(fullPath))
      continue
    }
    if (entry.name.endsWith('.check.ts')) {
      files.push(fullPath)
    }
  }
  return files
}

const discovered = walkCheckFiles(srcRoot)
  .map((filePath) => relative(frontendRoot, filePath).replaceAll('\\', '/'))

const explicitArgs = new Set(explicitChecks.flatMap((check) => check.args))
const extraChecks = discovered
  .filter((filePath) => !explicitArgs.has(filePath))
  .sort()
  .map((filePath) => ({ name: `check:discovered:${filePath}`, args: [filePath] }))

const runNode = (name, args) => {
  const result = spawnSync(process.execPath, ['--import', registerLoader, ...args], {
    cwd: frontendRoot,
    stdio: 'inherit',
  })
  if (result.status !== 0) {
    throw new Error(`${name} failed with status ${result.status ?? 'unknown'}`)
  }
}

for (const check of [...explicitChecks, ...extraChecks]) {
  runNode(check.name, check.args)
}

const reorder = spawnSync(process.execPath, ['test-reorder-constraints.mjs'], {
  cwd: frontendRoot,
  stdio: 'inherit',
})
if (reorder.status !== 0) {
  throw new Error(`test-reorder-constraints failed with status ${reorder.status ?? 'unknown'}`)
}

console.log(`frontend checks passed (${explicitChecks.length + extraChecks.length + 1} jobs) from ${frontendRoot}`)
