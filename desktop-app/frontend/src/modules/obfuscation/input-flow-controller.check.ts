import { createInitialRunState } from './state'
import { applyDroppedJarPath, isAbsoluteJarPath, resolveInspectableJarPath } from './input-flow-controller'

const assert = (condition: boolean, message: string): void => {
  if (!condition) {
    throw new Error(message)
  }
}

const windowsJarPath = 'C:\\Users\\Public\\Desktop\\obfuscator-engine.jar'
const uncJarPath = '\\\\server\\share\\sample.jar'
const unixJarPath = '/tmp/sample.jar'
const relativeJarPath = '.\\sample.jar'

assert(isAbsoluteJarPath(windowsJarPath), `expected Windows path to be absolute: ${windowsJarPath}`)
assert(isAbsoluteJarPath(uncJarPath), `expected UNC path to be absolute: ${uncJarPath}`)
assert(isAbsoluteJarPath(unixJarPath), `expected Unix path to be absolute: ${unixJarPath}`)
assert(!isAbsoluteJarPath(relativeJarPath), `expected relative path to be rejected: ${relativeJarPath}`)

const state = createInitialRunState()
const dropped = applyDroppedJarPath(state, windowsJarPath)
assert(dropped.inputJarPath === windowsJarPath, 'expected dropped Windows jar path to be accepted')
assert(dropped.errorMessage === null, 'expected no drop error for absolute Windows jar path')
assert(resolveInspectableJarPath(dropped.nextState) === windowsJarPath, 'expected inspect path resolution to keep Windows jar path')

console.log('input-flow-controller checks passed')
