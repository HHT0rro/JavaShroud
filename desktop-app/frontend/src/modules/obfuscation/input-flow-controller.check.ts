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
const windowsApkPath = 'C:\\Users\\Public\\Desktop\\app-release.apk'
const relativeApkPath = '.\\app-release.apk'
const unsupportedTxtPath = 'C:\\Users\\Public\\Desktop\\notes.txt'

assert(isAbsoluteJarPath(windowsJarPath), `expected Windows path to be absolute: ${windowsJarPath}`)
assert(isAbsoluteJarPath(uncJarPath), `expected UNC path to be absolute: ${uncJarPath}`)
assert(isAbsoluteJarPath(unixJarPath), `expected Unix path to be absolute: ${unixJarPath}`)
assert(!isAbsoluteJarPath(relativeJarPath), `expected relative path to be rejected: ${relativeJarPath}`)
assert(isAbsoluteJarPath(windowsApkPath), `expected Windows apk path to be accepted: ${windowsApkPath}`)
assert(!isAbsoluteJarPath(relativeApkPath), `expected relative apk path to be rejected: ${relativeApkPath}`)
assert(!isAbsoluteJarPath(unsupportedTxtPath), `expected unsupported extension to be rejected: ${unsupportedTxtPath}`)

const state = createInitialRunState()
const dropped = applyDroppedJarPath(state, windowsJarPath)
assert(dropped.inputJarPath === windowsJarPath, 'expected dropped Windows jar path to be accepted')
assert(dropped.errorMessage === null, 'expected no drop error for absolute Windows jar path')
assert(resolveInspectableJarPath(dropped.nextState) === windowsJarPath, 'expected inspect path resolution to keep Windows jar path')

const droppedApk = applyDroppedJarPath(state, windowsApkPath)
assert(droppedApk.inputJarPath === windowsApkPath, 'expected dropped Windows apk path to be accepted')
assert(droppedApk.errorMessage === null, 'expected no drop error for absolute Windows apk path')
assert(
  droppedApk.nextState.outputJarPath === 'C:\\Users\\Public\\Desktop\\app-release-shrouded.apk',
  `expected apk output path to keep the apk extension, got: ${droppedApk.nextState.outputJarPath}`,
)
assert(resolveInspectableJarPath(droppedApk.nextState) === windowsApkPath, 'expected inspect path resolution to keep Windows apk path')

console.log('input-flow-controller checks passed')
