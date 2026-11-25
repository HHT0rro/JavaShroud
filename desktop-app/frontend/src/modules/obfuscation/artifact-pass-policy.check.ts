import { readFileSync } from 'node:fs'
import { APK_FORBIDDEN_PASS_IDS, unavailableApkPassIds } from './artifact-pass-policy.ts'
import { buildObfuscationRequest, createInitialRunState, setArtifactFormat, setAllPassesEnabled, setEngineSchema, setInputJarPath } from './state.ts'
import { exportWorkbenchTomlConfig, importWorkbenchTomlConfig } from './config-toml.ts'
import { applyDroppedJarPath } from './input-flow-controller.ts'
import type { EngineSchemaPayload, PassItem } from './types.ts'

const assert = (condition: boolean, message: string): void => { if (!condition) throw new Error(message) }
const engineSource = readFileSync(new URL('../../../../../core-engine/src/main/kotlin/io/github/hht0rro/javashroud/model/config/ConfigModels.kt', import.meta.url), 'utf8')
const engineIds = [...(engineSource.match(/APK_FORBIDDEN_PASS_IDS[^=]*= setOf\(([\s\S]*?)\)/)?.[1] ?? '').matchAll(/"([^"]+)"/g)].map((match) => match[1]).sort()
assert(engineIds.join(',') === [...APK_FORBIDDEN_PASS_IDS].sort().join(','), 'frontend APK policy must match the engine blacklist')

const pass = (id: string, requiredPassIds: string[] = []): PassItem => ({
  id, name: id, description: '', category: 'checks', tagIds: [], enabled: true, params: {}, paramSchemas: [],
  stability: 'stable', risk: 'low', requiresOptIn: false, requiredPassIds, requiresAnyPassIds: [], variantRequirements: [],
  targeting: { supported: false, targetKinds: [] },
})
const passes = [
  pass('rename-classes'), pass('jni-microkernel-loader'), pass('nativeshroud', ['jni-microkernel-loader']),
  pass('method-virtualization'), pass('os-anti-debug'), pass('os-anti-vm'),
  pass('callsite-rotation-protection', ['jni-microkernel-loader']),
  { ...pass('string-encryption'), params: { decoderBackend: 'native-kernel' }, variantRequirements: [{ whenParam: 'decoderBackend', equals: 'native-kernel', requiredPassIds: ['jni-microkernel-loader'] }] },
  pass('strip-compile-debug-info'),
]
const state = { ...createInitialRunState(), passes }
const apk = setArtifactFormat(state, 'apk')
assert(apk.passes.map((p) => p.id).join(',') === 'rename-classes,strip-compile-debug-info', 'APK hides desktop passes and transitive/variant dependencies')
assert(apk.apkUnavailablePasses.length === 7, 'APK keeps hidden settings for the JAR mode')
const allApk = setAllPassesEnabled(apk, true)
assert(allApk.passes.length === 2 && allApk.passes.every((p) => p.enabled), 'APK select all only enables available modules')
const jar = setArtifactFormat(allApk, 'jar')
assert(jar.passes.map((p) => p.id).join(',') === passes.map((p) => p.id).join(','), 'switching back to JAR restores pass order')
assert(jar.passes.find((p) => p.id === 'nativeshroud')?.enabled === true, 'JAR restores hidden selections')
assert(jar.apkUnavailablePasses.length === 0, 'JAR has no hidden passes')

const input = setInputJarPath(state, 'C:\\apps\\sample.APK')
assert(input.artifactFormat === 'apk', 'typing an APK auto-selects the APK mode')
assert(input.outputJarPath === 'C:\\apps\\sample-shrouded.apk', 'APK output uses the matching extension')
const dropped = applyDroppedJarPath(state, 'C:\\apps\\sample.apk')
assert(dropped.nextState.artifactFormat === 'apk' && dropped.errorMessage === null, 'dropping an APK auto-selects the mode')
const changed = setArtifactFormat(input, 'jar')
assert(changed.inputJar === null && changed.outputJarPath === '' && changed.classTree.length === 0, 'manual mode change clears incompatible paths and inspection')

const defensiveRequest = buildObfuscationRequest({ ...input, passes })
assert(defensiveRequest.artifactFormat === 'apk', 'APK mode reaches the desktop request')
assert(defensiveRequest.passes.map((p) => p.id).join(',') === 'rename-classes,strip-compile-debug-info', 'request filtering blocks injected or imported desktop passes')
let rejected = false
try { buildObfuscationRequest({ ...input, artifactFormat: 'jar' }) } catch { rejected = true }
assert(rejected, 'mismatched mode and input cannot be submitted')

const exported = exportWorkbenchTomlConfig(input)
const [metaSection, inputSection] = exported.split('[input]')
assert(metaSection?.includes('artifactFormat = "apk"') && !inputSection?.includes('artifactFormat'), 'export uses the engine-readable meta section for mode')
assert(!exported.includes('id = "jni-microkernel-loader"'), 'APK export omits hidden passes')
const imported = importWorkbenchTomlConfig(state, exported)
assert(imported.nextState.artifactFormat === 'apk' && imported.nextState.passes.length === 2, 'APK config import preserves filtering')
const oldImport = importWorkbenchTomlConfig(state, exported.replace('artifactFormat = "apk"\n', ''))
assert(oldImport.nextState.artifactFormat === 'apk', 'old configs infer format from the path')
const emptyConfig = importWorkbenchTomlConfig(state, '[input]\nartifactFormat = "apk"\n')
assert(emptyConfig.nextState.artifactFormat === 'apk', 'previous workbench configs can set mode under input')
const autoImport = importWorkbenchTomlConfig(state, exported.replace('artifactFormat = "apk"', 'artifactFormat = "auto"'))
assert(autoImport.nextState.artifactFormat === 'apk', 'auto resolves to the workbench mode from the input path')
rejected = false
try { importWorkbenchTomlConfig(state, exported.replace('artifactFormat = "apk"', 'artifactFormat = "jar"')) } catch { rejected = true }
assert(rejected, 'explicit imported mode must match the file')
rejected = false
try { importWorkbenchTomlConfig(state, '[meta]\nartifactFormat = "jar"\n[input]\nartifactFormat = "apk"\n') } catch { rejected = true }
assert(rejected, 'conflicting config locations must be rejected')

const jvmString = { ...passes[7]!, params: { decoderBackend: 'jvm-resolver' } }
assert(!unavailableApkPassIds([pass('jni-microkernel-loader'), jvmString]).has('string-encryption'), 'JVM string resolver remains available when it has no native dependency')
const schema: EngineSchemaPayload = { schemaVersion: '2', engineVersion: 'test', tags: [], modules: passes.map((p) => ({ ...p, params: [] })), compatibility: [], orderingConstraints: [], defaultPipeline: [] }
const loadedInApk = setEngineSchema(setArtifactFormat(createInitialRunState(), 'apk'), schema)
assert(!loadedInApk.passes.some((p) => APK_FORBIDDEN_PASS_IDS.has(p.id)), 'schema loaded after selecting APK stays filtered')
console.log('artifact-pass-policy checks passed')
