const assert = (condition: boolean, message: string): void => {
  if (!condition) {
    throw new Error(message)
  }
}

const { parseEngineSchema } = await import('./capability-parser.ts')
const { buildPassItemsFromSchema, disablePassAndDependents } = await import('./pass-catalog.ts')

const schema = parseEngineSchema({
  schemaVersion: '2',
  engineVersion: 'check-engine',
  vbcVersion: 'VBC4-dev',
  tags: [
    { id: 'native-kernel', name: 'Native', description: 'Native kernel' },
    { id: 'runtime-defense', name: 'Runtime', description: 'Runtime defense' },
  ],
  modules: [
    { id: 'jni-microkernel-loader', name: 'JNI Loader', description: 'JNI loader', tagIds: ['native-kernel'], stability: 'experimental', defaultEnabled: false, requiresAnyPassIds: ['anti-instrumentation', 'environment-bound-keys'], params: [] },
    { id: 'anti-instrumentation', name: 'Anti Instrumentation', description: 'Anti instrumentation', tagIds: ['runtime-defense'], stability: 'experimental', defaultEnabled: true, requiredPassIds: ['jni-microkernel-loader'], params: [] },
    { id: 'environment-bound-keys', name: 'Environment Bound Keys', description: 'Environment binding', tagIds: ['runtime-defense'], stability: 'experimental', defaultEnabled: false, requiredPassIds: ['jni-microkernel-loader'], params: [] },
  ],
  compatibility: [],
  orderingConstraints: [],
  defaultPipeline: ['anti-instrumentation'],
})

const builtPasses = buildPassItemsFromSchema(schema)
const enabledIds = builtPasses.filter((passItem) => passItem.enabled).map((passItem) => passItem.id)
assert(enabledIds.includes('anti-instrumentation'), 'expected anti-instrumentation to be enabled from default pipeline')
assert(enabledIds.includes('jni-microkernel-loader'), 'expected requiredPassIds dependency to auto-enable jni-microkernel-loader')
assert(!enabledIds.includes('environment-bound-keys'), 'expected environment-bound-keys to remain disabled when not selected')

const disabledPasses = disablePassAndDependents(builtPasses, 'jni-microkernel-loader')
const disabledIds = disabledPasses.filter((passItem) => passItem.enabled).map((passItem) => passItem.id)
assert(!disabledIds.includes('jni-microkernel-loader'), 'expected jni-microkernel-loader to be disabled')
assert(!disabledIds.includes('anti-instrumentation'), 'expected disabling jni-microkernel-loader to disable its dependents')

const standaloneJniSchema = parseEngineSchema({
  ...schema,
  modules: [
    { id: 'jni-microkernel-loader', name: 'JNI Loader', description: 'JNI loader', tagIds: ['native-kernel'], stability: 'experimental', defaultEnabled: true, requiresAnyPassIds: ['anti-instrumentation'], params: [] },
    { id: 'anti-instrumentation', name: 'Anti Instrumentation', description: 'Anti instrumentation', tagIds: ['runtime-defense'], stability: 'experimental', defaultEnabled: false, requiredPassIds: ['jni-microkernel-loader'], params: [] },
  ],
  defaultPipeline: ['jni-microkernel-loader'],
})
const standaloneJniPasses = buildPassItemsFromSchema(standaloneJniSchema)
assert(!standaloneJniPasses.some((passItem) => passItem.id === 'jni-microkernel-loader' && passItem.enabled), 'expected standalone jni-microkernel-loader to be disabled')

console.log('state dependency checks passed')
