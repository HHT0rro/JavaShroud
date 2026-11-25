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
  tags: [
    { id: 'native-kernel', name: 'Native', description: 'Native kernel' },
    { id: 'runtime-defense', name: 'Runtime', description: 'Runtime defense' },
  ],
  modules: [
    { id: 'jni-microkernel-loader', name: 'JNI Loader', description: 'JNI loader', tagIds: ['native-kernel'], stability: 'experimental', defaultEnabled: false, requiresAnyPassIds: ['os-anti-debug', 'os-anti-vm'], params: [], targeting: { supported: false, targetKinds: [] } },
    { id: 'os-anti-debug', name: 'OS Anti Debug', description: 'Native debugger and instrumentation defense', tagIds: ['runtime-defense'], stability: 'experimental', defaultEnabled: true, requiredPassIds: ['jni-microkernel-loader'], params: [], targeting: { supported: false, targetKinds: [] } },
    { id: 'os-anti-vm', name: 'OS Anti VM', description: 'Native virtual-machine defense', tagIds: ['runtime-defense'], stability: 'experimental', defaultEnabled: false, requiredPassIds: ['jni-microkernel-loader'], params: [], targeting: { supported: false, targetKinds: [] } },
  ],
  compatibility: [],
  orderingConstraints: [],
  defaultPipeline: ['os-anti-debug'],
})

const builtPasses = buildPassItemsFromSchema(schema)
const enabledIds = builtPasses.filter((passItem) => passItem.enabled).map((passItem) => passItem.id)
assert(enabledIds.includes('os-anti-debug'), 'expected os-anti-debug to be enabled from default pipeline')
assert(enabledIds.includes('jni-microkernel-loader'), 'expected requiredPassIds dependency to auto-enable jni-microkernel-loader')
assert(!enabledIds.includes('os-anti-vm'), 'expected os-anti-vm to remain disabled when not selected')

const disabledPasses = disablePassAndDependents(builtPasses, 'jni-microkernel-loader')
const disabledIds = disabledPasses.filter((passItem) => passItem.enabled).map((passItem) => passItem.id)
assert(!disabledIds.includes('jni-microkernel-loader'), 'expected jni-microkernel-loader to be disabled')
assert(!disabledIds.includes('os-anti-debug'), 'expected disabling jni-microkernel-loader to disable its dependents')

const standaloneJniSchema = parseEngineSchema({
  ...schema,
  modules: [
    { id: 'jni-microkernel-loader', name: 'JNI Loader', description: 'JNI loader', tagIds: ['native-kernel'], stability: 'experimental', defaultEnabled: true, requiresAnyPassIds: ['os-anti-debug'], params: [], targeting: { supported: false, targetKinds: [] } },
    { id: 'os-anti-debug', name: 'OS Anti Debug', description: 'Native debugger and instrumentation defense', tagIds: ['runtime-defense'], stability: 'experimental', defaultEnabled: false, requiredPassIds: ['jni-microkernel-loader'], params: [], targeting: { supported: false, targetKinds: [] } },
  ],
  defaultPipeline: ['jni-microkernel-loader'],
})
const standaloneJniPasses = buildPassItemsFromSchema(standaloneJniSchema)
assert(!standaloneJniPasses.some((passItem) => passItem.id === 'jni-microkernel-loader' && passItem.enabled), 'expected standalone jni-microkernel-loader to be disabled')

console.log('state dependency checks passed')
