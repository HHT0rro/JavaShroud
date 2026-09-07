import type { ClassTreeNode, EngineSchemaPayload, JarInspectionPayload, ModuleDefinition, ParamSchema } from '../modules/obfuscation/types'

export const MOCK_SCENARIO_QUERY = 'scenario'

export type MockScenarioId =
  | 'default'
  | 'empty'
  | 'done'
  | 'error'
  | 'canceled'
  | 'long-paths'
  | 'large-tree'
  | 'stream'
  | 'full-catalog'

export type MockRunOutcome = 'progress-done' | 'done' | 'error' | 'canceled' | 'stream'

export interface MockEngineEvent {
  readonly type: string
  readonly level: string
  readonly message: string
  readonly progress: number | null
  readonly outPath: string | null
}

export interface MockScenario {
  readonly id: MockScenarioId
  readonly outcome: MockRunOutcome
  readonly inputJarPath: string
  readonly outputJarPath: string
  readonly configPath: string
  readonly schema: EngineSchemaPayload
  readonly inspection: JarInspectionPayload
  readonly runSteps: readonly MockEngineEvent[]
}

const defaultSchema: EngineSchemaPayload = {
  schemaVersion: '2',
  engineVersion: 'browser-mock-dev',
  tags: [
    { id: 'metadata', name: 'Metadata', description: 'Metadata cleanup and stripping.' },
    { id: 'obfuscation', name: 'Obfuscation', description: 'Name and bytecode transforms.' },
    { id: 'vm-protection', name: 'VM Protection', description: 'Method-level virtual machine protection.' },
  ],
  modules: [
    {
      id: 'strip-compile-debug-info',
      name: 'Strip Compile Debug Info',
      description: 'Removes source and debug metadata.',
      tagIds: ['metadata'],
      stability: 'stable',
      targeting: { supported: true, targetKinds: ['class'] },
      params: [],
    },
    {
      id: 'rename-classes',
      name: 'Rename Classes',
      description: 'Renames class symbols for debug preview.',
      tagIds: ['obfuscation'],
      stability: 'beta',
      targeting: { supported: true, targetKinds: ['class'] },
      params: [
        {
          key: 'dictionary',
          type: 'enum',
          defaultValue: 'ascii',
          options: ['ascii', 'greek', 'compact'],
          description: 'Select the preview rename dictionary.',
          hidden: false,
        },
      ],
    },
    {
      id: 'method-virtualization',
      name: 'Method Virtualization',
      description: 'Lowers selected methods into the native bytecode VM path.',
      tagIds: ['vm-protection'],
      stability: 'experimental',
      risk: 'high',
      requiresOptIn: true,
      targeting: { supported: true, targetKinds: ['class', 'method'] },
      params: [
        {
          key: 'methodSelection',
          type: 'enum',
          defaultValue: 'critical-plus',
          options: ['safe', 'critical-auto', 'critical-plus', 'all-compatible'],
          description: 'Selects compatible methods for virtualization under broad class rules.',
          hidden: false,
        },
        {
          key: 'maxInstructions',
          type: 'number',
          defaultValue: 0,
          options: null,
          description: 'Maximum bytecode instructions per virtualized method; 0 means unlimited.',
          hidden: false,
        },
        {
          key: 'maxBroadVirtualizedMethods',
          type: 'number',
          defaultValue: 0,
          options: null,
          description: 'Maximum methods selected by broad class rules; 0 means unlimited.',
          hidden: false,
        },
      ],
    },
  ],
  compatibility: [],
  orderingConstraints: [],
  defaultPipeline: ['strip-compile-debug-info', 'rename-classes'],
}

const defaultInspection: JarInspectionPayload = {
  jarPath: 'C:\\debug\\demo-app.jar',
  classCount: 5,
  packageCount: 3,
  nodes: [
    {
      id: 'pkg-com-example',
      label: 'com.example',
      qualifiedName: 'com.example',
      internalName: 'com/example',
      selector: 'com/example/*',
      kind: 'package',
      children: [
        {
          id: 'class-main',
          label: 'MainApplication',
          qualifiedName: 'com.example.MainApplication',
          internalName: 'com/example/MainApplication',
          selector: 'com/example/MainApplication',
          kind: 'class',
          children: [
            {
              id: 'method-main-run',
              label: 'run()V',
              qualifiedName: 'com.example.MainApplication#run:()V',
              internalName: 'com/example/MainApplication#run:()V',
              selector: 'com/example/MainApplication#run:()V',
              kind: 'method',
              children: [],
            },
          ],
        },
        {
          id: 'class-service',
          label: 'UserService',
          qualifiedName: 'com.example.UserService',
          internalName: 'com/example/UserService',
          selector: 'com/example/UserService',
          kind: 'class',
          children: [
            {
              id: 'method-user-find-string',
              label: 'find(Ljava/lang/String;)Ljava/lang/String;',
              qualifiedName: 'com.example.UserService#find:(Ljava/lang/String;)Ljava/lang/String;',
              internalName: 'com/example/UserService#find:(Ljava/lang/String;)Ljava/lang/String;',
              selector: 'com/example/UserService#find:(Ljava/lang/String;)Ljava/lang/String;',
              kind: 'method',
              children: [],
            },
            {
              id: 'method-user-find-int',
              label: 'find(I)Ljava/lang/String;',
              qualifiedName: 'com.example.UserService#find:(I)Ljava/lang/String;',
              internalName: 'com/example/UserService#find:(I)Ljava/lang/String;',
              selector: 'com/example/UserService#find:(I)Ljava/lang/String;',
              kind: 'method',
              children: [],
            },
          ],
        },
      ],
    },
    {
      id: 'pkg-com-example-api',
      label: 'com.example.api',
      qualifiedName: 'com.example.api',
      internalName: 'com/example/api',
      selector: 'com/example/api/*',
      kind: 'package',
      children: [
        {
          id: 'class-controller',
          label: 'AuthController',
          qualifiedName: 'com.example.api.AuthController',
          internalName: 'com/example/api/AuthController',
          selector: 'com/example/api/AuthController',
          kind: 'class',
          children: [],
        },
      ],
    },
    {
      id: 'pkg-com-example-model',
      label: 'com.example.model',
      qualifiedName: 'com.example.model',
      internalName: 'com/example/model',
      selector: 'com/example/model/*',
      kind: 'package',
      children: [
        {
          id: 'class-user',
          label: 'UserRecord',
          qualifiedName: 'com.example.model.UserRecord',
          internalName: 'com/example/model/UserRecord',
          selector: 'com/example/model/UserRecord',
          kind: 'class',
          children: [],
        },
        {
          id: 'class-role',
          label: 'RoleRecord',
          qualifiedName: 'com.example.model.RoleRecord',
          internalName: 'com/example/model/RoleRecord',
          selector: 'com/example/model/RoleRecord',
          kind: 'class',
          children: [],
        },
      ],
    },
  ],
}

const emptyInspection: JarInspectionPayload = {
  jarPath: '',
  classCount: 0,
  packageCount: 0,
  nodes: [],
}

const longPathPrefix = `C:\\debug\\${'very\\long\\nested\\workspace\\path\\segment\\'.repeat(4)}`
const longInspection: JarInspectionPayload = {
  jarPath: `${longPathPrefix}demo-app.jar`,
  classCount: 1,
  packageCount: 1,
  nodes: [
    {
      id: 'pkg-long',
      label: 'com.example.very.long.package.name.for.layout',
      qualifiedName: 'com.example.very.long.package.name.for.layout',
      internalName: 'com/example/very/long/package/name/for/layout',
      selector: 'com/example/very/long/package/name/for/layout/*',
      kind: 'package',
      children: [
        {
          id: 'class-long',
          label: 'ExtremelyLongClassNameForWorkbenchLayoutPreview',
          qualifiedName: 'com.example.very.long.package.name.for.layout.ExtremelyLongClassNameForWorkbenchLayoutPreview',
          internalName: 'com/example/very/long/package/name/for/layout/ExtremelyLongClassNameForWorkbenchLayoutPreview',
          selector: 'com/example/very/long/package/name/for/layout/ExtremelyLongClassNameForWorkbenchLayoutPreview',
          kind: 'class',
          children: [],
        },
      ],
    },
  ],
}

const enumParam = (key: string, defaultValue: string, options: readonly string[], description: string): ParamSchema => ({
  key,
  type: 'enum',
  defaultValue,
  options,
  description,
  hidden: false,
})

const numberParam = (key: string, defaultValue: number, description: string): ParamSchema => ({
  key,
  type: 'number',
  defaultValue,
  options: null,
  description,
  hidden: false,
})

const stringParam = (key: string, defaultValue: string, description: string, hidden = false): ParamSchema => ({
  key,
  type: 'string',
  defaultValue,
  options: null,
  description,
  hidden,
})

const booleanParam = (key: string, defaultValue: boolean, description: string, hidden = false): ParamSchema => ({
  key,
  type: 'boolean',
  defaultValue,
  options: null,
  description,
  hidden,
})

const renamingParams: readonly ParamSchema[] = [
  enumParam('dictionaryStyle', 'sequential', ['iiliii', 'ooO0oO', 'nnmnmnm', 'sequential', 'unicode-confusable', 'custom-file'], 'Naming dictionary style.'),
  numberParam('seed', 0, 'Deterministic seed; 0 means random in this mock.'),
  numberParam('preservePackageDepth', 0, 'Leading package segments to preserve.'),
  enumParam('collisionPolicy', 'append-index', ['append-index', 'rehash', 'fail'], 'Name collision policy.'),
  stringParam('dictionaryFile', '', 'Custom dictionary path when dictionaryStyle=custom-file.'),
]

const moduleDef = (
  id: string,
  name: string,
  tagIds: readonly string[],
  params: readonly ParamSchema[],
  extras: Partial<ModuleDefinition> = {},
): ModuleDefinition => ({
  id,
  name,
  description: name,
  tagIds,
  stability: extras.stability ?? 'stable',
  targeting: extras.targeting ?? { supported: true, targetKinds: ['class'] },
  params,
  ...extras,
})

const fullCatalogSchema: EngineSchemaPayload = {
  schemaVersion: '2',
  engineVersion: 'browser-mock-full-catalog',
  tags: [
    { id: 'metadata', name: 'Metadata', description: 'Metadata cleanup and stripping.' },
    { id: 'renaming', name: 'Renaming', description: 'Symbol renaming.' },
    { id: 'encryption', name: 'Encryption', description: 'String and resource encryption.' },
    { id: 'obfuscation', name: 'Obfuscation', description: 'Control-flow and hiding transforms.' },
    { id: 'runtime-defense', name: 'Runtime Defense', description: 'Native runtime defense.' },
    { id: 'vm-protection', name: 'VM Protection', description: 'Method-level virtual machine protection.' },
    { id: 'native-kernel', name: 'Native Kernel', description: 'JNI microkernel and packer.' },
  ],
  modules: [
    moduleDef('strip-compile-debug-info', 'Strip Compile Debug Info', ['metadata'], []),
    moduleDef('strip-kotlin-metadata', 'Strip Kotlin Metadata', ['metadata'], [booleanParam('keepVisibleAnnotations', false, 'Keep visible annotations.')]),
    moduleDef('rename-classes', 'Rename Classes', ['renaming'], renamingParams, { requiresOptIn: true, risk: 'medium' }),
    moduleDef('rename-packages', 'Rename Packages', ['renaming'], [...renamingParams, booleanParam('shufflePackageSegmentCount', true, 'Change renamed package depth.')], { requiresOptIn: true, risk: 'medium' }),
    moduleDef('rename-methods', 'Rename Methods', ['renaming'], [
      ...renamingParams,
      enumParam('descriptorPadding', 'off', ['off', 'fixed', 'random'], 'Descriptor padding policy.'),
      enumParam('parameterPacking', 'off', ['off', 'object-array'], 'Parameter packing policy.'),
      booleanParam('returnSensitiveNaming', false, 'Reuse short names using final descriptors.'),
    ], { requiresOptIn: true, risk: 'medium', targeting: { supported: true, targetKinds: ['class', 'method'] } }),
    moduleDef('rename-fields', 'Rename Fields', ['renaming'], renamingParams, { requiresOptIn: true, risk: 'medium' }),
    moduleDef('string-encryption', 'String Encryption', ['encryption'], [
      enumParam('backend', 'jni', ['jni', 'java'], 'Encryption backend.'),
      enumParam('intensity', 'standard', ['standard', 'aggressive'], 'Encryption intensity.'),
      numberParam('seed', 0, 'Diversification seed.'),
    ], { requiredPassIds: ['jni-microkernel-loader'] }),
    moduleDef('resource-encryption', 'Resource Encryption', ['encryption'], [
      booleanParam('encryptClassResources', true, 'Encrypt class-adjacent resources.'),
      stringParam('includeGlob', '**/*', 'Included resource glob.'),
    ]),
    moduleDef('control-flow-flattening', 'Control Flow Flattening', ['obfuscation'], [
      enumParam('strength', 'medium', ['low', 'medium', 'high'], 'Flattening strength.'),
      numberParam('maxBlocks', 0, 'Maximum flattened blocks; 0 unlimited.'),
    ], { targeting: { supported: true, targetKinds: ['class', 'method'] } }),
    moduleDef('hide-access', 'Hide Access', ['obfuscation'], [booleanParam('rewriteInvokespecial', true, 'Rewrite invokespecial access.')]),
    moduleDef('os-anti-debug', 'OS Anti Debug', ['runtime-defense'], [
      booleanParam('detectDebugger', true, 'Detect attached debuggers.'),
      enumParam('response', 'fail-closed', ['fail-closed', 'degrade'], 'Detection response.'),
    ], { stability: 'experimental', requiredPassIds: ['jni-microkernel-loader'] }),
    moduleDef('os-anti-vm', 'OS Anti VM', ['runtime-defense'], [
      booleanParam('detectHypervisor', true, 'Detect hypervisor signals.'),
    ], { stability: 'experimental', requiredPassIds: ['jni-microkernel-loader'] }),
    moduleDef('method-virtualization', 'Method Virtualization', ['vm-protection'], [
      enumParam('methodSelection', 'critical-plus', ['safe', 'critical-auto', 'critical-plus', 'all-compatible'], 'Broad class method selection.'),
      numberParam('maxInstructions', 0, 'Max bytecode instructions per method; 0 unlimited.'),
      numberParam('maxBroadVirtualizedMethods', 0, 'Max methods from broad class rules; 0 unlimited.'),
      numberParam('seed', 0, 'Non-secret personalization input.'),
      stringParam('highValueMethods', '', 'Explicit high-value method list.', true),
      booleanParam('qpStateBoundEncoding', true, 'Fixed QP invariant.', true),
    ], {
      stability: 'experimental',
      risk: 'high',
      requiresOptIn: true,
      requiredPassIds: ['jni-microkernel-loader'],
      targeting: { supported: true, targetKinds: ['class', 'method'] },
    }),
    moduleDef('jni-microkernel-loader', 'JNI Microkernel Loader', ['native-kernel'], [
      enumParam('kernelComponents', 'loader', ['loader', 'decrypt', 'vm', 'guards', 'all'], 'Native capability subset.'),
      stringParam('targetPlatform', 'auto', 'auto, all, windows-x64, linux-x64, or comma-separated targets.'),
      booleanParam('nativeRecompilation', true, 'Rebuild and validate the bundled Rust runtime.'),
      numberParam('seed', 0, 'Deterministic native diversification seed.'),
    ], {
      stability: 'experimental',
      risk: 'high',
      requiresOptIn: true,
      requiresAnyPassIds: ['os-anti-debug', 'os-anti-vm', 'method-virtualization', 'string-encryption'],
    }),
    moduleDef('nativeshroud', 'NativeShroud Packer', ['native-kernel'], [
      enumParam('profile', 'max', ['fast', 'standard', 'max'], 'NativeShroud pack profile.'),
      stringParam('cliPath', '', 'Absolute path to nativeshroud.exe.'),
    ], { stability: 'experimental', risk: 'high', requiresOptIn: true, requiredPassIds: ['jni-microkernel-loader'] }),
  ],
  compatibility: [
    { passIds: ['rename-classes', 'rename-packages'], severity: 'soft', description: 'Package and class renaming both rewrite observed names.' },
  ],
  orderingConstraints: [
    { before: 'strip-compile-debug-info', after: 'rename-classes', reason: 'Strip metadata before renaming.', hard: false },
    { before: 'jni-microkernel-loader', after: 'method-virtualization', reason: 'Native loader must precede VM lowering.', hard: true },
  ],
  defaultPipeline: ['strip-compile-debug-info', 'rename-classes', 'string-encryption'],
}

const buildLargeTree = (): JarInspectionPayload => {
  const packages: ClassTreeNode[] = []
  let classCount = 0
  for (let packageIndex = 0; packageIndex < 12; packageIndex += 1) {
    const children: ClassTreeNode[] = []
    for (let classIndex = 0; classIndex < 8; classIndex += 1) {
      classCount += 1
      const methods: ClassTreeNode[] = []
      for (let methodIndex = 0; methodIndex < 4; methodIndex += 1) {
        methods.push({
          id: `method-${packageIndex}-${classIndex}-${methodIndex}`,
          label: `m${methodIndex}()V`,
          qualifiedName: `pkg${packageIndex}.C${classIndex}#m${methodIndex}:()V`,
          internalName: `pkg${packageIndex}/C${classIndex}#m${methodIndex}:()V`,
          selector: `pkg${packageIndex}/C${classIndex}#m${methodIndex}:()V`,
          kind: 'method',
          children: [],
        })
      }
      children.push({
        id: `class-${packageIndex}-${classIndex}`,
        label: `C${classIndex}`,
        qualifiedName: `pkg${packageIndex}.C${classIndex}`,
        internalName: `pkg${packageIndex}/C${classIndex}`,
        selector: `pkg${packageIndex}/C${classIndex}`,
        kind: 'class',
        children: methods,
      })
    }
    packages.push({
      id: `pkg-${packageIndex}`,
      label: `pkg${packageIndex}`,
      qualifiedName: `pkg${packageIndex}`,
      internalName: `pkg${packageIndex}`,
      selector: `pkg${packageIndex}/*`,
      kind: 'package',
      children,
    })
  }

  return {
    jarPath: 'C:\\debug\\large-tree.jar',
    classCount,
    packageCount: packages.length,
    nodes: packages,
  }
}

const progressDoneSteps: readonly MockEngineEvent[] = [
  { type: 'log', level: 'info', message: '浏览器调试模式已启动', progress: 0, outPath: null },
  { type: 'progress', level: 'info', message: '浏览器调试进度 20%', progress: 20, outPath: null },
  { type: 'progress', level: 'info', message: '浏览器调试进度 45%', progress: 45, outPath: null },
  { type: 'progress', level: 'info', message: '浏览器调试进度 70%', progress: 70, outPath: null },
  { type: 'progress', level: 'info', message: '浏览器调试进度 90%', progress: 90, outPath: null },
  { type: 'done', level: 'success', message: '浏览器调试模式已完成模拟输出。', progress: 100, outPath: null },
]

const streamSteps: readonly MockEngineEvent[] = Array.from({ length: 24 }, (_, index) => ({
  type: index === 23 ? 'done' : 'log',
  level: index === 23 ? 'success' : 'info',
  message: index === 23 ? '浏览器调试模式已完成模拟输出。' : `stream-line-${String(index + 1).padStart(2, '0')}`,
  progress: index === 23 ? 100 : Math.min(95, index * 4),
  outPath: null,
}))

export const MOCK_SCENARIO_IDS: readonly MockScenarioId[] = [
  'default',
  'empty',
  'done',
  'error',
  'canceled',
  'long-paths',
  'large-tree',
  'stream',
  'full-catalog',
]

export const parseMockScenarioId = (raw: string | null | undefined): MockScenarioId => {
  const value = (raw ?? '').trim().toLowerCase()
  if ((MOCK_SCENARIO_IDS as readonly string[]).includes(value)) {
    return value as MockScenarioId
  }
  return 'default'
}

export const resolveMockScenario = (id: MockScenarioId): MockScenario => {
  const basePaths = {
    inputJarPath: defaultInspection.jarPath,
    outputJarPath: 'C:\\debug\\demo-app-shrouded.jar',
    configPath: 'C:\\debug\\javashroud-config.toml',
  }

  switch (id) {
    case 'empty':
      return {
        id,
        outcome: 'progress-done',
        inputJarPath: '',
        outputJarPath: '',
        configPath: basePaths.configPath,
        schema: defaultSchema,
        inspection: emptyInspection,
        runSteps: progressDoneSteps,
      }
    case 'done':
      return {
        id,
        outcome: 'done',
        ...basePaths,
        schema: defaultSchema,
        inspection: defaultInspection,
        runSteps: [
          { type: 'done', level: 'success', message: '浏览器调试模式已完成模拟输出。', progress: 100, outPath: basePaths.outputJarPath },
        ],
      }
    case 'error':
      return {
        id,
        outcome: 'error',
        ...basePaths,
        schema: defaultSchema,
        inspection: defaultInspection,
        runSteps: [
          { type: 'log', level: 'info', message: '浏览器调试模式已启动', progress: 0, outPath: null },
          { type: 'error', level: 'error', message: '浏览器调试模式模拟失败。', progress: null, outPath: null },
        ],
      }
    case 'canceled':
      return {
        id,
        outcome: 'canceled',
        ...basePaths,
        schema: defaultSchema,
        inspection: defaultInspection,
        runSteps: [
          { type: 'log', level: 'info', message: '浏览器调试模式已启动', progress: 0, outPath: null },
          { type: 'canceled', level: 'warn', message: '浏览器调试模式已取消当前任务。', progress: null, outPath: null },
        ],
      }
    case 'long-paths':
      return {
        id,
        outcome: 'progress-done',
        inputJarPath: longInspection.jarPath,
        outputJarPath: `${longPathPrefix}demo-app-shrouded.jar`,
        configPath: `${longPathPrefix}javashroud-config.toml`,
        schema: defaultSchema,
        inspection: longInspection,
        runSteps: progressDoneSteps,
      }
    case 'large-tree':
      return {
        id,
        outcome: 'progress-done',
        inputJarPath: 'C:\\debug\\large-tree.jar',
        outputJarPath: 'C:\\debug\\large-tree-shrouded.jar',
        configPath: basePaths.configPath,
        schema: defaultSchema,
        inspection: buildLargeTree(),
        runSteps: progressDoneSteps,
      }
    case 'stream':
      return {
        id,
        outcome: 'stream',
        ...basePaths,
        schema: defaultSchema,
        inspection: defaultInspection,
        runSteps: streamSteps,
      }
    case 'full-catalog':
      return {
        id,
        outcome: 'progress-done',
        inputJarPath: 'C:\\debug\\full-catalog.jar',
        outputJarPath: 'C:\\debug\\full-catalog-shrouded.jar',
        configPath: basePaths.configPath,
        schema: fullCatalogSchema,
        inspection: buildLargeTree(),
        runSteps: progressDoneSteps,
      }
    default:
      return {
        id: 'default',
        outcome: 'progress-done',
        ...basePaths,
        schema: defaultSchema,
        inspection: defaultInspection,
        runSteps: progressDoneSteps,
      }
  }
}

export const defaultConfigToml = (scenario: MockScenario): string => [
  '[meta]',
  'format = "javashroud-workbench"',
  'version = 1',
  '',
  '[input]',
  `inputJarPath = ${JSON.stringify(scenario.inputJarPath)}`,
  `outputJarPath = ${JSON.stringify(scenario.outputJarPath)}`,
  '',
  '[[passes]]',
  'id = "strip-compile-debug-info"',
  'enabled = true',
  '',
  '[passes.params]',
  '',
  '[[passes]]',
  'id = "rename-classes"',
  'enabled = true',
  '',
  '[passes.params]',
  'dictionary = "ascii"',
  '',
  '[[rules]]',
  'target = "com/example/api/*"',
  'action = "exclude"',
  '',
].join('\n')
