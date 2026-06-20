import { parseEngineSchema } from './capability-parser.ts'
import { buildPassItemsFromSchema } from './pass-catalog.ts'
import { hasEnabledSoftCompatibilityConflict, resolvePassCompatibility } from './pass-compatibility.ts'

const assert = (condition: boolean, message: string): void => {
  if (!condition) {
    throw new Error(message)
  }
}

const baseSchema = {
  schemaVersion: '2',
  engineVersion: 'check-engine',
  vbcVersion: 'VBC4-dev',
  tags: [
    {
      id: 'obfuscation',
      name: 'Obfuscation',
      description: 'Obfuscation passes',
    },
  ],
  modules: [
    {
      id: 'sample-pass',
      name: 'Sample pass',
      description: 'Sample pass',
      tagIds: ['obfuscation'],
      stability: 'stable',
      compatibilityNotes: 'Use only the current VBC4 native VM target.',
      defaultEnabled: false,
      params: [
        {
          key: 'mode',
          type: 'enum',
          defaultValue: 'safe',
          options: ['safe', 'fast'],
          description: 'Mode',
        },
        {
          key: 'enabled',
          type: 'boolean',
          defaultValue: true,
          description: 'Enabled',
        },
        {
          key: 'salt',
          type: 'number',
          defaultValue: 42,
          description: 'Salt',
          hidden: true,
        },
      ],
    },
  ],
  compatibility: [],
  orderingConstraints: [],
  defaultPipeline: ['sample-pass'],
}

const expectParseError = (schema: unknown, expectedMessagePart: string): void => {
  try {
    parseEngineSchema(schema)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    assert(message.includes(expectedMessagePart), `expected parse error to include "${expectedMessagePart}", actual=${message}`)
    return
  }

  throw new Error(`expected schema parse to fail with "${expectedMessagePart}"`)
}

const parsedSchema = parseEngineSchema(baseSchema)
assert(parsedSchema.modules[0]?.params[0]?.defaultValue === 'safe', 'expected valid enum default to be preserved')
assert(parsedSchema.modules[0]?.params[2]?.hidden === true, 'expected hidden param flag to be preserved')
assert(parsedSchema.modules[0]?.compatibilityNotes === 'Use only the current VBC4 native VM target.', 'expected compatibility notes to be preserved')
assert(buildPassItemsFromSchema(parsedSchema)[0]?.params.salt === 42, 'expected hidden param default to be preserved in pass params')
assert(buildPassItemsFromSchema(parsedSchema)[0]?.compatibilityNotes === 'Use only the current VBC4 native VM target.', 'expected compatibility notes to be copied to pass items')
assert(!buildPassItemsFromSchema(parsedSchema)[0]?.paramSchemas.some((paramSchema) => paramSchema.key === 'salt'), 'expected hidden params to be omitted from visible param schemas')
assert(buildPassItemsFromSchema(parsedSchema)[0]?.paramSchemas.some((paramSchema) => paramSchema.key === 'enabled'), 'expected visible params to be included in visible param schemas')
assert(parsedSchema.defaultPipeline[0] === 'sample-pass', 'expected defaultPipeline to be preserved')

expectParseError(
  {
    ...baseSchema,
    schemaVersion: 'check-v1',
  },
  'schemaVersion 不受支持',
)

expectParseError(
  {
    ...baseSchema,
    tags: [
      baseSchema.tags[0],
      {
        ...baseSchema.tags[0],
        name: 'Duplicate obfuscation tag',
      },
    ],
  },
  'tags[1].id 重复',
)

expectParseError(
  {
    ...baseSchema,
    modules: [
      baseSchema.modules[0],
      {
        ...baseSchema.modules[0],
        name: 'Duplicate sample pass',
      },
    ],
  },
  'modules[1].id 重复',
)

expectParseError(
  {
    ...baseSchema,
    modules: [
      {
        ...baseSchema.modules[0],
        tagIds: ['obfuscation', 'obfuscation'],
      },
    ],
  },
  'tagIds[1] 重复',
)

expectParseError(
  {
    ...baseSchema,
    modules: [
      {
        ...baseSchema.modules[0],
        params: [
          baseSchema.modules[0].params[0],
          {
            ...baseSchema.modules[0].params[0],
            description: 'Duplicate mode param',
          },
        ],
      },
    ],
  },
  'params[1].key 重复',
)

const parsedPasses = buildPassItemsFromSchema(parsedSchema)
assert(parsedPasses[0]?.enabled === true, 'expected defaultPipeline to enable listed pass even when module defaultEnabled is false')

const dependencySchema = parseEngineSchema({
  ...baseSchema,
  modules: [
    {
      ...baseSchema.modules[0],
      id: 'jni-microkernel-loader',
      defaultEnabled: false,
      requiresAnyPassIds: ['anti-instrumentation'],
      params: [],
    },
    {
      ...baseSchema.modules[0],
      id: 'anti-instrumentation',
      requiredPassIds: ['jni-microkernel-loader'],
      defaultEnabled: false,
      params: [],
    },
  ],
  defaultPipeline: ['anti-instrumentation'],
})
const dependencyPasses = buildPassItemsFromSchema(dependencySchema)
assert(dependencyPasses.find((passItem) => passItem.id === 'jni-microkernel-loader')?.enabled === true, 'expected requiredPassIds dependency to auto-enable jni-microkernel-loader')

const singleJniSchema = parseEngineSchema({
  ...baseSchema,
  modules: [
    {
      ...baseSchema.modules[0],
      id: 'jni-microkernel-loader',
      defaultEnabled: true,
      requiresAnyPassIds: ['sample-pass'],
      params: [],
    },
    {
      ...baseSchema.modules[0],
      defaultEnabled: false,
      params: [],
    },
  ],
  defaultPipeline: ['jni-microkernel-loader'],
})
const singleJniPasses = buildPassItemsFromSchema(singleJniSchema)
assert(singleJniPasses.find((passItem) => passItem.id === 'jni-microkernel-loader')?.enabled === false, 'expected standalone requiresAnyPassIds pass to be disabled')

const anchoredJniSchema = parseEngineSchema({
  ...baseSchema,
  modules: [
    {
      ...baseSchema.modules[0],
      id: 'jni-microkernel-loader',
      defaultEnabled: false,
      requiresAnyPassIds: ['sample-pass'],
      params: [],
    },
    {
      ...baseSchema.modules[0],
      defaultEnabled: true,
      requiredPassIds: ['jni-microkernel-loader'],
      params: [],
    },
  ],
  defaultPipeline: ['sample-pass'],
})
const anchoredJniPasses = buildPassItemsFromSchema(anchoredJniSchema)
assert(anchoredJniPasses.find((passItem) => passItem.id === 'jni-microkernel-loader')?.enabled === true, 'expected requiresAnyPassIds pass to stay enabled when its anchor is enabled')

expectParseError(
  {
    ...baseSchema,
    modules: [
      {
        ...baseSchema.modules[0],
        params: [
          {
            key: 'mode',
            type: 'enum',
            defaultValue: 'unsupported',
            options: ['safe', 'fast'],
            description: 'Mode',
          },
        ],
      },
    ],
  },
  'defaultValue 必须包含在 enum options 中',
)

expectParseError(
  {
    ...baseSchema,
    modules: [
      {
        ...baseSchema.modules[0],
        params: [
          {
            key: 'enabled',
            type: 'boolean',
            defaultValue: 'true',
            description: 'Enabled',
          },
        ],
      },
    ],
  },
  'defaultValue 必须是布尔值',
)

expectParseError(
  {
    ...baseSchema,
    modules: [
      {
        ...baseSchema.modules[0],
        params: [
          {
            key: 'salt',
            type: 'number',
            defaultValue: '42',
            description: 'Salt',
          },
        ],
      },
    ],
  },
  'defaultValue 必须是数字',
)

expectParseError(
  {
    ...baseSchema,
    modules: [
      {
        ...baseSchema.modules[0],
        params: [
          {
            key: 'salt',
            type: 'number',
            defaultValue: 42,
            hidden: 'yes',
            description: 'Salt',
          },
        ],
      },
    ],
  },
  'params[0].hidden 必须是布尔值',
)

expectParseError(
  {
    ...baseSchema,
    compatibility: [
      {
        passIds: ['sample-pass', 'missing-pass'],
        severity: 'hard',
        description: 'Missing pass conflict.',
      },
    ],
  },
  'compatibility[0].passIds[1] 未声明',
)

expectParseError(
  {
    ...baseSchema,
    compatibility: [
      {
        passIds: ['sample-pass', 'sample-pass'],
        severity: 'hard',
        description: 'Duplicate pass conflict.',
      },
    ],
  },
  'compatibility[0].passIds[1] 重复',
)

expectParseError(
  {
    ...baseSchema,
    orderingConstraints: [
      {
        before: 'sample-pass',
        after: 'missing-pass',
        reason: 'Missing pass ordering.',
      },
    ],
  },
  'orderingConstraints[0].after 未声明',
)

expectParseError(
  {
    ...baseSchema,
    modules: [
      {
        ...baseSchema.modules[0],
        requiredPassIds: ['missing-pass'],
      },
    ],
  },
  'requiredPassIds[0] 未声明',
)

expectParseError(
  {
    ...baseSchema,
    modules: [
      {
        ...baseSchema.modules[0],
        requiredPassIds: ['sample-pass'],
      },
    ],
  },
  'requiredPassIds[0] 不能引用自身',
)

expectParseError(
  {
    ...baseSchema,
    modules: [
      {
        ...baseSchema.modules[0],
        id: 'sample-dependency',
        name: 'Sample dependency',
        defaultEnabled: false,
        params: [],
      },
      {
        ...baseSchema.modules[0],
        requiredPassIds: ['sample-dependency', 'sample-dependency'],
      },
    ],
  },
  'requiredPassIds[1] 重复',
)

expectParseError(
  {
    ...baseSchema,
    modules: [
      {
        ...baseSchema.modules[0],
        requiresAnyPassIds: ['missing-pass'],
      },
    ],
  },
  'requiresAnyPassIds[0] 未声明',
)

expectParseError(
  {
    ...baseSchema,
    modules: [
      {
        ...baseSchema.modules[0],
        requiresAnyPassIds: ['sample-pass'],
      },
    ],
  },
  'requiresAnyPassIds[0] 不能引用自身',
)

expectParseError(
  {
    ...baseSchema,
    modules: [
      {
        ...baseSchema.modules[0],
        id: 'sample-anchor',
        name: 'Sample anchor',
        defaultEnabled: false,
        params: [],
      },
      {
        ...baseSchema.modules[0],
        requiresAnyPassIds: ['sample-anchor', 'sample-anchor'],
      },
    ],
  },
  'requiresAnyPassIds[1] 重复',
)

const softCompatibilitySchema = parseEngineSchema({
  ...baseSchema,
  modules: [
    {
      ...baseSchema.modules[0],
      id: 'soft-a',
      defaultEnabled: false,
      params: [],
    },
    {
      ...baseSchema.modules[0],
      id: 'soft-b',
      defaultEnabled: false,
      params: [],
    },
  ],
  compatibility: [
    {
      passIds: ['soft-a', 'soft-b'],
      severity: 'soft',
      description: 'Soft overlap.',
    },
  ],
  defaultPipeline: ['soft-a', 'soft-b'],
})
const softCompatibilityPasses = resolvePassCompatibility(buildPassItemsFromSchema(softCompatibilitySchema), softCompatibilitySchema.compatibility)
assert(softCompatibilityPasses.every((passItem) => passItem.enabled), 'expected soft compatibility rules to preserve enabled passes')
assert(hasEnabledSoftCompatibilityConflict(softCompatibilityPasses, softCompatibilitySchema.compatibility), 'expected enabled soft compatibility conflict to require redundant allowance')

const hardCompatibilitySchema = parseEngineSchema({
  ...softCompatibilitySchema,
  compatibility: [
    {
      passIds: ['soft-a', 'soft-b'],
      severity: 'hard',
      description: 'Hard conflict.',
    },
  ],
})
const hardCompatibilityPasses = resolvePassCompatibility(buildPassItemsFromSchema(hardCompatibilitySchema), hardCompatibilitySchema.compatibility)
assert(hardCompatibilityPasses.filter((passItem) => passItem.enabled).length === 1, 'expected hard compatibility rules to keep only one enabled pass')

// 引擎实际输出的 TOML：为 null 的 options/defaultValue 被省略；number 参数无 options。
// 经 parseTomlDocument -> parseEngineSchema 文本往返，确认不再误判 options 必须是字符串数组。
const tomlSchema = [
  "schemaVersion = '2'",
  "engineVersion = 'check-engine'",
  "vbcVersion = 'VBC4-dev'",
  "tags = [{id = 'runtime-defense', name = 'Runtime Defense', description = 'runtime defense', order = 80}]",
  "modules = [{id = 'anti-symbolic-execution', name = 'Anti Symbolic', description = 'adds runtime traps', tagIds = ['runtime-defense'], params = [{key = 'seed', type = 'number', description = 'deterministic seed', hidden = false}], stability = 'experimental'}]",
  'compatibility = []',
  "defaultPipeline = ['anti-symbolic-execution']",
  'orderingConstraints = []',
].join('\n')
const tomlParsedSchema = parseEngineSchema(tomlSchema)
assert(tomlParsedSchema.modules[0]?.params[0]?.key === 'seed', 'expected TOML number param to parse')
assert(tomlParsedSchema.modules[0]?.params[0]?.options === null, 'expected omitted options to parse as null')
assert(tomlParsedSchema.modules[0]?.params[0]?.defaultValue === null, 'expected omitted defaultValue to parse as null')

// 防御加固：即使引擎回归把 null 写成空字符串 ''，前端也应按缺省处理而非抛错。
const emptyStringSchema = {
  ...baseSchema,
  modules: [
    {
      ...baseSchema.modules[0],
      params: [
        {
          key: 'seed',
          type: 'number',
          defaultValue: '',
          options: '',
          description: 'deterministic seed',
        },
      ],
    },
  ],
}
const emptyStringParsed = parseEngineSchema(emptyStringSchema)
assert(emptyStringParsed.modules[0]?.params[0]?.options === null, 'expected empty-string options to parse as null')
assert(emptyStringParsed.modules[0]?.params[0]?.defaultValue === null, 'expected empty-string defaultValue to parse as null')

console.log('capability-parser checks passed')
