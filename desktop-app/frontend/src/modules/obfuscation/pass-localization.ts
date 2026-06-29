import type { ParamSchema, PassItem } from './types'

export type DisplayLanguage = 'zh' | 'en'

interface LocalizedText {
  readonly zh: string
  readonly en: string
}

interface LocalizedPassCopy {
  readonly name: LocalizedText
  readonly description: LocalizedText
  readonly params?: Readonly<Record<string, LocalizedText>>
}

const text = (zh: string, en: string): LocalizedText => ({ zh, en })

const categoryLabels: Readonly<Record<string, LocalizedText>> = {
  all: text('全部', 'All'),
  'metadata-cleanup': text('元数据清理', 'Metadata cleanup'),
  'symbol-renaming': text('符号重命名', 'Symbol renaming'),
  'member-hiding': text('成员隐藏', 'Member hiding'),
  'string-protection': text('字符串与载荷保护', 'String and payload protection'),
  'helper-loader': text('辅助运行时与加载器', 'Runtime helpers and loaders'),
  'control-flow': text('控制流与调用伪装', 'Control flow and call camouflage'),
  'decompiler-traps': text('反编译干扰', 'Decompiler disruption'),
  'runtime-defense': text('运行时防御', 'Runtime defense'),
  virtualization: text('虚拟化保护', 'Virtualization protection'),
  'native-kernel': text('Native 内核', 'Native kernel'),
  metadata: text('元数据', 'Metadata'),
  renaming: text('重命名', 'Renaming'),
  encryption: text('加密', 'Encryption'),
  obfuscation: text('结构混淆', 'Structure'),
  hiding: text('隐藏', 'Hiding'),
  aggressive: text('激进', 'Aggressive'),
  unknown: text('其他', 'Other'),
}

const riskLabels: Readonly<Record<PassItem['risk'], LocalizedText>> = {
  low: text('低风险', 'Low risk'),
  medium: text('中风险', 'Medium risk'),
  high: text('高风险', 'High risk'),
}

export const uiText: Readonly<Record<string, LocalizedText>> = {
  home: text('首页', 'Home'),
  inputOutput: text('输入与输出', 'Input and output'),
  passes: text('功能', 'Passes'),
  passFeatures: text('混淆功能', 'Obfuscation features'),
  rules: text('排除规则', 'Rules'),
  classScope: text('类树范围', 'Class scope'),
  logs: text('日志', 'Logs'),
  eventStream: text('事件流', 'Event stream'),
  about: text('关于', 'About'),
  projectLicense: text('项目与协议', 'Project and license'),
  enabledPasses: text('启用 Pass', 'Enabled passes'),
  excludedRules: text('排除规则', 'Excluded rules'),
  start: text('开始混淆', 'Start obfuscation'),
  cancel: text('取消任务', 'Cancel task'),
  importConfig: text('导入配置', 'Import config'),
  exportConfig: text('导出配置', 'Export config'),
  windowControls: text('窗口与语言控制', 'Window and language controls'),
  switchTo: text('切换到', 'Switch to'),
  appNav: text('JavaShroud 工作台导航', 'JavaShroud workbench navigation'),
  workbenchSections: text('工作台分区', 'Workbench sections'),
  configSummary: text('当前配置摘要', 'Current configuration summary'),
  projectInfo: text('项目信息', 'Project information'),
  minimize: text('最小化窗口', 'Minimize window'),
  restore: text('还原窗口', 'Restore window'),
  maximize: text('最大化窗口', 'Maximize window'),
  close: text('关闭窗口', 'Close window'),
  aboutApp: text('关于应用', 'About app'),
  aboutDescription: text('一款基于 GPL-3.0 开源协议发布的 JVM 字节码混淆器。', 'A JVM bytecode obfuscator released under the GPL-3.0 open-source license.'),
  aboutStack: text('核心混淆引擎基于 Kotlin，桌面宿主采用 Go/Wails，前端由 Vue 3 提供可视化配置与运行反馈。', 'The core engine is built with Kotlin, the desktop host uses Go/Wails, and the Vue 3 frontend provides visual configuration and run feedback.'),
  openSourceLicense: text('开源协议', 'Open-source license'),
  licenseDescription: text('JavaShroud 基于 GNU General Public License v3.0 发布，允许使用、研究、修改与分发。', 'JavaShroud is released under the GNU General Public License v3.0, allowing use, study, modification, and distribution.'),
  licenseObligation: text('如果分发修改版或衍生版本，需要在同一协议下提供对应源代码，并保留必要的版权与协议声明。', 'If you distribute modified or derived versions, the corresponding source code must be provided under the same license with required copyright and license notices.'),
  viewGpl: text('查看 GPL-3.0 协议', 'View GPL-3.0 license'),
}

export const t = (key: keyof typeof uiText, language: DisplayLanguage): string => pick(uiText[key], language)

const commonParamDescriptions: Readonly<Record<string, LocalizedText>> = {
  algebraicFamily: text('代数谓词族：决定生成不透明谓词时采用哪类恒等式，用来改变假分支的形态和分析成本。', 'Algebraic predicate family: chooses which identity family builds opaque predicates, changing fake branch shape and analysis cost.'),
  algorithm: text('兼容算法：旧版字符串算法选项；新配置建议优先使用“加密策略”。', 'Legacy algorithm: older string algorithm selector. Prefer strategy for new configurations.'),
  bindingSource: text('环境绑定来源：指定密钥依赖哪些环境特征，例如硬件指纹、JVM 参数或证书指纹。', 'Binding source: defines which environment signals keys depend on, such as hardware identity, JVM parameters, or certificate fingerprints.'),
  collisionPolicy: text('命名冲突策略：新名称重复时选择追加序号、重新生成，或直接报错停止。', 'Collision policy: chooses whether duplicate names receive a suffix, are regenerated, or fail the run.'),
  count: text('注入数量：控制每个插入点加入多少条垃圾指令；值越高体积和性能风险越高。', 'Injection count: controls how many junk instructions are added at each site. Higher values increase size and performance risk.'),
  codeSectionEncryption: text('代码段扰动：通过重编译期源码和编译参数变化制造 native 二进制差异。', 'Code-section diversity: varies native binaries through recompilation-time source and compiler changes.'),
  density: text('扰动密度：控制每个方法中插入多少分发节点、异常边或噪声块。值越高混淆越强，字节码也越膨胀。', 'Density: controls how many dispatcher nodes, exception edges, or noise blocks are inserted per method. Higher values strengthen obfuscation and grow bytecode.'),
  depth: text('嵌套深度：控制 try-finally 或包装层数。越深越难读，也越容易产生体积膨胀。', 'Depth: controls try-finally or wrapper nesting. Deeper nesting is harder to read and can grow bytecode quickly.'),
  detectionLevel: text('检测级别：控制反插桩检查的强度，仅保留 standard 与 aggressive 两档。', 'Detection level: controls anti-instrumentation intensity with only standard and aggressive modes.'),
  detectionMode: text('检测模式：选择被动检查还是主动持续观察 agent 或运行时状态变化。', 'Detection mode: chooses passive checks or active monitoring of agent and runtime state changes.'),
  dictionaryFile: text('自定义字典文件：每行一个候选名称，仅在字典风格选择自定义文件时使用。', 'Custom dictionary file: one candidate name per line, used when dictionary style is set to custom file.'),
  dictionaryStyle: text('命名字典风格：决定生成新名称的字符形态，例如顺序编号、相似字符或自定义词库。', 'Naming dictionary style: controls generated name appearance, such as sequential counters, confusable characters, or a custom dictionary.'),
  dispatchMode: text('分发模式：选择控制流重组时的跳转结构，例如条件链、查找表或混合 switch。', 'Dispatch mode: selects the jump structure used for rewritten control flow, such as if chains, lookup tables, or hybrid switch dispatch.'),
  encryptionStrategy: text('加密策略：决定类、方法体或载荷使用的加密算法与包装方式，影响强度、依赖和启动成本。', 'Encryption strategy: selects the algorithm and wrapping style for classes, method bodies, or payloads, affecting strength, dependencies, and startup cost.'),
  frequency: text('插入频率：每隔多少条指令插入一个不透明谓词或噪声逻辑；值越小覆盖越密。', 'Insertion frequency: inserts an opaque predicate or noise block every N instructions. Smaller values mean denser coverage.'),
  handlerComplexity: text('处理器复杂度：控制虚假异常处理器或分发块中放入多少噪声逻辑。', 'Handler complexity: controls how much noise logic is placed inside bogus exception handlers or dispatcher blocks.'),
  kernelComponents: text('内核组件集：选择 JNI 微内核携带哪些能力，例如加载器、解密器或调度桥。', 'Kernel components: selects which JNI microkernel capabilities ship, such as loader, decryptor, or dispatch bridge.'),
  keyMode: text('密钥作用域：选择密钥按类、按方法还是全局复用；粒度越细，泄露影响面越小。', 'Key scope: chooses per-class, per-method, or global key reuse. Finer scope reduces blast radius after disclosure.'),
  layerMode: text('解密层级：选择单层或多层解密 stub；多层更难逆向，但会增加调用和初始化成本。', 'Layer mode: chooses single or multi-layer decrypt stubs. More layers are harder to reverse but add call and initialization cost.'),
  lengthThreshold: text('长度阈值：按长度过滤时，只有达到该长度的字符串才会参与加密。', 'Length threshold: when length filtering is active, only strings at or above this length are encrypted.'),
  migrationStrategy: text('迁移策略：选择常量或敏感值迁移到 condy、运行时构造器，或两者混合。', 'Migration strategy: chooses whether constants or sensitive values move to condy, runtime builders, or a hybrid of both.'),
  methodSelection: text('方法选择策略：控制广义类规则虚拟化哪些方法，可保守选择、自动识别关键方法或强制覆盖所有 VM 兼容方法。', 'Method selection strategy: controls which methods broad class rules virtualize, from conservative selection to critical auto-detection or all VM-compatible methods.'),
  mode: text('工作模式：控制该 pass 的主要行为分支，例如自动排序、仅校验、拒绝冲突或延迟解密。', 'Mode: controls the main behavior branch for this pass, such as auto-sort, validate-only, reject-conflicts, or delayed decryption.'),
  nativeProtectionLevel: text('native 反逆向保护级别：standard 包含反调试与反反汇编扰动；aggressive 额外启用反虚拟机检测和完整性自校验。', 'Native anti-reverse protection level: standard includes anti-debug and anti-disassembly diversity; aggressive adds anti-VM detection and integrity self-check.'),
  nativeRecompilation: text('混淆时编译：强制使用 Zig 从内置 C 源码编译 native 微内核；优先使用本机 Zig，缺失时下载到用户目录 .javashroud/zig（Windows 形如 C:\\Users\\<用户名>\\.javashroud\\zig）。', 'Compile during obfuscation: requires Zig to build the native microkernel from bundled C sources; uses local Zig first and downloads under the user .javashroud/zig directory when missing.'),
  pattern: text('插入模式：选择噪声块或分发块使用的字节码形态，例如死分支、算术空操作或字段噪声。', 'Insertion pattern: selects the bytecode shape for noise or dispatcher blocks, such as dead branches, arithmetic no-ops, or field noise.'),
  preservePackageDepth: text('保留包层级：重命名包路径时保留前几层，兼顾反射、资源路径和包级约定。', 'Preserve package depth: keeps the first N package segments during package renaming for reflection, resource paths, or package conventions.'),
  protectionLevel: text('防护等级：控制内存转储、heap dump 或密钥材料保护深度。', 'Protection level: controls the depth of memory-dump, heap-dump, or key-material protection.'),
  response: text('响应策略：检测到风险环境后选择记录、降级、切换路径或拒绝运行。', 'Response strategy: chooses whether a risky environment is logged, degraded, switched to another path, or refused.'),
  rotationStrategy: text('轮换策略：决定调用点或目标绑定按 epoch、计数器、线程局部或随机方式切换。', 'Rotation strategy: controls whether call sites or target bindings rotate by epoch, counter, thread-local state, or randomness.'),
  scope: text('作用范围：选择哪些字符串、类或载荷进入该 pass 的处理范围。', 'Scope: selects which strings, classes, or payloads are processed by this pass.'),
  seed: text('种子：作为非秘密个性化输入；具体 pass 是否可复现以能力说明为准，VMBC/NBVM 输出始终包含每产物随机材料。', 'Seed: non-secret personalization input. Reproducibility depends on the pass; VMBC/NBVM output always includes per-artifact random material.'),
  strategy: text('字符串加密策略：选择 AES、RSA、混合或逐字符串随机策略。', 'String encryption strategy: chooses AES, RSA, hybrid, or per-string random strategy.'),
  targetPlatform: text('目标平台：选择原生微内核产物面向的系统和架构。', 'Target platform: selects the operating system and architecture for the native microkernel artifact.'),
  trapDensity: text('陷阱密度：控制符号执行陷阱的注入频率；越密越难约束求解，也越重。', 'Trap density: controls symbolic-execution trap frequency. Denser traps are harder to solve and heavier to run.'),
  virtualizationLevel: text('虚拟化级别：选择只保护关键路径还是更激进地虚拟化语义。', 'Virtualization level: chooses whether only key paths or more aggressive semantics are virtualized.'),
}

const optionLabels: Readonly<Record<string, LocalizedText>> = {
  active: text('主动', 'Active'),
  'aes-128': text('AES-128', 'AES-128'),
  'aes-256': text('AES-256', 'AES-256'),
  aggressive: text('激进', 'Aggressive'),
  all: text('随机混用', 'All / random mix'),
  'all-compatible': text('全部兼容方法', 'All compatible'),
  'all-strings': text('全部字符串', 'All strings'),
  annotated: text('仅注解标记', 'Annotated only'),
  annotation: text('注解', 'Annotation'),
  'append-index': text('追加序号', 'Append index'),
  'arithmetic-chain': text('算术链', 'Arithmetic chain'),
  'arithmetic-nop': text('算术空操作', 'Arithmetic no-op'),
  attribute: text('类属性', 'Class attribute'),
  auto: text('自动', 'Auto'),
  'auto-sort': text('自动排序', 'Auto sort'),
  basic: text('基础', 'Basic'),
  'bitwise-identity': text('位运算恒等式', 'Bitwise identity'),
  caesar: text('凯撒位移', 'Caesar'),
  'call-stack-depth': text('调用栈深度', 'Call stack depth'),
  'certificate-fingerprint': text('证书指纹', 'Certificate fingerprint'),
  chain: text('链式', 'Chain'),
  combined: text('组合', 'Combined'),
  'complexity-threshold': text('复杂度阈值', 'Complexity threshold'),
  'critical-auto': text('关键方法自动识别', 'Critical auto'),
  condy: text('ConstantDynamic', 'ConstantDynamic'),
  conservative: text('保守', 'Conservative'),
  counter: text('计数器', 'Counter'),
  'custom-file': text('自定义字典', 'Custom file'),
  'dead-branch': text('不可达分支', 'Dead branch'),
  decryptor: text('解密器', 'Decryptor'),
  degrade: text('降级运行', 'Degrade'),
  'dynamic-proxy': text('动态代理', 'Dynamic proxy'),
  'encrypted-table': text('加密分发表', 'Encrypted table'),
  'entry-exit': text('入口/出口块', 'Entry/exit blocks'),
  epoch: text('Epoch', 'Epoch'),
  fail: text('报错停止', 'Fail'),
  'field-noise': text('字段读写噪声', 'Field noise'),
  'field-scramble': text('字段扰乱', 'Field scramble'),
  'field-write': text('写入合成字段', 'Synthetic field write'),
  full: text('完整', 'Full'),
  global: text('全局', 'Global'),
  'global-registry': text('共享全局注册表', 'Global registry'),
  'hardware-id': text('硬件指纹', 'Hardware ID'),
  'hidden-class': text('隐藏类', 'Hidden class'),
  'hidden-class-redirect': text('隐藏类重定向', 'Hidden-class redirect'),
  hybrid: text('混合', 'Hybrid'),
  'if-chain': text('条件链分发', 'If-chain dispatch'),
  iiliii: text('i/l 相似字符', 'i/l homoglyphs'),
  'interface-dispatch': text('接口分发', 'Interface dispatch'),
  invokedynamic: text('InvokeDynamic', 'InvokeDynamic'),
  'jni-key-hold': text('JNI 持有密钥', 'JNI-held key'),
  'jvm-params': text('JVM 参数', 'JVM parameters'),
  'lambda-wrapper': text('Lambda 包装', 'Lambda wrapper'),
  layout: text('布局差异', 'Layout'),
  'lazy-decrypt': text('延迟解密', 'Lazy decrypt'),
  'length-threshold': text('按长度阈值', 'Length threshold'),
  'linux-x64': text('Linux x64', 'Linux x64'),
  loader: text('加载器', 'Loader'),
  log: text('仅记录', 'Log only'),
  'lookup-table': text('查找表', 'Lookup table'),
  lookupswitch: text('查找表分发', 'LOOKUPSWITCH'),
  'macos-arm64': text('macOS ARM64', 'macOS ARM64'),
  'macos-x64': text('macOS x64', 'macOS x64'),
  'method-call': text('调用合成方法', 'Synthetic method call'),
  'methodhandle-chain': text('MethodHandle 链', 'MethodHandle chain'),
  mixed: text('混合', 'Mixed'),
  moderate: text('中等', 'Moderate'),
  'modular-arithmetic': text('模运算恒等式', 'Modular arithmetic'),
  multi: text('多层', 'Multi layer'),
  'naming-only': text('仅命名差异', 'Naming only'),
  nnmnmnm: text('n/m 相似字符', 'n/m homoglyphs'),
  nop: text('仅空操作', 'NOP only'),
  ooO0oO: text('o/O/0 相似字符', 'o/O/0 homoglyphs'),
  pair: text('成对', 'Pair'),
  passive: text('被动', 'Passive'),
  'per-class': text('按类', 'Per class'),
  'per-method': text('按方法', 'Per method'),
  'quadratic-residue': text('二次剩余', 'Quadratic residue'),
  random: text('随机', 'Random'),
  'random-register': text('随机寄存器', 'Random register'),
  'random-sample': text('随机采样', 'Random sample'),
  'random-stack': text('随机栈', 'Random stack'),
  refuse: text('拒绝运行', 'Refuse'),
  rehash: text('重新生成', 'Rehash'),
  reject: text('拒绝', 'Reject'),
  'reject-conflicts': text('拒绝冲突', 'Reject conflicts'),
  resource: text('资源', 'Resource'),
  ring: text('环状', 'Ring'),
  'rsa-2048': text('RSA-2048', 'RSA-2048'),
  'runtime-builder': text('运行时构造器', 'Runtime builder'),
  safe: text('安全保守', 'Safe'),
  selective: text('选择性', 'Selective'),
  sequential: text('顺序命名', 'Sequential'),
  silent: text('静默', 'Silent'),
  single: text('单层', 'Single layer'),
  standard: text('标准', 'Standard'),
  strict: text('严格', 'Strict'),
  'tigress-like': text('Tigress-like', 'Tigress-like'),
  'switch-path': text('切换路径', 'Switch path'),
  'tableswitch-hybrid': text('表分发混合', 'TABLESWITCH hybrid'),
  'thread-hash': text('线程哈希', 'Thread hash'),
  'thread-id': text('线程 ID', 'Thread ID'),
  'thread-local': text('线程局部', 'Thread local'),
  'time-epoch': text('时间 Epoch', 'Time epoch'),
  'unicode-confusable': text('Unicode 相似字符', 'Unicode confusables'),
  'unreachable-method': text('不可达方法', 'Unreachable method'),
  'unsafe-define': text('Unsafe 定义类', 'Unsafe define'),
  'validate-only': text('仅校验', 'Validate only'),
  'vm-interpreter': text('VM 解释器', 'VM interpreter'),
  warn: text('警告', 'Warn'),
  'windows-x64': text('Windows x64', 'Windows x64'),
  'arithmetic-split': text('算术分裂', 'Arithmetic split'),
}

const passCopies: Readonly<Record<string, LocalizedPassCopy>> = {
  'anti-decompiler-structure': {
    name: text('反编译干扰结构', 'Anti-decompiler structure'),
    description: text('加入虚假异常处理器和死代码块，让反编译器更难还原清晰结构，同时不改变运行结果。', 'Adds bogus exception handlers and dead blocks that confuse decompilers without changing runtime behavior.'),
  },
  'anti-dump-protection': {
    name: text('内存转储防护', 'Anti-dump protection'),
    description: text('通过 JNI/native 层降低 dump 中关键材料的可见性；jni-key-hold/full 依赖 native 可用并失败拒绝。', 'Uses JNI/native support to reduce key-material visibility in dumps; jni-key-hold/full require native availability and fail closed.'),
  },
  'anti-instrumentation': {
    name: text('反插桩检测', 'Anti-instrumentation'),
    description: text('检测 -javaagent、ByteBuddy、JVMTI、attach 与 class retransformation，并按策略记录、降级或拒绝。', 'Detects -javaagent, ByteBuddy, JVMTI, attach, and class retransformation, then logs, degrades, or refuses according to policy.'),
  },
  'anti-symbolic-execution': {
    name: text('符号执行陷阱', 'Anti-symbolic execution'),
    description: text('插入依赖运行时环境的谓词，让符号执行工具更难通过约束求解覆盖真实分支。', 'Adds runtime-dependent predicates that make constraint solving and symbolic branch coverage harder.'),
  },
  'callsite-rotation-protection': {
    name: text('调用点轮换防护', 'Callsite rotation protection'),
    description: text('用 MutableCallSite、epoch、线程或随机信号动态切换调用目标，提高静态恢复成本。', 'Uses MutableCallSite, epoch, thread, or random signals to rotate call targets and raise static recovery cost.'),
  },
  'class-encryption-loader': {
    name: text('类加密加载器', 'Class encryption loader'),
    description: text('把选定 .class 以 AES-GCM 认证加密存入资源，由 native 派生密钥；认证失败拒绝加载。', 'Stores selected .class files as AES-GCM authenticated resources with native-derived keys; authentication failure refuses loading.'),
  },
  'condy-constant-indirection': {
    name: text('动态常量间接化', 'ConstantDynamic indirection'),
    description: text('用 ConstantDynamic 延迟解析字符串和整数常量，让静态分析更难直接读出值。', 'Uses ConstantDynamic to resolve string and integer constants lazily, making static extraction harder.'),
  },
  'control-flow-flattening': {
    name: text('控制流平坦化', 'Control-flow flattening'),
    description: text('把方法逻辑改写为分发器驱动结构，作为中等强度扰动提高 CFG 恢复成本。', 'Rewrites method logic into dispatcher-driven structure as medium-strength perturbation that raises CFG recovery cost.'),
  },
  'control-flow-obfuscation': {
    name: text('控制流混淆', 'Control-flow obfuscation'),
    description: text('通过不透明谓词、分发逻辑和代数恒等式重组方法控制流。', 'Restructures method control flow using opaque predicates, dispatch logic, and algebraic identities.'),
  },
  'environment-bound-keys': {
    name: text('环境绑定密钥', 'Environment-bound keys'),
    description: text('把规范化环境信号纳入 native KDF；材料缺失或绑定不匹配时拒绝解密。', 'Feeds normalized environment signals into the native KDF; missing material or binding mismatch refuses decryption.'),
  },
  'exception-semantic-virtualization': {
    name: text('异常语义虚拟化', 'Exception semantic virtualization'),
    description: text('把部分正常控制流转换为自定义异常路径，是实验性语义扰动而非完整 VM 保护。', 'Converts selected normal control flow into custom exception paths as experimental semantic perturbation, not full VM protection.'),
  },
  'field-string-encryption': {
    name: text('字段字符串加密', 'Field string encryption'),
    description: text('加密 static final String 字段常量，并在类初始化时解密，避免常量池出现明文。', 'Encrypts static final String field constants and decrypts them during class initialization to avoid plaintext in the constant pool.'),
  },
  'integer-constant-obfuscation': {
    name: text('整数常量混淆', 'Integer constant obfuscation'),
    description: text('把整数常量改写为等价表达式，避免简单常量模式被直接匹配。', 'Rewrites integer constants into equivalent expressions to avoid direct constant pattern matching.'),
  },
  'invoke-dynamic-indirection': {
    name: text('InvokeDynamic 间接调用', 'InvokeDynamic indirection'),
    description: text('把静态调用改写为由 bootstrap 查找表解析的 invokedynamic 调用。', 'Rewrites direct calls into invokedynamic calls resolved through bootstrap lookup tables.'),
  },
  'jni-microkernel-loader': {
    name: text('JNI 微内核加载器', 'JNI microkernel loader'),
    description: text('把部分加载、解密或调度逻辑转移到平台相关的 native 微内核中。', 'Moves selected loading, decryption, or dispatch logic into a platform-specific native microkernel.'),
  },
  'member-hide': {
    name: text('隐藏成员', 'Member hide'),
    description: text('把字段和方法标记为合成成员，让 IDE 和反编译器更不容易直接展示。', 'Marks fields and methods as synthetic so IDEs and decompilers are less likely to show them directly.'),
  },
  'method-body-delayed-decryption': {
    name: text('方法体延迟解密', 'Method body delayed decryption'),
    description: text('把方法体放入 AES-GCM 认证资源，trampoline 仅携带 metadata，native 派生密钥并在认证失败时拒绝。', 'Stores method bodies in AES-GCM authenticated resources; trampolines carry metadata only, native-derived keys, and fail closed on authentication failure.'),
  },
  'method-virtualization': {
    name: text('方法虚拟化', 'Method virtualization'),
    description: text('把方法语义转换为 VBC4 指令和 native VM 执行，默认自动识别 VM 兼容关键方法以减少回退裸露面。', 'Converts method semantics into VBC4 instructions executed by a native VM, defaulting to critical VM-compatible method selection to reduce fallback exposure.'),
    params: {
      methodSelection: text('方法选择策略：控制类规则如何自动选择 VM 兼容方法；显式方法规则仍优先。', 'Method selection strategy: controls how class rules auto-select VM-compatible methods. Explicit method rules still take precedence.'),
      strictVirtualization: text('严格虚拟化：在广义类规则下强制纳入所有 VM 兼容且未跳过的方法，减少明文实现保留。', 'Strict virtualization: includes every VM-compatible, non-skipped method under broad class rules to reduce plaintext implementation fallback.'),
      maxInstructions: text('最大指令数：超过该阈值的方法保持原样；默认值足够高，避免显式命中的大型方法被意外跳过。', 'Maximum instruction count: methods above this threshold stay unchanged. The default is high enough to avoid unexpectedly skipping explicitly selected large methods.'),
      vbc4StateBoundEncoding: text('VBC4 固定默认：state-bound encoding 始终开启，并作为隐藏的 fail-closed 不变量。', 'VBC4 fixed default: state-bound encoding is always on and remains a hidden fail-closed invariant.'),
      vbc4HandlerMorphing: text('VBC4 固定默认：handler morphing 始终开启，并作为隐藏的 fail-closed 不变量。', 'VBC4 fixed default: handler morphing is always on and remains a hidden fail-closed invariant.'),
      vbc4StrengthMax: text('VBC4 固定默认：强度固定为 max，不暴露低强度或兼容 profile。', 'VBC4 fixed default: strength is locked to max, with no low-strength or compatibility profile exposed.'),
      vbc4InterpreterDiversity: text('VBC4 固定默认：native-only 路径始终启用解释器多样化；关闭会被引擎拒绝。', 'VBC4 fixed default: interpreter diversity is always enabled for the native-only path; disabling it is rejected by the engine.'),
      vbc4HashedJniSymbols: text('VBC4 固定默认：JNI VM 目标使用构建和方法级 token 定位，避免在热路径传递明文符号。', 'VBC4 fixed default: JNI VM targets use build- and method-scoped tokens to avoid passing plaintext symbols on hot paths.'),
      vbc4ExecutableRegisterIr: text('VBC4 固定默认：native dispatcher 以 register IR 执行，stack opcode 仅作为兼容输入。', 'VBC4 fixed default: the native dispatcher executes register IR, with stack opcodes retained only as compatible input.'),
      vbc4SuperOperators: text('VBC4 固定默认：serializer 按方法随机结构 seed 折叠 super-operator，并纳入认证状态。', 'VBC4 fixed default: the serializer folds super-operators by per-method randomized structure seed and binds them into authenticated state.'),
      vbc4IntegrityKeyBinding: text('VBC4 固定默认：session integrity digest 参与 seed unwrap、block key 和 CP key 派生。', 'VBC4 fixed default: the session integrity digest participates in seed unwrap, block-key, and CP-key derivation.'),
      vbc4EphemeralMasterKey: text('VBC4 固定默认：native 主密钥只按需短生命周期派生，用后擦除。', 'VBC4 fixed default: the native master key is derived only for a short on-demand lifetime and wiped after use.'),
    },
  },
  'reference-proxy': {
    name: text('引用代理', 'Reference proxy'),
    description: text('通过代理方法转发原始调用，打断直接调用图。', 'Forwards original calls through proxy methods, breaking direct call graphs.'),
  },
  'rename-classes': {
    name: text('重命名类', 'Rename classes'),
    description: text('重命名匹配的类，并同步改写字节码引用。', 'Renames matched classes and rewrites bytecode references consistently.'),
  },
  'rename-fields': {
    name: text('重命名字段', 'Rename fields'),
    description: text('重命名匹配的字段，支持多种名称风格和冲突处理策略。', 'Renames matched fields with configurable naming styles and collision policies.'),
  },
  'rename-methods': {
    name: text('重命名方法', 'Rename methods'),
    description: text('重命名匹配的方法，并尽量保持接口方法关系一致。', 'Renames matched methods while preserving interface method consistency where possible.'),
  },
  'rename-packages': {
    name: text('重命名包路径', 'Rename packages'),
    description: text('改写匹配类的包路径，可按需保留前几层包名。', 'Rewrites package paths for matched classes while optionally preserving leading package segments.'),
  },
  'static-init-perturbation': {
    name: text('静态初始化扰动', 'Static init perturbation'),
    description: text('把编译期静态常量移到运行时初始化，并加入噪声赋值。', 'Moves compile-time static constants into runtime initialization and adds noisy assignments.'),
  },
  'string-encryption': {
    name: text('字符串加密', 'String encryption'),
    description: text('加密字符串常量并注入解密逻辑，支持多种算法、密钥作用域和过滤范围。', 'Encrypts string constants and injects decrypt logic with configurable algorithms, key scopes, and filtering.'),
  },
  'strip-compile-debug-info': {
    name: text('清理编译调试信息', 'Strip compile debug info'),
    description: text('移除源码名、行号、参数名和局部变量等调试元数据。', 'Removes source names, line numbers, parameter names, local variables, and other debug metadata.'),
  },
}

const pick = (copy: LocalizedText, language: DisplayLanguage): string => copy[language]

const looksMojibake = (value: string): boolean => value.includes('�') || value.includes('Ԫ') || value.includes('���')

const humanizeIdentifier = (value: string): string => value
  .split('-')
  .filter((part: string): boolean => part.length > 0)
  .map((part: string): string => `${part.charAt(0).toUpperCase()}${part.slice(1)}`)
  .join(' ')

export const languageToggleLabel = (language: DisplayLanguage): string => nextLanguageLabel(language)

export const nextLanguageLabel = (language: DisplayLanguage): string => (language === 'zh' ? 'English' : '简体中文')

export const toggleLanguage = (language: DisplayLanguage): DisplayLanguage => (language === 'zh' ? 'en' : 'zh')

export const localizeCategoryLabel = (category: string, language: DisplayLanguage): string => {
  const matched = categoryLabels[category]
  if (matched !== undefined) {
    return pick(matched, language)
  }

  return language === 'en' ? humanizeIdentifier(category) : category
}

export const localizeRiskLabel = (risk: PassItem['risk'], language: DisplayLanguage): string => pick(riskLabels[risk], language)

export const localizePassName = (passItem: PassItem, language: DisplayLanguage): string => {
  const copy = passCopies[passItem.id]?.name
  if (copy !== undefined) {
    return pick(copy, language)
  }

  if (language === 'en') {
    return looksMojibake(passItem.name) ? humanizeIdentifier(passItem.id) : passItem.name
  }

  return looksMojibake(passItem.name) ? humanizeIdentifier(passItem.id) : passItem.name
}


export const localizePassNameById = (passId: string, language: DisplayLanguage): string => {
  const copy = passCopies[passId]?.name
  if (copy !== undefined) {
    return pick(copy, language)
  }
  return language === 'en' ? humanizeIdentifier(passId) : passId
}
export const localizePassDescription = (passItem: PassItem, language: DisplayLanguage): string => {
  const copy = passCopies[passItem.id]?.description
  if (copy !== undefined) {
    return pick(copy, language)
  }

  return looksMojibake(passItem.description) ? humanizeIdentifier(passItem.id) : passItem.description
}

export const localizeParamDescription = (passItem: PassItem, paramSchema: ParamSchema, language: DisplayLanguage): string => {
  const passParamCopy = passCopies[passItem.id]?.params?.[paramSchema.key]
  if (passParamCopy !== undefined) {
    return pick(passParamCopy, language)
  }

  const commonCopy = commonParamDescriptions[paramSchema.key]
  if (commonCopy !== undefined) {
    return pick(commonCopy, language)
  }

  return looksMojibake(paramSchema.description) ? humanizeIdentifier(paramSchema.key) : paramSchema.description
}

export const localizeOptionLabel = (value: string, language: DisplayLanguage): string => {
  const copy = optionLabels[value]
  if (copy !== undefined) {
    return pick(copy, language)
  }

  return language === 'en' ? humanizeIdentifier(value) : value
}
