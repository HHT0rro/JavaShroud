# JavaShroud 混淆产物 key 解密逻辑解析

## 0. 总览：密钥分层

产物中**不存在任何明文根密钥**。整条链是一个五层结构：

```
部署层  Boot KEK（32B，产物之外：sidecar 文件 / 环境变量 / 内嵌 JSBK 密文）
  │  AES-256-GCM
构建层  JSBM envelope（META-INF/.r/boot.dat）→ masterKey + jarLayoutDigest
  │     + 6~16 个 partition key + 1 个 anchor key（全部独立 SecureRandom，互不可推导）
  ├─ HKDF ─→ 字符串链：stringRoot → classKey → 每条字符串 AES-128-CTR key/iv
  ├─ HKDF ─→ VM 链：build key → method key → session leaf（VBC4 虚拟化方法）
  ├─ HKDF ─→ 类加密链：anchor key + keyId‖salt → 每类 AES-GCM key
  └─ HMAC ─→ 资源链：partition key → JSRP v7 资源 AES-CTR + HMAC
外壳层  shell seed（32B，由 KEK 域分离 KDF 包裹，嵌在 native stub 的 payload 头）
  └─ HMAC-KDF ─→ stream key → 逐 chunk AES-128-CTR 解出内层 kernel 映像
段保护层 .jsx section key（32B，拆成 3~6 条 XOR lane 编入 native_secrets.inc）
```

## 1. 构建期：密钥在哪生成、怎么派生

核心文件：`core-engine/src/main/kotlin/.../protection/Vbc4BuildContext.kt`、`RuntimeKeyPartitions.kt`

- **masterKey(32B)**：`generateMasterKey()`（Vbc4BuildContext.kt:297）= `SHA-256("javashroud-vbc4-build-root" ‖ nativeSeed ‖ jarLayoutDigest ‖ buildAuthority ‖ 64B SecureRandom 熵)`。每次构建随机，不可复现。
- **jarLayoutDigest(32B)**：全部 jar 条目（名字+大小+SHA-256）的 SHA-256（:323），产物布局一变全部派生密钥失效。
- **RuntimeKeyPartitions.generate()**（RuntimeKeyPartitions.kt:79）：`6 + random(11)` 个分区密钥 + 1 个 anchor key，**独立随机、不从共同根派生**——注释明确 "recovering any one partition key yields nothing about the others"。
- **统一 KDF**：HKDF-SHA256（RFC 5869，`hkdfSha256` :360）；`deriveSubKey(label, keyId, salt)` IKM=anchor key。
- 构建端卫生：`withVbc4BuildContext` 作用域结束 `wipe()`（:160）把全部根材料填零；各变换 `finally { Arrays.fill(…,0) }`。

## 2. 密钥以什么形态嵌入产物

### 2.1 JSBM envelope —— 根密钥的运输信封
`BootMaterialEnvelope.kt:30-101`，资源路径 `META-INF/.r/boot.dat`：

```
明文 = version(1)|partitionCount(1)|slotCount(1)|bindingCount(1)
     | masterKey(32)@off4 | jarLayoutDigest(32)@off36
     | slotCount × 32B(分区密钥+anchor) | bindingCount × (platformId(1)+shellBindingCommitment(32))
密封 = AES-256-GCM(key=Boot KEK, nonce=12B 随机, tag=128bit,
       AAD="javashroud-boot-material-v2" 或 v3+sidecarBinding)
信封 = "JSBM"|version|[v3: bindingLen|binding(32)]|nonceLen|nonce|le32(len)|sealed
```

max-hardening 下 `RuntimeArtifactSealing.seal()` 把它改名为 seed 派生的伪装路径（`META-INF/<sha2>/<sha30>.properties` 等），并重写 helper 内字符串引用。

### 2.2 JSBK sidecar —— KEK 的加密外衣（118B）
`BootKekSidecar.kt:73-109`：

```
wrappingKey = HMAC-SHA256(artifactBinding, "JavaShroud/BootKekSidecar/v1/key" ‖ salt(16))
sealed = AES-256-GCM(wrappingKey, nonce(12), AAD=header‖binding‖salt‖nonce) 加密 KEK(32)
二进制 = "JSBK"|ver|flags|16|12|le16(48) | binding(32)明文 | salt(16) | nonce(12) | sealed(48)
文本   = "JSBK1." + base64url(二进制)
```

artifactBinding 域分离 ⇒ sidecar 不能跨产物重放。交付方式（`bootKeyDelivery`）：`external-file`（产物之外）或 `embedded`（`META-INF/.r/kek.dat`，仍非明文）。也可 `JAVASHROUD_BOOT_SECRET_V1`/`_FILE_V1` 环境变量供给。

### 2.3 native 外壳 payload（max/max-hardening）
`NativeKernelShellPacker.kt:179-280`：shell seed(32B 随机) 是外壳加密根：

- `encryptedSeed = AES-CTR(seedKdf(bootSecret,"…-seed-key-v3")[0..16], iv)` + HMAC tag；全部渲染为 C 数组嵌进 stub 编译。
- payload 按 4096B 分块，每块独立 `shellKdf(streamKey, domain, nonce, bindingTag, chunkIndex)` 派生 key/iv 的 AES-128-CTR + 逐块 HMAC（EtM）。
- `shellKdf(key, domain, nonce, bindingTag, value) = HMAC-SHA256(key, nonce‖bindingTag‖value‖domain)`（:789）。
- 构建承诺 `payloadMac` + `artifactBindingCommitment`；per-platform `bindingTag` 回写 boot.dat 绑定区，与 native 库互锁。

### 2.4 native_secrets.inc —— 刻意不含根材料
只有：多样性常量、AES-CTR 加密的 JNI 字符串、`.jsx` 段密钥的 3~6 车道 XOR 份额（旋转移位/掩码/步长索引，生成后校验重构并 wipe）。注释明示："Root and layout material arrive through the one-shot boot ABI"。

## 3. 运行时解密流程

### 3.1 JVM 层 boot（`JniMicrokernelHelper.java`）
1. 读 boot.dat → `loadBootSecret()`(:1376)：env → sidecar 文件 → 内嵌 kek.dat；`decodeBootKekSidecar`(:1526) 镜像构建端 HMAC 派生 + GCM 解密，`MessageDigest.isEqual` 常量时间比对 binding，v3 拒绝一切非 sidecar 形态（fail-closed）。
2. `decryptBootMaterial()`(:1592)：AES-256-GCM 开信封 —— **masterKey 唯一一次短暂落在 JVM 堆**。
3. `nativeInstallBootMaterial(material)`（JNI `jsn_k7`, js_vm_core.c:7050）成功后立即把 material [4,68) 填零；失败统一 `clearJavaBootMaterial()` + `nativeAbortBootMaterial()`。
4. max-hardening 走 `nativeInstallBootEnvelope`：整信封在 native 内解封，**masterKey 零 JVM 接触**。

### 3.2 native 层根密钥落地：3 份 XOR shares
`jsn_k7`（js_vm_core.c:7050）把 masterKey、layoutDigest、17 个 slot 密钥各拆成 3 份 XOR 份额（`js_rrk_split_runtime_value` :7031；前两份 = RDTSC/时钟/栈地址混合的每进程熵，第三份 = raw⊕前两份），存静态数组。注释："the generated native image contains no master/layout/partition bytes in .rodata"。使用时 `js_rrk_xor_assemble` 重组到栈上，用完 `js_vbc4_wipe_volatile` 擦除。**任何时刻内存中都没有完整根密钥**。

### 3.3 外层 shell 自举（`js_shell_stub.c` `JNI_OnLoad` :1177）
取 binding commitment（Java 一次性桥，取后即清）→ 取 KEK（env/sidecar/Java 桥 `takeBootSecretForNativeShell`，线程绑定一次性）→ **先验 build HMAC 再解密** → 开 seed envelope（js_shell_crypto.c:382）→ 解敏感头 → 验 artifact binding commitment → 派生 streamKey → 逐 chunk HMAC+CTR 解密 → zstd 解压 → 验 inner digest → manual-map 内层 kernel → 校验 ABI 表 → 注册 19 个 shim。KEK/shell_seed/stream_key 用完即 `js_shell_secure_wipe`。

### 3.4 字符串解密链
- 构建端（`bytecode/StringEncryptionTransforms.kt`）：每个 `LDC` 替换为
  `StringEncryptionHelper.cachedDecodeString(payload[], seed, flags, classHi, classLo)`；
  `seed=mix32(methodSalt+idx+rand)`、`flags=mix32(classSalt↻5+methodSalt↻3+idx)` 只是 KDF 上下文，不是密钥。
- 派生链（HKDF 四级）：masterKey →(salt "javashroud-string-root-v1", info=layoutDigest)→ stringRoot →("javashroud-string-class-v1", info=classIdentity)→ classKey → 双重 HMAC(label "js-string-aes-key"/"js-string-aes-iv", seed, flags, len) → 16B key + 16B IV。
- 算法：**AES-128-CTR/NoPadding**（软件实现 js_crypto.c:161），无 tag，大端计数器。
- 运行时 `jsn_r21`（js_vm_core.c:3613）每次调用从 shares 重组 masterKey → 重放整条派生链 → CTR 解密 → 栈上全部 wipe。boot state≠2 时派生出全零 key ⇒ 解出垃圾而非明文。
- Java 层 `cachedDecodeString` 用 ConcurrentHashMap 缓存明文 String——这是 dump 明文的实际抓手；纯离线静态解密需复现完整 HKDF 链且持有 Boot KEK。

### 3.5 VBC4 虚拟化方法
- VM 链：`build_key = HKDF(masterKey, layoutDigest)` → `method_key = HMAC(build_key, token‖resourcePath‖methodNonce)` → `session_leaf = HMAC(method_key, startupNonce)`（每次启动注入，换路径/入口即失效）。
- 程序块（`VBC4` magic）：wrapped_seed 由 `session_integrity_material = SHA256("vbc4-session-integrity"‖masterKey‖layoutDigest‖entryIntegrity)` 派生的 HMAC mask 解包并认证 → 整资源 HMAC 门控（先验后解）→ CP/指令/异常区按 section+block_id 派生 key/iv 的 **AES-128-CTR** 逐块解密；SEALED_STRING 再叠加一层 build_key 派生的 EtM（HMAC tag + CTR）。
- 反 trace 毒化：检测到 trace 时故意用错误 seed 解密产出垃圾（js_vm_core.c:428）。

### 3.6 类加密 loader（class-encryption-loader）
- 每类随机 keyId(8B)/salt(16B)/nonce(12B)；**密钥本体不写入产物**，只有 `deriveClassEncryptionKey = HKDF(anchor key, "javashroud-vbc4-jse-class-v1", keyId‖salt)`。
- 密文 `__jse/<name>.enc`：**AES-GCM**（tag 128bit，AAD 绑定类名/资源路径/策略/sealing 状态）；`index.tab` 存 v2 元数据 `v2:strategy:b64(keyId):b64(salt):b64(nonce):b64(SHA256(AAD))`。
- 运行时：`SharedDecryptingClassLoader` → 元数据常量时间比对 AAD 哈希 → JNI `jsn_k10`（js_vm_core.c:6982）从 anchor shares 重组 root、栈上 HKDF 派生 → 回 Java 做 AES-GCM 解密 → `defineClass`（helper 的 ProtectionDomain，统一 loader 保住 package-private）→ `finally Arrays.fill(key,0)`。native 缺席直接 SecurityException（fail-closed，无 Java 兜底）。
- 原类替换为 stub：方法体 → `ClassEncryptionLoaderHelper.invokeMethod(Object[])` 反射委托；`<clinit>` 注入 `loadClass` 调用。

### 3.7 JSRP v7 资源
`jsn_k13`/`js_runtime_resource_decode_current_owned`（js_vm_core.c:2932）：按 partition_id 选 slot（anchor=16）重组 shares → `HMAC(root,"jsrp-auth-v3"‖nonce‖raw)` 整包认证 → 域分离派生 CTR key/iv 分别解 96B 元数据与 body → 校验 partition 一致性、元数据自哈希、stored/plain SHA-256 双摘要。逐层 fail-closed。

### 3.8 .jsx 受保护代码段
- 算法非 AES：keystream 块 i = `SHA-256(key ‖ le32(i))`，与段体 XOR（`js_protected_section.c:70`，加解密同函数，无认证）。
- 密钥 = 构建期随机 32B，以 lanes+mask 形态编入 native_secrets.inc，`JS_PROTECTED_COPY_SCOPED_KEY` 每次调用在栈上乱序 XOR+旋转重建。
- `js_protected_section_enter/leave`：mprotect 可写→解密→可执行→调真正函数→重新加密→NOACCESS。**敏感函数（parse_program、hmac、xor_assemble 等）只在执行瞬间以明文存在**。

## 4. JVM ↔ native 密钥交接面

收敛到极少几个点，全部一次性、用后清零：

| 方向 | 桥 | 内容 |
|---|---|---|
| Java→native | `takeBootSecretForNativeShell()` | Boot KEK（线程绑定，取走即 null+清零） |
| Java→native | `takeExpectedShellBindingCommitment()` | 32B shell binding commitment |
| Java→native | `nativeInstallBootMaterial` / `nativeInstallBootEnvelope` | boot 材料（native 分片化后 Java 侧清零） |
| native→Java | `nativeDeriveClassEncryptionKey` | 派生类密钥（根密钥设计上永不出 native，js_vm_core.c:1813） |

helper 类名/方法绑定经系统属性 `j.l`/`j.m`（FNV1a 哈希映射重命名后名）传递，防静态定位；依赖 anchor 的 natives 推迟到 boot 材料装好后才注册（`js_jni_register_deferred_natives`）。

## 5. 内存卫生与验证

- 全程统一原则：**先 HMAC/GCM 认证、后解密**；任何失败立即擦除已解明文并 fail-closed。
- 长期形态：native 根密钥 = 3 份随机 XOR shares（每进程熵，重启即变）；`.jsx` 代码 = 加密+只读/NOACCESS；Java 密钥数组全部 `Arrays.fill(0)`。
- 端到端验证：`scripts/heap_key_lifecycle.py` 复刻 JSBK 解码拿 KEK → 跑产物 → `jcmd GC.heap_dump` → **断言堆转储中 KEK 出现 0 次**。
- `scripts/max_hardening_case.py` 只读验收：旧格式残留（JSBI/0.dat/JSRP 旧版/明文 key helper）必须为 0，sidecar 必须是 JSBK 认证信封。

## 6. 攻击面结论（为什么静态提取失效）

静态分析者拿到产物只有：keyId/salt/nonce/AAD 哈希、每字符串密文+seed/flags、加密封 envelope。没有 Boot KEK → 解不开 boot.dat → 拿不到 masterKey/anchor key → 所有 HKDF 链无法重算 → AES-GCM/CTR 密文不可解不可伪造。KEK 在产物之外（或 artifact-binding 包裹），运行时又只以 XOR shares 瞬时存在，堆转储验证为零出现。

## 关键文件索引

- 构建期：`Vbc4BuildContext.kt`、`RuntimeKeyPartitions.kt`、`BootMaterialEnvelope.kt`、`BootKekSidecar.kt`、`NativeKernelShellPacker.kt`、`ClassEncryptionLoaderTransforms.kt`、`RuntimeResourceCodec.kt`、`RuntimeArtifactSealing.kt`、`NativeProtectedSectionPacker.kt`、`bytecode/StringEncryptionTransforms.kt`
- 运行时 Java：`JniMicrokernelHelper.java`、`StringEncryptionHelper.java`、`ClassEncryptionLoaderHelper.java`
- 运行时 native：`js_vm_core.c`（shares/HKDF/JSRP/VM）、`js_shell_stub.c`+`js_shell_crypto.c`（外壳）、`js_vm_symbol.c`（CP/字符串）、`js_protected_section.c`（.jsx）、`js_jni_runtime.c`（jsw 包装）
