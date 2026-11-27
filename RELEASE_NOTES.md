# JavaShroud v0.31.2-rc.3

## 中文

- Windows Native 检查每次枚举当前进程模块后，通过进程内模块 API 读取路径。保留现有匹配条件及检查频率，并覆盖缓冲边界、Unicode、长路径、失效句柄和并发装卸的回归。
- 每次成功 JVMTI GetEnv 创建的环境由所属调用同步释放，缺失函数或释放错误通过桥接异常报告。真实 JDK17/21 各60,000次所有权检查中，独立控制环境持续有效。
- Android 自有设备夹具追加编号命令、invocation 与 sample JSONL，绑定 APK 摘要、token、boot_id、WebView provider、PID 和原始输出摘要。失败时逐项收集 crash、exit-info、完整日志及 DropBox，保留诊断失败和原始异常。
- 完整 Calc 10,000 次循环在 Native 候选两轮观察中返回正确结果。JDK17为1,555/1,603ms，JDK21为2,369/2,227ms，相对3倍预算仍失败。独立随机产物及宿主负载绑定各自计时记录。
- 完整集成 CI 和 Linux JVMTI 实际运行结果按候选提交登记。ARM实机、ARM16KiB、API35 WebView间歇崩溃归因及本机火绒厂商处置继续保留未决状态。

## English

- Windows Native checks enumerate current-process modules on each sweep and query paths through the in-process module API. Regressions cover the existing predicates, buffer boundaries, Unicode, long paths, invalid handles and concurrent loading and unloading.
- Each environment created by a successful JVMTI GetEnv call is disposed synchronously by its owner. Missing functions and disposal errors propagate through bridge exceptions. Independent control environments stayed valid during60,000 ownership checks on each of JDK17 and JDK21.
- Owned Android fixtures append numbered command, invocation and sample JSONL records. Evidence binds APK digests, tokens, boot IDs, WebView providers, PIDs and raw output hashes. Failure diagnostics independently retain crash buffers, exit information, full logs and DropBox results while preserving the original exception.
- The complete10,000-loop Calc returned correct results in two Native candidate rounds. Observed protected times were1,555/1,603ms onJDK17 and2,369/2,227ms onJDK21. The relative3x budget remains failed. Each timing record retains its randomized artifact and host load identity.
- Full integrated CI and actual Linux JVMTI results are recorded against the candidate commit. ARM hardware, ARM16KiB execution, API35 WebView crash attribution and local Huorong vendor disposition retain their pending status.

# JavaShroud v0.31.2-rc.2

## 中文

- 桌面配置导入、导出、JSON 任务请求及后端 TOML 保留显式 `protectionProfile`。覆盖三个合法值、非法值及省略字段的原有默认行为。
- 内嵌 Rust workspace 缓存按完整源码内容求摘要，复用时核对内容。相同文件清单中的源码更新会选择新缓存，缺失资源与缓存变更会被拒绝，并发解包只接收完整且摘要一致的目录。
- 缓存缺陷的六项回归和相关 JVM、Rust 定向验证已通过。完整 Gradle、GUI 和发行验证继续按当前候选提交记录。
- 同一完整 Calc 夹具在缓存修复后的处理件上输出正确结果，JDK17 观察14339ms、JDK21观察25250ms，相对3倍性能预算仍未通过。该结果与旧产物535638ms的观察各自绑定独立产物及宿主负载。
- ARM 设备、ARM16KiB及 API35 WebView 间歇崩溃继续保留未验证项与原始失败证据。

## English

- Desktop configuration import, export, JSON task requests, and generated backend TOML preserve an explicit `protectionProfile`. Regressions cover all three supported values, invalid values, and the existing behavior for omitted fields.
- The bundled Rust workspace cache uses the complete source content digest and verifies cached contents before reuse. Updated sources select a new cache even when file names stay the same. Missing resources and modified caches fail closed. Concurrent extraction accepts a complete directory only after checking its digest.
- Six cache regressions and related JVM and Rust focused checks passed. Full Gradle, GUI, and release validation continue to be recorded against the candidate commit.
- The complete Calc fixture returned the correct result with the repaired source cache. Observed protected times were 14,339 ms on JDK 17 and 25,250 ms on JDK 21. The relative 3x performance budget remains failed. These results and the earlier 535,638 ms observation retain their individual artifact and host load bindings.
- ARM devices, ARM16KiB execution, and the intermittent API35 WebView crash retain their pending checks and original failure evidence.

# JavaShroud v0.31.2-rc.1

## 中文

- APK 名称保留涵盖按模型类名加 `Impl` 反射构造的生成实现，延续已有 `_Impl` 约定。回归夹具执行实际重命名和反射构造。
- Android 清单中的 `appComponentFactory`、备份代理、应用管理界面、类加载器、父 Activity 和别名目标等类引用进入保留集合，新增引用按声明元素和 Android 命名空间解析。
- 预发行标签自动标记为 GitHub prerelease，发行工作流正确读取带前缀的 PowerShell tag 变量。
- 已知的本机火绒 Native Image 隔离、默认加固 Calc 耗时、ARM 设备及部分历史 APK 验证仍在维护记录中逐项跟进。

## English

- APK keep rules retain generated implementation names constructed from a model class name plus `Impl`, alongside the existing `_Impl` convention. The regression exercises class renaming and reflective construction.
- Android manifest references for component factories, backup agents, management activities, class loaders, parent activities, and alias targets enter the keep set. Additional references are scoped to their declared elements and Android namespace.
- Prerelease tags produce GitHub prereleases. The release workflow delimits PowerShell tag variables correctly.
- Local Huorong Native Image quarantine, default hardened Calc latency, ARM device coverage, and remaining historical APK checks continue to be tracked individually.
