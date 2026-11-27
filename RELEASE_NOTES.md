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
