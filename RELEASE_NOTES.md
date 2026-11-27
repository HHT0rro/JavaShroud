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
