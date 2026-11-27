# JavaShroud v0.31.1

## 中文

- APK 管线在转换不完整、签名或对齐验证失败时拒绝发布，并保护输入、已有输出和附属文件。处理过程保留 Android 框架回调及必要的类和成员访问关系。
- CI 在 API 21、26 和 35 的 x86_64 模拟器中实际运行单 DEX、多 DEX 和 JNI 夹具，并拒绝任何跳过。API 35 使用报告 16 KiB 页大小的模拟器；这不构成 ARM 实机证据。
- Windows 原生构建使用相对源码路径。交付包固定 Xenolith v1.2.0-rc2 的 Windows CLI 摘要，工具链和最终包均独立验证。

## English

- The APK pipeline preserves inputs, existing outputs, and companion files if conversion is incomplete or signature or alignment verification fails. It retains Android framework callbacks and required class and member access relationships.
- CI runs the owned single-DEX, multidex, and JNI fixtures on Android API 21, 26, and 35 x86_64 emulators and rejects skipped cases. The API 35 results are emulator evidence for its reported 16 KiB page size. ARM device verification is separate.
- Windows native builds use relative source paths. The Windows distribution pins the Xenolith v1.2.0-rc2 CLI and verifies the exact executable digest.
