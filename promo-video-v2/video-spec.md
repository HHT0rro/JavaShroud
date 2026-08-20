# JavaShroud 90 秒跨平台技术发布片 v2

## 1. 成片目标

- 平台：B 站技术发布片，同时适合 GitHub README 外链。
- 受众：Java 开发者、JVM 工具链用户、开源项目用户。
- 画幅：1920×1080，16:9。
- 帧率：30 fps。
- 时长：精确 90.0 秒 / 2700 帧。
- 音频：无旁白；原创 126 BPM 工业电子底轨与功能性转场音效；无需第三方署名。
- 叙事核心：`代码，换一种执行方式。`
- 事实核心：一个自写 Java 17 样本，经冻结 JavaShroud Engine 0.12 / VBC 4.55 生成唯一 protected JAR；同一 SHA-256 JAR 在 Windows x64 与 Linux x64 的 Java 17 上输出逐字一致。

## 2. 证据边界

HyperFrames 只读取同步生成的：

```text
generated-evidence/evidence.js
```

其源数据由：

```text
scripts/build_evidence_manifest.py
```

从冻结 artifact、engine metadata、CFR、`javap`、`jar tf`、字符串扫描和 Windows/Linux 回执中 fail-closed 生成。成片不在运行时请求网络，也不手写任何 artifact 哈希、随机资源路径或运行结果。

唯一最终 artifact：

```text
demo-protected-final.jar
SHA-256 2eee7edd9aa226dea0dc6489f092477892e2b364b43cb3bac143b1b6071bd305
```

## 3. 视觉与动效

- 自定义主题：项目根 `DESIGN.md`。
- 视觉比例：Apple 发布会式极简硬件感 70% + NVIDIA 工程图形密度 30%。
- 主色：黑石墨、冷白、荧光绿执行状态。
- 主转场：机械快门 + 克制的网格消解。
- 高潮：45 秒处一次性“压缩—开启”，将原始方法体压成 dispatcher，再打开 `Java stub → JNI → VMBC resource → native runtime`。
- 每场有进入动画；CTA 之前不做提前离场；86–90 秒是唯一允许整体淡黑的场景。

## 4. 精确时间轴 / 分镜

| 时间 | 帧 | 场景 | 画面结构 | 中文字幕 / 屏显 | 证据来源 |
|---:|---:|---|---|---|---|
| 0.0–5.0 | 0–149 | 跨平台 Hook | 左 PowerShell、右 Ubuntu，中线同一 SHA；三案例回执快速锁定，最终合并成 `RESULT MATCH`。 | `同一受保护 JAR。两套系统。三条一致结果。` | `artifact.sha256`、`cases[]`、Windows/Linux runtime |
| 5.0–10.0 | 150–299 | 核心主张 | 大面积黑色留白；Logo 原色短暂出现；主张从细线切口中展开。 | `代码，换一种执行方式。` / `JavaShroud · Open Source · GPL-3.0` | 固定品牌文案 |
| 10.0–30.0 | 300–899 | 20 秒构建见证 | 英文 Vue/Wails 语义工作台：Input JAR → Scan Jar → Passes → Rules → TOML → Engine Events → Done。真实四 Pass 状态逐步点亮，底部证据条展示 Java 17 build、engine、CFR、SHA。 | `从可运行的 Java 样本开始。` / `选择要保护的高价值方法。` | baseline、pass targets、engine events、CFR metadata |
| 30.0–45.0 | 900–1349 | 源码 / CFR | 完整 `AccessPolicy` 源码与最终 CFR 双栏同步滚动；对应区域横向对齐，资格闸门、套餐 switch、风险循环、阈值分支依次被绿线连接。 | `可读策略进入经过变换的控制结构。` / `CFR 0.152 · SAME PROTECTED JAR` | 完整原始类、完整 CFR、protected SHA |
| 45.0–60.0 | 1350–1799 | VMBC 高潮 | 原始 `ProtectedOperation.execute()` 被横向压缩；真实 `javap` dispatcher tail 锁定 token/args；画面连续转化为 Java stub → JNI → sealed VMBC resource → platform runtime。 | `VMBC` / `Method body moved to VMBC resource.` / `同一逻辑，进入不同的执行形态。` | `vmbc.dispatcherDisplay`、VMBC resource、native entries |
| 60.0–68.0 | 1800–2039 | 控制流与字符串 | 左侧真实 `lookupswitch` / `tableswitch` / predicate 片段；右侧敏感字面量从 baseline hit 变为 final 0 hits，并显示真实 decoder call。下方保留 analyzer-safe 限制脚注。 | `Control Flow · String Protection` / `直接字面量不再保留。` | `controlFlow.javapHighlights`、string scan、MessageVault CFR |
| 68.0–78.0 | 2040–2339 | 受保护产物结构 | 中央 JAR 轮廓展开为真实资源树；明确标注 Windows runtime、Linux runtime、VMBC resource、boot resource，并用同一 SHA 线连接。右下出现额外能力蒙太奇，但标注 `TOOLCHAIN CAPABILITIES`。 | `2 PLATFORM RUNTIMES · SEALED RESOURCES` | build evidence natives/methods、jar tree、SHA |
| 78.0–86.0 | 2340–2579 | 完整双平台证明 | Windows / Linux 并列，按 approved / step-up / denied 三行逐一执行；每行出现退出码 0 和相同摘要；中央最终锁定 `RESULT MATCH`。 | `Windows x64 · Linux x64 · Java 17。` / `RESULT MATCH。` | `cases[]`、platform metadata、same SHA gate |
| 86.0–90.0 | 2580–2699 | CTA | Logo 原色、超大 CTA、仓库地址和 GPL-3.0 身份；最后 0.8 秒整体淡黑。 | `STAR · BUILD · PROTECT` / `github.com/HHT0rro/JavaShroud` / `JavaShroud · 开源 Java 保护工具链 · GPL-3.0` | 固定 CTA |

## 5. 音画节奏

- 126 BPM，四拍约 1.9048 秒；视觉动作按半拍 / 一拍对齐，但段落边界严格服从锁定时间轴。
- 0–5 秒：快速低频脉冲与三个确认音，`RESULT MATCH` 在强拍锁定。
- 5–10 秒：底轨抽薄，给主张留出空间。
- 10–30 秒：持续机械推进，工作台每次状态变化对应短促 click / relay。
- 30–45 秒：底轨保持，代码滚动节奏放慢，突出可读性。
- 45–60 秒：全片最大能量；45 秒压缩冲击，JNI 与 VMBC 关键词在鼓点处点亮。
- 60–78 秒：恢复工程节奏，证据逐项出现，不乱切。
- 78–86 秒：三组命令各获得明确确认音，最终合成 `RESULT MATCH`。
- 86–90 秒：减少高频，保留低频与一次稳定 CTA 收束。

## 6. 固定中文字幕句义

```text
同一受保护 JAR。两套系统。三条一致结果。
代码，换一种执行方式。
从可运行的 Java 样本开始。
选择要保护的高价值方法。
可读策略进入经过变换的控制结构。
Method body moved to VMBC resource.
同一逻辑，进入不同的执行形态。
直接字面量不再保留。
Windows x64 · Linux x64 · Java 17。
RESULT MATCH。
```

## 7. 实现约束

- 根 composition：`data-duration="90"`、`data-width="1920"`、`data-height="1080"`、`data-fps="30"`。
- 9 个 scene 均为 timed `.clip`，进入动画写入同一 paused GSAP timeline。
- 所有 scene 使用不同 track，允许在转场期间短暂重叠；CSS `z-index` 控制图层。
- HTML 是 source of truth；evidence JS 在 composition 初始化前同步载入。
- 禁止 `fetch()`、`Date.now()`、`Math.random()`、异步 timeline、`repeat:-1`。
- 音频使用独立 `<audio>`，精确 90 秒。
- 画面不展示第三方音乐、不交付完整 CFR 原文、完整运行日志或样本 JAR；这些仅保留在制作期 evidence 中。

## 8. 最终验收

```text
HyperFrames doctor / lint / validate / inspect / render 全部通过
codec_name=h264
width=1920
height=1080
avg_frame_rate=30/1
nb_frames=2700
duration=90.000000
```

