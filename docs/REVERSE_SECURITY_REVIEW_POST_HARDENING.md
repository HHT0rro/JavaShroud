# AKEN v4 加固后安全复核

## 1. 当前结论

当前实现的目标是 artifact-only 静态恢复成本化，而非从自足产物中构造不存在的外部秘密。安全验收以页面独立性、访问时完整性、native 必经、构建多态性、静态 marker 消除和 fail-closed 行为为准。

## 2. 复核矩阵

| 项目 | 当前要求 | 验证方式 |
|---|---|---|
| 页面独立性 | 恢复一个页面不应导出其他页面 DEK、locator 或 proof | 页面 evaluator 与 locator 单元/集成测试 |
| 无全局解封面 | Java heap 不持有全量页面材料、全局根或完整高价值目录 | helper 静态面扫描与运行时字段审计 |
| native 必经 | VM、字符串、class 与 native chunk 都经用途限定的 native bridge | JNI dispatcher 测试与无回退断言 |
| 完整性 | 页、路由、proof、helper 和 native chunk 篡改都 fail-closed | tamper matrix |
| 跨构建多态 | evaluator、表布局、路径、handle 与 dispatcher 随构建变化 | 多次构建差异测试 |
| 协议断代 | 新产物不保留历史交付面、固定启动资源或通用解码入口 | JAR/native/常量池扫描 |
| 直接启动 | 四个 packing profile 均保持 `java -jar` 启动契约 | `-Xverify:all` 与真实 fixture |

## 3. 已知边界

- 完整自足模型不提供 artifact 外的高熵未知量；
- 可动态控制执行的攻击者不在静态恢复通过条件内；
- JVM 返回对象和已定义 class 的自然生命周期不应被误说成内存隔离；
- 性能门槛需要与同一 pass 集和同一 packing profile 的基线逐项比较。

## 4. 发布前剩余门槛

1. 完成多平台 native target 验证；
2. 完成 production fixture 的完整 tamper matrix；
3. 完成多样本静态恢复预算测试；
4. 完成构建多态差异测试；
5. 完成 JAR、冷启动与首次访问的性能基线比较；
6. 对文档、CLI、schema、错误信息和产物扫描执行一次全量术语审计。
