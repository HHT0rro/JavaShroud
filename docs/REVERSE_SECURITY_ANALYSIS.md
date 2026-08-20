# AKEN v4 静态恢复分析

## 1. 结论边界

AKEN v4 的安全表述是 **artifact-only static cost hardening**。它降低单一静态材料被抽取后横向恢复所有高价值资源的可行性，并提高跨构建自动化脚本的复用成本；它不把完全自足产物描述为密码学秘密隔离。

静态分析者可读取完整 JAR、native payload、公开完整性材料与生成的 evaluator 代码。运行时仍必然具有等价解密语义。评估重点应是恢复工作的页面局部化、构建间不可复用性和 fail-closed 完整性，而不是声称不存在任何可执行的解密语义。

## 2. 静态攻击面的变化

高价值资源按页独立封装。每页具有独立 DEK、独立认证绑定、独立 locator route 和独立 evaluator graph。不存在一次解封即可导出全部高价值页面材料的静态入口，也不存在可枚举全体资源的 central catalog。

攻击者要恢复一个页面，需要同时重构该页的 handle、locator、call-site proof、完整性路径、Java/native fragment 和终端运算。该工作不能直接扩展为其他页面的解封能力。

## 3. 结构性阻力

1. **资源局部化**：页面间不共享可横向派生的根材料。
2. **多态 evaluator**：构建随机化 fragment 分割、控制流、表排列、调用图与 native 函数形状。
3. **跨层绑定**：页密文、路由、proof 与 canonical commitment 共同参与认证。
4. **native 必经**：高价值访问只能通过用途限定的 native bridge，校验失败没有 Java 备用实现。
5. **访问时验证**：完整性验证发生在页面访问点，而非只在启动时依赖一个可替换检查。

## 4. 仍然不在声明范围内的能力

拥有完整动态执行控制权的攻击者可以观察程序执行、拦截明文使用点或修改运行时。AKEN v4 不将这种控制权纳入 artifact-only 静态恢复通过条件。字符串返回值、已定义 class 与业务对象的 JVM 生命周期同样不属于 native 内存擦除能够覆盖的边界。

## 5. 推荐验证方法

- 对多个独立构建执行固定时间预算的 artifact-only 恢复；
- 确认单样本恢复脚本不能无修改用于其他构建；
- 验证任一密文页、locator、proof、helper、native chunk 或 commitment shard 的篡改均 fail-closed；
- 对四个 native packing profile 执行静态 marker 扫描、`-Xverify:all` 与真实应用启动；
- 记录 JAR 体积、冷启动和高价值首次访问相对基线的增量。
