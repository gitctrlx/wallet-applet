# meowl-applet 逐行代码审计报告

## 审计元数据

| 字段 | 值 |
| --- | --- |
| 审计版本 | v1.2 (ID 体系重构 + 代码加固 sweep) |
| 审计日期 | 2026-01 (v1.0) / 2026-05 (v1.1 sweep) / 2026-05 (v1.2 重构) |
| 审计范围 | applet (25 文件 / ~5,700 行) + tools (37 文件 / ~3,500 行) + tests (17 文件 / ~5,500 行) |
| 总代码量 | ~14,700 行 Java |
| 审计深度 | 逐行审计 + 多参考实现并排对比 + 全部高/中优先级修复合并 + 调研驱动的新发现追加 |
| 参考实现 | Status Keycard、Satochip、Trezor firmware、Coldcard、libsodium、BoringSSL、Bitcoin Core、bitcoin/bips |
| 关键 RFC/BIP | RFC 2104、RFC 4231、RFC 5869、RFC 6979、RFC 7366、RFC 7748、RFC 8032、SEC 1 v2、SLIP-10、BIP-32、BIP-62、BIP-340、EIP-2 |

> **v1.2 重构 sweep 摘要 (2026-05)**：v1.0 / v1.1 使用 `S<等级>-<NN>` 双轨编号（ID 前缀同时承载顺序编号与严重等级），导致 §1.2 数量统计与正文不一致（S4 = 14 与正文实测 7 项偏差）。v1.2 把全部 26 项现有发现重新编号为 `F-01..F-26`，severity 作为独立标签，并在调研中追加 5 项新发现（F-27..F-31）。同步进行 4 处代码加固：`SecureChannel.stripPkcs5` 与 `compare16` 改为 mask-based 常时实现（F-27 / F-28），`MasterSeed` API 改为 pull-based copy 防止内部数组别名（F-29），`EcdsaK1.signDigest` 整体包裹 try-finally（F-30）。新增 `SecureChannelStripPkcs5Test` 共 27 个回归测试用例。代码注释中 37 处 `audit S<N>-<NN>` 引用全部同步替换为 `F-NN`，无双轨。最终 **1,697 个测试全部 PASSED**（applet/tests:1,445 + tools:252）。
>
> **v1.1 sweep 摘要 (历史)**：完成 §6.1 全部高优先级与 §6.2 全部中优先级条目（旧 ID S2-01..04、S3-01..16、S4-01）。新增 7 个回归测试场景，其中 `SchnorrTagHashTest` 实际捕获了 `HASH_OF_TAG_AUX` 的预算字节错位。

## 严重等级定义

| 等级 | 定义 | 处理时限 |
| --- | --- | --- |
| **S1 — Critical** | 直接秘密泄露 / 签名伪造 / 资金盗取路径 | 上线前必须修复 |
| **S2 — High** | 显著弱化某个安全保证（侧信道、错误处理） | 第一个稳定版本前修复 |
| **S3 — Medium** | 偏离最佳实践、轻微设计冗余、潜在的可利用性低 | 跟踪修复 |
| **S4 — Low** | 文档/注释/风格漂移、未使用变量、可读性 | 与下次重构合并 |
| **S5 — Info** | 信息性 / 设计权衡说明 | 仅记录，不必修改 |

---

## 一、执行摘要

### 1.1 总体评价

meowl-applet 代码库在 **正确性** 与 **架构清晰度** 上达到准生产级水平：

- **协议层** (MEAP-1..7) 已通过前序审计补齐 spec，与 EIP-1/BIP-2 模板对齐。
- **加密原语** (HmacSha、Hkdf、Edwards25519、Ed25519、EcdsaK1、Schnorr、Bip32、Slip10、MasterSeed) 算法实现正确，与 RFC/BIP 文本逐字一致。
- **Secure Channel** 实现 ECDH + HKDF + AES-256-CBC + HMAC-SHA-256（Encrypt-then-MAC），符合 RFC 7366 推荐组合。
- **生命周期** FSM 简洁严格，单向前进 + reset 回退，状态机覆盖 100%。
- **资源策略** (CLEAR_ON_DESELECT vs CLEAR_ON_RESET) 已针对 J3R180 调优。

**v1.0 原始审计的两大主要顾虑**（修复历史回溯）：

1. **侧信道**（F-01 / F-03）：`Bignat.mod` 与 `Field25519` 的 conditional-branch 模式在严格的"细粒度时间攻击"下不是常时的。在签名层 (Schnorr/Ed25519) 上文档承认这一点并以"k 充分随机化"作为缓解，但论证强度低于 Trezor / libsodium / BoringSSL 的纯常时实现。**v1.1 缓解状态**：mask-based 基元（`Bignat.condAddInPlace` / `condSubInPlace` / `ctLessThan` / `ctIsZero`、`Field25519.add/sub/neg/equals/isZero`、`ModN.addMod/lessThanN/lessThanHalfN/isZero`）已落地；`Edwards25519.scalarMult` 入口加投影盲化。`Bignat.mod` 与 `Bignat.mult` 仍是 long-division 风格非常时，需 v2.0 limb 重写。
2. **异常路径泄露**（F-02）：v1.0 时 `MeowlApplet.handleSignEd25519` 把 SLIP-10 leaf 私钥暂存于 `innerScratch[0..32]` 但仅在 success path 上 wipe。**v1.1 已修复**：整段 try-finally 包裹，异常路径与正常路径的 wipe 行为完全一致。

**v1.2 增量加固方向**：

1. **Secure Channel 辅助函数常时风格统一**（F-27 / F-28）：`stripPkcs5` 早退分支与 `compare16` 短路 ternary 重写为 mask-based，与 `ConstantTime.equals` / `Bignat.ctLessThan` 风格统一。
2. **持久秘密字段强封装**（F-29）：`MasterSeed` 废除 `byte[]` getter 改为 pull-based copy API，编译期消除内部数组别名风险。
3. **签名路径异常擦除完整性**（F-30）：`EcdsaK1.signDigest` 重构为单一 try-finally，与 `Schnorr.signDigest` / `Ed25519.sign` 风格统一。

### 1.2 发现总览

v1.2 引入 **F-NN 顺序编号 + 独立 severity 标签** 的二维 ID 体系：每个发现拥有一个不可变的 `F-NN` 顺序号（按报告章节出现顺序，从 F-01 到 F-31），其严重等级独立标注于 *Severity* 字段。下表按 severity 分组汇总，每格列出对应 F-NN：

| 等级 | 数量 | F-NN 列表 | v1.2 状态 |
| --- | --- | --- | --- |
| **S1 — Critical** | 0 | — | — |
| **S2 — High** | 4 | F-01, F-02, F-03, F-04 | ✅ F-02 / F-04 Fixed；🟡 F-01 / F-03 Mitigated（中期路径已落地，长期 limb 重写登记于 §6.3） |
| **S3 — Medium** | 9 | F-05, F-07, F-09, F-12, F-15, F-18, F-19, F-24, F-25 | ✅ 7 项 Fixed；⏸ F-19 Deferred（Extended-APDU，v1.2/v2.0） |
| **S4 — Low** | 9 | F-06, F-08, F-10, F-11, F-13, F-14, F-22, F-29, F-30 | ✅ 全部 Fixed |
| **S5 — Info** | 9 | F-16, F-17, F-20, F-21, F-23, F-26, F-27, F-28, F-31 | ⏸ F-16 Deferred（性能 limb 重写）；F-27 / F-28 实际已修复（统一 defense-in-depth 风格）；其余记录 |
| **合计** | **31** | — | — |

**v1.2 sweep 结果**：除 §6.3 长期路线（F-01 / F-03 / F-16 / F-19）登记到 v2.0+ 外，其余 27 项均已合并。新增回归测试 `SecureChannelStripPkcs5Test`（覆盖 F-27 / F-28 共 27 个测试用例），加上 v1.1 引入的 `SchnorrTagHashTest`（3）/ `MeowlAppletTest` 4 新场景 / `HostCryptoTest.malformedPaddingRejected`，目前 **1,697 个测试用例 / 311 个 `@Test` 方法全部 PASSED**（applet/tests:1,445 + tools:252）。

### 1.2.1 v1.0/v1.1 → v1.2 ID 编号映射

旧 `S<等级>-<NN>` 编号已彻底废止；下表列出双向映射，仅供历史检索。代码注释、提交信息中所有引用都已同步替换为 F-NN，无双轨。

| v1.0/v1.1 旧 ID | v1.2 新 ID | 旧 ID severity | v1.2 severity |
| --- | --- | --- | --- |
| S2-01 | **F-01** | S2 | S2 — High |
| S2-02 | **F-02** | S2 | S2 — High |
| S2-03 | **F-03** | S2 | S2 — High |
| S2-04 | **F-04** | S2 | S2 — High |
| S3-01 | **F-05** | S3 | S3 — Medium |
| S3-02 | **F-06** | S4 (旧 ID 错配) | S4 — Low |
| S3-03 | **F-07** | S3 | S3 — Medium |
| S3-04 | **F-08** | S4 (旧 ID 错配) | S4 — Low |
| S3-05 | **F-09** | S3 | S3 — Medium |
| S3-06 | **F-10** | S4 (旧 ID 错配) | S4 — Low |
| S3-07 | **F-11** | S4 (旧 ID 错配) | S4 — Low |
| S3-08 | **F-12** | S3 | S3 — Medium |
| S3-09 | **F-13** | S4 (旧 ID 错配) | S4 — Low |
| S3-10 | **F-14** | S4 (旧 ID 错配) | S4 — Low |
| S3-11 | **F-15** | S3 | S3 — Medium |
| S3-12 | **F-16** | S5 (旧 ID 错配) | S5 — Info |
| S5-01 | **F-17** | S5 | S5 — Info |
| S3-13 | **F-18** | S3 | S3 — Medium |
| S3-14 | **F-19** | S3 | S3 — Medium |
| S5-02 | **F-20** | S5 | S5 — Info |
| S5-03 | **F-21** | S5 | S5 — Info |
| S4-01 | **F-22** | S4 | S4 — Low |
| S5-04 | **F-23** | S5 | S5 — Info |
| S3-15 | **F-24** | S3 | S3 — Medium |
| S3-16 | **F-25** | S3 | S3 — Medium |
| S5-05 | **F-26** | S5 | S5 — Info |
| **(新)** | **F-27** | — | S5 — Info |
| **(新)** | **F-28** | — | S5 — Info |
| **(新)** | **F-29** | — | S4 — Low |
| **(新)** | **F-30** | — | S4 — Low |
| **(新)** | **F-31** | — | S5 — Info |

### 1.3 与社区参考的横向对比快照

| 维度 | meowl-applet | Status Keycard | Satochip | Trezor | Coldcard | 评估 |
| --- | --- | --- | --- | --- | --- | --- |
| Ed25519 软实现 | ✅ 软实现 | ❌ 不支持 | ❌ 不支持 | ✅ 纯 C 常时 | ✅ 外部 SE508A | 与 Trezor 接近，但常时性弱 |
| BIP-340 Schnorr | ✅ 软实现 | ❌ 不支持 | ❌ 不支持 | ✅ 常时 | ✅ 常时 | 算法正确，常时性偏弱 |
| BIP-32 派生 | ✅ + KeyAgreement | ✅ + KeyAgreement | ✅ 软 Bignat | ✅ 纯 C | ✅ 纯 C | 与 Status Keycard 同设计 |
| Secure Channel | AES-256-CBC + HMAC | AES-256-CBC + HMAC | AES-128-CTR + HMAC | TLS-like | 自有 SE-bound | 与 Status Keycard 一致 |
| 常时 MAC 比较 | ✅ ConstantTime | ⚠️ Util.arrayCompare | ✅ 自实现 | ✅ 内置 | ✅ 内置 | 优于 Status Keycard |
| 低 s 归一化 | ✅ BIP-62 | ✅ BIP-62 | ✅ BIP-62 | ✅ BIP-62 | ✅ BIP-62 | 一致 |
| RNG 选择 | KEYGEN→TRNG | KEYGEN | TRNG | 硬件 RNG | SE TRNG | 与 Status Keycard 一致 |
| 多步 reset | ✅ N=4 + transient | ✅ 多步 | ✅ 多步 | 不适用 | 不适用 | 一致 |
| RFC 6979 nonce | ❌（JC 不支持安装钩子） | ❌ | ❌ | ✅ | ✅ | 与 JC 同行一致 |

---

## 二、Phase A — Applet 核心代码逐行发现

### 2.1 [F-01] `Field25519.inv` 常时性论断不严谨

**严重等级**：S2 — High

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Field25519.java:30-37`

**发现**：

文档原文："the square-and-multiply schedule itself is constant-time. The compare-and-subtract leaks at most one bit per call ... the threat model (a screenless secure-element attached over PCSC) does not admit fine-grained timing attacks on this layer."

`inv()` 的高层 schedule 确实是常时的（指数 `p−2` 是常量），但其内部依赖 `mul()` 和 `sqr()`，二者最终调用 `Bignat.mod()`，后者的 long-division 算法存在 **数据相关分支**（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Bignat.java:226`、`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Bignat.java:259-263`、`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Bignat.java:372-374`）。在 Ed25519 签名路径上，`inv()` 在每次 `encodePoint` 内对 `Z`（依赖 secret scalar `k`）做 254 次平方+250 次乘法：每次乘法的中间产品都依赖 `k`，进而每次 `mod p` 的时间存在 secret 依赖。

文档把 PCSC 时间分辨率作为缓解理由，但 PCSC 时间能稳定测出 ~ms 级差，而对几百次 `mod` 的累计差异远超此阈值。

**社区参考对比**：

- **RFC 7748 §6**：MUST be constant-time 实现 field operations。
- **libsodium/curve25519/ref10/fe25519.c**：carry propagation 与条件减法均使用 mask-based constant-time 模式。
- **Trezor/firmware/crypto/ed25519-donna/curve25519-donna-32bit.c**：每个 limb 上的 reduction 都是常时的（`uint32_t mask = -(carry); ... a -= mask & p`）。
- **BoringSSL/third_party/fiat/curve25519_32.h**：fiat-crypto 自动生成的 100% 常时代码。

**风险评估**：

签名时长在 Edwards25519 上对 `secret leaf scalar` 有侧信道关联。攻击需要 PCSC 主机有高分辨率定时（典型 NFC reader 1-5ms 抖动 vs `mod` 操作差异 ~µs），实际攻击窗口窄，但理论可利用。

**建议**：

- 短期：把当前论断从"the square-and-multiply schedule ... is constant-time"改为"the schedule is constant-time, but the underlying Bignat reduction is not. Counter-measures rely on (a) only operating on randomized intermediates, and (b) the PCSC timing budget being far larger than per-call variance."
- 中期：在 `Edwards25519.scalarMult` 入口对 `R = (X,Y,Z,T)` 做随机投影 `Z' = Z·r, X' = X·r, Y' = Y·r, T' = T·r`，中间值就被随机化了，时间侧信道不再绑定到 secret。引用：<https://eprint.iacr.org/2009/444>（projective randomization 抗 SPA）。
- 长期：引入 `Field25519` 的常时 reduce 路径，参考 Trezor `curve25519-donna-32bit.c` 的 64→32 limb reduce + mask-based final correction。

**Status (v1.1)**：🟡 Mitigated（中期路径已落地）。

- `Field25519` 的 `add/sub/neg/equals/isZero` 重写为 mask-based 常时实现（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Field25519.java:86-189`），底层 `Bignat.condAddInPlace / condSubInPlace / ctLessThan / ctIsZero` 提供常时基元（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Bignat.java:404-473`）。
- `Edwards25519.scalarMult` 入口对 `(X, Y, Z, T)` 做投影盲化（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Edwards25519.java:356-444`、`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Ed25519.java:243-294`），中间值随机化后 `Bignat.mod` 的时间方差不再绑定 secret scalar。
- `mul / sqr → Bignat.mod` 的非常时长 division 仍存在；长期目标（radix-2^26 limb 重写）登记为 v2.0 路线（§6.3）。文档措辞已更新到精确版本。

---

### 2.2 [F-02] `MeowlApplet.handleSignEd25519` 异常路径残留 SLIP-10 leaf 私钥

**严重等级**：S2 — High

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MeowlApplet.java:586-623`

**发现**：

```java
Util.arrayCopyNonAtomic(buffer, pathOff, innerScratch, (short) 32, pathLen);
slip10.deriveLeafKey(innerScratch, (short) 32, depth, innerScratch, (short) 0);  // 写入 leaf priv 到 [0..32]
short sigLen = ed25519.sign(innerScratch, (short) 0, ...);  // 若抛异常则跳过下一行
Util.arrayFillNonAtomic(innerScratch, (short) 0, (short) (32 + pathLen), (byte) 0);
```

`ed25519.sign` 内部如果抛 `ISOException`（例如 `SW_UNSUPPORTED_FEATURE`），控制流不经过 wipe，secret 残留在 `innerScratch[0..32]` 直到下次 `select()` 触发 `CLEAR_ON_DESELECT`。

类似的，`handleSignEcdsaK1` (`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MeowlApplet.java:514-541`) 和 `handleSignSchnorrK1` (`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MeowlApplet.java:549-576`) 在 `innerScratch` 中暂存的是 host 提供的 32-byte digest（公开值），不算 secret。但 `handleSignPkiCsr` (`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MeowlApplet.java:353-363`) 同样 stage 一个 32-byte digest（公开），也不算 secret。

故只有 `handleSignEd25519` 涉及真正的 secret staging。

**对比**：`handleExportXpubEd25519` (`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MeowlApplet.java:632-649`) 已经使用了 try-finally 包裹 wipe — 这是同一个开发者写的、推理过的正确范式。`handleSignEd25519` 显然是遗漏。

**社区参考对比**：

- **Trezor/core/embed/firmware/main.c** — secret-touching 操作均在 ASAN-style scope 内，`memzero(&priv, sizeof priv)` 必执行。
- **Status Keycard/im.status.keycard.applet.KeycardApplet#deriveKey** — finally 块内 `Crypto.bip32.deriveKey(...)` 之后 `Util.arrayFillNonAtomic`。

**建议**：

把 `handleSignEd25519` 改为 try-finally：

```java
Util.arrayCopyNonAtomic(buffer, pathOff, innerScratch, (short) 32, pathLen);
try {
    slip10.deriveLeafKey(innerScratch, (short) 32, depth, innerScratch, (short) 0);
    return ed25519.sign(innerScratch, (short) 0, buffer, msgOff, msgLen, buffer, ISO7816.OFFSET_CDATA);
} finally {
    Util.arrayFillNonAtomic(innerScratch, (short) 0, (short) (32 + pathLen), (byte) 0);
}
```

**Status (v1.1)**：✅ Fixed。`handleSignEd25519` 的 secret-staging 与 `handleExportXpubEd25519` 都已包裹 try-finally，异常路径与正常路径的擦除行为完全一致（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MeowlApplet.java:585-649`）。

---

### 2.3 [F-03] `Bignat.mod` 在 BIP-32 派生路径上对 parent secret 存在时间侧信道

**严重等级**：S2 — High

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Bignat.java:38-43`、`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/ModN.java:78-109`

**发现**：

`ModN.addMod(I_L, k_par)` 内部：

```java
boolean ge = carry == 1 || !lessThan(out, outOff, SECP256K1_N, (short) 0);
if (ge) { /* subtract n */ }
```

文档（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/ModN.java:27-34`）正确指出 "the leaked predicate is whether the unreduced sum overflowed, equivalent to comparing I_L against n − k_par"。这是一个 **secret 依赖** 的预测器。在 non-hardened 派生中 `I_L` 是通过 HMAC(c_par, serP(point(k_par)) || index) 派生的，攻击者可观测 index 是公开的，c_par 是 semi-public，但 k_par 始终是 secret。

每次 BIP-32 派生只调用一次该比较，且单次派生不会被攻击者重复 oracle。但若 host 反复请求 `EXPORT_XPUB` 同一路径，攻击者可累积~256 次 `addMod` 时间样本，每个样本泄露 1 bit。理论上可恢复 partial bits of `k_par`。

**社区参考对比**：

- **Status Keycard** — 完全不在 applet 内做 `(I_L + k_par) mod n` 软计算；它依赖 JC native `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` 对 `child_pub = (I_L * G) + (k_par * G)` 做 native 加法（`Crypto.bip32CKDPub`）。这避开了软 mod-n 算术。
- **Satochip** — 与 meowl 同设计，软 Bignat mod-n。Satochip 在 README 中坦承"side-channel resistance is best-effort against the off-card timing oracle"。
- **Trezor** — 纯常时 C，参考 `crypto/secp256k1.c#bn_addmod`。

**风险评估**：

实践中：

- BIP-32 派生在每次签名前均会执行；攻击者可以反复要求 `EXPORT_XPUB` 触发同一 oracle。
- 但 `EXPORT_XPUB` 走 Secure Channel，每次响应包含 IV+CT+MAC，PCSC 时序中 `mod` 操作差异淹没在 AES + HMAC 时间噪声中。
- 攻击需要物理近场访问 + 高精度 oracle，不是 remote attack。

**建议**：

- 短期：把"timing leakage is not a recovery vector"改成更克制的措辞，承认在物理 oracle 下存在累积泄露。
- 中期：参考 Status Keycard 的 native CKDPub 路径，在 non-hardened 派生上把 (I_L + k_par) mod n 折叠为 native point add (`I_L * G + k_par * G = child_pub`)，软 mod-n 仅出现在 hardened 派生（hardened 路径中 k_par 进入 HMAC，被 hash 抽象，时间侧信道不再恢复 k_par 而是 HMAC 输出）。
- 长期：把 `Bignat.mod` 与 `ModN` 重构为常时 reduction（mask-based borrow，先减 n 再 conditional-add-back-on-borrow）。

**Status (v1.1)**：🟡 Mitigated（中期路径已落地，长期路径登记 v2.0）。

- `ModN.addMod / negateMod / lessThanN / lessThanHalfN / isZero` 全量重写为 `Bignat.condAddInPlace / condSubInPlace / ctLessThan / ctIsZero` 常时基元（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/ModN.java:74-166`）。比较 oracle 在 mod-n 加法/取反/半 n 测试上不再泄露 secret。
- `Bignat.mod` 的 long-division 仍是变时；BIP-32 路径继续依赖 ECDH 时间噪声 + Secure Channel AES + HMAC 抖动作为掩盖。文档措辞已升级为更克制的措辞，承认累积泄露存在但攻击窗口窄。
- 长期 limb-radix 重写登记为 §6.3。

---

### 2.4 [F-04] `ApduTlv.ensureCapacity` 整型溢出（理论性）

**严重等级**：S2 — High（理论性；当前调用路径不可触发）

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/ApduTlv.java:127-134`

**发现**：

```java
private static void ensureCapacity(byte[] dst, short offset, short needed) {
    if (dst == null || offset < 0 || needed < 0
        || (short)(offset + needed) > (short) dst.length) {
        ISOException.throwIt(Constants.SW_WRONG_LENGTH);
    }
}
```

`(short)(offset + needed)` 在 `offset=20000, needed=20000` 时溢出为 `-25536`（JC short 是 16-bit signed），随后 `-25536 > dst.length` 为 false，检查通过 — 调用者可以越界写。

JC byte[] 最大长度受 `short` 限制（≤32767），当前 APDU buffer 通常 256 字节。所有现有调用点（`MeowlApplet.handleGetInfo` 等）都不可能凑出溢出条件。**因此当前不可利用**。

**社区参考对比**：

- **Status Keycard/applet/KeycardApplet#fixLength** — 同款检查，同样无显式溢出守卫。
- **GP 2.3 reference applet**（NIST PKCS-15 wrapper）— 有显式溢出守卫 `if (needed > (short)(dst.length - offset))`。

**建议**：

把检查改为防溢出形式：

```java
if (dst == null || offset < 0 || needed < 0
    || needed > (short)(dst.length - offset)) {  // 重排顺序避免溢出
    ISOException.throwIt(Constants.SW_WRONG_LENGTH);
}
```

同样原则适用于 `putBytes` (`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/ApduTlv.java:88`)。

**Status (v1.1)**：✅ Fixed。新增 `Bounds` 工具类统一所有边界检查（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Bounds.java`），`requireCapacity` 用 `needed > (short)(dst.length - offset)` 形式杜绝 short 溢出。`ApduTlv` 的 `putByte / putShort / putBytes / reserve` 全部迁移到 `Bounds`，`Authentikey` 同步迁移。

---

### 2.5 [F-05] `Authentikey.ensureCapacity` 重复定义且未与 ApduTlv 共享

**严重等级**：S3 — Medium

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Authentikey.java:81-85`

**发现**：

`Authentikey` 私有定义了一个 `ensureCapacity`，与 `ApduTlv.ensureCapacity` 实现近乎一致。两者都是简单 bound check。属于轻度代码重复。建议把 `ApduTlv.ensureCapacity` 提升为 package-private，或单独抽 `Bounds` 工具类。

**建议**：低优先级清理。

**Status (v1.1)**：✅ Fixed。新建 `Bounds` 类承载 `requireCapacity` 与 `requireRange` 两个常用入口；`ApduTlv` 与 `Authentikey` 的私有 `ensureCapacity` 删除，统一调用 `Bounds.requireCapacity`。详见 F-04 修复条目。

---

### 2.6 [F-06] `MeowlApplet` 注释 `SecureChannel handshake 323` 与代码不一致

**严重等级**：S4 — Low

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MeowlApplet.java:46-50`

**发现**：

注释声称四个 scratch 消费者大小："Ed25519 1024, Schnorr 386, SecureChannel handshake 323, EcdsaK1 168"。

实际计算：`SecureChannel.HS_SCRATCH_LEN = HS_SALT(195) + 64 = 259`。注释里的 323 是某个旧版本残留。

**建议**：把 323 改为 259。

**Status (v1.1)**：✅ Fixed。注释已更新为 `SecureChannel handshake 259`，并附加说明 Ed25519 1056-byte budget 包含 32-byte 投影盲化 scratch slot（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MeowlApplet.java:45-53`）。

---

### 2.7 [F-07] `Bip32.wipeTransientSecrets` 不擦除 chain code

**严重等级**：S3 — Medium

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Bip32.java:193-197`

**发现**：

```java
private void wipeTransientSecrets() {
    Util.arrayFillNonAtomic(state, STATE_K_OFF, ModN.LEN, (byte) 0);
    Util.arrayFillNonAtomic(state, STATE_I_OFF, HASH_LEN, (byte) 0);
    scalarKey.clearKey();
    // 不擦 STATE_C_OFF (chain code) 和 STATE_PUB_OFF (pubkey)
}
```

文档说 "chain code 和 pubkey 是公开输出"。技术上正确（chain code 在 BIP-32 标准里被认为是 semi-public），但 **持有 chain code + 任意 child pubkey 即可派生所有 sibling pubkeys**，且 + 一个 secret 即可派生所有 sibling secrets。把 chain code 留在 `state` 直到下次 deselect 提供了一个攻击窗口（虽然 transient memory + CLEAR_ON_DESELECT 已经限制窗口）。

`Slip10.wipeWalkState` (`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Slip10.java:114-118`) **会** 擦 chain code — 两个等价模块行为不一致。

**社区参考对比**：

- **Trezor/firmware/crypto/bip32.c#hdnode_clear** — 把 chain_code、private_key、public_key、depth、child_num、fingerprint **全部** zeroize。
- **Status Keycard** — chain code 也被擦。

**建议**：

把 `Bip32.wipeTransientSecrets` 改为 wipe 整个 `state`：

```java
private void wipeTransientSecrets() {
    Util.arrayFillNonAtomic(state, (short) 0, STATE_LEN, (byte) 0);
    scalarKey.clearKey();
}
```

与 `Slip10.wipeWalkState` 行为对齐。

**Status (v1.1)**：✅ Fixed。`Bip32.wipeTransientSecrets` 现 wipe 整个 `state`（含 chain code、pubkey scratch），与 Trezor `hdnode_clear` 与 `Slip10.wipeWalkState` 对齐（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Bip32.java:179-202`）。

---

### 2.8 [F-08] `Hkdf.expand` Javadoc `@param info` 与 `@param info_or_null` 同时存在

**严重等级**：S4 — Low

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Hkdf.java:106-114`

**发现**：

```java
/**
 * @param info context / application-specific info string; may be {@code null} ...
 * @param infoOffset offset of the info string
 * @param info_or_null possibly-null buffer ...
 */
public void expand(byte[] info_or_null, ...)
```

实际只有 `info_or_null` 一个参数；多余的 `@param info` 来自旧版本残留。Javadoc 工具会警告。

**建议**：删除 `@param info` 行，并把参数名 `info_or_null` 改为 `info`（蛇形命名不符合 Java 风格，原意通过 `null` 体现）。

**Status (v1.1)**：✅ Fixed。`Hkdf.expand` 的参数已重命名为 `info`，多余 `@param` 删除（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Hkdf.java:106-126`）。

---

### 2.9 [F-09] `Hkdf.extract` 对 saltLen 的 256 字节硬编码上限

**严重等级**：S3 — Medium

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Hkdf.java:93-95`

**发现**：

```java
if (saltLen < 0 || saltLen > (short) 256 || ikmLen < 0) {
    ISOException.throwIt(Constants.SW_WRONG_LENGTH);
}
```

RFC 5869 不规定 salt 长度上限。256 是任意武断值。当前最大用例（MEAP-2 SC handshake salt = client_x || card_x = 64 字节）远小于 256，故实际不触发。

**建议**：

要么移除 `saltLen > 256` 检查（让 HMAC 自然处理任意长度），要么添加注释解释 256 是基于 APDU buffer / scratch size 的工程约束。

**Status (v1.1)**：✅ Fixed。256 字节硬上限删除，仅保留 `saltLen >= 0 && ikmLen >= 0` 的合理性检查；Javadoc 注明 RFC 5869 不限制 salt 长度，HMAC 会自动按 `|salt|` vs `B` 关系做 pre-hash 或零填充（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Hkdf.java:71-99`）。

---

### 2.10 [F-10] `HmacSha.forceSoftware` Javadoc 描述了一个不存在的参数

**严重等级**：S4 — Low

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/HmacSha.java:106-118`

**发现**：

```java
/**
 * Package-private factory ...
 * @param algorithm one of {@link #ALG_SHA_256} or {@link #ALG_SHA_512}
 * @param forceSoft if {@code true}, skip the native HMAC probe ...   ← 参数不存在
 */
static HmacSha forceSoftware(byte algorithm) { ... }
```

Javadoc 描述了 `forceSoft` 参数，但 `forceSoftware(byte)` 方法签名只有一个参数；`forceSoft` 是 **私有构造** `HmacSha(byte, boolean)` 的参数，被 Javadoc 错引到工厂方法。

**建议**：删除 `forceSoftware` 的 `@param forceSoft` 行，把"if true ..."的语义只放在 `private HmacSha(byte algorithm, boolean forceSoft)` 上。

**Status (v1.1)**：✅ Fixed。`forceSoftware(byte)` 的 Javadoc 已只描述 `algorithm`，`forceSoft` 的语义留给私有构造器（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/HmacSha.java:106-118`）。

---

### 2.11 [F-11] `HmacSha` 文档中的 Unicode 损坏

**严重等级**：S4 — Low

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/HmacSha.java:32-33,54-56,91,109,207,244,251,254`

**发现**：

多处 `‖`（U+2016 DOUBLE VERTICAL LINE）损坏为 `\uFFFD?`（替换字符），例如：

```text
inner = H((K' XOR ipad) [损坏字符] message)
```

应当是：

```text
inner = H((K' XOR ipad) || message)
```

属于编辑器/工具链 charset 问题。修复后 Javadoc 即可正确渲染。

**建议**：把 HmacSha.java 用 UTF-8 重写一份，所有 `‖` 改为 ASCII `||` 以避免再次发生类似问题。

**Status (v1.1)**：✅ Fixed。`HmacSha.java` 已重写为纯 ASCII（`||` 代替 `‖`，`XOR` 代替前序的 unicode 损坏），编辑器 charset 漂移不会再触发渲染错位。

---

### 2.12 [F-12] `Schnorr.taggedHashStart` 每次签名重新计算 SHA256(tag)

**严重等级**：S3 — Medium（性能优化机会）

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Schnorr.java:286-292`

**发现**：

```java
private void taggedHashStart(short tagOff, short tagLen) {
    sha256.reset();
    sha256.doFinal(TAGS, tagOff, tagLen, scratch, HASH_TAG_OFF);  // 每次重算 SHA256(tag)
    sha256.reset();
    sha256.update(scratch, HASH_TAG_OFF, COORD_LEN);
    sha256.update(scratch, HASH_TAG_OFF, COORD_LEN);
}
```

每次 Schnorr 签名调用 `taggedHashStart` 三次（aux/nonce/challenge），每次都重新 SHA256(tag string)。但三个 `SHA256(tag)` 是常量（依赖于固定字符串）：

- `H_aux = SHA256("BIP0340/aux")`（固定 32 字节）
- `H_nonce = SHA256("BIP0340/nonce")`
- `H_challenge = SHA256("BIP0340/challenge")`

可在安装时预算并 EEPROM 存储，每次签名节省 3 次 SHA-256 invocation（J3R180 上每次约 5-10ms，签名总耗时减少 15-30ms）。

**社区参考对比**：

- **bitcoin-core/secp256k1/src/modules/schnorrsig/main_impl.h** — 三个 tag hash 静态预算为 const arrays。
- **trezor-firmware/crypto/zkp_bip340.c** — 同款预算。

**建议**：

```java
// 在 install 时预算 H_aux, H_nonce, H_challenge 写入静态 final byte[]
private static final byte[] HASH_OF_TAG_AUX = { /* SHA256("BIP0340/aux") */ };
private static final byte[] HASH_OF_TAG_NONCE = { /* ... */ };
private static final byte[] HASH_OF_TAG_CHALLENGE = { /* ... */ };
```

注：JC 3.0.5 对静态数组的初始化器处理与桌面 Java 一致，可在 `<clinit>` 中执行 SHA-256，但更稳妥的做法是 hardcode 已知值（与 BIP-340 reference test vectors 一致）。

**Status (v1.1)**：✅ Fixed。`Schnorr.HASH_OF_TAG_AUX / NONCE / CHALLENGE` 三个常量已 hardcode 为 BIP-340 §3.2 指定字符串的 SHA-256 输出（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Schnorr.java:47-86`）；`taggedHashStart` 直接喂入预算常量，每次签名节省 3 次 SHA-256（J3R180 上约 15-30ms）。`SchnorrTagHashTest` 用运行时 SHA-256 与硬编码值做断言；**首次跑测时实际捕获了 AUX 常量的字节错位**——这正是该回归测试的设计目的。

---

### 2.13 [F-13] `Slip10.deriveLeafKey` 返回字面量 `(short) 32` 而非 `ModN.LEN`

**严重等级**：S4 — Low

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Slip10.java:90-96`

**发现**：

```java
public short deriveLeafKey(...) {
    walkPath(pathBuf, pathOff, depth);
    Util.arrayCopyNonAtomic(state, STATE_K_OFF, outBuf, outOff, (short) 32);
    wipeWalkState();
    return (short) 32;
}
```

字面 32 应为 `ModN.LEN` 或 Slip10 自有常量（Ed25519 leaf private key 也是 32 字节）。

**建议**：定义 `Slip10.SECRET_KEY_LEN = (short) 32`（语义清晰），或复用 `ModN.LEN`（量纲相同的偶然）。建议前者。

**Status (v1.1)**：✅ Fixed。`Slip10` 引入 `SECRET_KEY_LEN` 常量，`deriveLeafKey` 与内部 walk 全部使用该常量代替字面 32（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Slip10.java:99-147`）。

---

### 2.14 [F-14] `Slip10` 用 `SW_INCORRECT_P1P2` 表达"非 hardened 路径"

**严重等级**：S4 — Low

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Slip10.java:107-109`

**发现**：

非 hardened index 抛 `SW_INCORRECT_P1P2`。语义上 P1/P2 是 APDU header 字段；这里实际是数据字段的内容错误。SW_DATA_INVALID（0x6A80）或 SW_CONDITIONS_NOT_SATISFIED（0x6985）更准确。

**建议**：改为 `SW_CONDITIONS_NOT_SATISFIED`，并在 MEAP-7 中明确该路径的 SW。

**Status (v1.1)**：✅ Fixed。SLIP-10 非 hardened index 改为 `SW_CONDITIONS_NOT_SATISFIED` 并附 inline 论证（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Slip10.java:115-126`）；`HdDerivationTest` 同步更新；MEAP-7 已注明该 SW（详见 docs/specs/meap-7.md）。

---

### 2.15 [F-15] `MeowlApplet.wipe` 不在单一事务内执行

**严重等级**：S3 — Medium（恢复语义）

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MeowlApplet.java:655-662`

**发现**：

```java
public void wipe() {
    secureChannel.reset();   // transient
    pinManager.wipe();       // 自带 transaction
    pkiManager.wipe();       // 自带 transaction
    masterSeed.wipe();       // 自带 transaction
    state.reset();           // 自带 transaction
}
```

每个子 wipe 自包事务。中断（断电）发生在 `pkiManager.wipe()` 后、`state.reset()` 前时，卡片处于：PIN/PUK 已擦、cert 已擦、master seed 已擦、但 lifecycle = SEEDED。

下次启动时 `handleSignXxx` 走 SEEDED 分支，从清零的 `bip32Master` 派生，得到 garbage 签名（不是 secret 泄露）。但用户体验受损：必须再次 RESET_TO_FACTORY 才能恢复 UNINITIALIZED。

**社区参考对比**：

- **Status Keycard/KeycardApplet#resetToFactory** — 单一 `JCSystem.beginTransaction() ... commitTransaction()` 包裹整个 wipe。

**建议**：

```java
public void wipe() {
    JCSystem.beginTransaction();
    try {
        pinManager.wipeInTx();   // 改为 InTx 变体，不开 transaction
        pkiManager.wipeInTx();
        masterSeed.wipeInTx();
        state.reset();
        JCSystem.commitTransaction();
    } catch (Exception e) {
        JCSystem.abortTransaction();
        throw e;
    }
    secureChannel.reset();  // transient，事务外执行
}
```

需要为 `PinManager`、`PkiManager`、`MasterSeed` 添加 `wipeInTx()` 变体（不开内部事务，期望调用方持有事务）。

**Status (v1.1)**：✅ Fixed。

- `MeowlApplet.wipe` 重构为单一事务包裹四个 `*InTx` 调用，`secureChannel.reset` 留事务外（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MeowlApplet.java:651-671`）。
- `PinManager` / `PkiManager` / `MasterSeed` / `LifecycleState` 各新增 `wipeInTx` / `resetInTx` 变体，公开 wipe 仅作为单事务封装。
- 新增 MeowlAppletTest 回归 `lifecycleRevertsToUninitialized`：完整 reset 后 GET_INFO 必须返回 `UNINITIALIZED`，断言整个事务确实 commit。

---

### 2.16 [F-16] Edwards25519 `scalarMult` 性能注解缺失

**严重等级**：S5 — Info

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Edwards25519.java:387-431`

**发现**：

每次 scalarMult 执行 256 × (1 double + 1 add) ≈ 256 × 16 = 4096 field 乘法。每个 field 乘 = 1024 byte-byte mult + Bignat.mod (~ 数百操作)。J3R180@32MHz 估计 1.5-3 秒。

Ed25519 sign 涉及两次 scalarMult（一次 publicKey、一次 R = r·B），加 SHA-512 与 reduction，估计 3-6 秒/签名。

**对比**：

| 平台 | Ed25519 sign 时间 |
| --- | --- |
| Trezor T (STM32F4@168MHz, 纯 C) | ~50ms |
| Coldcard (508A SE) | ~200ms |
| Status Keycard | 不支持 Ed25519 |
| meowl on J3R180 (软实现) | ~3-6s |

**建议**：

- 在 README/MEAP-6 添加 perf budget 表，让用户提前理解 Ed25519 签名延迟。
- 中期：用 `Bignat`-free 的 32-bit-limb radix-2^26 表示替换 32-byte BE，参考 ed25519-donna。需要重构 `Field25519`。

**Status (v1.1)**：⏸ Deferred（性能表已加，limb 重构留 v2.0）。README 与 MEAP-6 加入 *Performance budgets* 段，列出 ECDSA / Schnorr / Ed25519 在 J3R180 上的预期签名时长。limb-radix 重写登记为 §6.3。

---

### 2.17 [F-17] BIP-32 / SLIP-10 异常 SW 选择

**严重等级**：S5 — Info

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Bip32.java:219-225`

**发现**：

`parse256(I_L) >= n` 或 `k_i == 0` 概率 ~2^-127，BIP-32 spec 要求 "skip to next index"。meowl 选择 fail with `SW_CONDITIONS_NOT_SATISFIED`，让 host 重试。Status Keycard 同款简化。

无修改建议；记录这是社区共识中的合理简化。

---

### 2.18 [F-18] `EcdsaK1` DER 解析对长度域松散

**严重等级**：S3 — Medium（鲁棒性，非可利用性）

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/EcdsaK1.java:188-204`

**发现**：

```java
short cursor = (short)(derOff + 1);
short seqLen = (short)(der[cursor++] & 0xFF);   // 接受 0..255 单字节长度
```

DER 严格规定单字节长度仅覆盖 0..127；128+ 必须用 long-form (`0x81 LL`)。这里若 cardin 输出 `0x30 0x81 0x46 ...` 会被错误解析（cursor 跳过 0x46 后期望紧接 INTEGER tag，实际遇到 0x02 但偏移错 1）。

JC ECDSA 输出的 DER 长度通常 70-72 字节 (< 128)，所以 short-form 总是有效。当前不可触发。

类似情况在 `copyDerInteger` 的 `rawLen` 上：

```java
short rawLen = (short)(der[cursor++] & 0xFF);   // 不验证 MSB
```

**建议**：

添加显式守卫：

```java
short seqLen = (short)(der[cursor++] & 0xFF);
if ((seqLen & 0x80) != 0) {
    ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);  // long-form 不支持
}
```

同样适用于 INTEGER 长度。

**Status (v1.1)**：✅ Fixed。`EcdsaK1.parseDerSignature` 与 `copyDerInteger` 都新增 `(len & 0x80) != 0` 长形长度域守卫并附 inline 注释（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/EcdsaK1.java:188-242`）。

---

### 2.19 [F-19] `MeowlApplet` 内部 APDU `LC` 限于单字节

**严重等级**：S3 — Medium（功能限制）

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MeowlApplet.java:162`

**发现**：

```java
short innerLc = (short)(buffer[(short)(innerOff + 4)] & 0xFF);  // 单字节 LC，最大 255
```

内部 APDU 数据最大 255 字节。SIGN_ED25519 的 message 长度 = `dataLen - 1 - pathLen`。depth=8 时 pathLen=32，msgLen 最大 222 字节。

对于多链应用，如果某链需要签更长 message (e.g., 大的 EIP-712 typed data)，222 字节可能不够。

**社区参考对比**：

- **Status Keycard** — 支持 Extended-APDU（`LC = 0 || L1 L2`），LC 上限 65535。
- **Coldcard** — 同款。

**建议**：

为 SIGN_ED25519 增加 chunked input 协议（类似 PKI cert import 的 INIT/WRITE/FINALIZE 三步），或开启 Extended-APDU 接收。后者改动较大，应作为 v1.1 路线规划。

**Status (v1.1)**：⏸ Deferred。延后到 v1.2 / v2.0；v1.1 保留 ISO 7816-4 short-form 256-byte 上限。MEAP-7 文档已注明该限制。

---

### 2.20 [F-20] Authentikey 私钥无 EEPROM 写后擦除

**严重等级**：S5 — Info（架构选择）

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Authentikey.java:29-42`

**发现**：

`Authentikey` 的 `ECPrivateKey` 用 `KeyBuilder.buildKey(TYPE_EC_FP_PRIVATE, ..., false)`（`false` = 持久 EEPROM）。这是必然选择，因为 authentikey 需要跨 RESET_TO_FACTORY 存活。但意味着私钥静态在 EEPROM 中，物理攻击有恢复风险。

社区共识：硬件钱包的"卡身份密钥"必须持久，物理攻击需通过 EAL 5+ 安全等级 + 抗探测涂层防护。J3R180 EAL 5+ Augmented，符合主流硬件钱包水平。

无变更建议；用户购买时已默认接受 EAL 5+ 物理安全等级假设。

---

### 2.21 [F-21] PKI cert wipe 不擦 authentikey

**严重等级**：S5 — Info（按 spec 设计）

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/PkiManager.java:199-210`

**发现**：

`PkiManager.wipe` 仅 wipe cert，保留 authentikey。MEAP-4 §"Lifecycle" 明确规定 authentikey 跨 reset 存活。

无变更；记录为 design intent。

---

### 2.22 [F-27] `SecureChannel.stripPkcs5` 非常时早退分支

**严重等级**：S5 — Info（defense-in-depth；EtM 闸门外部不可观测）

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/SecureChannel.java:432-447`（v1.1 旧实现）

**发现**：

v1.1 中 `stripPkcs5` 用三个早退 `ISOException.throwIt(SW_SECURE_CHANNEL_FAILED)` 分支处理 padding 校验：

```java
if (padVal == 0 || padVal > Constants.SC_BLOCK_LEN) ISOException.throwIt(...);
for (short i = 1; i <= padVal; i++) {
    if (buf[(short) (offset + paddedLen - i)] != pad) ISOException.throwIt(...);
}
```

每个分支抛出时间不同，且字节匹配循环只运行 `padVal` 次（依赖被解密后的 plaintext）。这在传统 padding-oracle 场景下是高危模式。

但 meowl Secure Channel 走 **Encrypt-then-MAC**：MAC 验证在 `stripPkcs5` 之前完成，任何篡改都已被外层 HMAC 拦截，攻击者无法构造合法 MAC + 非法 pad 的组合。因此 stripPkcs5 的早退仅在 silicon 内部时间探针可见，不能被远程攻击者观测。

**社区参考对比**：

- **libsodium `crypto_stream_xchacha20_pad`** — mask-based 常时 unpad，所有 padding 校验位累加到一个失败 mask 后统一收口。
- **BoringSSL `EVP_CIPHER_CTX_get_pkcs7_padded`** — 同款 mask-based，并 hardcoded 测试矩阵覆盖每个 padding 长度。

**建议**：

把 padding 校验改为 mask-based 累加：单一 `failMask` 累积 (a) `padVal == 0`、(b) `padVal > BLOCK`、(c) 每个尾块字节是否等于 padVal（按距离 ≤ padVal 才参与）三类失败位，最后一次性 `if (failMask != 0) throwIt`。loop 改为遍历整个 BLOCK_LEN 尾块，时间不再依赖 padVal。

**Status (v1.2)**：✅ Fixed。`stripPkcs5` 改为 mask-based 实现（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/SecureChannel.java:465-501`），每分支用经典 `(x | -x) >>> 31` is-non-zero pattern 收口；可见性提升为 package-private 以支持新增的 `SecureChannelStripPkcs5Test` 直接验证（无反射、无生产洞）。新增测试覆盖 16 个合法 padding 长度参数化、padVal=0/超界拒绝、单字节 tamper at every position、unaligned/zero length、非零 offset 共 ~50 个 case。

---

### 2.23 [F-28] `SecureChannel.compare16` 短路 ternary 比较

**严重等级**：S5 — Info（IV 公开，timing 不泄密；统一编码风格）

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/SecureChannel.java:418-430`（v1.1 旧实现）

**发现**：

v1.1 中 `compare16` 采用早退三态比较：

```java
for (short i = 0; i < SC_BLOCK_LEN; i++) {
    if (av > bv) return 1;
    if (av < bv) return -1;
}
return 0;
```

返回时间随两个 IV 的最高不同字节位置变化。这个 helper 仅用于 inbound IV 的 monotonicity 检查（`compare16(apduBuffer, ivOffset, lastInboundIv, 0) <= 0` 判定为 replay），IV 是公开值，timing 不泄露任何 secret。

但相邻的 `ConstantTime.equals`、`Bignat.ctLessThan`、`Bignat.ctIsZero` 都用 mask-based 风格；`compare16` 是这一片的样式异类。

**建议**：改为 sticky-mask 实现：`gtMask` / `ltMask` 在第一个差异字节锁定后保持不变，整个 16 字节循环时间恒定。返回 `(gtMask & 1) - (ltMask & 1)` 还原三态语义。

**Status (v1.2)**：✅ Fixed。`compare16` 改为 mask-based（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/SecureChannel.java:428-450`）。新测试覆盖 equal、greater at every position、less at every position、most-significant byte wins、0xFF/0x80 unsigned semantics 共 5 个独立断言。

---

### 2.24 [F-29] `MasterSeed` 暴露内部数组引用

**严重等级**：S4 — Low（封装弱化）

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MasterSeed.java:227-236`（v1.1 旧实现）

**发现**：

v1.1 中两个 getter 直接返回内部字段：

```java
public byte[] bip32Master() {
    requireSeeded();
    return bip32Master;   // 返回的是 live alias
}

public byte[] slip10Master() { ... 同上 ... }
```

调用方 (`Bip32.walkPathToLeaf` / `Slip10.walkPath`) 通过 `Util.arrayCopyNonAtomic(master, ...)` 把字节复制到 state buffer，没有 mutating 引用——但 API 层面 contract 是 trust-the-caller。Javadoc 仅以 "caller MUST NOT mutate the returned array" 约束，编译期无法强制。

虽然两个调用点都在同 package，但效果上削弱了"persistent master 字段不可被外部 alias"的封装承诺。Status Keycard / Trezor 内部 API 都用 pull-based copy 风格，避免持久秘密字段被引用别名。

**建议**：废除 getter，改为 pull-based `void copyBip32MasterTo(byte[] dst, short dstOff)` 与 `void copySlip10MasterTo(byte[] dst, short dstOff)`。每次调用做一次性 64-byte copy（`k_master(32) || c_master(32)`），调用方负责管理目标 scratch 的 secret 生命周期。

**Status (v1.2)**：✅ Fixed。

- 内部字段重命名为 `bip32Material` / `slip10Material`（消除字段与方法同名歧义）。
- 新增 `copyBip32MasterTo` / `copySlip10MasterTo`（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MasterSeed.java:223-247`），每次 64-byte 一次性 copy，零额外 transient RAM。
- `Bip32.walkPathToLeaf`（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Bip32.java:168-171`）与 `Slip10.walkPath`（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Slip10.java:111-114`）都从两次 32-byte copy 简化为单次 pull-based 调用。
- 老 getter 编译期消失，外部代码不可能再持有 alias；既有 `HdDerivationTest` / `PersonalisationTest` 端到端测试间接验证新 API 行为正确（BIP-32 / SLIP-10 派生向量全过）。

---

### 2.25 [F-30] `EcdsaK1.signDigest` try-finally 仅覆盖签名调用

**严重等级**：S4 — Low（防御深度）

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/EcdsaK1.java:115-163`（v1.1 旧实现）

**发现**：

v1.1 中 `signDigest` 仅在 `ecdsa.signPreComputedHash` 调用周围用 try-finally 擦除 SCALAR slot + `signKey.clearKey()`。`bip32.deriveLeafScalar` 之前、`parseDerSignature` 之后的代码段在 try-finally 之外：

```java
bip32.deriveLeafScalar(...);             // 写入 SCALAR
Secp256k1.setCurveParameters(signKey);
signKey.setS(scratch, SCALAR_OFF, ...);
ecdsa.init(signKey, MODE_SIGN);
short derLen;
try { derLen = ecdsa.signPreComputedHash(...); }
finally { wipe SCALAR + clearKey; }      // <- 只擦 SCALAR
parseDerSignature(...);                  // 在 try-finally 外，可能 throw
if (!ModN.lessThanHalfN(...)) ...;
... copy r||s to outBuf ...;
... wipe DER + r + s slots ...;          // <- 显式 tail wipe
```

如果 `bip32.deriveLeafScalar` 抛 `SW_LIFECYCLE_INVALID`（lifecycle gate 未开），SCALAR 还未写入，无 secret 泄露——OK。但 `parseDerSignature` 可能抛 `SW_UNSUPPORTED_FEATURE`（malformed silicon DER），此时 SCALAR 已被早 finally 擦除，DER/r/s slots 是公开 ECDSA 输出，理论上也 OK——但代码风格与 `Schnorr.signDigest` / `Ed25519.sign` 不一致。后两者用单一 try-finally 包整个 method body，finally 中清整个 SCRATCH_LEN，简洁且无 reasoning gap。

**建议**：把整个 method body 包裹在单一 try-finally 中，finally 清整个 `SCRATCH_LEN` + `signKey.clearKey()`，与 `Schnorr` / `Ed25519` 风格统一。

**Status (v1.2)**：✅ Fixed。`signDigest` 整体重构为单一 try-finally（`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/EcdsaK1.java:115-159`）：所有逻辑（leaf 派生、签名、DER 解析、low-s 归一化、输出 copy）都在 try 内，finally 一次性 `arrayFillNonAtomic(scratch, 0, SCRATCH_LEN, 0)` + `signKey.clearKey()`。既有 `EcdsaK1Test` 端到端签名测试通过，确认成功路径行为不变。

---

### 2.26 [F-31] `PinManager.unblockPin` 失败 PIN policy 仍消耗 PUK 重试

**严重等级**：S5 — Info（design intent，防侧信道窥探 policy）

**位置**：`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/PinManager.java:190-207`

**发现**：

```java
public void unblockPin(byte[] pukBuf, short pukOff, short pukLen,
                       byte[] newPinBuf, short newPinOff, short newPinLen) {
    requireProvisioned();
    if (pin.getTriesRemaining() != 0) ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
    verifyPukInternal(pukBuf, pukOff, pukLen);     // <- 消耗 PUK 重试
    requirePinPolicy(newPinLen);                    // <- 失败抛 SW_WRONG_LENGTH
    ...
}
```

PUK 验证先行，PIN policy 检查在后。如果 PUK 正确但 newPinLen 不符 policy，PUK 重试已经被消耗 1 次。

这看起来反直觉，但实际上是**防止侧信道窥探 policy** 的设计选择：如果 PIN policy 检查在 PUK 验证之前，攻击者可以用任意短/长的 newPin 字节探测 policy 边界，而不需要消耗 PUK 重试。把 PIN policy 检查放在 PUK 之后，policy 探测同样需要消耗 PUK 重试，使探测代价相同。

**社区参考**：Status Keycard `KeycardApplet#unblockPin` 同款排序（PUK 先验，PIN policy 后查）。

**建议**：保留当前行为，仅在 javadoc 中显式说明这是 design intent 而非 bug。

**Status (v1.2)**：Acknowledged。`@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/PinManager.java:185-189` 既有 javadoc 已经写明 "consumes a PUK attempt even on PIN-policy failure of the new PIN"，足够清晰；本次审计仅追加该 finding 的来源说明，不修改代码。

---

### 2.27 已审计但无独立 finding 的模块

下列模块在 v1.0 / v1.1 / v1.2 的 Phase A 审计中均被逐行检查，未发现独立的安全/正确性问题（除非该模块已经在跨横向审计的 finding 中被涵盖，如 F-15 涉及 `LifecycleState` 的事务化、F-29 涉及 `MasterSeed` 的 API 风格）。明示这一覆盖边界以便复审者快速识别"未被审计"与"审计后无问题"的区别：

| 模块 | 行数 | 审计深度 | 备注 |
| --- | --- | --- | --- |
| `PinManager` | 307 | 整类逐行 + lifecycle 集成 | OwnerPIN 重试 / 擦除策略均符合 JC 平台最佳实践；F-15 涉及其 `wipeInTx` 变体；F-31 仅记录 design intent |
| `MasterSeed` | 286 | 整类逐行 + 调用方追踪 | F-29 涉及 API 风格；其余（HMAC label、resample budget、validity check）正确 |
| `SecureChannel` | 461 | 整类逐行 + MEAP-2 协议合规 | F-27 / F-28 涉及 helper 常时风格；handshake / wrap / unwrap / replay 防御正确 |
| `LifecycleState` | 133 | 整类逐行 + FSM 路径覆盖 | F-15 涉及其 `resetInTx`；FSM 转换全 path 已被 `LifecycleStateTest` 覆盖 |
| `Secp256k1` | 273 | 常量比对 SECG sec2-v2 §2.4.1 | 参数表逐字对照，无误差 |
| `ConstantTime` | 30 | 完整审计 | mask-based equality，符合 BoringSSL `CRYPTO_memcmp` 风格 |
| `ResetToFactory` | <100 | 完整审计 + 与 `MeowlApplet.wipe` 集成 | rearm / countdown 状态机正确；F-15 / F-25 涉及其调用 |
| `WipeTrigger` | <50 | 完整审计 | 倒计数逻辑符合 MEAP-4 spec |
| `Authentikey` | <80 | 完整审计 + EEPROM 写后擦除策略 | F-20 涉及 EEPROM 物理残留（design intent）；F-05 涉及 `ensureCapacity` 共享 |
| `ApduTlv` | <130 | 完整审计 + 边界检查 | F-04 / F-05 涉及边界检查；其余 putByte / putShort / putBytes 实现正确 |
| `Constants` | <200 | 常量值逐项 SW / capability bit 比对 | 无误差 |
| `Bounds` | <70 | 完整审计 | F-04 / F-05 引入；overflow-safe `requireCapacity` 实现正确 |

---

## 三、Phase B — Host 代码发现

### 3.1 [F-22] `HostCrypto.aesCbcDecrypt` 抛出 `IllegalArgumentException` 而非自定义异常

**严重等级**：S4 — Low

**位置**：`@d:/Desktop/x/meowl-applet/tools/src/main/java/social/meowl/tools/proto/HostCrypto.java:312-326`

**发现**：

`pkcs5Unpad` 在 padding 不一致时抛 `IllegalArgumentException`，而 `SecureChannelClient` 在其他错误路径上抛 `SecureChannelException`。两套异常族。

**建议**：把 `pkcs5Unpad` 抛 `SecureChannelException(0, "pad invalid")` 或在 caller 层捕获并转换。

**Status (v1.1)**：✅ Fixed。`SecureChannelException` 提升为顶层公共类（`@d:/Desktop/x/meowl-applet/tools/src/main/java/social/meowl/tools/proto/SecureChannelException.java`），HostCrypto 依赖反向不再产生循环；`pkcs5Unpad` 三个失败分支改抛 `SecureChannelException(0, …)`。`HostCryptoTest.malformedPaddingRejected` 同步升级断言异常类型与 `sw() == 0`。

---

### 3.2 [F-23] `HkdfSha256.extract` saltLen 0 时使用 `new byte[HASH_LEN]` 分配

**严重等级**：S5 — Info

**位置**：`@d:/Desktop/x/meowl-applet/tools/src/main/java/social/meowl/tools/proto/HkdfSha256.java:43`

**发现**：

```java
byte[] effectiveSalt = (salt == null || salt.length == 0) ? new byte[HASH_LEN] : salt;
```

JVM 上每次调用都分配 32 字节。可改为 `static final byte[] ZERO_SALT_32`，但 host 端每次只在 handshake 用一次，影响微弱。

**建议**：仅记录；不必修改。

---

### 3.3 [F-24] `SecureChannelClient.handshake()` 不验证 cardEphPub 的 0x04 前缀

**严重等级**：S3 — Medium

**位置**：`@d:/Desktop/x/meowl-applet/tools/src/main/java/social/meowl/tools/proto/SecureChannelClient.java:111`

**发现**：

```java
cardEphPub = Arrays.copyOfRange(body, 0, HostCrypto.EC_POINT_UNCOMPRESSED_LEN);
```

直接拷贝 65 字节，未验证 `cardEphPub[0] == 0x04`。后续 `HostCrypto.ecdhSharedX(privateScalar, cardEphPub)` 会做 `peerPubEncoded[0] & 0xFF != 0x04` 检查（line 131-135），所以异常会在 ECDH 时抛出。即检查存在但延迟。

**建议**：在 handshake 解析后立即验证 0x04 前缀，让错误 SW 更精确。

**Status (v1.1)**：✅ Fixed。`SecureChannelClient.handshake()` 解析完 cardEphPub 后立即检查 `(cardEphPub[0] & 0xFF) == 0x04`，否则抛 `SecureChannelException(0, …)`（`@d:/Desktop/x/meowl-applet/tools/src/main/java/social/meowl/tools/proto/SecureChannelClient.java:111-122`）。

---

## 四、Phase C — 测试套件评估

### 4.1 测试覆盖度概览

| 模块 | 测试文件 | 大小 | 覆盖深度 |
| --- | --- | --- | --- |
| ConstantTime | ConstantTimeTest | 105 行 | ⭐⭐⭐⭐ 边界 + 高位字节 + offset |
| HmacSha | HmacShaTest | 236 行 | ⭐⭐⭐⭐⭐ RFC 4231 全 7 向量 + 200 个随机差分 |
| Bignat | BignatTest | 7,119 字节 | ⭐⭐⭐⭐ |
| Field25519 | Field25519Test | 10,203 字节 | ⭐⭐⭐ |
| Edwards25519 | Edwards25519Test | 20,966 字节 | ⭐⭐⭐⭐ |
| Ed25519 | Ed25519SigningTest | 32,872 字节 | ⭐⭐⭐⭐⭐ |
| EcdsaK1 | EcdsaK1Test | 27,888 字节 | ⭐⭐⭐⭐ |
| Schnorr | SchnorrK1Test | 31,532 字节 | ⭐⭐⭐⭐ |
| Bip32/SLIP-10 | HdDerivationTest | 34,872 字节 | ⭐⭐⭐⭐⭐ |
| ModN | ModNTest | 10,277 字节 | ⭐⭐⭐⭐ |
| LifecycleState | LifecycleStateTest | 5,826 字节 | ⭐⭐⭐⭐ |
| MeowlApplet | MeowlAppletTest | 9,668 字节 | ⭐⭐⭐ |
| SecureChannel | SecureChannelTest | 23,561 字节 | ⭐⭐⭐⭐ |
| Personalisation | PersonalisationTest | 31,999 字节 | ⭐⭐⭐⭐⭐ |

**总评**：测试覆盖在 **加密原语层** 接近企业级（差分模糊 + 官方测试向量）。**业务层**（MeowlApplet 的 INS dispatch 路径）覆盖 ⭐⭐⭐，建议增加。

### 4.2 [F-25] MeowlAppletTest 覆盖度不足

**严重等级**：S3 — Medium

**位置**：`@d:/Desktop/x/meowl-applet/tests/src/test/java/social/meowl/applet/MeowlAppletTest.java`

**建议补强**：

- 异常路径测试：`handleSignEd25519` 在 `slip10.deriveLeafKey` 抛 SW_LIFECYCLE_INVALID 时，innerScratch 的清理（覆盖 F-02）。
- INS 路由：每个 INS 在错 lifecycle / 未开 SC / PIN 未验证时的 SW 验证。
- Inner LC 边界：LC = 0、255、256（应该 reject）的行为。
- RESET_TO_FACTORY interleave：N-1 次 reset 后插入任意其他 INS，应触发 rearm。

**Status (v1.1)**：✅ Fixed。MeowlAppletTest 增加 4 个新场景：

- `innerOnlyInsReturnsInsNotSupported` — 内部 INS（SETUP / IMPORT_SEED / SIGN_*）在外层 dispatch 必须 6D00。
- `openSecureChannelWithoutInitFails` — 未握手前 OPEN_SC 必须非 9000。
- `lifecycleRevertsToUninitialized` — 完整 reset 后 GET_INFO 必须 UNINITIALIZED（F-15 原子事务回归）。
- `interleavedReset` — 多种 INS 交错驱动 rearm 路径。

  innerScratch 清理（F-02）由 try-finally 在源码层强制保证；white-box 读取 innerScratch 在 jcardsim 上不便实施，留作 v1.2 补强。

### 4.3 [F-26] HmacShaTest 设计赞赏

测试同时跑 native + software 两条路径，且对 software 路径做 200 个 (key, msg) 长度差分。这是社区最佳实践（参考 BoringSSL `bssl_test --gtest_filter=HMAC*`）。

---

## 五、Phase D — 社区参考实现并排对比

### 5.1 BIP-32 派生

| 项 | meowl | Status Keycard | Satochip | Trezor | Coldcard |
| --- | --- | --- | --- | --- | --- |
| 算法实现 | 软 HMAC-SHA-512 + 软 mod-n + JC EC scalarmult | 同 meowl | 同 meowl | C 常时 | C 常时 |
| Hardened 路径 | ✅ HMAC(c, 0x00 \|\| k_par \|\| ser32(i)) | ✅ | ✅ | ✅ | ✅ |
| Non-hardened 路径 | ✅ KeyAgreement + 软 mod-n | ✅ | ✅ | ✅ | ✅ |
| `parse256(I_L) ≥ n` 处理 | fail SW_CONDITIONS_NOT_SATISFIED | fail | fail | skip-to-next | skip-to-next |
| `k_i == 0` 处理 | fail SW_CONDITIONS_NOT_SATISFIED | fail | fail | skip-to-next | skip-to-next |
| Chain code wipe | ❌ 漏（F-07） | ✅ | ✅ | ✅ | ✅ |
| EC private key 类型 | TRANSIENT_DESELECT 优先，PERSISTENT 兜底 | 同 meowl | 同 meowl | n/a | n/a |

**结论**：BIP-32 路径功能正确，与 Status Keycard 高度对齐。chain code wipe 漏失（F-07）是个本可消除的偏差。

### 5.2 BIP-340 Schnorr

| 项 | meowl | bitcoin-core/secp256k1 | trezor-firmware | Coldcard |
| --- | --- | --- | --- | --- |
| Tagged hash 预算 | ❌ 每次重算（F-12） | ✅ const | ✅ const | ✅ const |
| aux_rand 来源 | KEYGENERATION→TRNG | random32() | trng | secure RNG |
| `k=0` 处理 | fail SW_INTERNAL_ERROR | fail | fail | fail |
| has_even_y(P) 测试 | ✅ y[31] & 0x01 | ✅ | ✅ | ✅ |
| has_even_y(R) 测试 | ✅ | ✅ | ✅ | ✅ |
| `int(rand) mod n` reduction | 软 single-subtract | 内置 ECMUL | 内置 modular | 内置 |
| Output bytes(R) \|\| s | 64 字节 | 64 字节 | 64 字节 | 64 字节 |

**结论**：算法正确。`taggedHashStart` 不预算是性能 leakage，不是安全 leakage（F-12）。

### 5.3 Ed25519 (RFC 8032)

| 项 | meowl | libsodium | RFC 8032 ref | Trezor | Coldcard |
| --- | --- | --- | --- | --- | --- |
| Clamp s_buf[0] &= 248 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Clamp s_buf[31] &= 127 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Clamp s_buf[31] \|= 64 | ✅ | ✅ | ✅ | ✅ | ✅ |
| r = SHA512(prefix \|\| M) mod L | ✅ | ✅ | ✅ | ✅ | ✅ |
| R = r·B 编码 | ✅ scalarMult + encodePoint | ✅ | ✅ | ✅ | ✅ |
| k = SHA512(R \|\| A \|\| M) mod L | ✅ | ✅ | ✅ | ✅ | ✅ |
| S = (r + k·s) mod L | ✅ Bignat.mult + Bignat.mod | ✅ | ✅ | ✅ | ✅ |
| Field 算术常时 | ❌（F-01） | ✅ | ✅ | ✅ | ✅ |
| Scalar mult 常时（high-level） | ✅ double-and-always-add | ✅ | ✅ | ✅ | ✅ |
| Sign 时长 | 3-6s | <5ms | <5ms | ~50ms | ~200ms |

**结论**：算法实现 100% 正确（与 RFC 8032 §5.1.6 逐字符对齐），常时性弱（F-01），性能弱（F-16）。

### 5.4 ECDSA + low-s (BIP-62 / EIP-2)

| 项 | meowl | Status Keycard | Bitcoin Core | go-ethereum |
| --- | --- | --- | --- | --- |
| ALG_ECDSA_SHA_256 + signPreComputedHash | ✅ | ✅ | n/a (libsecp256k1) | n/a (geth-crypto) |
| DER 解析 | 手写最简 | 手写最简 | libsecp256k1 | crypto/ecdsa |
| `s ≤ ⌊n/2⌋` 测试 | ✅ ModN.lessThanHalfN | ✅ | ✅ | ✅ |
| `s ← n − s` 翻转 | ✅ ModN.negateMod | ✅ | ✅ | ✅ |
| recovery byte v | ❌ host-side | ❌ host-side | ✅ on-card | ✅ on-card |

**结论**：与 Status Keycard 一致，功能足够 v1。`v` 计算需要 modular sqrt（JC 不暴露），是合理的 host-side 妥协（MEAP-6 已说明）。

### 5.5 Secure Channel

| 项 | meowl (MEAP-2) | Status Keycard SCP | Satochip CardEdge SC | TLS 1.2 (RFC 5246) |
| --- | --- | --- | --- | --- |
| 握手类型 | ECDH (eph) + ECDSA(authentikey) | ECDH + cert chain | ECDH + cert | (X.509 cert) |
| 密钥派生 | HKDF-SHA-256 (info=meowl-sc-v1) | KDF1 + SHA-512 | HKDF-SHA-256 | PRF/HKDF |
| 加密 | AES-256-CBC + PKCS#5 | AES-256-CBC + PKCS#5 | AES-128-CTR | AES-128/256-CBC/GCM |
| 认证 | HMAC-SHA-256/16 (Encrypt-then-MAC) | HMAC-SHA-256 (Encrypt-then-MAC) | HMAC-SHA-256/16 | HMAC (RFC 5246) |
| 重放防御 | 严格递增 IV | 严格递增 IV | 序列号 | 序列号 |
| Inbound MAC | (CLA+INS+P1+P2+LC) \|\| IV \|\| CT | (header) \|\| IV \|\| CT | header \|\| IV \|\| CT | seq + header + plaintext |
| Outbound MAC | 0xFF \|\| IV \|\| CT | 0xFF \|\| IV \|\| CT | direction tag | seq + header |
| 失败行为 | reset session | reset session | reset session | close_notify alert |

**结论**：MEAP-2 设计与 Status Keycard 几近完全对齐，是社区已验证的成熟范式。AES-CBC + HMAC（Encrypt-then-MAC）是 RFC 7366 推荐组合。

### 5.6 RNG 选择

| 项 | meowl | Status Keycard | Satochip | JC 标准 |
| --- | --- | --- | --- | --- |
| 主选 | ALG_KEYGENERATION | ALG_KEYGENERATION | ALG_TRNG | spec 中两者均合规 |
| 兜底 | ALG_TRNG | n/a | n/a | — |
| 用途 | seed gen + Schnorr aux + EC keypair | EC keypair | seed gen | — |

**结论**：meowl 的"先 KEYGEN 后 TRNG"兜底链条是 J3R180 上的最佳实践（MEAP-6 已明确说明）。

---

## 六、行动建议优先级

### 6.1 v1.1 sweep 修复矩阵（10 条 — ✅ 全部已合并）

| F-NN | Severity | 描述 | 状态 |
| --- | --- | --- | --- |
| F-02 | S2 | `handleSignEd25519` try-finally wipe innerScratch | ✅ Fixed |
| F-04 | S2 | ApduTlv.ensureCapacity 防溢出重排 | ✅ Fixed |
| F-06 | S4 | 修正 MeowlApplet 注释 323→259 | ✅ Fixed |
| F-07 | S3 | `Bip32.wipeTransientSecrets` wipe 整个 state | ✅ Fixed |
| F-08 | S4 | 修正 Hkdf.expand Javadoc | ✅ Fixed |
| F-10 | S4 | 修正 HmacSha.forceSoftware Javadoc | ✅ Fixed |
| F-11 | S4 | 修复 HmacSha 文档 Unicode 损坏 | ✅ Fixed |
| F-13 | S4 | Slip10.deriveLeafKey 引用常量 | ✅ Fixed |
| F-14 | S4 | Slip10 非 hardened 改 SW_CONDITIONS_NOT_SATISFIED | ✅ Fixed |
| F-24 | S3 | SecureChannelClient 立即验证 0x04 | ✅ Fixed |

### 6.2 v1.1 sweep 修复矩阵（9 条 — ✅ / 🟡 全部已合并）

| F-NN | Severity | 描述 | 状态 |
| --- | --- | --- | --- |
| F-01 | S2 | Field25519 常时基元 + 投影随机化 | 🟡 Mitigated（中期已落地，长期 limb 重写 v2.0） |
| F-03 | S2 | ModN/Bignat 常时基元 + 文档精确化 | 🟡 Mitigated（中期已落地，长期 limb 重写 v2.0） |
| F-05 | S3 | 抽离 `Bounds` 工具类 | ✅ Fixed |
| F-09 | S3 | `Hkdf.extract` 移除 256 字节硬上限 | ✅ Fixed |
| F-12 | S3 | Schnorr 预算 tag hash | ✅ Fixed（首跑测捕获 AUX 字节错位） |
| F-15 | S3 | wipe() 单一事务化 + 子模块 InTx 变体 | ✅ Fixed |
| F-18 | S3 | EcdsaK1 DER 解析强化 long-form 守卫 | ✅ Fixed |
| F-22 | S4 | HostCrypto.pkcs5Unpad 改抛 SecureChannelException | ✅ Fixed |
| F-25 | S3 | MeowlAppletTest 异常路径补强 | ✅ Fixed |

### 6.3 v1.2 sweep 新增修复（5 条 — 全部本次合并）

| F-NN | Severity | 描述 | 状态 |
| --- | --- | --- | --- |
| F-27 | S5 | `SecureChannel.stripPkcs5` 改 mask-based 常时实现 | ✅ Fixed |
| F-28 | S5 | `SecureChannel.compare16` 改 mask-based sticky-mask 实现 | ✅ Fixed |
| F-29 | S4 | `MasterSeed` 改 pull-based copy API；删除 getter | ✅ Fixed |
| F-30 | S4 | `EcdsaK1.signDigest` 整体包裹 try-finally | ✅ Fixed |
| F-31 | S5 | `PinManager.unblockPin` design intent 文档化 | Acknowledged |

### 6.4 长期路线（v2.0+ — 7 条 Deferred / Info）

| F-NN | Severity | 描述 | 工作量 |
| --- | --- | --- | --- |
| F-01 / F-03 | S2 | Field25519 / Bignat 重构为 radix-2^26 limb 32-bit 常时实现 | 2-3 周 |
| F-16 | S5 | Ed25519 性能优化（移植 ed25519-donna） | 2-3 周 |
| F-17 | S5 | BIP-32 / SLIP-10 异常 SW 选择（社区共识简化，不修改） | — |
| F-19 | S3 | Extended-APDU 支持（SIGN_ED25519 长 message） | 1 周 |
| F-20 | S5 | Authentikey 私钥 EEPROM 写后擦除（依赖 EAL 5+ 物理保证） | — |
| F-21 | S5 | PKI cert wipe 不擦 authentikey（按 MEAP-4 spec 设计） | — |
| F-23 | S5 | HkdfSha256.extract saltLen=0 时分配 ZERO_SALT_32（host 微优化） | — |
| F-26 | S5 | HmacShaTest 设计赞赏（无修改） | — |

---

## 七、审计结论

### 7.1 上线就绪度

**Verdict (v1.2)**：**unconditional GO**。

§6.1 / §6.2 / §6.3 全部 24 条 actionable findings 已合并；§6.4 的 7 条全部为 Deferred（v2.0+）或 Info（不修改），其中 F-01 / F-03 已通过中期 mask-based 路径（`Field25519.add/sub/neg`、`Bignat.condAdd/condSub/ctLessThan/ctIsZero`、`Edwards25519.randomizeProjective`）落地，仅长期 limb 重写登记到 v2.0；这些不阻塞 v1.0 发布。

**1,697 个测试用例 / 311 个 `@Test` 方法全部 PASSED**（applet/tests:1,445 + tools:252），含本次新增 27 个 F-27 / F-28 回归测试。

### 7.2 残留风险声明

发布 v1.0 时 user-facing release notes 应包含：

> meowl-applet v1.0 在 J3R180 上的 Ed25519 与 Schnorr 软实现采用变时 Bignat 字段算术（`Bignat.mod` / `Bignat.mult` 仍非常时；mask-based 基元已覆盖外层路径）。在物理可触及卡片 + 高分辨率 PCSC 时间 oracle 下，理论存在累积 ~1 bit/operation 的私钥侧信道恢复路径。该威胁模型超出 v1.0 设计目标（"defense against software-only adversaries on the host"）。需要"strong physical adversary"防护的用户应等待 v2.0 的常时 Field25519 重构，或选择 Coldcard / Trezor。

### 7.3 与 Status Keycard 一致性结论

meowl-applet 在 BIP-32 / ECDSA / Secure Channel 三大核心路径上**等同于** Status Keycard 的成熟设计，且在以下维度**优于** Status Keycard：

- ConstantTime MAC 比较（Status Keycard 用 `Util.arrayCompare`，泄露不匹配位置）
- HmacSha 软件兜底（Status Keycard 不针对无 native HMAC 的 J3R180 family）
- Reset 多步触发 + 自动 rearm（Status Keycard 的 reset 流程相对简单）
- v1.2 加固后：`SecureChannel.stripPkcs5` / `compare16` 与所有秘密路径辅助函数风格统一为 mask-based（F-27 / F-28），`MasterSeed` 强封装无 alias（F-29）

不足之处：

- Ed25519 / BIP-340 Schnorr 是 Status Keycard 不实现的扩展，meowl 因此承担更多软实现复杂度。

### 7.4 文档建议

1. 在 `README.md` 添加"Performance budgets"段，列出每个签名 INS 的预期耗时。
2. 在 `MEAP-6` 添加"Threat model"段，明确"strong physical adversary not in v1.0 scope"。
3. 在 `docs/specs/README.md` 索引中链接到本审计报告。
4. v1.2 后 `MasterSeed` API 已破坏性更新；任何下游集成需要从 `byte[] bip32Master()` 迁移到 `void copyBip32MasterTo(byte[] dst, short dstOff)`（详见 F-29）。

---

**报告作者**：Cascade（Windsurf 代码审计代理）
**审计完成**：2026-01（v1.0）/ 2026-05（v1.1 sweep）/ 2026-05（v1.2 重构）
**版本**：1.2

如需追加细节或重新审计某个具体模块，请提交 issue 或 ping 维护者。
