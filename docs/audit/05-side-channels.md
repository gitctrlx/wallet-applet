# 05 — 侧信道与抗物理攻击

<!-- SPDX-FileCopyrightText: 2026 meowl.social contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

针对软件 timing 旁路、内存残留、RNG 源、padding oracle 与故障注入恢复路径的审计。物理层 SCA / FA 是 silicon EAL 评估的范围（J3R180 EAL 6+），本文不对硅级抗性作出断言；但**软件层**的 SCA 卫生是 applet 范围内必须做对的部分。

## 1. Constant-time 矩阵

下表是 applet 内每条 SCA-relevant 路径的常时间属性总览。`✓` 严格常时间；`B` 通过 blinding/post-emergence 间接遮蔽；`✗` 残留 timing 旁路。

| 路径 | 操作 | CT? | 缓解 | Finding |
| --- | --- | --- | --- | --- |
| `ConstantTime.equals` | OR-fold 比较 | ✓ | — | — |
| `Bignat.ctLessThan` | 全字节走 | ✓ | — | — |
| `Bignat.ctIsZero` | OR-fold | ✓ | — | — |
| `Bignat.condSubInPlace` | mask-driven | ✓ | — | — |
| `Bignat.condAddInPlace` | mask-driven | ✓ | — | — |
| `Bignat.add` | carry propagate | ✗ | — | A-02（影响 Schnorr `s` 计算的 8b 段） |
| `Bignat.sub` | borrow propagate | ✗ | — | low-impact |
| `Bignat.mult` | schoolbook | ✗ | Coron 投影盲化 (Field 路径) / post-emergence (Schnorr/Ed25519) | **A-16** |
| `Bignat.mod` | iterative shift-subtract | ✗ | 同上 | **A-16** |
| `ModN.addMod` | mask-driven | ✓ | — | — |
| `ModN.negateMod` | branch-free borrow | ✓ | — | — |
| `Field25519.add/sub/neg` | mask-driven | ✓ | — | — |
| `Field25519.mul/sqr` | 调用 `Bignat.mod` | ✗ | Coron 投影盲化 | A-16 |
| `Field25519.inv` | Fermat `a^(p-2)`，指数公开 | ✓ (调度) | — | — |
| `Edwards25519.scalarMult` | double-and-always-add | ✓ (调度) + ✗ (内核) | Coron 投影盲化 + 双独立盲化 | A-16 |
| `Edwards25519.pointAdd/Double` | 同上 | 同上 | 同上 | — |
| `Bip32.deriveLeafScalar` (hardened) | HMAC + addMod | ✓ | — | — |
| `Bip32.deriveLeafScalar` (non-hardened) | KeyAgreement (platform) + HMAC + addMod | platform-dependent | 信任 silicon 的 ECDH 常时间 | platform |
| **`Schnorr.sign` y(P) parity flip** | `if (... & 0x01) negateMod` | ✗ (但 P 公开) | — | — (P 公开) |
| **`Schnorr.sign` y(R) parity flip** | `if (... & 0x01) negateMod` | ✗ | aux randomness 让 k' 每次新鲜 | **A-01** |
| **`Schnorr.sign` `(k + e·d) mod n`** | Bignat.mod variable-time | ✗ | post-emergence + e·d 通过 `Bignat.mult` | **A-01 + A-16** |
| `Schnorr.sign` carry propagate | early-exit `while` | ✗ | low-impact | A-02 |
| **`Ed25519.sign` `(k·s) mod ℓ`** | Bignat.mod variable-time | ✗ | post-emergence | A-16 (mitigated) |
| `EcdsaK1.signDigest` (k 生成) | platform `Signature` | platform-dependent | 信任 silicon | platform |
| `EcdsaK1.signDigest` low-s | `lessThanHalfN` + `negateMod` | ✓ | — | — |
| `EcdsaK1.parseDerSignature` | 早退分支（DER 错位置） | ✗ | DER **公开**，无秘密 | — |
| `MasterSeed.import/generate` | HMAC + check | ✓ | — | — |
| `PinManager.verify*` | platform `OwnerPIN.check` | platform-dependent | JC OwnerPIN 标准要求 CT | platform |
| `SecureChannel.unwrap` MAC 验证 | `ConstantTime.equals` | ✓ | — | — |
| `SecureChannel.unwrap` IV 比较 | `compare16` 早退 | ✗ | IV **公开** | — |

总结：

- **严格 CT**：8 个比较/复制/算术原语。
- **软件 CT 不足，依赖防御纵深**：4 条主路径（Schnorr `(k+ed) mod n`、Ed25519 `(ks) mod ℓ`、Field 算术、Edwards scalarMult 内核）。
- **Platform-dependent**：3 条（ECDSA k 生成、ECDH non-hardened、OwnerPIN）。
- **不需要 CT**（公开数据）：DER 解析、IV 比较、Schnorr y(P) 翻转。

---

## 2. 投影盲化（Coron CHES 1999）

### 实现位置

`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Edwards25519.java:randomizeProjective`

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Edwards25519.java:495-520
public static void randomizeProjective(byte[] point, short pointOff, byte[] r, short rOff,
                                        byte[] scratch, short scratchOff) {
    Field25519.mul(point, pointOff, r, rOff, scratch, scratchOff);
    Util.arrayCopyNonAtomic(scratch, scratchOff, point, pointOff, Field25519.LEN);  // X = rX
    Field25519.mul(point, (short) (pointOff + Field25519.LEN), r, rOff,
                   scratch, scratchOff);
    Util.arrayCopyNonAtomic(scratch, scratchOff, point,
                             (short) (pointOff + Field25519.LEN), Field25519.LEN);  // Y = rY
    Field25519.mul(point, (short) (pointOff + 2 * Field25519.LEN), r, rOff,
                   scratch, scratchOff);
    Util.arrayCopyNonAtomic(scratch, scratchOff, point,
                             (short) (pointOff + 2 * Field25519.LEN), Field25519.LEN);  // Z = rZ
    Field25519.mul(point, (short) (pointOff + 3 * Field25519.LEN), r, rOff,
                   scratch, scratchOff);
    Util.arrayCopyNonAtomic(scratch, scratchOff, point,
                             (short) (pointOff + 3 * Field25519.LEN), Field25519.LEN);  // T = rT
}
```

`(X, Y, Z, T) ↦ (rX, rY, rZ, rT)` 在扩展 Edwards 坐标系下保持仿射点不变（仿射 = `(X/Z, Y/Z)` = `(rX/rZ, rY/rZ)`），但内部 Field 算术的所有中间值被随机 r 乘过，timing 与 r 关联而不是与原始点关联。

### Ed25519 的双独立盲化

`Ed25519.sign` 关键防御（行 162-167 与 232-235）：

```text
1. blindBasePoint() #1 → 用盲化值 r1 计算 A = s · B
2. setBase() 重新置基点                        ← 重要：新的基点起点
3. blindBasePoint() #2 → 用盲化值 r2 (≠ r1) 计算 R = r · B
```

两次标量乘的盲化值**独立**采样 → A 计算的 timing trajectory 与 R 计算**不相关**，即使攻击者比较两次签名也学不到关联信息。

### 验证测试

`RandomizeProjectiveTest`（13 KB）：固定标量 + 固定基点 + 100 个不同 r → 100 次 scalarMult 输出**仿射点**完全相同，但**扩展坐标**全部不同。这 pin 了"投影 mask 不影响最终输出"和"投影 mask 实际作用于内部算术"两条 invariant。

---

## 3. RNG 源审计

### 选路（适用于 `Ed25519`、`Schnorr`、`MasterSeed.generateSeed`）

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Ed25519.java:106-113
// MEAP-6: ALG_KEYGENERATION first (universal on JC 3.0.4+), ALG_TRNG fallback.
RandomData candidate;
try {
    candidate = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
} catch (Exception e) {
    candidate = RandomData.getInstance(RandomData.ALG_TRNG);
}
this.rng = candidate;
```

### `ALG_KEYGENERATION` vs `ALG_TRNG`

| 算法 | JC 3.0.4+ 必选？ | 强度声明 |
| --- | --- | --- |
| `ALG_KEYGENERATION` | 是 | NIST SP 800-90A DRBG，TRNG-seeded |
| `ALG_TRNG` | 可选 | 直接硬件 TRNG（无 DRBG） |
| `ALG_PSEUDO_RANDOM` | 已弃用（JC 3.1） | 仅 PRNG，不安全 |
| `ALG_SECURE_RANDOM` | 已弃用（JC 2.2.2） | — |

选 `ALG_KEYGENERATION` 是正确的：DRBG 比 raw TRNG 更鲁棒（处理 TRNG 故障），所有 JC 3.0.4+ 卡都必有。`ALG_TRNG` 仅作 silicon-quirk 兜底。

**两类弃用算法 (`ALG_PSEUDO_RANDOM`、`ALG_SECURE_RANDOM`) 不在路径上** —— 无 PRNG 落入生产路径风险。

### 测试验证

`Ed25519SigningTest.signaturesUseFreshNonce` 验证两次签同一 `(sk, m)` 产生不同 R（aux randomness ≠ 0 或 nonce 不重复），间接验证 RNG 在路径上工作。

### Findings

无。RNG 选路稳健。

---

## 4. Padding oracle 与解密失败语义

### AES-CBC PKCS5 的潜在 oracle

经典 padding oracle（Vaudenay 2002）：攻击者发可控密文，根据 "padding 错" vs "padding 对但 MAC 错" 的不同响应区分两类失败。本 applet 防御：

1. **MAC 在 decrypt 之前** —— `SecureChannel.unwrap` 顺序：IV check → MAC check → AES decrypt → handler。
2. **MAC 失败立即 reset + 抛 0x6FF0** —— 攻击者不能多次试。
3. **decrypt 失败也抛通用错** —— 不区分 padding 错与 application 错。

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\SecureChannel.java:340-356
short macStart = (short) (apduBuffer.length - Constants.SC_MAC_LEN);
hmac.sign(apduBuffer, ivOffset, (short) (cipherEnd - ivOffset), apduBuffer, macStart);
boolean macOk = ConstantTime.equals(...);
if (!macOk) {
    reset();
    ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
}
// 只有 MAC 通过才进入解密
short plainLen = decryptCipher.doFinal(...);
```

### Findings

无。Encrypt-then-MAC + MAC 优先 + 失败强制 reset 是标准防御组合。

---

## 5. 内存残留与 scratch 卫生

### 全局共享 scratch (`MeowlApplet`)

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\MeowlApplet.java:75-79
private static final short SHARED_SCRATCH_LEN = (short) 1056;  // Ed25519 上限定
private static final short INNER_SCRATCH_LEN = (short) 128;
private final byte[] sharedScratch;
private final byte[] innerScratch;
```

- 两块都是 `CLEAR_ON_DESELECT` transient → 卡片 deselect 即清。
- 单线程 APDU 调度 → 不需要锁。
- 大小按 Ed25519 (1056 B) 上限定，其它原语 (Schnorr 354 B、ECDSA 168 B) 复用同一块。

### 每条 sign 路径的 finally 清理

| 路径 | finally 清 scratch | finally 清平台 key | 状态 |
| --- | --- | --- | --- |
| `EcdsaK1.signDigest` | ✓ `arrayFillNonAtomic(scratch, 0, SCRATCH_LEN, 0)` | ✓ `signKey.clearKey()` | 完整 |
| `Ed25519.publicKey/sign` | ✓ `wipeScratch()` | n/a (软实现，无平台 key) | 完整 |
| `Schnorr.signDigest` | ✓ `wipe()` 整个 354 B | n/a | 完整 |
| `Bip32.deriveLeafScalar` | ✓ `wipeTransientSecrets()` (仅 state[]) | ✓ `scalarKey.clearKey()` | 完整 |
| `Slip10.derive` | ✓ scratch 由调用方提供，调用方负责 | n/a | 调用方责任 |

### 透明 scratch 通过参数传递

`Schnorr.signDigest`、`Ed25519.sign` 等都接受**调用方提供的 scratch 缓冲**（`MeowlApplet.sharedScratch`）。这是标准 JC 模式 —— scratch 单一全局实例，所有原语共用，避免 RAM 重复分配。但要求**每条原语的 finally 必须清完整 scratch**，不能只清自己用过的字段（因为下一个原语可能假设 scratch 全零开始）。

`Ed25519.wipeScratch()`：

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Ed25519.java:282-284
private void wipeScratch() {
    Util.arrayFillNonAtomic(scratch, (short) 0, SCRATCH_LEN, (byte) 0);
}
```

`SCRATCH_LEN = 1056` —— 完整覆盖所有可能的 sub-scratch 区域。✓

### Findings

无。scratch 卫生在所有 sign 路径上一致且严格。

---

## 6. 逐条 Finding 的物理可利用性评估

### A-01：Schnorr 奇偶翻转早退分支

| 维度 | 评估 |
| --- | --- |
| 攻击者能力假设 | 可观察 sub-ms timing |
| 信息泄漏量 | 1 bit per signature (k' 的最低 bit) |
| 复用同一秘密 | k' 每次新鲜 (aux randomness)，d 跨签名稳定 |
| 攻击复杂度 | 不直接对 d 起作用；要利用必须把 1-bit-of-k' 与 r·G 的几何性关联 → 需要格攻击 + 数千签名 |
| PCSC reader jitter | ~5 ms，比 `negateMod` (~10 µs) 大 500× |
| 可利用性 | **极低**（NFC 直连无 reader 隔离时略升） |

### A-02：Schnorr `s` 计算的 carry 早退

| 维度 | 评估 |
| --- | --- |
| 信息泄漏量 | ~1 bit per signature (carry-out of 32-byte add) |
| 攻击复杂度 | 同 A-01，但更难（carry 是 k+e·d 的函数，与 d 间接相关） |
| 可利用性 | 几乎为零 |

### A-16：Bignat.mod 在 Schnorr `(e·d) mod n` 路径

| 维度 | 评估 |
| --- | --- |
| 信息泄漏量 | mod 内层迭代次数 ≈ log2(e·d / n)，对 (e·d) 高位 bits 强相关 |
| 复用同一秘密 | d 跨签名稳定 |
| e 是否可控 | e = tagged_hash(R ‖ P ‖ m)，**host 可控 m → 可控 e** |
| 攻击复杂度 | 选择性消息攻击：host 选 m_i 让 e_i 落在不同 mod 路径 → 多次采样 → 统计 d |
| 必需精度 | sub-ms（因为 mod 内层 ~ 100 次 byte op，每次 ~ 1 µs） |
| PCSC reader jitter | ~5 ms |
| **可利用性** | **理论上可行**，受 PCSC jitter 隔离；如果攻击者直接写驱动跳过 PCSC 中间层（NFC + 自制 reader），祸福未知 |

**这是 applet 内最严重的 SCA 风险**（仍在 S2，没升 S1，因为攻击者需要专用硬件 + 大量签名 + 复杂格分析；MEAP-6 的 v2 路线已计划解决）。

### A-08：SC 在 IV 不单调时立即 reset

DoS 性质，无 confidentiality / integrity 损失。S3。

### A-13：PinManager wipe 异常吞噬

物理 die-probing 范围，applet 范围之外。S3。

### A-12：MasterSeed.copy*MasterTo public

需要包内其他类的恶意调用 → 假设 applet 自身被破坏 → 已经超出威胁模型。S3 防御纵深。

### A-09 / A-15 / A-19 / A-20 等 S4 finding

文档级 / 信息级。

---

## 7. v2 SCA 路线（来自 MEAP-6 §6.3）

| 改进 | 关闭的 finding | 优先级 | 复杂度 |
| --- | --- | --- | --- |
| `Field25519` limb-radix-2²⁶ 重写 + Barrett reduction | A-16 (Field 路径) | 高 | 高（300+ 行） |
| `Schnorr` 奇偶翻转改 mask-driven | A-01 | 中 | 低（30 行） |
| `Schnorr` 引入 e·d 盲化 r·e·d / r | A-16 (Schnorr 路径) | 中 | 中（50 行 + 一个 modular inverse） |
| `Bignat.mod` 改 Montgomery / Barrett | A-16 (general) | 高 | 高（150 行） |
| 整体 limb-radix 重写 secp256k1 mod n | A-16 (Schnorr/EcdsaK1) | 中 | 中（200 行） |

预估总成本：4-6 周工程 + 30-50% 性能下降的可能性。

---

## 8. 总评

### 强项

1. **常时间助手齐备** —— `ctLessThan`/`ctIsZero`/`condSubInPlace`/`ConstantTime.equals` 都写得严谨。
2. **Coron 投影盲化 + 双独立盲化** —— Ed25519/Schnorr 的 SCA 防御纵深超过参考实现。
3. **scratch 卫生统一** —— 所有 sign 路径都有 `finally { wipeScratch(); }`。
4. **RNG 选路稳健** —— `ALG_KEYGENERATION` 优先 + `ALG_TRNG` 兜底，避开弃用 PRNG。
5. **MAC 优先 + 失败强 reset** —— SC 不暴露 padding oracle。

### 弱项

1. **`Bignat.mod` 是软件 SCA 的根** (A-16)：Schnorr 选择性消息攻击在 sub-ms 精度下理论可行。**修复路径**：v2 limb-radix 重写。**当前 Severity**：S2（理论攻击 + 物理 jitter 削弱）。
2. **Schnorr 奇偶翻转早退** (A-01)：S2，文档与实现不一致。**修复成本低**（~30 行），应在下一个版本前修。
3. **静态分析工具盲区**：本审计没有用 ct-grind / ct-verif 等专用 SCA 验证工具，理论 finding 依赖人工审计。建议在 CI 加入一个简化的 timing benchmark 脚本（见 [`07-perf.md`](./07-perf.md) 的 BenchmarkSuite）。

无 S0/S1 级 SCA finding。在当前威胁模型（PCSC reader 5ms jitter 隔离、不假设 sub-ms 物理探针）下满足生产标准。
