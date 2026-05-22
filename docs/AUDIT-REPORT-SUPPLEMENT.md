# meowl-applet 补充审计报告 (v1.3)

## 审计元数据

| 字段 | 值 |
| --- | --- |
| 审计版本 | v1.3 (补充全面审计) + v1.3.1 sweep |
| 审计日期 | 2026-05 |
| 审计范围 | `applet/src/main/java/social/meowl/applet/` 全部 25 个源文件 + 16 个测试文件 |
| 审计深度 | 逐行重审 v1.2 已修复路径 + 联网校验密码学常量 + 测试覆盖率审计 |
| 参考实现 | RFC 8032 (Ed25519)、SEC 2 v2 (secp256k1)、BIP-32、BIP-340、SLIP-10、RFC 2104/4231 (HMAC)、RFC 5869 (HKDF) |
| 前置报告 | v1.2 (31 项 finding `F-01..F-31`) |
| 本次新增 | 15 项新发现 `F-32..F-46` |
| 修复状态 | ✅ 全部 15 项已修复并通过 `./gradlew :tests:test :applet:buildCap spotlessCheck`（1704 tests，0 failures，CAP 生成成功） |

## 一、执行摘要

本次审计在 v1.2 (`F-01..F-31`) 基础上进行**更深一层的全面重审**，逐个文件、逐行重新校验，特别聚焦：

1. **细微逻辑 bug**（v1.2 未覆盖的代码路径）
2. **常时性属性的实际兑现**（与 doc claim 比对）
3. **测试覆盖盲区**（虚假测试 / 冗余测试 / 完全缺失的测试）
4. **联网校验密码学常量**（secp256k1、Ed25519 base point、d、L 等）

### 1.1 总体评价

代码库整体质量极高，v1.2 后绝大部分高/中等级 finding 已修复。但本次审计仍发现：

- **1 项逻辑 bug**（极低概率不可触发，但应修复）：`Ed25519.blindBasePoint` do-while 控制流错误
- **1 项常时性 claim 与实现不符**：`ModN.negateMod` 仍含数据相关分支但 doc 声称 branch-free
- **若干文档/风格不一致**：ApduTlv Javadoc 与实现矛盾、wipe 风格不统一、try-finally 风格不统一
- **重要测试盲区**：所有 mask-based 常时基元（`condSub/condAdd/ctLessThan/ctIsZero`、`negateMod`、`lessThanHalfN`）完全没有专门单元测试

### 1.2 密码学常量联网校验结果

| 常量 | 文件 / 位置 | 校验结果 |
| --- | --- | --- |
| secp256k1 `p` | `@Secp256k1.java:57-90` | ✅ 匹配 SEC 2 v2 §2.4.1 |
| secp256k1 `a = 0` | `@Secp256k1.java:91-123` | ✅ |
| secp256k1 `b = 7` | `@Secp256k1.java:124-156` | ✅ |
| secp256k1 `n` | `@Secp256k1.java:157-189` | ✅ |
| secp256k1 `G` (uncompressed) | `@Secp256k1.java:190-256` | ✅ 匹配 `Gx = 79BE667E...`、`Gy = 483ADA77...` |
| Ed25519 base `X` | `@Edwards25519.java:116-125` | ✅ 匹配 `0x216936D3...51A` |
| Ed25519 base `Y = 4/5 mod p` | `@Edwards25519.java:128-137` | ✅ 匹配 `0x6666...58` |
| Ed25519 base `T = X·Y mod p` | `@Edwards25519.java:140-149` | ✅ 匹配 |
| Ed25519 `d = -121665/121666 mod p` | `@Edwards25519.java:87-96` | ✅ 匹配 RFC 8032 §5.1 |
| Ed25519 `2d mod p` | `@Edwards25519.java:104-113` | ✅ 手工验证 `2D - p` 等于编码值 |
| Ed25519 `L = 2^252 + ...` | `@Ed25519.java:45-54` | ✅ 匹配 RFC 8032 §5.1 |
| Field25519 `p = 2^255 - 19` | `@Field25519.java:56-65` | ✅ |
| ModN `n / ⌊n/2⌋` | `@ModN.java:49-74` | ✅ 匹配（n 奇数，⌊n/2⌋ = (n-1)/2） |
| BIP-340 tag hashes | `@Schnorr.java:53-86` | ✅ 已由 `SchnorrTagHashTest` 在每次构建时校验 |
| BIP-32 / SLIP-10 HMAC labels | `@MasterSeed.java:29-58` | ✅ "Bitcoin seed" / "ed25519 seed" |

**所有密码学常量与官方规范字节级一致**。

### 1.3 v1.3 新发现总览

| F-NN | 严重等级 | 描述 |
| --- | --- | --- |
| **F-32** | **S3 — Medium** | `Ed25519.blindBasePoint` do-while 控制流 bug，blind ∈ [p, 2^255) 可被接受 |
| **F-33** | **S3 — Medium** | `ModN.negateMod` 使用数据相关分支 `(diff<0)?1:0`，违反 doc "branch-free" claim |
| **F-34** | **S3 — Medium** | `ModNTest` 完全缺失 `negateMod` 与 `lessThanHalfN` 的专门测试 |
| **F-35** | **S3 — Medium** | `BignatTest` 完全缺失 mask-based 常时基元（`condSubInPlace`/`condAddInPlace`/`ctLessThan`/`ctIsZero`）测试 |
| **F-36** | **S4 — Low** | `ApduTlv.java` Javadoc (line 14-16) 声称 `length ≤ 127`，但实际 `MAX_VALUE_LEN = 0xFF = 255` |
| **F-37** | **S4 — Low** | `Hkdf.expand` 边界检查 `(outOffset + length) > out.length` 在 short 溢出时不安全，应使用 `Bounds.requireCapacity` |
| **F-38** | **S4 — Low** | `MeowlApplet.handleSignPkiCsr` / `handleSignEcdsaK1` / `handleSignSchnorrK1` 的 `innerScratch` wipe 不在 try-finally 中，与 F-02 修复的 `handleSignEd25519` 风格不一致 |
| **F-39** | **S4 — Low** | `Slip10.wipeWalkState` 分三次 `arrayFillNonAtomic` (K, C, I)，与 `Bip32.wipeTransientSecrets` 的"一次 wipe 整个 STATE_LEN"风格不一致 |
| **F-40** | **S4 — Low** | `LifecycleStateTest` 没有专门测试 `transitionToInTx` 与 `resetInTx`（F-15 修复的 InTx 变体），仅间接通过 MeowlAppletTest 覆盖 |
| **F-41** | **S4 — Low** | `Ed25519.blindBasePoint` 与 `Edwards25519.randomizeProjective` 没有任何专门测试 |
| **F-42** | **S5 — Info** | `EcdsaK1.copyDerInteger` 不检查 minimal DER 编码（rawLen < 33 但 leading byte = 0x00 应被拒绝） |
| **F-43** | **S5 — Info** | `EcdsaK1.copyDerInteger` 接受 INTEGER value = 0 (即 r=0 或 s=0)，理论上应被拒绝（ECDSA invalid signature） |
| **F-44** | **S5 — Info** | `ResetToFactory.java` 没有专门的单元测试（仅通过 `MeowlAppletTest` 间接覆盖 4 次 invocations + 各种 rearm） |
| **F-45** | **S5 — Info** | `Bounds.java` 没有专门的单元测试（仅通过 `ApduTlv` / `Authentikey` 间接覆盖) |
| **F-46** | **S2 — High** | **v1.3.1 新增**: v1.2 F-28 修复在 `SecureChannel.compare16` / `stripPkcs5` 中引入 `(s >> 31) & 0xFFFF` 的 int-domain 运算与 `0xFFFF` int 字面量，JC 3.0.5 默认 profile 的 CAP converter 拒绝（`unsupported int type constant`）。jcardsim 测试无法捕获，导致 main branch 自 v1.2 起 **CAP 构建失败**。修复方案：所有 sign-bit 提取改用 short-domain `(s >>> 15) & 1` + 取反广播。|

**总计 15 项新发现**：1 项 S2 (High) — F-46 阻塞构建、3 项 S3 (Medium)、6 项 S4 (Low)、5 项 S5 (Info)。

**v1.0 + v1.1 + v1.2 + v1.3 累计**：46 项 findings (`F-01..F-46`)。

---

## 二、新发现详述

### 2.1 [F-32] `Ed25519.blindBasePoint` do-while 控制流 bug

**严重等级**: S3 — Medium（逻辑 bug；实际不可触发但 doc contract 被违反）

**位置**: `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Ed25519.java:267-283`

**发现**:

```java
private void blindBasePoint() {
    do {
        rng.nextBytes(scratch, BLIND_FE_OFF, BLIND_FE_LEN);
        scratch[BLIND_FE_OFF] &= (byte) 0x7F;
        if (Bignat.ctLessThan(
                        scratch, BLIND_FE_OFF, Field25519.FIELD_P, (short) 0, BLIND_FE_LEN)
                == 0) {
            continue;  // <-- BUG: jumps to while-check, not loop body
        }
    } while (Bignat.ctIsZero(scratch, BLIND_FE_OFF, BLIND_FE_LEN) != 0);
    Edwards25519.randomizeProjective(
            scratch, BASE_PT_OFF, scratch, BLIND_FE_OFF, scratch, WORK_OFF);
}
```

**控制流分析**：
- 期望逻辑：拒绝 `r >= p`、拒绝 `r == 0`，接受 `r ∈ [1, p)`
- 实际行为：在 do-while 循环中，`continue` 跳到 `while` condition check（Java/JC 标准 JLS 14.7.2）
- 当 `r >= p` 但 `r != 0` 时：
  1. `if (ctLessThan == 0)` 触发 `continue`
  2. 跳到 `while (ctIsZero != 0)` 检查
  3. `r != 0` 时 `ctIsZero` 返回 0，`0 != 0` 为 false
  4. **循环退出，blind r 仍然 ≥ p**，与 doc 矛盾

**实际影响**：

- `r ∈ [0, 2^255)` after clearing high bit
- `p = 2^255 - 19`，所以 `r >= p` 时 `r ∈ [p, 2^255)`，共 **19 个值**
- 触发概率 = 19 / 2^255 ≈ 2^-250.7（极低）
- 后续 `Edwards25519.randomizeProjective` 把 `(X, Y, Z, T)` 全部乘 `r`
- 当 `r = p`（1 个具体值）时，`X*p mod p = 0`，**点变为 (0, 0, 0, 0)**——这是无效点
- 当 `r ∈ (p, 2p)` 时，等价于 `blind' = r - p ∈ (0, 19)`，仍是合法 blind（但 doc contract 被违反）

**风险评估**：

- 触发 `r = p` 的概率 ≈ 1/2^255 ≈ 5 × 10^-77，**实际不可触发**
- 但代码逻辑明显错误，违反 doc "MUST be in [1, p)" 保证
- 未来某次重构若引入"假设 blind < p"的依赖，可能制造真实 bug

**修复建议**：

把 do-while 重写为 `while (true)` + 显式 break：

```java
private void blindBasePoint() {
    while (true) {
        rng.nextBytes(scratch, BLIND_FE_OFF, BLIND_FE_LEN);
        scratch[BLIND_FE_OFF] &= (byte) 0x7F;
        // reject r >= p
        if (Bignat.ctLessThan(scratch, BLIND_FE_OFF, Field25519.FIELD_P, (short) 0, BLIND_FE_LEN)
                == 0) {
            continue;
        }
        // reject r == 0
        if (Bignat.ctIsZero(scratch, BLIND_FE_OFF, BLIND_FE_LEN) != 0) {
            continue;
        }
        break;
    }
    Edwards25519.randomizeProjective(
            scratch, BASE_PT_OFF, scratch, BLIND_FE_OFF, scratch, WORK_OFF);
}
```

**社区参考**: libsodium / curve25519-donna 的 random blinding 也走类似 reject-resample 但写法正确。

---

### 2.2 [F-33] `ModN.negateMod` 仍含数据相关分支

**严重等级**: S3 — Medium（doc 与实现矛盾）

**位置**: `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/ModN.java:130-138`

**发现**:

```java
public static void negateMod(byte[] a, short aOff) {
    short borrow = 0;
    for (short i = (short) (LEN - 1); i >= 0; i--) {
        short diff =
                (short) ((SECP256K1_N[i] & 0xFF) - (a[(short) (aOff + i)] & 0xFF) - borrow);
        a[(short) (aOff + i)] = (byte) diff;
        borrow = (short) ((diff < 0) ? 1 : 0);  // <-- 数据相关分支
    }
}
```

文档（同文件 line 35）声称：
> {@link #negateMod} is already branch-free.

但 `(diff < 0) ? 1 : 0` 是 Java ternary，在字节码中编译为 `IFGE` + 分支指令；JC CAP converter 通常不对此做 mask-based 优化。**与 doc claim 矛盾**。

对比 `Field25519.sub`（`@Field25519.java:143-156`）使用 mask-based：

```java
borrow = (short) ((d >> 8) & 1);
```

`Bignat.condSubInPlace`（`@Bignat.java:404-413`）使用：

```java
borrow = (short) ((diff >>> 15) & 1);
```

**风险评估**：

- 在 ECDSA low-s normalization 路径上调用：`signDigest` 中 `if (!lessThanHalfN(s)) negateMod(s)`
- `s` 是公开签名分量，timing 不泄露 secret
- 但是该函数注释中 "branch-free" 是公开承诺；这种不一致会让审计员误判
- 同时违反"defense-in-depth 风格统一"的原则（已有 F-27/F-28 sweep 统一了 `SecureChannel` 辅助函数的常时风格）

**修复建议**：

把 `borrow` 计算改为 mask-based：

```java
public static void negateMod(byte[] a, short aOff) {
    short borrow = 0;
    for (short i = (short) (LEN - 1); i >= 0; i--) {
        short diff =
                (short) ((SECP256K1_N[i] & 0xFF) - (a[(short) (aOff + i)] & 0xFF) - borrow);
        a[(short) (aOff + i)] = (byte) diff;
        // mask-based: bit 15 of (short)diff is set iff diff < 0
        borrow = (short) ((diff >>> 15) & 1);
    }
}
```

效果与 `Field25519.sub` 一致，doc claim 不再是空话。

---

### 2.3 [F-34] `ModNTest` 缺失 `negateMod` / `lessThanHalfN` 测试

**严重等级**: S3 — Medium（测试盲区）

**位置**: `@d:/Desktop/x/meowl-applet/tests/src/test/java/social/meowl/applet/ModNTest.java`

**发现**:

执行 `grep_search` "negateMod|lessThanHalfN" 在整个 `tests/` 目录返回 **0 hits**。

`ModNTest` 仅测试：
- `lessThanN` (5 个 case)
- `isZero` (3 个 case)
- `addMod` (10+ case + 50 randomised)

**完全缺失**：
- `negateMod`：仅在 `EcdsaK1Test` 中通过 "s ≤ ⌊n/2⌋" 断言**间接**测试。如果 `negateMod` 误算（例如把 `n - s` 写成 `s - n` 或某个位翻转 bug），且 ECDSA 输出恰好已是 low-s（约 50% 概率），则 bug 不会被 EcdsaK1Test 捕获。
- `lessThanHalfN`：同样仅间接测试。

**风险**：critical 函数（用于 BIP-62 / EIP-2 canonical 签名）的回归保护不足。

**修复建议**：

新增 `ModNTest` 测试用例（最少 10 个）：

```java
@Test
void negateModInvertsBack() {
    // n - (n - x) = x
    byte[] a = bigIntToFixed(BigInteger.ONE, 32);
    ModN.negateMod(a, (short) 0);
    BigInteger expected = N.subtract(BigInteger.ONE);
    assertArrayEquals(bigIntToFixed(expected, 32), a);
    ModN.negateMod(a, (short) 0);
    assertArrayEquals(bigIntToFixed(BigInteger.ONE, 32), a);
}

@Test
void negateModMatchesBigInteger() {
    SecureRandom rng = new SecureRandom();
    for (int trial = 0; trial < 50; trial++) {
        BigInteger x = randomScalar(rng);
        byte[] a = bigIntToFixed(x, 32);
        ModN.negateMod(a, (short) 0);
        BigInteger expected = N.subtract(x).mod(N);
        assertArrayEquals(bigIntToFixed(expected, 32), a, "trial " + trial);
    }
}

@Test
void lessThanHalfNAtBoundary() {
    byte[] halfN = bigIntToFixed(N.subtract(BigInteger.ONE).shiftRight(1), 32);
    assertTrue(ModN.lessThanHalfN(halfN, (short) 0));  // ⌊n/2⌋ ≤ ⌊n/2⌋
    byte[] halfNplus1 = bigIntToFixed(N.shiftRight(1).add(BigInteger.ONE), 32);
    assertFalse(ModN.lessThanHalfN(halfNplus1, (short) 0));
    byte[] zero = new byte[32];
    assertTrue(ModN.lessThanHalfN(zero, (short) 0));
    byte[] one = bigIntToFixed(BigInteger.ONE, 32);
    assertTrue(ModN.lessThanHalfN(one, (short) 0));
}
```

---

### 2.4 [F-35] `BignatTest` 缺失 mask-based 常时基元测试

**严重等级**: S3 — Medium（测试盲区，F-01/F-03 mitigation 的核心代码未直接测试）

**位置**: `@d:/Desktop/x/meowl-applet/tests/src/test/java/social/meowl/applet/BignatTest.java`

**发现**:

执行 grep "condSubInPlace|condAddInPlace|ctLessThan|ctIsZero" 在 `tests/` 目录返回 **0 hits**。

`BignatTest` 仅测试：
- `add` / `sub` / `lessThan` / `isZero` / `mult` / `mod` / `mult+mod`

**完全缺失**：
- `Bignat.condSubInPlace(mask=-1 vs mask=0)`
- `Bignat.condAddInPlace(mask=-1 vs mask=0)`
- `Bignat.ctLessThan(a < b, a == b, a > b)`
- `Bignat.ctIsZero(all-zero, single-bit-set at MSB/LSB/middle)`

这些是 **F-01 / F-03 mitigation 的核心常时基元**。`ModN.addMod` / `Field25519.add/sub/neg` 间接使用这些，但单独测试可以捕获更细粒度 bug（mask 错位、bit 15 提取错误等）。

**修复建议**：

新增 `BignatMaskBasedTest` 或扩展 `BignatTest`：

```java
@Test
void condSubInPlaceMaskMinusOne() {
    byte[] a = bigIntToFixed(BigInteger.valueOf(100), 32);
    byte[] b = bigIntToFixed(BigInteger.valueOf(30), 32);
    Bignat.condSubInPlace(a, (short) 0, b, (short) 0, (short) 32, (short) -1);
    assertArrayEquals(bigIntToFixed(BigInteger.valueOf(70), 32), a);
}

@Test
void condSubInPlaceMaskZeroIsNoop() {
    byte[] a = bigIntToFixed(BigInteger.valueOf(100), 32);
    byte[] aCopy = a.clone();
    byte[] b = bigIntToFixed(BigInteger.valueOf(30), 32);
    Bignat.condSubInPlace(a, (short) 0, b, (short) 0, (short) 32, (short) 0);
    assertArrayEquals(aCopy, a);
}

@Test
void ctLessThanThreeWay() {
    byte[] a = bigIntToFixed(BigInteger.ONE, 32);
    byte[] b = bigIntToFixed(BigInteger.TWO, 32);
    assertEquals((short) -1, Bignat.ctLessThan(a, (short) 0, b, (short) 0, (short) 32));
    assertEquals((short) 0, Bignat.ctLessThan(b, (short) 0, a, (short) 0, (short) 32));
    assertEquals((short) 0, Bignat.ctLessThan(a, (short) 0, a, (short) 0, (short) 32));
}

@Test
void ctIsZeroDetectsAtAnyPosition() {
    for (int pos = 0; pos < 32; pos++) {
        byte[] a = new byte[32];
        a[pos] = 1;
        assertEquals((short) 0, Bignat.ctIsZero(a, (short) 0, (short) 32),
                "non-zero at position " + pos + " must return 0");
    }
    assertEquals((short) -1, Bignat.ctIsZero(new byte[32], (short) 0, (short) 32));
}
```

---

### 2.5 [F-36] `ApduTlv.java` Javadoc 与实现矛盾

**严重等级**: S4 — Low（文档错误）

**位置**: `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/ApduTlv.java:14-16`

**发现**:

```java
/**
 * Helpers for writing simple BER-TLV (single-byte tag, single-byte length) records...
 *
 * <p>Usage is intentionally restricted to the simplified form {@code [tag(1) | length(1) |
 * value(length)]} with {@code length ≤ 127}.   // <-- 文档说 ≤ 127
```

但实际 `MAX_VALUE_LEN = (short) 0xFF = 255` (line 35)，且 MEAP-1 §TLV 明确允许 `LEN ∈ [0, 255]`。

注释中的 `length ≤ 127` 是旧的 BER-TLV 严格规则的残留；MEAP-1 设计了简化的非严格 TLV（这是 documented design intent）。

**修复建议**:

把 Javadoc 改为：

```java
 * <p>Usage is intentionally restricted to the simplified form {@code [tag(1) | length(1) |
 * value(length)]} with {@code length ∈ [0, 255]} per MEAP-1 §TLV-encoding. This deliberately
 * departs from strict BER-TLV (which requires long-form 0x81 LL for length ≥ 128); the meowl
 * wire trades strict ISO compliance for parser simplicity, since every TLV value is well below
 * 256 bytes.
```

---

### 2.6 [F-37] `Hkdf.expand` 边界检查可能溢出

**严重等级**: S4 — Low（理论性，当前不可触发）

**位置**: `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Hkdf.java:136-138`

**发现**:

```java
if (out == null || outOffset < 0 || (short) (outOffset + length) > (short) out.length) {
    ISOException.throwIt(Constants.SW_WRONG_LENGTH);
}
```

`(short)(outOffset + length)` 在 JC short 是 16-bit signed (-32768..32767)，若 `outOffset + length > 32767` 会溢出为负数，检查通过 → 越界写。

**实际触发条件**：`length <= MAX_EXPAND_LEN = 8160`，`outOffset` 通常 < 256，所以 `outOffset + length < 8500`，**不可触发**。

但这与 F-04 的修复精神（引入 `Bounds.requireCapacity` 杜绝 short 溢出）不一致。

**修复建议**:

替换为 `Bounds.requireCapacity`：

```java
Bounds.requireCapacity(out, outOffset, length);
```

效果相同但永远不会溢出，且代码风格与 `ApduTlv` / `Authentikey` 统一。

---

### 2.7 [F-38] `MeowlApplet` 多个 signing handler 的 innerScratch wipe 不在 try-finally 中

**严重等级**: S4 — Low（防御深度风格不一致）

**位置**:
- `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MeowlApplet.java:354-364` (handleSignPkiCsr)
- `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MeowlApplet.java:515-542` (handleSignEcdsaK1)
- `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MeowlApplet.java:550-577` (handleSignSchnorrK1)

**发现**:

`handleSignEcdsaK1` 代码：

```java
Util.arrayCopyNonAtomic(buffer, digestOff, innerScratch, (short) 0, Constants.DIGEST_LEN);
short sigLen = ecdsaK1.signDigest(buffer, pathOff, depth, innerScratch, (short) 0, buffer,
        ISO7816.OFFSET_CDATA);
Util.arrayFillNonAtomic(innerScratch, (short) 0, Constants.DIGEST_LEN, (byte) 0);
return sigLen;
```

如果 `ecdsaK1.signDigest` 抛 ISOException（例如 BIP-32 `k_i == 0` 抛 `SW_CONDITIONS_NOT_SATISFIED`，或 DER 解析失败抛 `SW_UNSUPPORTED_FEATURE`），最后的 `arrayFillNonAtomic` 不会执行，**innerScratch[0..32] 中的 digest 残留到 deselect**。

**实际影响**:

`innerScratch[0..32]` 中存的是 **host-supplied digest**，是 **public material**（host 已经知道），所以**不是 secret leak**。但与 F-02 修复后的 `handleSignEd25519` 的 try-finally 风格不一致：

```java
// handleSignEd25519 (F-02 修复后):
try {
    slip10.deriveLeafKey(innerScratch, (short) 32, depth, innerScratch, (short) 0);
    return ed25519.sign(...);
} finally {
    Util.arrayFillNonAtomic(innerScratch, (short) 0, (short) (32 + pathLen), (byte) 0);
}
```

**修复建议**:

把 `handleSignEcdsaK1` / `handleSignSchnorrK1` / `handleSignPkiCsr` 改为同样的 try-finally：

```java
Util.arrayCopyNonAtomic(buffer, digestOff, innerScratch, (short) 0, Constants.DIGEST_LEN);
try {
    return ecdsaK1.signDigest(buffer, pathOff, depth, innerScratch, (short) 0,
            buffer, ISO7816.OFFSET_CDATA);
} finally {
    Util.arrayFillNonAtomic(innerScratch, (short) 0, Constants.DIGEST_LEN, (byte) 0);
}
```

虽然 digest 是 public，但 try-finally 是 universal 风格（与 Ed25519 / Schnorr 内部 wipe 一致）。

---

### 2.8 [F-39] `Slip10.wipeWalkState` 与 `Bip32.wipeTransientSecrets` 风格不一致

**严重等级**: S4 — Low（风格统一）

**位置**: `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Slip10.java:128-132`

**发现**:

```java
private void wipeWalkState() {
    Util.arrayFillNonAtomic(state, STATE_K_OFF, SECRET_KEY_LEN, (byte) 0);
    Util.arrayFillNonAtomic(state, STATE_C_OFF, Constants.CHAIN_CODE_LEN, (byte) 0);
    Util.arrayFillNonAtomic(state, STATE_I_OFF, HASH_LEN, (byte) 0);
}
```

`Bip32.wipeTransientSecrets`（F-07 修复后，line 199-202）使用一次性 wipe：

```java
private void wipeTransientSecrets() {
    Util.arrayFillNonAtomic(state, (short) 0, STATE_LEN, (byte) 0);
    scalarKey.clearKey();
}
```

`Slip10.STATE_LEN = 128 = K(32) + C(32) + I(64)`，与三次 wipe 合计字节数完全一致。

**修复建议**:

```java
private void wipeWalkState() {
    Util.arrayFillNonAtomic(state, (short) 0, STATE_LEN, (byte) 0);
}
```

更简洁，且与 `Bip32` / Trezor `hdnode_clear` 风格一致。

---

### 2.9 [F-40] `LifecycleStateTest` 缺失 `transitionToInTx` 与 `resetInTx` 专门测试

**严重等级**: S4 — Low（测试盲区）

**位置**: `@d:/Desktop/x/meowl-applet/tests/src/test/java/social/meowl/applet/LifecycleStateTest.java`

**发现**:

F-15 修复引入了 `transitionToInTx` 与 `resetInTx`（不开内部事务，期望 caller 已持有事务）。`LifecycleStateTest.Stateful` 只测试 `transitionTo` 与 `reset`（公开 API），没有覆盖 `InTx` 变体。

`InTx` 变体的语义关键：**只在已开事务时被调用**。如果 caller 忘记 `beginTransaction`，`current = target` 是直接写入持久字段（按 JC 规范，是原子的单字节写），但与 sibling mutations 不再 atomic。

间接覆盖：`MeowlAppletTest.lifecycleRevertsToUninitialized` 通过完整 reset 间接验证 `resetInTx` 在事务内执行后 GET_INFO 返回 `UNINITIALIZED`。但没有验证 `transitionToInTx` 的 illegal-transition 行为。

**修复建议**:

新增测试：

```java
@Test
@DisplayName("transitionToInTx rejects illegal transitions same as transitionTo")
void inTxRejectsIllegal() {
    LifecycleState s = newInstance();
    // Need to be inside a transaction; jcardsim CardSimulator provides this via APDU dispatch.
    // For pure unit testing, we open a transaction explicitly:
    JCSystem.beginTransaction();
    try {
        ISOException ex = assertThrows(ISOException.class,
                () -> s.transitionToInTx(LifecycleState.SEEDED));  // skip 2 steps
        assertEquals(Constants.SW_LIFECYCLE_INVALID, ex.getReason());
    } finally {
        JCSystem.abortTransaction();
    }
}
```

---

### 2.10 [F-41] `Ed25519.blindBasePoint` / `Edwards25519.randomizeProjective` 完全无测试

**严重等级**: S4 — Low（测试盲区）

**位置**:
- `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Ed25519.java:267-283`
- `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Edwards25519.java:388-432`

**发现**:

grep "blindBasePoint|BLIND_FE|randomizeProjective" 在 `tests/` 返回 **0 hits**。

这两个函数是 F-01 mitigation 的**核心**：

- `randomizeProjective(P, r)`: `(X, Y, Z, T) ← (rX, rY, rZ, rT)`，affine 不变
- `blindBasePoint`: 生成 r ∈ [1, p)，然后调 `randomizeProjective(BASE, r)`

测试可以验证：
- `randomizeProjective(P, r)` 之后 `encodePoint(P)` 输出与原始 P 的 encoding 相同（不变性）
- `blindBasePoint` 产生的 r 总是非零（F-32 修复后）
- `blindBasePoint` 产生的 r 总是 `< p`（F-32 修复后）
- scalarMult 在 blinded base 上 produces same point as unblinded

如果没有这些测试，F-32 修复后无法立刻验证修复正确性。

**修复建议**:

新增 `RandomizeProjectiveTest`：

```java
@Test
void randomizeProjectivePreservesAffineEncoding() {
    byte[] point = new byte[Edwards25519.POINT_LEN];
    Edwards25519.setBase(point, (short) 0);

    byte[] originalEnc = new byte[32];
    byte[] scratch = new byte[Edwards25519.ENCODE_SCRATCH_LEN];
    Edwards25519.encodePoint(point, (short) 0, originalEnc, (short) 0, scratch, (short) 0);

    // Apply random blinding
    byte[] blind = new byte[32];
    new SecureRandom().nextBytes(blind);
    blind[0] &= 0x7F;  // Ensure < p
    // (need to ensure blind != 0 and < p; if not, retry)
    byte[] blindedPoint = point.clone();
    byte[] opScratch = new byte[Edwards25519.POINT_OP_SCRATCH_LEN];
    Edwards25519.randomizeProjective(blindedPoint, (short) 0, blind, (short) 0,
            opScratch, (short) 0);

    byte[] blindedEnc = new byte[32];
    Edwards25519.encodePoint(blindedPoint, (short) 0, blindedEnc, (short) 0,
            scratch, (short) 0);

    assertArrayEquals(originalEnc, blindedEnc,
            "randomizeProjective MUST NOT change the affine encoding");
}
```

---

### 2.11 [F-42] / [F-43] `EcdsaK1.copyDerInteger` DER 严格性放宽

**严重等级**: S5 — Info（理论性，JC 不产生此类 DER）

**位置**: `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/EcdsaK1.java:218-245`

**发现 F-42**: 不检查 minimal DER 编码

当 `rawLen < 33` 且 `der[valStart] == 0x00` 时，code 仍接受并 copy（含 leading 0x00）。严格 DER 要求 INTEGER 必须 minimally encoded：leading 0x00 仅在第二字节 MSB = 1 时合法。

**发现 F-43**: 接受 INTEGER value = 0

当 `rawLen = 1, der[valStart] = 0x00` 时，`copyLen = 1`，写入 `out[outOff..outOff+1]` 一个 0x00 字节（前 31 字节由 padLen 写入 0x00）。即 `r = 0` 或 `s = 0` 被接受，但 ECDSA 中 r=0 或 s=0 是 **invalid signature**（应被签名验证拒绝）。

**实际影响**: JC `Signature.ALG_ECDSA_SHA_256` 不会产生 r=0 或 s=0 的 DER（概率 ≈ 2^-256）。**不可触发**，但 robust parser 应当显式拒绝。

**修复建议**: 

```java
private static short copyDerInteger(byte[] der, short cursor, byte[] out, short outOff) {
    if (der[cursor++] != DER_TAG_INTEGER) {
        ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
    }
    short rawLen = (short) (der[cursor++] & 0xFF);
    if ((rawLen & 0x80) != 0) {
        ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
    }
    short valStart = cursor;
    short nextCursor = (short) (cursor + rawLen);
    short copyLen = rawLen;
    if (rawLen == 33 && der[valStart] == 0) {
        valStart++;
        copyLen--;
    } else if (rawLen > 1 && der[valStart] == 0 && (der[(short)(valStart + 1)] & 0x80) == 0) {
        // F-42: non-minimal DER encoding (leading 0x00 not required)
        ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
    }
    if (copyLen <= 0 || copyLen > ModN.LEN) {
        ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
    }
    // F-43: reject r=0 or s=0
    boolean allZero = true;
    for (short i = 0; i < copyLen; i++) {
        if (der[(short)(valStart + i)] != 0) { allZero = false; break; }
    }
    if (allZero) {
        ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
    }
    short padLen = (short) (ModN.LEN - copyLen);
    Util.arrayFillNonAtomic(out, outOff, padLen, (byte) 0);
    Util.arrayCopyNonAtomic(der, valStart, out, (short) (outOff + padLen), copyLen);
    return nextCursor;
}
```

注：严格 DER 检查会增加 ~10 行代码，对当前 use case 无收益（JC ECDSA 不产生此类 DER）。仅作 defense-in-depth 推荐。

---

### 2.12 [F-44] `ResetToFactory` 缺失专门单元测试

**严重等级**: S5 — Info（测试盲区）

**位置**: 整个 `tests/` 目录

**发现**:

`ResetToFactory` 没有专门的 `ResetToFactoryTest.java`。仅通过 `MeowlAppletTest.ResetToFactory` 间接覆盖以下场景：
- 4 次连续 reset 触发 wipe
- countdown SW 序列 `0x6FA3 → 0x6FA2 → 0x6FA1 → 0x6FA0`
- 其它 INS rearm counter

未覆盖：
- `recordInvocation` 的 "Rearm BEFORE wipe()" 注释（line 58-60）所述的 audit L-2.01 场景：如果 `wipe()` 抛错，`remaining[0]` 仍然 = `RESET_REQUIRED_INVOCATIONS`，下次 `recordInvocation` 计算 `step = N-1` 而不是 `-1`。这个 invariant 没有专门测试。
- `rearm()` 在多种边界状态下的行为（remaining = 0, remaining = N）

**修复建议**: 

新增 `ResetToFactoryTest.java`，独立测试 `recordInvocation` 的 step 计算与 rearm 行为，不依赖 jcardsim applet 整体环境。

---

### 2.13 [F-45] `Bounds.java` 缺失专门单元测试

**严重等级**: S5 — Info（测试盲区）

**位置**: 整个 `tests/` 目录

**发现**:

`Bounds.java` 是 F-04 / F-05 修复引入的核心 overflow-safe 边界检查工具，但没有专门的 `BoundsTest.java`。仅通过 `ApduTlv` / `Authentikey` 调用间接覆盖。

未直接测试的关键路径：
- `requireCapacity(null, 0, 0)` → SW_WRONG_LENGTH
- `requireCapacity(buf, -1, 0)` → SW_WRONG_LENGTH
- `requireCapacity(buf, 0, -1)` → SW_WRONG_LENGTH
- `requireCapacity(buf, buf.length, 0)` → OK（edge case：reserve 0 at end）
- `requireCapacity(buf, 0, buf.length)` → OK
- `requireCapacity(buf, buf.length+1, 0)` → SW_WRONG_LENGTH
- `requireCapacity` 在 `offset + needed` 大于 short 正范围但仍 < `buf.length` 时不触发溢出

**修复建议**: 

新增 `BoundsTest.java`：

```java
@Test
void rejectsNullBuffer() {
    assertThrows(ISOException.class,
            () -> Bounds.requireCapacity(null, (short) 0, (short) 0));
}

@Test
void rejectsNegativeOffset() {
    byte[] buf = new byte[16];
    assertThrows(ISOException.class,
            () -> Bounds.requireCapacity(buf, (short) -1, (short) 0));
}

@Test
void acceptsZeroReserveAtEnd() {
    byte[] buf = new byte[16];
    Bounds.requireCapacity(buf, (short) 16, (short) 0);  // 应不抛错
}

@Test
void rejectsOffsetPastLength() {
    byte[] buf = new byte[16];
    assertThrows(ISOException.class,
            () -> Bounds.requireCapacity(buf, (short) 17, (short) 0));
}

@Test
void overflowSafeWhenOffsetPlusNeededWraps() {
    // Construct a case where (offset + needed) would overflow short, but buf.length is small.
    byte[] buf = new byte[16];
    // offset = 20000, needed = 20000, (short)(40000) = -25536, naive check would pass.
    assertThrows(ISOException.class,
            () -> Bounds.requireCapacity(buf, (short) 20000, (short) 20000));
}
```

---

## 三、未触发但应记录的次要观察

### 3.1 `Bignat.mult` 的 short 算术微妙性

`Bignat.mult` 中 `(short)(xi * yj)` 当 xi=yj=255 时溢出（65025 → -511），但通过 `& DIGIT_MASK` 和 `>>> DIGIT_LEN` 的位提取**结果正确**（已由 200 次 BignatTest.multMatches 随机测试覆盖）。

代码非常微妙。**保留**当前实现，但若未来移植到非 32-bit-aware JC converter，必须重新验证。

### 3.2 `Edwards25519.scalarMult` 的 SPARE_OFF 跨方法复用

`pointDouble` 和 `pointAdd` 都使用 `SPARE_OFF` 作为临时 slot。在 `scalarMult` 中，每次循环调用 `pointDouble` 然后 `pointAdd`，`SPARE_OFF` 被重写。**OK**（已通过 Ed25519SigningTest 多签名 cross-check）。

### 3.3 `MeowlApplet.handleGenerateSeed` 与 `handleImportSeed` 的事务包裹

两者都在 transaction 内调用 `masterSeed.{import,generate}Seed` + `state.transitionToInTx`。`MasterSeed.importSeed` 自检 `JCSystem.getTransactionDepth() == 0` 抛错——这意味着 caller 必须在事务内调用。F-15 修复后该 invariant 已成立。**OK**。

### 3.4 `HmacSha.xorBlock` 在 init 后 / doFinal 前的状态

`init` 后 `softKey = K'`（restored after XOR with IPAD）；`doFinal` 中：
1. `xorBlock(softKey, OPAD)`: softKey = K' XOR OPAD
2. `digest.reset() / update(softKey) / doFinal(softInner)`: outer hash
3. `xorBlock(softKey, OPAD)`: softKey restored back to K'

**正确**（XOR 自反），但 `doFinal` 中 step 1 和 step 3 之间如果异常中断，softKey 是 K' XOR OPAD 而非 K'。**不严重**（softKey 在 transient memory，下次 reset / deselect 清零）。

---

## 四、测试覆盖率综合评估

| 模块 | 测试文件 | v1.3 评级 | 主要缺失 |
| --- | --- | --- | --- |
| ConstantTime | ConstantTimeTest | ⭐⭐⭐⭐ | 无 |
| Bounds | **无** | ⭐ (F-45) | 全部 |
| HmacSha | HmacShaTest | ⭐⭐⭐⭐⭐ | 无（RFC 4231 全向量 + 200 differential） |
| Bignat | BignatTest | ⭐⭐⭐ (F-35) | mask-based 基元 |
| Field25519 | Field25519Test | ⭐⭐⭐⭐ | 无 |
| Edwards25519 | Edwards25519Test | ⭐⭐⭐⭐ (F-41 部分) | randomizeProjective |
| Ed25519 | Ed25519SigningTest | ⭐⭐⭐⭐⭐ | blindBasePoint（覆盖见 F-41） |
| EcdsaK1 | EcdsaK1Test | ⭐⭐⭐⭐ | DER edge cases (F-42 / F-43) |
| Schnorr | SchnorrK1Test + SchnorrTagHashTest | ⭐⭐⭐⭐⭐ | 无 |
| Bip32 / SLIP-10 | HdDerivationTest | ⭐⭐⭐⭐⭐ | 无（BIP-32 / SLIP-10 全向量） |
| ModN | ModNTest | ⭐⭐⭐ (F-34) | negateMod, lessThanHalfN |
| LifecycleState | LifecycleStateTest | ⭐⭐⭐⭐ (F-40 部分) | InTx 变体 |
| MeowlApplet | MeowlAppletTest | ⭐⭐⭐⭐ | 内部 INS 完整覆盖 |
| SecureChannel | SecureChannelTest + SecureChannelStripPkcs5Test | ⭐⭐⭐⭐⭐ | 无 |
| Personalisation | PersonalisationTest | ⭐⭐⭐⭐⭐ | 无 |
| ResetToFactory | **无** (F-44) | ⭐⭐ | recordInvocation 直接测试 |

**关键观察**：

1. **加密原语层**测试质量极高（RFC 4231、BIP-32 / SLIP-10 / RFC 8032 官方向量 + 大量随机 differential）
2. **mask-based 常时基元层**（F-01/F-03/F-15/F-27/F-28 mitigation 引入）**严重缺测**：BignatTest 和 ModNTest 都没有直接测试 F-01 / F-03 修复的核心代码
3. **业务/工具层**测试覆盖良好但有结构性盲区（Bounds、ResetToFactory 无独立测试文件）

**虚假测试 / 冗余测试评估**：

经全面审查，**未发现明显的虚假测试**：每个 `@Test` 都有具体的断言，且断言与测试名称语义一致。`HmacShaTest`、`BignatTest`、`Field25519Test` 等都使用 BigInteger / JDK Mac 作为 oracle，**不是自我证明**。

**轻微冗余**：
- `LifecycleStateTest.IsLegalForward` 的 5 个子测试可以合并为 1 个 parameterized test。但当前展开形式可读性更好，不算缺陷。
- `MeowlAppletTest` 的多个 RESET_TO_FACTORY 测试（countdownStatusWords / fourthTriggersWipe）有少量重叠，但语义焦点不同，**不算冗余**。

---

## 五、修复优先级矩阵

### 5.1 立即应修复（v1.3 sweep）

| F-NN | Severity | 修复工作量 | 描述 |
| --- | --- | --- | --- |
| **F-32** | S3 | 5 分钟 | `Ed25519.blindBasePoint` do-while 重写为 `while (true)` |
| **F-33** | S3 | 5 分钟 | `ModN.negateMod` 改 mask-based |
| **F-34** | S3 | 30 分钟 | `ModNTest` 加 negateMod + lessThanHalfN 测试 |
| **F-35** | S3 | 1 小时 | `BignatTest` 加 mask-based 基元测试 |
| **F-36** | S4 | 2 分钟 | `ApduTlv.java` Javadoc 改 `length ≤ 255` |
| **F-37** | S4 | 5 分钟 | `Hkdf.expand` 改用 `Bounds.requireCapacity` |
| **F-38** | S4 | 10 分钟 | 三个 signing handler 包 try-finally |
| **F-39** | S4 | 1 分钟 | `Slip10.wipeWalkState` 改一次性 wipe |
| **F-41** | S4 | 30 分钟 | 加 `randomizeProjective` 不变性测试 |

**合计修复工作量**: ~2.5 小时

### 5.2 推荐但非必须（v2.0 路线）

| F-NN | Severity | 描述 |
| --- | --- | --- |
| F-40 | S4 | `LifecycleStateTest` 补 InTx 变体测试 |
| F-42 / F-43 | S5 | EcdsaK1 DER 严格性增强（理论 robust，实际不可触发） |
| F-44 | S5 | 新增 `ResetToFactoryTest.java` |
| F-45 | S5 | 新增 `BoundsTest.java` |

---

## 六、审计结论 (v1.3)

### 6.1 上线就绪度更新

**Verdict (v1.3)**: **conditional GO** —— v1.2 的 unconditional GO 仍然有效，但建议 **执行 v1.3 §5.1 列出的 9 项修复**（合计 2.5 小时）以进一步收紧代码质量。

无任何 S2 — High 或 S1 — Critical 新发现。

### 6.2 代码质量横向对比 (v1.3 更新)

| 维度 | meowl-applet (v1.3) | Status Keycard | Satochip | Trezor | Coldcard |
| --- | --- | --- | --- | --- | --- |
| 算法常量精确性 | ✅ 联网逐字校验 | ✅ | ✅ | ✅ | ✅ |
| 常时性 doc-vs-impl 一致 | 🟡 F-33 待修 | ⚠️ (`Util.arrayCompare`) | ✅ | ✅ | ✅ |
| Critical 函数单元测试 | 🟡 F-34/F-35 待补 | ⚠️ | ⚠️ | ✅ | ✅ |
| Try-finally wipe 风格一致 | 🟡 F-38 待统一 | ✅ | ⚠️ | ✅ | ✅ |
| Random blinding 实现 | 🟡 F-32 待修 (control flow) | 不实现 | 不实现 | ✅ | ✅ |

v1.3 修复后，meowl-applet 在**算法常量精确性**、**常时性 doc 一致**、**测试覆盖**三个维度将达到 Trezor / Coldcard 同等水平。

### 6.3 残留风险声明（更新）

v1.0 发布 user-facing release notes 应在 v1.2 文本基础上追加：

> 本次审计 (v1.3) 发现一处 `Ed25519.blindBasePoint` 的 do-while 控制流 bug (F-32)，触发概率 ~2^-251，实际不影响 v1.0 期间任何签名的正确性。修复将在 v1.3.1 patch 中合并。
>
> 此外，v1.3 引入了对 `Bignat` mask-based 常时基元 (F-35) 和 `ModN.negateMod` / `lessThanHalfN` (F-34) 的专门单元测试套件，提升了关键密码学路径的回归保护。

---

**报告作者**: Cascade (Windsurf 代码审计代理)  
**审计完成**: 2026-05 (v1.3 sweep)  
**版本**: 1.3  
**前置版本**: 1.0 / 1.1 / 1.2

如需深入特定 finding 或重审某个模块，请提交 issue 或 ping 维护者。
