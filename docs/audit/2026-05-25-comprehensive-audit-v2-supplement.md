<!--
SPDX-FileCopyrightText: 2026 meowl.social contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# meowl-applet 全方位审计报告 · v2 补充

**审计日期**：2026-05-25（第二轮独立探查）
**审计 commit**：`c0150b1` (HEAD on `main`)
**审计员**：Cascade（仓内只读）
**审计性质**：在 v1 报告 (`2026-05-25-comprehensive-audit.md`，30 finding) 基础上，**从第一性原理重做一次仓内只读探查**，聚焦 v1 未逐行审过的文件、跨文件不变量、supply-chain、constant-time / 异常路径 / wipe 完整性。**不重复 v1 已识别的 finding**；本文件新增编号 `NEWAUDIT-001..NEWAUDIT-024`。

---

## 第 1 章 · 执行摘要

### 1.1 v2 总评

第二轮独立复核**未发现 v1 漏掉的 Critical / High security 漏洞**。核心密码学路径在数学层面经独立手算复核仍然正确：

- `Fp25519.reducePseudoMersenne` 两个 corner case 手算 (`p² ≡ 0`、`(2⁵¹² − 1) ≡ 1443`) 通过。
- `Barrett.multTruncLo` 控制流仅依赖 public 尺寸常量，constant-time 成立。
- `Wei25519 (s/8)·(8G)` cofactor trick 推导正确 (clamped `s ∈ [2²⁵⁴, 2²⁵⁵ − 8]` ⇒ `s/8 < 2²⁵² < ℓ`)。
- `EcdsaK1` DER parser 严格、所有抛错路径有 cursor 一致性兜底。
- `SecureChannel` Encrypt-then-MAC 顺序、IV 单调性、AES-CMAC-128 MAC 计算正确。

但本轮挖出 **24 个 v1 未覆盖的 findings**，集中在三类盲区：

1. **Defense-in-depth wipe 缺口**（applet 层）：`Schnorr.signDigest` 不清 hardware EC key 槽、PIN/PUK handler 不 wipe APDU buffer、`Fp25519Inv` 缺 try-finally。
2. **Supply-chain SHA-pinning + REUSE compliance**：GitHub Actions 全用 floating tag、`REUSE.toml` 把 `BigNat.java` 拼成 `Bignat.java`（与 v1 AUDIT-027 同源但更严重，因为 REUSE 是 license metadata）。
3. **SLSA L3 落地 gap**：`release.yml` 的 attestation step 有 `continue-on-error: true`，与 `SECURITY.md` 中的 "SLSA L3 verifiable" claim 不一致。

### 1.2 Top-5 v2 新发现

| # | 编号 | Severity | 一句话描述 |
| --- | --- | --- | --- |
| 1 | NEWAUDIT-001 | **Medium** | `Schnorr.signDigest` finally 缺 `secp256k1Ec.wipe()`；BIP-340 ephemeral nonce `k'` 残留在硬件 EC key 槽直到 deselect |
| 2 | NEWAUDIT-005 | **Medium** | `handleVerifyPin/Setup/ChangePin/ChangePuk/UnblockPin` 缺 APDU buffer 内 PIN/PUK 字节 wipe（仅 `handleImportSeed` 做了） |
| 3 | NEWAUDIT-014 | **Medium** | `REUSE.toml:37` 把 `BigNat.java` 拼成 `Bignat.java`，REUSE/SPDX 工具完全跳过该文件的上游 GPL attribution |
| 4 | NEWAUDIT-015 | **Medium** | GitHub Actions 全部用 floating tag (`@v6` 等)，未 SHA-pin — SLSA L3 要求 build input 必须可信摘要 |
| 5 | NEWAUDIT-016 | **Medium** | `release.yml:70` `attest-build-provenance` 有 `continue-on-error: true`；release 可在没 attestation 时完成 |

### 1.3 v2 Findings 分布

| Severity | 数量 | 编号 |
| --- | --- | --- |
| **High** | 0 | (none — v1 已找完) |
| **Medium** | 9 | 001, 002, 003, 005, 007, 014, 015, 016, 017 |
| **Low** | 6 | 004, 011, 012, 018, 019, 020 |
| **Info** | 9 | 006, 008, 009, 010, 013, 021, 022, 023, 024 |

| 类别 | 数量 |
| --- | --- |
| security | 10 |
| docs | 4 |
| tooling | 5 |
| quality | 3 |
| tests | 2 |

### 1.4 v1 + v2 综合修复路线图

#### Sprint 1（P0，下个 commit；新增 v2 项 + v1 P0）

| Finding | Action | Cost |
| --- | --- | --- |
| NEWAUDIT-014 | `REUSE.toml:37` `Bignat.java` → `BigNat.java` | trivial |
| NEWAUDIT-009 | `SecureChannel.java:329` 注释 "non-constant-time compare is fine" 改为与 constant-time `compare16` 一致 | trivial |

#### Sprint 2（P1，下个 sprint）

| Finding | Action | Cost |
| --- | --- | --- |
| NEWAUDIT-001 | `Schnorr.signDigest` finally 增 `bip32.wipeEc()` 调用 + Bip32 暴露 `wipeEc()` | trivial |
| NEWAUDIT-002 | `Bip32.derivePath` / `deriveLeafScalar` 包 try-finally | small |
| NEWAUDIT-003 | `Fp25519Inv.inv` 包 try-finally | small |
| NEWAUDIT-005 | 5 个 PIN/PUK handler 加 APDU buffer wipe（或集中 `handleOpenSecureChannel` 统一 wipe inner plaintext） | small |
| NEWAUDIT-007 | `handleOpenSecureChannel` 包 try-finally wipe inner plaintext | small |
| NEWAUDIT-015 | GitHub Actions SHA-pinning | small |
| NEWAUDIT-016 | 移除 `continue-on-error: true` 或 update SECURITY.md 为 "SLSA L3 best-effort" | trivial |
| NEWAUDIT-004 | `Fp25519Inv` overlapping copy 改 backward loop | small |

#### Sprint 3（P2，机会维护）

NEWAUDIT-006 / 008 / 010..013 / 017..024 — 各自 javadoc / 文档 / CI 增强。

---

## 第 2 章 · Applet · Wipe 完整性盲区（v2 最大焦点）

v1 AUDIT-005 只覆盖了**软件 transient buffer** 残留，本章挖出 **hardware EC key 槽 / APDU buffer / RSA scratch / dispatch 异常路径** 几条独立 wipe 缺口。

### NEWAUDIT-001 · Schnorr.signDigest 不清 hardware EC key 槽

- **Severity**: Medium · **类别**: security · **位置**: `Schnorr.java:283-285`

#### 证据

`Schnorr.signDigest` 调用 `bip32.scalarMultG` 两次（line 165 计算 `P = d'·G`，line 214 计算 `R = k'·G`），后者把 BIP-340 ephemeral nonce `k'` 加载到 `bip32.secp256k1Ec.scalarKey`：

```@/d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Schnorr.java:213-214
            bip32.scalarMultG(scratch, K_OFF, scratch, R_OFF);
```

`EcPoint.multiplyG` → `multiplyPoint` 内部 `scalarKey.setS(scalar, ...)`，但**不在出口清除**——清除责任在 caller：

```@/d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/EcPoint.java:137-140
    /** Erases the scalar slot. Caller MUST invoke this in their {@code finally} block. */
    public void wipe() {
        scalarKey.clearKey();
    }
```

`Schnorr.signDigest` finally **只清 scratch**：

```@/d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Schnorr.java:283-285
        } finally {
            Util.arrayFillNonAtomic(scratch, (short) 0, SCRATCH_LEN, (byte) 0);
        }
```

对比：`EcdsaK1.signDigest` finally 调 `signKey.clearKey()` ✓；`Ed25519.wipeScratch` 调 `ec.wipe()` ✓。**Schnorr 缺一环**。

#### 影响

签名结束后，`bip32.secp256k1Ec.scalarKey` 残留 BIP-340 ephemeral nonce `k'`。`k'` 是 secret——若泄漏，配合公开的 `R = k'·G` 和 `s = k + e·d` 可直接反推私钥 `d`（经典 nonce-leak 攻击）。残留期到下次 `setS` 覆盖或 deselect 时自动清零（`TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT`）。实际可达性低（攻击者无 API 读 EC key），但属于 **对称性破缺** 的 defense-in-depth gap。

#### 修复

为 Bip32 新增 `wipeEc()` 并在 Schnorr finally 调用：

```java
// Bip32.java
void wipeEc() {
    secp256k1Ec.wipe();
}

// Schnorr.java finally
Util.arrayFillNonAtomic(scratch, (short) 0, SCRATCH_LEN, (byte) 0);
bip32.wipeEc();
```

成本：**trivial**（2 行 + 1 方法）。

---

### NEWAUDIT-002 · Bip32 derive 异常路径不清 hardware EC key 槽

- **Severity**: Medium · **类别**: security · **位置**: `Bip32.java:79-105`

#### 证据

```@/d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Bip32.java:79-90
    public short derivePath(
            byte[] pathBuf, short pathOff, short depth, byte[] outBuf, short outOff) {
        walkPathToLeaf(pathBuf, pathOff, depth);
        short pubLen = computeCompressedPubkey(state, STATE_K_OFF, state, STATE_PUB_OFF);
        Util.arrayCopyNonAtomic(state, STATE_PUB_OFF, outBuf, outOff, pubLen);
        Util.arrayCopyNonAtomic(
                state, STATE_C_OFF, outBuf, (short) (outOff + pubLen), Constants.CHAIN_CODE_LEN);
        wipeTransientSecrets();
        return (short) (pubLen + Constants.CHAIN_CODE_LEN);
    }
```

`wipeTransientSecrets()` 包含 `secp256k1Ec.wipe()`（line 138-141），但**只在 success path 调用**。若 `walkPathToLeaf` 抛 `SW_CONDITIONS_NOT_SATISFIED`（在 `ckdPriv` line 167-170 / 182-184），或 `computeCompressedPubkey` 内部 EC 抛错，**hardware EC scalarKey 残留**当前 walk 的某个 intermediate scalar。

`deriveLeafScalar`（line 99-105）同样。

#### 关系

v1 **AUDIT-005** 描述了"walkPath 异常路径不 wipe transient secrets"，但 v1 修复建议聚焦 `state` 软件 buffer。本 finding 是 AUDIT-005 的**精确化扩展**：明确把 `secp256k1Ec.scalarKey` (hardware key 槽) 也纳入 wipe 集合。建议两个 finding 在 Sprint 2 一起修。

#### 修复

```java
public short derivePath(...) {
    try {
        walkPathToLeaf(...);
        // ... existing body ...
        return ...;
    } finally {
        wipeTransientSecrets();
    }
}
```

`deriveLeafScalar` 同样。

成本：**small**（2 个方法 × try-finally 包装）。

---

### NEWAUDIT-003 · Fp25519Inv.inv 缺 try-finally 包 wipe scratch

- **Severity**: Medium · **类别**: security · **位置**: `Fp25519Inv.java:122-146`

#### 证据

`Fp25519Inv.inv` 在最后一行 `Util.arrayFillNonAtomic(scratch, scOff, SCRATCH_LEN, 0)`，**仅 success path**。若 `rsaCipher.doFinal` 抛 `CryptoException`（罕见，但 J3R180 DEFERRED_INITIALIZATION 边缘状态可能触发），**scratch[scOff..scOff+128) 残留输入 `a` 的明文** + 32 字节 zero padding。

`a` 在 `Wei25519.encodeEdwards` 调用中含义：

- 第一次 `inv(Y_wei, ...)`：`a = Y_wei`，是 `s·G` 或 `r·G` 的 Y 坐标。`r·G` 的 Y 坐标 + Ed25519 sign 的 `S` → 可放大 fault-injection 攻击面。
- 第二次 `inv((u+1), ...)`：`a = X_wei − a/3 + 1`，secret-derived。

#### 缓解（已存在）

Caller `Ed25519.publicKey` / `Ed25519.sign` 的 outer finally `wipeScratch()` 清 609 bytes，**覆盖整个 Fp25519Inv 用到的 scratch 区段**。所以实际**outer finally 兜底**。但 defense-in-depth 角度，每个 module 应自己保证 wipe 完整性，不依赖 caller — 否则将来新调用方加入时会暴露。

#### 修复

```java
public void inv(byte[] a, short aOff, byte[] out, short outOff, byte[] scratch, short scOff) {
    if (BigNat.ctIsZero(a, aOff, Fp25519.LEN) != 0) {
        ISOException.throwIt(Constants.SW_INTERNAL_ERROR);
    }
    try {
        // ... existing body without trailing arrayFillNonAtomic ...
    } finally {
        Util.arrayFillNonAtomic(scratch, scOff, SCRATCH_LEN, (byte) 0);
    }
}
```

成本：**small**（try-finally 包装）。

---

### NEWAUDIT-004 · Fp25519Inv 使用 arrayCopyNonAtomic 做同数组 overlapping right-shift

- **Severity**: Low · **类别**: correctness / security · **位置**: `Fp25519Inv.java:137-141`

#### 证据

```@/d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Fp25519Inv.java:137-142
        if (produced != RSA_BYTE_LEN) {
            short shift = (short) (RSA_BYTE_LEN - produced);
            Util.arrayCopyNonAtomic(
                    scratch, outBufOff, scratch, (short) (outBufOff + shift), produced);
            Util.arrayFillNonAtomic(scratch, outBufOff, shift, (byte) 0);
        }
```

当硬件 RSA engine 返回 strip 了 leading-zero 的结果（`produced < 64`），代码用**同数组 forward overlap copy** 做 right-align。

#### 风险

JC 3.0.5 API 规范对 `Util.arrayCopyNonAtomic` 同数组 overlap 行为 **未定义**（不像 Java SE `System.arraycopy` 强制 overlap-safe）。Forward copy 的语义会让 right-shift 产生错误结果：step 0 把 `dst[0] = src[0]`，覆盖 src 在 overlap 区的 byte；后续 step 读已被污染的 byte。

实测可能"恰好正确"因为：(a) NXP J3R180 RSA 几乎不 strip leading zeros (mod p 输出最高 byte ≤ 0x7F，但 ≥ 0x80 占 ~50% 输入)；(b) NXP 的 `arrayCopyNonAtomic` 可能 backward-safe（仿 `System.arraycopy`）。两者中至少一个为真，测试套件才能全绿。

升级 silicon / 跨 JC 版本时风险变化。

#### 修复

backward loop 显式 right-shift：

```java
if (produced != RSA_BYTE_LEN) {
    short shift = (short) (RSA_BYTE_LEN - produced);
    for (short i = (short) (produced - 1); i >= 0; i--) {
        scratch[(short) (outBufOff + shift + i)] = scratch[(short) (outBufOff + i)];
    }
    Util.arrayFillNonAtomic(scratch, outBufOff, shift, (byte) 0);
}
```

成本：**small**（5 行）。

---

### NEWAUDIT-005 · PIN/PUK handler 缺 APDU buffer wipe

- **Severity**: Medium · **类别**: security · **位置**: `MeowlApplet.java:283-336`

#### 证据

`handleImportSeed` 是**唯一**显式 wipe APDU buffer 内 secret 字节的 handler：

```@/d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MeowlApplet.java:476-478
        // Overwrite the seed bytes in the APDU buffer before the response goes out.
        Util.arrayFillNonAtomic(buffer, (short) (dataOff + 1), seedLen, (byte) 0);
        return 0;
```

其他 5 个 handler **没有 wipe**：

- `handleSetup` (`MeowlApplet.java:283-298`)：PIN + PUK 残留
- `handleVerifyPin` (`:300-304`)：PIN 残留
- `handleChangePin` (`:307-313`)：old + new PIN 残留
- `handleChangePuk` (`:320-327`)：old + new PUK 残留
- `handleUnblockPin` (`:330-336`)：PUK + new PIN 残留

#### 影响

APDU buffer 是 SC 解密后的 plaintext 落地区。Handler 返回后 PIN/PUK 字节仍在 buffer 内，直到：(a) 下次 `unwrap` decrypt 新 ciphertext 部分覆盖；(b) `wrap` copy plaintext 前不 wipe 源，可能再次保留；(c) deselect 后 JC 自动清理（不强制）。

#### 修复（建议集中化）

更优做法不是 5 个 handler 各加 wipe，而是在 `handleOpenSecureChannel` 末尾统一 wipe inner plaintext（与 NEWAUDIT-007 合并修复）。

成本：**small**。

---

### NEWAUDIT-006 · Wei25519.encodeEdwards 缺自己的 try-finally

- **Severity**: Info · **类别**: security · **位置**: `Wei25519.java:323-364`

`encodeEdwards` 最后一行 wipe 仅在 normal exit 路径。caller `Ed25519` 的 outer finally `wipeScratch()` 已经兜底（清 609 bytes，覆盖整个 encodeEdwards 区段）。**实际无残留窗口**，降级 Info。

#### 修复（防未来 caller 漏兜底）

包 try-finally：

```java
public static void encodeEdwards(...) {
    try { /* body */ } finally {
        Util.arrayFillNonAtomic(scratch, scratchOff, ENCODE_SCRATCH_LEN, (byte) 0);
    }
}
```

成本：**trivial**。

---

### NEWAUDIT-007 · dispatchInner 异常时 buffer 残留 inner-APDU plaintext

- **Severity**: Medium · **类别**: security · **位置**: `MeowlApplet.java:182-203`

#### 证据

```@/d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MeowlApplet.java:182-203
    private short handleOpenSecureChannel(APDU apdu, byte[] buffer) {
        short lc = apdu.setIncomingAndReceive();
        short plainLen = secureChannel.unwrap(buffer, ISO7816.OFFSET_CDATA, lc);
        // ... parse inner header ...
        short respLen = dispatchInner(buffer, innerIns, innerP1, innerP2, innerDataOff, innerLc);
        return secureChannel.wrap(buffer, ISO7816.OFFSET_CDATA, respLen);
    }
```

`secureChannel.unwrap` 把 SC 解密后的 plaintext 写入 `buffer[OFFSET_CDATA..]`。`dispatchInner` 抛 ISOException 时 `wrap` 不被调用，**buffer 内 plaintext 不被 wipe**。下次 `unwrap` decrypt 新 ciphertext 时**partial 覆盖**——若新 ciphertext 比旧 plaintext 短，**tail residue 仍在**。

这是 NEWAUDIT-005 的更通用版本：覆盖所有 inner INS（不只 PIN/PUK，还有 IMPORT_SEED 的 seed、IMPORT_PKI_CERT 的 chunk、SIGN_* 的 path + digest）。

#### 修复

包 try-finally：

```java
private short handleOpenSecureChannel(APDU apdu, byte[] buffer) {
    short lc = apdu.setIncomingAndReceive();
    short plainLen = secureChannel.unwrap(buffer, ISO7816.OFFSET_CDATA, lc);
    try {
        // ... parse + dispatchInner ...
        return secureChannel.wrap(buffer, ISO7816.OFFSET_CDATA, respLen);
    } finally {
        Util.arrayFillNonAtomic(buffer, ISO7816.OFFSET_CDATA, plainLen, (byte) 0);
    }
}
```

**修了 NEWAUDIT-007，NEWAUDIT-005 自动 covered**（PIN/PUK 是 inner-APDU plaintext 的子集）。

成本：**small**。

---

### NEWAUDIT-008 · MasterSeed.copyBip32MasterTo 注释 misleading

- **Severity**: Info · **类别**: docs · **位置**: `MasterSeed.java:230-237`

注释声称"Widening to public would let any package-internal class (PKI, SC, …) copy the master"——逻辑错误：JC 中 package-private **不阻止同包内其他类调用**。当前所有 applet 类（PKI / SC / PIN 等）**已经能调** `copyBip32MasterTo`，仅靠 code review 约束。

修复：javadoc 改为说明"convention enforced by code review"。

成本：**trivial**。

---

### NEWAUDIT-009 · SecureChannel.unwrap 注释 stale

- **Severity**: Info · **类别**: docs · **位置**: `SecureChannel.java:328-336`

注释说 `"IV bytes are public, so a non-constant-time compare is fine"`，但代码用了 **constant-time** `compare16`（line 438-459 sticky-mask 实现）。注释与实际代码不一致。

修复：注释改为"虽然 IV 是 public，仍用 constant-time 与代码库其他部分（`BigNat.ctEquals`、`stripPkcs5`）保持同一 defense-in-depth 风格"。

成本：**trivial**。

---

### NEWAUDIT-010 · Bip32.scalarMultG API contract 缺 wipe 责任声明

- **Severity**: Info · **类别**: docs / quality · **位置**: `Bip32.java:107-115`

`scalarMultG` 是 public method 供 Schnorr 调用，javadoc 没说明 caller 必须在 finally 内清 `secp256k1Ec.scalarKey`。这是 NEWAUDIT-001 的根本原因。

修复：javadoc 增加 caller responsibility 段，指向 `wipeEc()`（NEWAUDIT-001 新增方法）。

成本：**trivial**。

---

## 第 3 章 · Tools · Host-side 新发现

### NEWAUDIT-011 · BenchCommand 硬编码 CLA_MEOWL = 0x80

- **Severity**: Low · **类别**: quality · **位置**: `BenchCommand.java:250`

```@/d:/Desktop/x/meowl-applet/tools/src/main/java/social/meowl/tools/cli/BenchCommand.java:248-257
    private static byte[] innerApdu(byte ins, byte p1, byte p2, byte[] data) {
        byte[] out = new byte[5 + data.length];
        out[0] = (byte) 0x80;
        ...
```

应使用 `SecureChannelClient.CLA_MEOWL`（已公开常量）。与 v1 AUDIT-013 / AUDIT-014 同质（host 端 mirror drift）。

成本：**trivial**。

---

### NEWAUDIT-012 · BenchCommand.innerApdu LC 字段 silent truncate

- **Severity**: Low · **类别**: quality · **位置**: `BenchCommand.java:254`

`out[4] = (byte) data.length`：若 `data.length > 255` silent truncate。缺 bounds check 会让调试困难。对比 `SecureChannelClient.sendInner:185-191` 对 outer envelope LC 已经做 check。

修复：增加显式 bounds check throw `IllegalArgumentException`。

成本：**trivial**。

---

### NEWAUDIT-013 · BenchCommand.Stats 百分位索引边界不对称

- **Severity**: Info · **类别**: quality · **位置**: `BenchCommand.java:374-382`

只有 p99 用 `Math.min(sorted.length - 1, ...)` 防越界，p50 / p95 没用。实际不会越界（系数 < 1.0），但风格不对称易混淆。

成本：**trivial**。

---

## 第 4 章 · Supply-chain / Tooling 新发现

### NEWAUDIT-014 · REUSE.toml 把 BigNat.java 拼成 Bignat.java

- **Severity**: Medium · **类别**: docs / supply-chain · **位置**: `REUSE.toml:37`

#### 证据

```@/d:/Desktop/x/meowl-applet/REUSE.toml:36-44
[[annotations]]
path = "applet/src/main/java/social/meowl/applet/Bignat.java"
precedence = "aggregate"
SPDX-FileCopyrightText = [
    "2026 meowl.social contributors",
    "2008-2009 Digital Security (DS) group, Radboud Universiteit Nijmegen (OV-chip 2.0)",
    "2015-2024 Toporin (Satochip)",
]
SPDX-License-Identifier = "AGPL-3.0-or-later"
```

实际文件是 `BigNat.java`（大写 N）。

#### 影响

REUSE/SPDX 工具按 path 精确匹配，**找不到 `Bignat.java`** ⇒ 完全跳过该 entry ⇒ `BigNat.java` 只继承顶层 `applet/**` aggregate（仅 meowl + AGPL），**上游 OV-chip 2.0 / Satochip 的 GPL attribution 链丢失**。

与 v1 AUDIT-027 (`SECURITY.md` 同样错误) **同质但更严重**：v1 是文档 link broken，本 finding 是 **license compliance metadata 失效**。下游 SBOM 工具会得出"BigNat.java 仅为 meowl 原创"的错误结论。

#### 修复

`REUSE.toml:37`：`Bignat.java` → `BigNat.java`。

成本：**trivial**。建议同时在 CI 加 `reuse lint` step（见 NEWAUDIT-019）。

---

### NEWAUDIT-015 · GitHub Actions 不 SHA-pinned

- **Severity**: Medium · **类别**: tooling / supply-chain · **位置**: `.github/workflows/{ci.yml,release.yml}`

#### 证据

`ci.yml`:

```@/d:/Desktop/x/meowl-applet/.github/workflows/ci.yml:25-52
        uses: actions/checkout@v6
        uses: actions/setup-java@v5
        uses: gradle/actions/setup-gradle@v6
        uses: actions/upload-artifact@v7
```

`release.yml` 同样全部 `@vN` floating tag (line 41, 46, 52, 71, 76)。

#### 影响

floating tag 可被 force-push 替换。若 upstream action 被攻陷（账户 hijack / 供应链投毒），CI/release 自动拉取新代码并执行——典型 SolarWinds / Codecov 攻击面。

[SLSA L3 spec](https://slsa.dev/spec/v1.0/requirements) 要求 "All build inputs are tracked by digest"。`SECURITY.md:8` 声称 SLSA L3 与此实际不符。

#### 修复

每个 action 用 `@<commit-SHA>` 并以 comment 标注版本：

```yaml
- uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v6
- uses: actions/setup-java@5fa4a31bbb33d9e6d5fee9ef0c7b6e3e0c7afad6 # v5
```

Dependabot 已配置自动 update `github-actions` ecosystem（`.github/dependabot.yml:13-16`），SHA pin 与 dependabot 兼容。

成本：**small**（6 个 action × 查 SHA + 替换）。

---

### NEWAUDIT-016 · release.yml attestation `continue-on-error: true` 与 SLSA L3 claim 矛盾

- **Severity**: Medium · **类别**: tooling / docs · **位置**: `release.yml:69-73`

#### 证据

```@/d:/Desktop/x/meowl-applet/.github/workflows/release.yml:69-73
      - name: Attest SLSA build provenance
        continue-on-error: true # Only works for public repos on Team/Pro/Free plans
        uses: actions/attest-build-provenance@v4
        with:
          subject-path: release/meowl-applet.cap
```

`SECURITY.md:8, 41` 同时声称 SLSA L3 + `gh attestation verify` 可用。但 attestation step 标 `continue-on-error: true`——若 GitHub plan 不支持 / OIDC 服务异常 / action 失败，**release 仍继续**，artifact 没有 attestation。

#### 影响

下游用户运行 `gh attestation verify meowl-applet.cap --repo qntx/meowl-applet` 在这些 release 上会失败但无显式警告——**信任锚被 silently 削弱**。

#### 修复（二选一）

**A**：移除 `continue-on-error: true`。release 失败时人工介入。强 SLSA L3。
**B**：保留 `continue-on-error`（适应 plan 限制），但 `SECURITY.md` claim 改为 "SLSA L3 best-effort attestation"。

建议 **A** 配合 GitHub Actions plan 升级（项目已是 public repo，应有免费 attestation）。

成本：**trivial**（A 选项），或 **small**（B 选项 + docs 同步）。

---

### NEWAUDIT-017 · `.gitmodules` 子模块状态未在 CI 验证

- **Severity**: Medium · **类别**: tooling · **位置**: `.gitmodules`, `ci.yml:25-28`

CI 用 `actions/checkout@v6 with: submodules: recursive` 拉取 `sdks/` 子模块。但 **没有验证子模块 commit SHA 是否与 main 期望一致**——攻击者若获得 `sdks/` upstream repo 写权限，可推送 malicious commit；CI 拉取新 SHA 时无 gate。

#### 修复

CI 加 step 验证子模块 commit:

```yaml
- name: Verify SDK submodule pin
  run: |
    git -C sdks rev-parse HEAD | grep -q '^<expected-sha>$'
```

或更好：把 `sdks/` 改为 vendored copy（如 `3rdparty/` 已是 vendored）+ 删除 submodule。

成本：**small**。

---

### NEWAUDIT-018 · CI 不跑 REUSE lint

- **Severity**: Low · **类别**: tooling · **位置**: `ci.yml`

`ci.yml` 没有 `reuse lint` step。NEWAUDIT-014 (REUSE.toml typo) 之所以没被发现，就是因为没 CI gate。

#### 修复

```yaml
- name: REUSE compliance
  uses: fsfe/reuse-action@v3  # SHA-pinned per NEWAUDIT-015
```

成本：**trivial**。

---

### NEWAUDIT-019 · CI 不跑 dependency vulnerability scan

- **Severity**: Low · **类别**: tooling · **位置**: `ci.yml`

Dependabot 自动 PR 但**没有静态 vulnerability scan**（OWASP dependency-check / Snyk / `gradle dependencyCheckAggregate`）。CVE 在 release 周期内可能未被发现。

#### 修复

加 OWASP Dependency-Check Gradle plugin + CI step：

```kotlin
plugins {
    id("org.owasp.dependencycheck") version "11.x.x"
}
```

```yaml
- name: OWASP Dependency Check
  run: ./gradlew dependencyCheckAggregate
```

成本：**small**（plugin 配置 + CI step + 初次 baseline 调整）。

---

### NEWAUDIT-020 · Dependabot grouping 把所有更新合一个 PR

- **Severity**: Info · **类别**: tooling · **位置**: `.github/dependabot.yml:9-11, 17-19`

`groups.all.patterns: ["*"]` 把所有 update 合并为单一 PR。大批 update 同时进来时难以 isolate breaking changes，回滚成本高。

#### 修复

按风险分组：

```yaml
groups:
  bouncycastle:
    patterns: ["org.bouncycastle:*"]
  build-tools:
    patterns: ["com.github.martinpaljak:*", "*-gradle-plugin"]
  test:
    patterns: ["org.junit:*", "info.picocli:*"]
```

成本：**trivial**。

---

## 第 5 章 · Tests / Process 新发现

### NEWAUDIT-021 · 缺 wipeInTx invariant 的 negative test

- **Severity**: Low · **类别**: tests · **位置**: `tests/src/test/java/...`

v1 AUDIT-001 提到 `MasterSeed.wipeInTx` 不清 EEPROM 是 trade-off，依赖 invariant "下次 `IMPORT_SEED` / `GENERATE_SEED` 完全覆盖旧 cells"。**当前测试套件没有 negative test 验证此 invariant**——例如：

1. `IMPORT_SEED(seed_A)` → 触发完整流程
2. `RESET_TO_FACTORY × 4`
3. `IMPORT_SEED(seed_B)` (seed_B 长度比 seed_A 短)
4. 通过 EXPORT_XPUB 验证派生与 seed_A 无关
5. （可选）通过 fault-injection-like 路径验证 EEPROM 真正被覆盖

修复：加 `ResetToFactoryInvariantTest` 验证完整覆盖。

成本：**small**。

---

### NEWAUDIT-022 · SecureRandom 在 SC 测试中不可复现

- **Severity**: Info · **类别**: tests · **位置**: `SecureChannelTest.java:60`, `testkit/TestConstants.java:34`

```@/d:/Desktop/x/meowl-applet/tests/src/test/java/social/meowl/applet/SecureChannelTest.java:60
    private static final SecureRandom RANDOM = new SecureRandom();
```

SC handshake / KDF 测试用不可复现 RNG。失败 case 难以 isolate 哪个 seed 触发。

#### 修复（折中）

测试日志中打印 seed bytes，让 reproduction 通过手动 seed override 可能：

```java
private static final SecureRandom RANDOM = SecureRandom.getInstanceStrong();
static {
    byte[] seed = new byte[16];
    RANDOM.nextBytes(seed);
    System.err.println("[test] SecureChannelTest RANDOM seed: " + HexFormat.of().formatHex(seed));
}
```

成本：**trivial**。

---

### NEWAUDIT-023 · 缺审计文档间 cross-link

- **Severity**: Info · **类别**: docs · **位置**: `docs/audit/`

`docs/audit/` 现有 v1 + v2 两份独立 markdown，**没有 index 或 link**。未来轮次审计能力依赖文档间交叉引用。

#### 修复

新增 `docs/audit/README.md` 作为索引：

```markdown
# meowl-applet 审计历史

| 日期 | 报告 | Commit | Findings |
| --- | --- | --- | --- |
| 2026-05-25 | [v1 全方位审计](2026-05-25-comprehensive-audit.md) | c0150b1 | 30 (AUDIT-001..036) |
| 2026-05-25 | [v2 独立复核补充](2026-05-25-comprehensive-audit-v2-supplement.md) | c0150b1 | 24 (NEWAUDIT-001..024) |
```

成本：**trivial**。

---

### NEWAUDIT-024 · PkiManager.signCsr length 检查潜在 short cast 风险

- **Severity**: Info · **类别**: correctness · **位置**: `PkiManager.java:99-101`

```@/d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/PkiManager.java:99-101
        if (digestOffset < 0
                || (short) ((short) digest.length - digestOffset) < Constants.EC_SCALAR_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
```

`(short) digest.length` 若 `digest` 是大数组（`> 32767`）会 wraparound 为负。**当前实际 digest = `innerScratch` 长度 128**，**不可达**。但 defensive 角度，short cast 隐式假设值在范围内。

#### 修复（如果在乎）

显式 bounds check：

```java
if (digest.length > Short.MAX_VALUE) {
    ISOException.throwIt(Constants.SW_INTERNAL_ERROR);
}
```

或文档化前置条件。

成本：**trivial**。

---

## 第 6 章 · 综合结论

### 6.1 v1 + v2 综合 finding 数

| | High | Medium | Low | Info | 总计 |
| --- | --- | --- | --- | --- | --- |
| v1 (AUDIT-001..036) | 3 | 11 | 6 | 10 | 30 |
| v2 (NEWAUDIT-001..024) | 0 | 9 | 6 | 9 | 24 |
| **合计** | **3** | **20** | **12** | **19** | **54** |

### 6.2 项目可发布性更新

v1 结论是"可打 v1.0-rc1 tag，前提是 Sprint 1 完成 + AUDIT-001 ADR sign-off"。**v2 不改变此结论**，但增加两个 Sprint 1 / Sprint 2 必须项：

- **Sprint 1 新增**：`REUSE.toml` typo 修（NEWAUDIT-014）+ SC.unwrap 注释修（NEWAUDIT-009）
- **Sprint 2 新增**：`Schnorr` ec key 槽清理（NEWAUDIT-001）+ APDU buffer wipe 集中化（NEWAUDIT-005 + NEWAUDIT-007 合并）+ Actions SHA-pinning（NEWAUDIT-015）+ SLSA L3 claim 与 attestation step 对齐（NEWAUDIT-016）

### 6.3 不在本次 v2 审计范围

- v1 列出的所有"不在范围"项（CAP binary verification / 物理 side-channel / formal verification 等）。
- 实卡 timing / power 分析——属于外部 audit。
- 测试套件覆盖率定量分析（需 JaCoCo）。
- 模糊测试（jqwik / quickcheck）扩展性 — 见 NEWAUDIT-022 部分讨论。

### 6.4 v2 审计员签字

**审计员**：Cascade
**报告时间**：2026-05-25（v1 同日，第二轮独立探查）
**报告版本**：v2.0 (final supplement to v1)
**v2 finding 总数**：24
**报告总行数**：约 770 行
**与 v1 关系**：补充非重叠，编号空间不冲突

---

> **后记**：v1 + v2 两轮独立探查得出一致结论——`meowl-applet` 是**架构清晰、密码学严谨、单平台硬化彻底**的 JavaCard 硬件钱包 applet，主要短板集中在 **defense-in-depth wipe 完整性**（v2 的 NEWAUDIT-001/002/003/005/007）和 **文档/supply-chain 同步**（v1 的 AUDIT-024..029 + v2 的 NEWAUDIT-014/015/016）。所有 finding 都是 trivial-to-small cost，**没有需要重写或破坏性变更的架构性缺陷**。
