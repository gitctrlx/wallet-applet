# 02 — 加密原语审计

<!-- SPDX-FileCopyrightText: 2026 meowl.social contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

横切角度 —— 把 applet 实现对照 RFC / BIP / SLIP / SEC 规范逐项核对，并与权威参考实现（Bitcoin Core libsecp256k1、RFC 8032 reference signer、Trezor `crypto`、Ledger speculos）做差异分析。Findings 用本仓库的 `A-XX` 编号，与 [`01-applet-files.md`](./01-applet-files.md) 互引。

## 算法清单与对应文件

| 算法 | 主入口 | 依赖原语 | 规范文档 |
| --- | --- | --- | --- |
| HMAC-SHA-{256, 512} | `HmacSha.java` | platform / RFC 2104 软实现 | RFC 2104 |
| HKDF-SHA-256 | `Hkdf.java` | `HmacSha` | RFC 5869 |
| BIP-32 secp256k1 HD | `Bip32.java` | `HmacSha`、`KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`、`ModN` | BIP-32 |
| SLIP-10 ed25519 HD | `Slip10.java` | `HmacSha512` | SLIP-10 |
| ECDSA secp256k1 (low-s) | `EcdsaK1.java` | `Signature.ALG_ECDSA_SHA_256`、`ModN` | SEC 1 v2.0、BIP-62 |
| Schnorr BIP-340 | `Schnorr.java` | `MessageDigest.ALG_SHA_256`、`Bip32.scalarMultG`、`ModN` | BIP-340 |
| Ed25519 (RFC 8032) | `Ed25519.java` | `MessageDigest.ALG_SHA_512`、`Edwards25519`、`Bignat` | RFC 8032 §5.1 |
| AES-256-CBC + HMAC-SHA-256 | `SecureChannel.java` | platform `Cipher`、`HmacSha256` | NIST SP 800-38A、RFC 2104 |
| Edwards25519 群运算 | `Edwards25519.java` | `Field25519`、`Bignat` | RFC 8032 §5.1.4、Hisil 2008 |
| F_p (p=2²⁵⁵−19) 算术 | `Field25519.java` | `Bignat` | RFC 7748 §4.1 |

---

## 1. HMAC-SHA-{256, 512} (`HmacSha.java`)

### 规范对照（RFC 2104）

| 要求 | 实现 | 状态 |
| --- | --- | --- |
| `H(K' ⊕ opad ‖ H(K' ⊕ ipad ‖ M))` | 软回退 inner+outer 双 SHA | ✅ |
| K 长度 > B 时 K' = H(K) | `compactKey` 逻辑 | ✅ |
| K 长度 < B 时 K 用 0 填充至 B | `Util.arrayFillNonAtomic(softKey, keyLen, blockSize-keyLen, 0)` | ✅ |
| K 长度 ≤ B 时直接复制 | `Util.arrayCopyNonAtomic(key, keyOff, softKey, 0, keyLen)` | ✅ |
| ipad = 0x36 重复 B 次 | `IPAD = (byte) 0x36` + `xorBlock` | ✅ |
| opad = 0x5C 重复 B 次 | `OPAD = (byte) 0x5C` | ✅ |

### Native vs 软回退选路

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\HmacSha.java:84-105
try {
    Signature s = Signature.getInstance(sigAlgo, false);
    HMACKey k = (HMACKey) KeyBuilder.buildKey(keyType, blockSize, false);
    return new HmacSha(blockSize, hashLen, s, k, null);
} catch (Exception e) {
    // ALG_HMAC_SHA_256 / 512 absent on JC 3.0.5 — fall through to software.
}
MessageDigest digest = MessageDigest.getInstance(digestAlgo, false);
byte[] softKey = JCSystem.makeTransientByteArray(blockSize, JCSystem.CLEAR_ON_DESELECT);
return new HmacSha(blockSize, hashLen, null, null, digest, softKey);
```

`forceSoftware` 测试钩子让 `HmacShaTest` 同时跑 native 和软路径 —— 真实卡上跑 native，jcardsim 上 native 也存在但软路径必须在测试中显式触发。✓

### Findings

无。RFC 4231 §4.1–4.7 全部 7 条 SHA-256 测试向量 + SHA-512 同套向量都被 `HmacShaTest.rfc4231` 验证（`@/d:/Desktop/x/meowl-applet/tests/src/test/java/social/meowl/applet/HmacShaTest.java`）。

### 对比参考实现

- **Bitcoin Core** `crypto/hmac_sha256.cpp`：同算法，C++ 模板风格。差异仅在分配器。
- **Trezor crypto** `hmac.c`：相同结构；`hmac_sha256_Init` 的 K' 计算与本 applet 的 `compactKey` 一致。
- **Status Keycard 旧代码**：使用 `Signature.ALG_HMAC_SHA_512` 直接，无软回退；在缺 native HMAC 的卡 (J3R180) 上无法运行。本 applet 的双路径设计**优于 Status Keycard**，是关键卖点。

---

## 2. HKDF-SHA-256 (`Hkdf.java`)

### 规范对照（RFC 5869）

| 要求 | 实现 | 状态 |
| --- | --- | --- |
| `Extract(salt, IKM) = HMAC(salt, IKM)` 输出 PRK | 行 88-93 | ✅ |
| salt 缺省时用 HashLen 个 0 | 行 86-87 | ✅ |
| `Expand(PRK, info, L) = T(1) ‖ T(2) ‖ ...` | 行 122-139 主循环 | ✅ |
| `T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i)` | counter 在 byte buf 中递增 | ✅ |
| 计数器从 0x01 开始 | 行 119 `byte counter = 1` | ✅ |
| `L ≤ 255 × HashLen = 8 160` | `MAX_EXPAND_LEN = 8 160` | ✅ |

### 关键正确性细节

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Hkdf.java:121-139
boolean firstBlock = true;
while (remaining > 0) {
    hmac.init(prk, (short) 0, HASH_LEN);
    if (!firstBlock) {
        hmac.update(scratch, (short) 0, HASH_LEN);
    }
    if (infoLen > 0) {
        hmac.update(info, infoOffset, infoLen);
    }
    counterBuf[0] = counter;
    hmac.doFinal(counterBuf, (short) 0, (short) 1, scratch, (short) 0);
    short take = remaining < HASH_LEN ? remaining : HASH_LEN;
    Util.arrayCopyNonAtomic(scratch, (short) 0, out, writeOffset, take);
    writeOffset += take;
    remaining -= take;
    counter++;
    firstBlock = false;
}
```

**首块 T(1)** 不拼接前一块（`firstBlock=true`），与 RFC 5869 §2.3 `T(0) = empty` 语义一致。⚠️ 注意：直接传 `hmac.update(scratch, 0, 0)` 在 JC 上某些 Signature 实现会调用 `IndexOutOfBoundsException`，这里用 `if (!firstBlock)` 跳过是防御性写法，正确。

`counterBuf` 单字节 transient 是为了避开 JC `Signature.update` "可能延迟摄取"导致 host buffer 在 `doFinal` 前被复用的问题：

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Hkdf.java:39-43
private final byte[] counterBuf;
```

参考 Oracle JC API 文档 `Signature.update`：`The handler may not retrieve the input bytes prior to the next update or doFinal call`. 但若 host 在 update 之间改写源缓冲，行为是 implementation-defined。`counterBuf` 是单卡只属变量，永不被覆写到 `doFinal` 完成之前。✓

### Findings

无。`HkdfTest` (4 803 字节 + tools 镜像 `tools/.../HkdfSha256Test.java` 5 KB) 用 RFC 5869 全部 3 条官方向量 (Test Case 1-3) 双向 cross-check：applet 实现产出 = `tools/HkdfSha256` 实现产出 = RFC 5869 expected。

---

## 3. BIP-32 secp256k1 HD (`Bip32.java`)

### 规范对照

| BIP-32 节 | 实现位置 | 状态 |
| --- | --- | --- |
| Master key generation | `MasterSeed.importSeed` 行 115-123 + `requireValidBip32MasterKey` | ✅ |
| `0 < parse256(I_L) < n` 检查 | `MasterSeed.java:204-210` | ✅ |
| Hardened CKDpriv: `HMAC(c_par, 0x00 ‖ ser256(k_par) ‖ ser32(i))` | `Bip32.java:179-188` (`hardenedDerivation`) | ✅ |
| Non-hardened CKDpriv: `HMAC(c_par, serP(K_par) ‖ ser32(i))` | `Bip32.java:194-216` (`nonHardenedDerivation`) | ✅ |
| `parse256(I_L) ≥ n` 或 `k_i == 0` 时跳到下一索引 | 行 224-227 抛 SW_CONDITIONS_NOT_SATISFIED | ⚠️ 见下 |

### Finding A-21 — invalid I_L 处理偏离 BIP-32 [S3 — Low]

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Bip32.java:224-227`

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Bip32.java:222-235
short ilOff = (short) (workOff + (short) 0);
boolean zero = ModN.addMod(ilOff_state, ilOff, kParOff_state, ilOff_state, derivedKey, derivedOff);
if (zero || !ModN.lessThanN(derivedKey, derivedOff)) {
    ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
}
```

**判定**：S3。BIP-32 §"Specification: Key derivation" 要求 invalid I_L 时**自动跳到下一个索引** (i+1)。本 applet 选择**抛错让 host 重试**：

> *In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid, and one should proceed with the next value for i. (Note: this has probability lower than 1 in 2¹²⁷.)*

宇宙年龄量级的概率事件（2⁻¹²⁷）—— 实际遇到的概率为零。本 applet 把它转成"客户端重试一个不同 path"是合理简化，但 BIP-32 严格指定的是"递增 i 重试"，*同一 path* 应该返回**有效**的下一索引而非错误。

**实际影响**：永远不会触发。若真触发了，host SDK 必须懂得递增 path index 再重试 —— 而当前 host SDK (`MeowlClient`) 不实现这个。一旦命中（数学上不会），整个钱包对该 path 不可用。

**修复建议**：把 invalid 处理移到 applet 内部 —— 在循环里直接 `++i` 重试。代价 ~10 行代码 + 一个本就有的 `state` 持久化 path。但鉴于发生概率 2⁻¹²⁷，更务实的方案是**在文档中明示这个偏离**，并让 host SDK 保留 retry 钩子。当前现状偏离 BIP-32 字面要求但等价于 BIP-32 在所有实际 path 上的行为。

---

### 对比参考

- **Trezor `bip32.c`** `hdnode_private_ckd`：使用 secp256k1 库直接计算，遇到 invalid I_L 直接 `return 0` 让 host 决定。本 applet 行为类似。
- **Ledger** Speculos / BOLOS bip32：在 native 层 retry。
- **libsecp256k1** `secp256k1_ec_seckey_tweak_add`：返回 0 表示 invalid，由调用者处理。

本 applet 的"抛错让 host 重试"更接近 Trezor / libsecp256k1 风格。

---

## 4. SLIP-10 ed25519 HD (`Slip10.java`)

### 规范对照

| SLIP-10 §1 | 实现 | 状态 |
| --- | --- | --- |
| Master from `HMAC-SHA512("ed25519 seed", S)` | `MasterSeed.copySlip10MasterTo` 拉 64-byte | ✅ |
| 仅支持 hardened derivation | `Slip10.java:96-105` | ✅ |
| `HMAC(c_par, 0x00 ‖ k_par ‖ ser32(i))` | `derive` 内 hmac.sign 调用 | ✅ |
| Output: `(I_L, I_R)` 直接作为 (k_i, c_i)，**不**做 `(I_L + k_par) mod n` 加法 | 行 119-126 | ✅ |
| **不**做 valid-key check（任何 32 字节都是合法 ed25519 priv） | 实现一致 | ✅ |

### 与 BIP-32 的关键差异

ed25519 上私钥是任意 32 字节（clamp 在签名时做，不在 derivation 时做），SLIP-10 因此：

1. **不需要** `parse256(I_L) < n` 检查（没有"群阶"限制）。
2. **不做模加法** —— 直接令 `k_i = I_L`。
3. **强制 hardened**：因为 ed25519 没有公钥派生原语（曲线 cofactor 8 + clamping 让 PoK 不一致）。

### Findings

无（`A-20` 仅 S4）。

### 对比参考

- **SLIP-10 reference** Python (`slips/slip-0010.md`)：完全一致。
- **Solana CLI** (`solana-cli` keystore)：使用 SLIP-10 ed25519，对照测试用例都在本 applet 测试中以 `HdDerivationTest.slip10WellKnownVector` 形式存在。
- **Trezor** `hdnode_private_ckd_curve25519`：等价。

---

## 5. ECDSA secp256k1 (`EcdsaK1.java`)

### 规范对照（SEC 1 v2.0 + BIP-62/EIP-2）

| 要求 | 实现 | 状态 |
| --- | --- | --- |
| 平台 ECDSA-SHA-256 | `Signature.ALG_ECDSA_SHA_256` | ✅ |
| `signPreComputedHash` 接受预算 32 字节摘要 | `EcdsaK1.java:117-119` | ✅ |
| DER 输出 | 平台原生输出 DER | ✅ |
| Low-s 归一化 (BIP-62 / EIP-2) | `ModN.lessThanHalfN` + `ModN.negateMod` | ✅ |
| 拒绝 r=0 / s=0 | `copyDerInteger` OR-fold | ✅ |
| 严格 DER 解析（拒非最小 0x00 sign byte） | `copyDerInteger` 行 202-213 | ✅ |
| 拒绝 long-form length | 行 167-171 + 195-197 | ✅ |

### 与 RFC 6979 的关系

平台 `Signature.ALG_ECDSA_SHA_256` 在不同硅上 nonce 来源不同：

- **NXP J3R180**：硬件 TRNG 派生 k（非确定性）。
- **JCardSim**：取决于 BC backend 的版本（默认 SecureRandom）。

两者都 FIPS 186-4 §6.4 兼容。BTC / EVM 链验签器接受任意 nonce 来源。host 想要确定性签名时，可以用 seed 离线复算。

### 对比参考

- **Bitcoin Core** `EcdsaSignatureHash`：用 RFC 6979 deterministic + low-s + DER 严格序列化。本 applet **不实现 RFC 6979**（JC 没有暴露 nonce 注入），但 low-s 与 DER 严格模式一致。
- **Trezor** `ecdsa_sign`：RFC 6979 确定性。
- **本 applet 的不同**：依赖平台 RNG，host SDK 必须假设 nonce 不可预测。

### Findings

无 finding（`A-10` 是 S4 设计明示）。

---

## 6. Schnorr BIP-340 (`Schnorr.java`)

### 规范对照

| BIP-340 节 | 实现位置 | 状态 |
| --- | --- | --- |
| `tagged_hash(tag, x) = SHA256(SHA256(tag) ‖ SHA256(tag) ‖ x)` | `TAG_HASH_AUX` / `TAG_HASH_NONCE` / `TAG_HASH_CHAL` 预计算 | ✅ |
| `t = bytes(d) XOR tagged_hash("BIP0340/aux", a)` | 行 134-141 | ✅ |
| `rand = tagged_hash("BIP0340/nonce", t ‖ bytes(P) ‖ m)` | 行 173-187 | ✅ |
| `k' = int(rand) mod n; k' ≠ 0` | 行 188-192 | ✅ |
| `R = k' · G; if y(R) odd: k = n - k' else k = k'` | 行 194-199 | ⚠️ **A-01** |
| `e = tagged_hash("BIP0340/challenge", bytes(R) ‖ bytes(P) ‖ m) mod n` | 行 201-211 | ✅ |
| `s = (k + e · d) mod n` | 行 213-228 | ⚠️ **A-02** + **A-16** |
| 输出 `bytes(R) ‖ bytes(s)` (64 字节) | 行 240-243 | ✅ |
| 强制 P 的 y 偶（`d_eff = -d mod n` if y(P) odd） | 行 162-165 | ⚠️ **A-01** |

### 测试向量覆盖

`SchnorrK1Test` 覆盖 BIP-340 测试向量 1-7（全部正向用例 + 部分负向）。`MeowlAppletTest.signSchnorrK1MatchesHostVerify` 用 BC 验签器交叉验证。

### Findings 汇总

- **A-01 [S2]**：y(P) 与 y(R) 的奇偶翻转用 `if` 分支而非 mask，理论 timing 旁路。详见 [`01-applet-files.md`](./01-applet-files.md#finding-a-01---yr-奇偶翻转的-if-分支不常时间-s2--medium) 和 [`05-side-channels.md`](./05-side-channels.md)。
- **A-02 [S3]**：`s` 计算的 carry-propagate 早退，影响轻微。
- **A-16 [S2]**：`Bignat.mod` 变时间，对 `(k + e·d) mod n` 中的 `e·d mod n` 路径有理论 timing 攻击面。

### 对比参考

- **Bitcoin Core libsecp256k1** `secp256k1_schnorrsig_sign32`：奇偶翻转用 `secp256k1_scalar_negate_cond`（mask-driven），constant-time。
- **bip-schnorr Python ref**：`if has_even_y(P)` 直接分支 —— Python 不在意 timing。
- **本 applet**：选 Python 风格的早退分支，性能更好但 timing 弱。MEAP-6 §SCA 已记，但实现与文档"branch-free"声称矛盾，需修。

---

## 7. Ed25519 RFC 8032 (`Ed25519.java`)

### 规范对照

| RFC 8032 §5.1 | 实现 | 状态 |
| --- | --- | --- |
| `h = SHA-512(sk)` | 行 217 | ✅ |
| Clamp `s = clamp_25519(h[0..32])` | 行 222-224 (`s[0]&=248; s[31]&=127; s[31]\|=64`) | ✅ |
| `prefix = h[32..64]` | 保留在 scratch[HASH_OFF+32..+64] | ✅ |
| `A = s · B` (基点) | `Edwards25519.scalarMult` 行 234-235 | ✅ |
| 编码 A 为 32-byte LE 压缩 | `Edwards25519.encodePoint` | ✅ |
| `r = SHA-512(prefix ‖ M) mod ℓ` | 行 153-160 | ✅ |
| `R = r · B` | 行 166-167 | ✅ |
| `k = SHA-512(R ‖ A ‖ M) mod ℓ` | 行 171-178 | ✅ |
| `S = (r + k · s) mod ℓ` | 行 182-195 | ✅ |
| 输出 `R ‖ S` (64-byte LE) | 行 198-202 | ✅ |

### 关键防御措施

- **每次 sign 重新 setBase + blindBasePoint**（行 164-165 与 232-233）：A 计算和 R 计算用**独立**盲化值，coordinate trajectory 不相关。这超出 RFC 8032 要求，是 SCA 加固。
- **`finally { wipeScratch(); }`** 覆盖所有异常路径（行 203-205）。
- **拒绝采样**保证盲化标量 r ∈ [1, p)（行 252-265）。

### 测试向量覆盖

`Ed25519SigningTest.rfcVectors` 覆盖 RFC 8032 §7.1 测试向量 1-3（含空消息、单字节消息、长消息）。`Edwards25519Test` 单独验证群运算。

### Findings 汇总

- **A-15 [S4]**：generated seed 在 SC wrap 之前明文驻 APDU buffer ~10 µs（信息级）。
- 内部 `(k · s) mod ℓ` 用 `Bignat.mod` 变时间 —— 但这步在签名输出后 k 与 S 都公开，**post-emergence** 论证有效。

### 对比参考

- **RFC 8032 reference Python**：递归 ladder，Python 风格，无 SCA 防御。
- **TweetNaCl**：变时间但极简。
- **Trezor** `ed25519/ge.c`：常时间 ladder + Curve25519 共享 Field 库。
- **本 applet**：JC 限制下的最强可达：double-and-always-add ladder + Coron 投影盲化 + 双独立盲值。Field 算术由 `Bignat` 变时间路径内核（缺陷 **A-16**）。

---

## 8. Secure Channel (`SecureChannel.java`)

### 协议层（MEAP-2）

```text
Host                                      Card (authentikey: d_A, A)
  ┌─ ECDH ephemeral keypair (d_E, E) ──→  Generate ephemeral (d_C, C)
  │                                       Compute shared = ECDH(d_C, E)
  │                                       Sign(d_A, shared || nonce)  → σ
  │  ←──────── (C, σ, nonce) ────────────
  ECDH(d_E, C) = shared
  Verify σ
  HKDF(shared, "meowl-sc-v1") → (k_enc, k_mac, IV_base)
  ...                                     Same HKDF
  ┌─ envelope: IV ‖ ciphertext ‖ tag ─→   Verify IV monotone, MAC, decrypt
  │                                       (replay defense, MAC-then-decrypt)
```

### 规范对照

| 要求 | 实现 | 状态 |
| --- | --- | --- |
| ECDH `ALG_EC_SVDP_DH_PLAIN_XY` 输出 (x, y) 64 bytes | `SecureChannel.java:230-237` | ✅ |
| HKDF-SHA-256 expand 80 bytes (k_enc 32 + k_mac 32 + IV_base 16) | `Hkdf.expand` | ✅ |
| AES-256-CBC + PKCS5 padding | `Cipher.ALG_AES_CBC_PKCS5` | ✅ |
| Encrypt-then-MAC | wrap 行 359-380 | ✅ |
| HMAC-SHA-256 truncated to 16 bytes | `MAC_LEN = 16` | ✅ |
| IV 严格递增（重放防御） | `compare16` 行 318-323 | ✅ ⚠ A-08 |
| MAC 失败 → 销毁 SC 状态 | `reset()` 行 348-352 | ✅ |
| 卡侧响应 IV 与请求 IV 解耦（独立 counter） | `outboundCounter` 行 113 | ✅ |
| `XOR(IV_base, counter)` 派生 IV | 行 388-396 | ✅ |

### 关键正确性

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\SecureChannel.java:340-352
short macStart = (short) (apduBuffer.length - Constants.SC_MAC_LEN);
hmac.sign(apduBuffer, ivOffset, (short) (cipherEnd - ivOffset), apduBuffer, macStart);
boolean macOk = ConstantTime.equals(
        apduBuffer, macStart, apduBuffer, macOffset, Constants.SC_MAC_LEN);
if (!macOk) {
    reset();
    ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
}
```

- **MAC 验证用 `ConstantTime.equals`**（OR-fold，无 early-exit）。✓
- **MAC 失败立即 reset + 抛错** —— 防 padding oracle。✓
- **MAC 计算覆盖 IV ‖ ciphertext** —— 防 IV 替换攻击。✓

### Findings 汇总

- **A-08 [S3]**：IV 不单调时立即 reset，给重放者一个 DoS 杠杆（不 break security）。
- **A-09 [S4]**：outboundCounter 无 wrap 保护，wrap 后会重用 (key, IV) —— 实操不可达。

### 对比参考

- **Status Keycard SC v3** (`im.status.keycard.applet.SecureChannel`)：使用 ECDH + AES-256-CBC + AES-CMAC（不是 HMAC）。MAC 算法不同，但协议骨架相同。Status 也用 IV 严格递增。
- **GlobalPlatform SCP03**：标准化的 secure channel，使用 AES-CMAC 和 R-MAC/C-MAC chaining。本 applet 不用 GP-SCP03 因为后者要求 GP card manager 介入，与 manufacturer-distinct 的 authentikey 模型冲突。
- **本 applet 自定义 SC** 比 SCP03 更轻：只需要 ECDH + HKDF + AES + HMAC，all platform-native。代码 299 LOC vs SCP03 reference applet ~1500 LOC。

---

## 9. Edwards25519 群运算 (`Edwards25519.java`)

### 编码与坐标

- **扩展射影坐标** `(X, Y, Z, T)` 与 `T = X·Y/Z`（Hisil-Wong-Carter-Dawson 2008）。
- **加法**：`add-2008-hwcd-3` 公式（9M），处理 identity 不退化（验算见 [`01-applet-files.md`](./01-applet-files.md#edwards25519java) Edwards25519 节）。
- **倍点**：`dbl-2008-hwcd` (3S+4M)。
- **标量乘**：256-bit double-and-always-add，每 iter 一次 double + 一次 add，constant-time 调度（`conditionalCopy` mask-driven）。

### 编码（RFC 8032 §5.1.2）

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Edwards25519.java:373-409
public static void encodePoint(byte[] in, short inOff, byte[] out, short outOff,
                                byte[] scratch, short scratchOff) {
    // affineX = X / Z, affineY = Y / Z
    Field25519.inv(in, (short) (inOff + 2 * Field25519.LEN), scratch,
                   (short) (scratchOff + Field25519.LEN));
    Field25519.mul(in, inOff, scratch, (short) (scratchOff + Field25519.LEN),
                   scratch, scratchOff);  // affineX
    Field25519.mul(in, (short) (inOff + Field25519.LEN), scratch,
                   (short) (scratchOff + Field25519.LEN), scratch,
                   (short) (scratchOff + 2 * Field25519.LEN));  // affineY
    // out[0..32] = affineY, LE
    for (short i = 0; i < Field25519.LEN; i++) {
        out[(short) (outOff + i)] =
                scratch[(short) (scratchOff + 2 * Field25519.LEN + Field25519.LEN - 1 - i)];
    }
    // 设置 sign bit (out[31] |= (affineX_LSB << 7))
    byte affineXLsb = scratch[(short) (scratchOff + Field25519.LEN - 1)];
    out[(short) (outOff + 31)] |= (byte) ((affineXLsb & 0x01) << 7);
}
```

✓ 编码顺序：y 在低 32 字节 LE，x 的奇偶位填到 byte31 的 bit 7。RFC 8032 §5.1.2 一致。

### Findings

无 finding。`Edwards25519Test` 用 BouncyCastle BC `Ed25519.PointAccum` oracle 比对：

- 200 轮随机标量乘 → 与 BC 结果一致；
- RFC 8032 §7.1 Test vectors 1-3 → A 值一致；
- RandomizeProjective 后 encode 结果不变（投影盲化的关键 invariant）。

### 对比参考

- **TweetNaCl** `crypto_scalarmult_base`：8-bit windowed lookup table，预计算 `B * 2^i for i in [0, 256)`。**比本 applet 快 5-10×**，但需要 ~8KB 静态表。代价不接受 — JC 卡 EEPROM 极紧张。
- **Ed25519 ref10** (D.J. Bernstein)：专用 ge_madd 公式，~50 字节预算量化的常数表。同样 EEPROM 不友好。
- **本 applet** 选最简单的 256-bit ladder + 投影盲化 — EEPROM 友好但慢。详见 [`07-perf.md`](./07-perf.md) 的 sign 延迟测量。

---

## 10. F_p 算术 (`Field25519.java`)

### 规范对照（RFC 7748 §4.1）

- **p = 2²⁵⁵ − 19** ✓
- **add/sub** mask-driven 模 p 修正 ✓
- **mul/sqr** 通过 `Bignat.mod` 长除法 → **变时间** —— 由上层 `Edwards25519.scalarMult` + Coron 投影盲化遮蔽。
- **inv** 用 Fermat `a^(p-2) mod p` —— 指数公开常量，调度数据无关 ✓
- **neg** = `p - a` 完全常时间 ✓

### Findings

无文件级 finding（变时间 mul/sqr 的根源在 `Bignat.mod` —— `A-16`）。

`Field25519Test` 200 轮随机 + 边界用例 + BigInteger oracle。

---

## 11. 大整数原语 (`Bignat.java`)

### 内核分解

| 函数 | CT? | 用途 |
| --- | --- | --- |
| `add(a, b) → out` | 变时间（carry propagate） | 通用 |
| `sub(a, b) → out` | 变时间（borrow） | 通用 |
| `mult(a, b) → out` | 变时间（schoolbook） | `Field25519.mul`、Schnorr e·d、Ed25519 k·s |
| `mod(dividend, divisor) → in-place` | **严重变时间**（迭代 shift-subtract） | 上述 mult 之后归约 |
| `condSubInPlace(a, b, mask)` | 常时间 | 模 p / 模 n 修正 |
| `condAddInPlace(a, b, mask)` | 常时间 | 对偶 |
| `ctLessThan(a, b) → 0xFFFF/0` | 常时间（每字节都过） | 比较谓词 |
| `ctIsZero(a) → 0xFFFF/0` | 常时间（OR-fold） | 零检测 |

### 实现质量

- 常时间助手 (`ct*`, `cond*`) 写得严谨，OR-fold + mask-driven，无早退。
- 变时间内核 (`add`/`sub`/`mult`/`mod`) 在关键 SCA 路径**仅**通过上层防御 (Coron 投影盲化、post-emergence) 间接保护。

### Finding 汇总

- **A-16 [S2]**：`Bignat.mod` 在 Schnorr `(e·d) mod n` 路径上是潜在 timing 旁路。详细论证见 [`01-applet-files.md`](./01-applet-files.md#finding-a-16) 和 [`05-side-channels.md`](./05-side-channels.md#bignatmod-timing-渗透到-schnorr)。

---

## 12. AES-256-CBC + HMAC-SHA-256 (`SecureChannel.java`)

详见上文 §8 (Secure Channel) 和 [`03-wire-protocol.md`](./03-wire-protocol.md)。

---

## 综合评估

### 强项

1. **HMAC / HKDF / Ed25519 / Edwards25519** —— 与 RFC 5869/2104/8032 完全一致，测试向量 100% 通过。
2. **Coron 投影盲化** + **每次 sign 双独立盲值** —— SCA 防御纵深超过 BIP-340 reference。
3. **Native + 软回退**双路径 (`HmacSha`、`RandomData`) —— 真正硬件兼容性优于 Status Keycard。
4. **JC `_TRANSIENT_DESELECT` 优先 + persistent 兜底** —— 标量永不落 EEPROM 是关键加固。
5. **Encrypt-then-MAC + IV 严格递增 + MAC 失败强制 reset** —— SC 协议的三大正确性条件全部满足。

### 弱项

1. **`Bignat.mod` 变时间** (A-16)：Schnorr `(e·d) mod n` 在 sub-ms 物理 timing 攻击者下可分析。**修复路径**：v2 limb-radix 重写（已在 MEAP-6 §6.3 跟踪）。
2. **Schnorr 奇偶翻转早退分支** (A-01)：与文档"branch-free"声称不一致。**修复成本**：~30 行代码 + 一个新 helper。**优先级**：中。
3. **`MasterSeed.copy*MasterTo` public 可见性** (A-12)：包内防御纵深松。**修复成本**：移除一个关键字。**优先级**：低。

### 与 Status Keycard / Ledger / Trezor 的横向对比

| 维度 | Status Keycard | Ledger BOLOS | Trezor Crypto | meowl-applet |
| --- | --- | --- | --- | --- |
| HW 平台 | NXP J3D081/J3R200 | ST31H320 (BOLOS) | STM32 (no SE) | NXP J3R180 |
| HMAC 软回退 | ❌ | N/A (BOLOS API) | N/A | ✅ |
| Schnorr BIP-340 | ❌ | ✅ | ✅ | ✅ |
| Ed25519 (RFC 8032) | ❌ | ✅ | ✅ | ✅ |
| 双独立投影盲化 | N/A | ✅ | N/A | ✅ |
| ECDSA RFC 6979 | ❌ | ✅ | ✅ | ❌（用平台 RNG） |
| Source available | ✅ AGPL | ❌ proprietary | ✅ GPL | ✅ AGPL |
| EAL 等级 | EAL 5+ silicon | EAL 5+ silicon | None (no SE) | EAL 6+ silicon |

**meowl-applet 的差异化定位**：在 EAL 6+ 通用 JC silicon 上提供 **HMAC 软回退 + 双独立盲化 + Schnorr/Ed25519 全栈** 的开源 AGPL 实现 —— 是对 Status Keycard (功能不全) 和 Ledger (闭源专有) 的补位。

---

## 跨章节 Finding 引用表

| Finding | 严重度 | 文件 | 关联章节 |
| --- | --- | --- | --- |
| A-01 | S2 | `Schnorr.java` | [`01`](./01-applet-files.md#finding-a-01---yr-奇偶翻转的-if-分支不常时间-s2--medium), [`05`](./05-side-channels.md), [`02`](#6-schnorr-bip-340-schnorrjava) |
| A-02 | S3 | `Schnorr.java` | [`01`](./01-applet-files.md#finding-a-02---if-carry-在-8b-步骤上的早退分支-s3--low), [`05`](./05-side-channels.md) |
| A-08 | S3 | `SecureChannel.java` | [`01`](./01-applet-files.md), [`03`](./03-wire-protocol.md) |
| A-09 | S4 | `SecureChannel.java` | [`01`](./01-applet-files.md), [`03`](./03-wire-protocol.md) |
| A-10 | S4 | `EcdsaK1.java` | [`01`](./01-applet-files.md), [`05`](./05-side-channels.md) |
| A-12 | S3 | `MasterSeed.java` | [`01`](./01-applet-files.md) |
| A-13 | S3 | `PinManager.java` | [`01`](./01-applet-files.md) |
| A-14 | S4 | `PkiManager.java` | [`01`](./01-applet-files.md), [`04`](./04-lifecycle.md) |
| A-15 | S4 | `MeowlApplet.java` | [`01`](./01-applet-files.md) |
| A-16 | S2 | `Bignat.java` | [`01`](./01-applet-files.md#finding-a-16), [`05`](./05-side-channels.md), [`02`](#11-大整数原语-bignatjava) |
| A-19 | S4 | `ApduTlv.java` | [`01`](./01-applet-files.md) |
| A-20 | S4 | `Slip10.java` | [`01`](./01-applet-files.md) |
| A-21 | S3 | `Bip32.java` | [`02`](#3-bip-32-secp256k1-hd-bip32java) (本节首发) |
