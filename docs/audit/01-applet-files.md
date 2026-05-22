# 01 — Applet 逐文件审计

<!-- SPDX-FileCopyrightText: 2026 meowl.social contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

对 `applet/src/main/java/social/meowl/applet/` 的 25 个 Java 文件逐文件审计。每文件一节：**摘要 → 关键代码点 → Findings → 验证状态**。Severity 等级见 [`README.md`](./README.md)。

源代码总规模：3 440 LOC（去除注释/空行），CAP on-card-loaded 17 359 字节（详见 [`07-perf.md`](./07-perf.md)）。

## 文件目录速览

| 文件 | LOC | 角色 | 高亮 finding |
| --- | --- | --- | --- |
| `WipeTrigger.java` | 4 | SAM | — |
| `ConstantTime.java` | 11 | CT 等值 | — |
| `Bounds.java` | 23 | 越界检查 | — |
| `ResetToFactory.java` | 26 | RTF 倒计数 | — |
| `ApduTlv.java` | 47 | TLV writer | A-19 (S4) |
| `LifecycleState.java` | 51 | FSM | — |
| `ModN.java` | 61 | secp256k1 mod n | — |
| `Slip10.java` | 65 | SLIP-10 | A-20 (S4) |
| `Hkdf.java` | 79 | HKDF | — |
| `Constants.java` | 83 | wire 常量 | — |
| `PkiManager.java` | 99 | PKI 个性化 | A-14 (S4) |
| `Field25519.java` | 125 | F_p 算术 | — |
| `EcdsaK1.java` | 133 | ECDSA k1 | A-10 (S4) |
| `Bip32.java` | 140 | BIP-32 | A-03 (S4) |
| `HmacSha.java` | 147 | HMAC | — |
| `Schnorr.java` | 155 | BIP-340 | **A-01 (S2)**, A-02 (S3) |
| `Ed25519.java` | 164 | RFC 8032 | A-15 (S4) |
| `PinManager.java` | 162 | PIN/PUK | A-13 (S3) |
| `MasterSeed.java` | 166 | seed | A-12 (S3), A-15 (S4) |
| `Secp256k1.java` | 216 | curve params | — |
| `Bignat.java` | 286 | 大整数 | **A-16 (S2)** |
| `SecureChannel.java` | 299 | MEAP-2 SC | A-08 (S3), A-09 (S4) |
| `Edwards25519.java` | 362 | ed25519 group | — |
| `Authentikey.java` | 45 | 设备身份 | A-11 (S4) |
| `MeowlApplet.java` | 491 | 路由 | — |

总 finding 数：**1 × S2、4 × S3、6 × S4**（applet 侧），无 S0/S1。

---

## `WipeTrigger.java`

**摘要**：纯接口（SAM），由 `MeowlApplet` 实现并传给 `ResetToFactory.recordInvocation` 作为 wipe 回调。JC 3.0.5 没有 `java.lang.Runnable`，所以自定义。

**Findings**：无。

---

## `ConstantTime.java`

**摘要**：`equals(byte[], short, byte[], short, short) → boolean` 的 OR-fold 常时间等值比较，11 行。

**关键代码点**：

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\ConstantTime.java:22-28
public static boolean equals(byte[] a, short aOffset, byte[] b, short bOffset, short length) {
    byte diff = 0;
    for (short i = 0; i < length; i++) {
        diff |= (byte) (a[(short) (aOffset + i)] ^ b[(short) (bOffset + i)]);
    }
    return diff == 0;
}
```

**Findings**：无。`diff` 是 `byte`，OR-fold 不会因符号扩展溢出，输出 `diff == 0` 是单一比较，无早退分支。`ConstantTimeTest` 覆盖了高比特、偏移、零长度等 6 种 case。

---

## `Bounds.java`

**摘要**：`requireCapacity` / `requireRange` 两个静态助手，做 `null` / 负数 / 越界检查；溢出安全表达式 `needed > dst.length - offset`。

**Findings**：无。`BoundsTest` 用 `(short) 20000 + (short) 20000 = -25536` 这种典型 wrap pattern 验证溢出安全性。

---

## `ResetToFactory.java`

**摘要**：MEAP-3 的 4 步 RTF 倒计时器。`remaining` 是 `CLEAR_ON_RESET` 的 1 字节 transient；`recordInvocation` 在 step→0 时 **先重置计数再调 wipe**，防止 wipe 抛异常导致 `remaining[0]==0` 在下次调用时计算 step=−1=0xFF（错误码 0x6FFF）。

**Findings**：无。`ResetToFactoryTest.wipeExceptionDoesNotCorruptCounter` (`@/d:/Desktop/x/meowl-applet/tests/src/test/java/social/meowl/applet/ResetToFactoryTest.java:111-128`) 直接 pin 这个反模式。

---

## `ApduTlv.java`

**摘要**：单字节 tag/length 的简化 BER-TLV writer，`MAX_VALUE_LEN=255`。`putByte` / `putShort` / `putBytes` / `reserve` + `finishReserved` 四个 API。

### Finding A-19 — `finishReserved` 不验证 dst 总长 [S4 — Info]

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\ApduTlv.java:104-109`

**判定**：S4。`finishReserved(dst, headerOffset, valueLen)` 只检查 `valueLen ∈ [0, 255]`，不再检查 `headerOffset + 2 + valueLen ≤ dst.length`。语义上调用方在 `reserve` 之后会自己往 `dst` 里写 valueLen 字节，那一步会撞到 `ArrayIndexOutOfBoundsException`，所以并非真漏；但若调用方写完才发现长度错，写入已经发生，不再可回滚。

**依据**：JC `IndexOutOfBoundsException` 抛出后会被 `MeowlApplet.process` 顶层 catch 不到（`Applet.process` 只声明 ISOException），实际行为是 silent abort + 6F00。MEAP-1 §TLV-encoding 没有强制要求 finishReserved 做 capacity check。

**修复建议**：增加一行 `Bounds.requireCapacity(dst, headerOffset, (short) (2 + valueLen));` 让错误以 SW_WRONG_LENGTH 形式上报，不靠 silent 6F00。

---

## `LifecycleState.java`

**摘要**：4 状态 FSM (`UNINITIALIZED→PERSONALIZED→SETUP_DONE→SEEDED`)，`transitionTo` / `transitionToInTx` / `reset` / `resetInTx`。`isLegalForward` 是纯函数，包级私有方便测试。

**Findings**：无。FSM 写得规范——所有状态变更都在 `JCSystem.beginTransaction()` 块内（或 `*InTx` 变体由调用方负责事务）。`LifecycleStateTest` 覆盖正向、反向、跳跃、终态四种非法转移以及事务变体。

---

## `ModN.java`

**摘要**：secp256k1 群阶 n 的常时间模运算。`addMod` / `negateMod` / `lessThanN` / `lessThanHalfN` / `isZero`。预计算的 `SECP256K1_HALF_N` 用于 BIP-62/EIP-2 low-s 判定。

**关键代码点**：

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\ModN.java:84-88
short carryMask = (short) -carry;
short lessMask = Bignat.ctLessThan(out, outOff, SECP256K1_N, (short) 0, LEN);
short reduceMask = (short) (carryMask | ~lessMask);
Bignat.condSubInPlace(out, outOff, SECP256K1_N, (short) 0, LEN, reduceMask);
```

**Findings**：无。`addMod` 是教科书级常时间实现：先 unconditional add，然后 mask-driven 条件减。两个 mask（`carryMask` 和 `~lessMask`）都来自常时间助手。`ModNTest` (12 976 字节) 全面覆盖。

---

## `Slip10.java`

**摘要**：SLIP-10 Ed25519 hardened-only HD 推导。Master 来自 `MasterSeed.copySlip10MasterTo`，`ckdPriv` 用 HMAC-SHA-512(c, 0x00 ‖ k ‖ ser32(i))；非 hardened 索引返回 `SW_CONDITIONS_NOT_SATISFIED`。

### Finding A-20 — hardened 检查在循环内、未常时间 [S4 — Info]

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Slip10.java:96-105`

**判定**：S4。`if ((pathBuf[idxOff] & HARDENED_MASK) == 0) ISOException.throwIt(...)` 是早退分支，但 path index 由 host 选定且本身公开（host 知道自己请求了什么 path），不属于秘密；定时旁路无收益。

**依据**：BIP-32 / SLIP-10 都未要求路径检查常时间。Ledger / Trezor / Status Keycard 的实现也都是早退式。

**修复建议**：无需修复。可补一行注释说明 path 公开。

---

## `Hkdf.java`

**摘要**：RFC 5869 HKDF-SHA-256，`extract`/`expand` 两阶段。共享 `HmacSha` 引擎；PRK 与 scratch 都是 CLEAR_ON_DESELECT。

**关键代码点**：

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Hkdf.java:122-139
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

**Findings**：无。

- `counter` 起始 `0x01` 与 RFC 5869 §2.3 一致。`MAX_EXPAND_LEN = 255 × 32 = 8 160` 也对。
- `counterBuf` 单独一字节 transient 的设计很到位 —— 解决了 JC `Signature.update` 可能延迟摄取的边缘情况。
- 空 salt 用 32 字节 `0x00` 替代（RFC 5869 §2.2）—— 行 86-87 `arrayFillNonAtomic(scratch, 0, HASH_LEN, 0); hmac.init(scratch, 0, HASH_LEN);` ✓
- `HmacShaTest` 与 `tools/.../HkdfSha256Test` 覆盖了 RFC 5869 全部 7 条官方测试向量。

---

## `Constants.java`

**摘要**：所有 wire 常量、状态字、能力位、TLV tag、size 常量、PIN/PUK 政策、HD 限制集中在此。

**Findings**：无。常量值与 MEAP-1/2/3/4/5/6 的规范文档完全一致；`MeowlAppletTest.protocolVersionMatches` 等测试 pin 了协议版本。

---

## `PkiManager.java`

**摘要**：MEAP-4 制造期 PKI 个性化。`exportPubkey` / `signCsr` / 三步 chunked `importInit/Write/Finalize` / `exportCert` / `wipe`。

### Finding A-14 — UNINITIALIZED 阶段的 SIGN_PKI_CSR 仅由 SC 保护 [S4 — Info]

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\MeowlApplet.java:352-365`

**判定**：S4 / 设计明确。`handleSignPkiCsr` 在 `UNINITIALIZED` 状态接受任意 host 提供的 32 字节摘要并用 authentikey 签名，**不需要 PIN**（PIN 在该阶段不存在）。授权完全依赖 Secure Channel 握手 —— 而 SC 握手不验证调用方身份，**任何能与卡建立 SC 的对端都能让其签任意摘要**。

**依据**：MEAP-4 §Personalization 明确把这一阶段定位为"制造商持有 GP 默认 CDK 密钥的阶段"，威胁模型是制造商内部 PKI 流水线，不是终端用户。一旦 `LOCK_PKI` 后无法回到 UNINITIALIZED（除非 reset-to-factory），`SIGN_PKI_CSR` 就被永久关闭。

**修复建议**：无需修复。但建议在文件级 javadoc 顶部加一段威胁模型说明，把"这条命令在 UNINITIALIZED 阶段是 SC-only 授权"显式写出，避免 review 时误判。

---

## `Field25519.java`

**摘要**：F_p (p=2²⁵⁵−19) 域算术。`add` / `sub` / `neg` 完全常时间；`mul` / `sqr` 通过 `Bignat.mod` 长除法变时间，由上层 `Edwards25519.scalarMult` + Coron 投影盲化遮蔽。`inv` 用费马小定理 `a^(p−2)`，指数为公开常量，调度数据无关。

**关键代码点（add 的 mask-driven 减 p）**：

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Field25519.java:113-117
short carryMask = (short) -carry;
short lessMask = Bignat.ctLessThan(out, outOff, FIELD_P, (short) 0, LEN);
short reduceMask = (short) (carryMask | ~lessMask);
Bignat.condSubInPlace(out, outOff, FIELD_P, (short) 0, LEN, reduceMask);
```

**Findings**：无文件级 finding。`mul/sqr` 的变时间问题汇聚在 `A-16` (`Bignat.mod`) — 见 `Bignat.java` 节。

`Field25519Test` (10 203 字节) 用 BigInteger oracle 做了 200+ 轮随机 + 边界用例。

---

## `EcdsaK1.java`

**摘要**：secp256k1 ECDSA 软实现：`Bip32.deriveLeafScalar` → 平台 `Signature.ALG_ECDSA_SHA_256.signPreComputedHash` → 严格 DER 解析 → BIP-62/EIP-2 low-s 归一化 → 输出 `r ‖ s`。

**关键代码点（DER 解析）**：

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\EcdsaK1.java:159-180
private void parseDerSignature(byte[] der, short derOff, short derLen) {
    if (derLen < (short) (DER_INT_HEADER + 1 + DER_INT_HEADER + 1)
            || derLen > Constants.ECDSA_DER_MAX_LEN
            || der[derOff] != DER_TAG_SEQUENCE) {
        ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
    }
    short cursor = (short) (derOff + 1);
    short seqLen = (short) (der[cursor++] & 0xFF);
    if ((seqLen & 0x80) != 0) {
        ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
    }
    if ((short) (cursor + seqLen) != (short) (derOff + derLen)) {
        ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
    }
    cursor = copyDerInteger(der, cursor, scratch, R_OFF);
    cursor = copyDerInteger(der, cursor, scratch, S_OFF);
    if (cursor != (short) (derOff + derLen)) {
        ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
    }
}
```

### Finding A-10 — ECDSA k 由平台 RNG 提供，非 RFC 6979 [S4 — Info]

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\EcdsaK1.java:117-119`

**判定**：S4 / 设计明确。`Signature.ALG_ECDSA_SHA_256.signPreComputedHash` 在真实硅上抽取 TRNG 派生的 k；JCardSim 上可能是 RFC 6979 deterministic。两者均符合 FIPS 186-4 §6.4，且 BTC / EVM / Cosmos / TON 等链都接受。MEAP-6 §"Why deterministic Ed25519, non-deterministic Schnorr, mixed ECDSA" 明确选型。

**修复建议**：无。host SDK 不应假设 ECDSA 确定性；如需 RFC 6979 复现，host 拥有 seed 后可在链下复算。

**其他子项**：

- DER 解析严格：拒绝 long-form length，拒绝非最小 0x00 sign byte，OR-fold 拒绝 r=0/s=0。✓
- low-s 归一化用 `ModN.lessThanHalfN` (常时间) + `ModN.negateMod`。✓
- `try { ... } finally { Util.arrayFillNonAtomic(scratch, 0, SCRATCH_LEN, 0); signKey.clearKey(); }` —— 异常路径也清。✓

---

## `Bip32.java`

**摘要**：BIP-32 secp256k1 HD。Hardened/non-hardened 两条路径；非 hardened 用 `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` 当通用标量乘原语推父公钥并压缩。

### Finding A-03 — `boolean hardened = ...` 早退分支 [S4 — Info]

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Bip32.java:170`

**判定**：S4。同 `A-20`。Path 索引公开，分支不泄露秘密。

**其他亮点**：

- `requireValidBip32MasterKey()` (`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\MasterSeed.java:204-210`) 在 import 时强制 `0 < parse256(I_L) < n`，与 BIP-32 §"Master key generation" 一致。
- `ckdPriv` 在 `addMod` 返回 `zero==true` 时抛 `SW_CONDITIONS_NOT_SATISFIED`，符合 BIP-32 mandates。
- `wipeTransientSecrets()` 同时清 `state[]` 和 `scalarKey.clearKey()` —— 防止 EEPROM-fallback 路径残留。
- `TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT` 优先 + persistent 兜底 (`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Bip32.java:81-95`)，符合"标量永不落 EEPROM"目标。

---

## `HmacSha.java`

**摘要**：HMAC-SHA-{256,512} 引擎。先尝试 native (`Signature.ALG_HMAC_SHA_*` + `TYPE_HMAC*`)，不可用时回退 RFC 2104 软实现。

**关键代码点（软回退）**：

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\HmacSha.java:172-178
xorBlock(softKey, IPAD);
digest.reset();
digest.update(softKey, (short) 0, blockSize);
xorBlock(softKey, IPAD);
```

**Findings**：无。XOR-then-restore 是 RFC 2104 §"Implementation note" 推荐写法，省一次完整 block 复制。`HmacShaTest` (10 496 字节) 覆盖了 RFC 4231 全部 7 条 SHA-256/512 官方向量；`forceSoftware` 测试钩子让软路径在 jcardsim 上被实际跑过（jcardsim 默认有 native HMAC，否则没有这个钩子两条路径之一就跑不到）。

---

## `Schnorr.java`

**摘要**：BIP-340 Schnorr 软实现。354 字节 scratch；预算量化的 `SHA256("BIP0340/aux"|"nonce"|"challenge")` 节省 SHA 调用；`finally` 强制清 scratch。

### Finding A-01 — y(R) 奇偶翻转的 `if` 分支不常时间 [**S2 — Medium**]

**位置**：

- y(P) 翻转：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Schnorr.java:162-165`
- y(R) 翻转：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Schnorr.java:196-199`

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Schnorr.java:194-199
// 6. R = k'·G; k = (y(R) odd ? n - k' : k').
bip32.scalarMultG(scratch, K_OFF, scratch, R_OFF);
byte ryLastByte = scratch[(short) (R_OFF + Constants.EC_POINT_UNCOMPRESSED_LEN - 1)];
if ((ryLastByte & 0x01) != 0) {
    ModN.negateMod(scratch, K_OFF);
}
```

**判定**：S2。

- y(P) 的奇偶**是公开的**（P 通过 EXPORT_XPUB 公开），分支不泄露秘密。✓
- y(R) 的奇偶**取决于 ephemeral k'**（k' = tagged_hash(t ‖ P ‖ m) 派生），k' 是秘密。条件分支 `if (ryLastByte & 1) negateMod(K)` 在 50% 路径上多执行一次 ~32 字节常时间减法 (`ModN.negateMod`)。**理论上**为攻击者提供一个"k' 最低 bit 是否奇"的定时旁路。

实际可利用性受三重削弱：

1. BIP-340 aux randomness 让两次签同一摘要的 k' 不同 → 攻击者无法多次"复测"同一 k'。
2. 仅一个 bit 的泄漏，需要 ~256 个独立样本配合格攻击才能恢复 d。
3. JC 平台 reader 的总线延迟（PCSC 1–5 ms）远大于一次 `negateMod` (~32 byte ops)，实际信噪比极低。

但是 MEAP-6 §"Side channels in software primitives" 自己声称"the secret bit never branches the control flow"，**实现与文档不一致**。

**依据**：BIP-340 reference signer (Python) 也是 if-based，但 Python 不是 SCA 关心的目标。Bitcoin Core 的 secp256k1 库 `secp256k1_schnorrsig_sign32` 用了 `secp256k1_fe_normalizes_to_zero_var` 并显式注释"The secret nonce was always required to be in range, so this is non-secret"，但底层 `secp256k1_scalar_negate_cond` 是常时间的（mask-driven）。

**修复建议**：把两个 `if` 改成 mask 驱动：

```java
// 提取奇偶位（0 或 1）→ 全 mask（0x0000 或 0xFFFF）
short parityMask = (short) -((ryLastByte & 0x01) & 0x01);
ModN.negateModConditional(scratch, K_OFF, parityMask);
```

需要在 `ModN` 新增 `negateModConditional(byte[], short, short mask)`：mask=−1 时执行 n−k 写回，mask=0 时也写一次但内容不变（即都跑减法但选择性写）。或更简洁：分别算 `n-k` 和 `k`，用 mask 选择。代价 ~30 行代码 + 32 字节临时。

**测试建议**：在 `RandomizeProjectiveTest` 之外新增 `SchnorrCtParityTest`，断言 100 次 signDigest 调用中两条分支都被走过且耗时差不超过 10%（比较 `ManagementFactory.getThreadMXBean().getCurrentThreadCpuTime()` 中位数）。

---

### Finding A-02 — `if (carry)` 在 8b 步骤上的早退分支 [S3 — Low]

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Schnorr.java:216-228`

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Schnorr.java:216-228
boolean carry =
        Bignat.add(scratch, (short) (WORK_OFF + COORD_LEN), scratch, K_OFF, COORD_LEN);
if (carry) {
    short i = (short) (WORK_OFF + COORD_LEN - 1);
    while (i >= WORK_OFF) {
        short sum = (short) ((scratch[i] & 0xFF) + 1);
        scratch[i] = (byte) sum;
        if ((sum & 0x100) == 0) {
            break;
        }
        i--;
    }
}
```

**判定**：S3。`carry` 在 ~50% 的签名上为真（k 与 e·d 都接近均匀，相加溢出概率 ≈ 0.5），且 carry-propagate 进一步 ~99.6% 在第一个高位字节就停下。两次时间差很小（~1 byte op），且后续 `Bignat.mod` 的可变时间淹没所有差异。

**修复建议**：合并到 `Bignat.add` 的 64 字节宽变体（在 64 字节 buffer 上 add，不需要分两段）。或者把 carry 处理改成 mask-driven。Severity 为 S3，机会性修复。

---

## `Ed25519.java`

**摘要**：RFC 8032 Ed25519 软实现。1056 字节 scratch（applet 中最大），按字段切片 (HASH_OUT/S_BE/A_ENC/R_ENC/R_BE/K_BE/S_OUT_BE/BLIND_FE/BASE_PT/POINT/WORKSPACE)。`finally { wipeScratch(); }` 强制清。

**关键代码点（投影盲化）**：

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Ed25519.java:252-268
private void blindBasePoint() {
    while (true) {
        rng.nextBytes(scratch, BLIND_FE_OFF, BLIND_FE_LEN);
        scratch[BLIND_FE_OFF] &= (byte) 0x7F;
        if (Bignat.ctLessThan(
                        scratch, BLIND_FE_OFF, Field25519.FIELD_P, (short) 0, BLIND_FE_LEN)
                == 0) {
            continue;
        }
        if (Bignat.ctIsZero(scratch, BLIND_FE_OFF, BLIND_FE_LEN) != 0) {
            continue;
        }
        break;
    }
    Edwards25519.randomizeProjective(
            scratch, BASE_PT_OFF, scratch, BLIND_FE_OFF, scratch, WORK_OFF);
}
```

### Finding A-15 — Generated seed 在 wrap 之前明文驻留 APDU buffer [S4 — Info]

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\MeowlApplet.java:467-479`

**判定**：S4。`generateSeed` 把 64 字节 seed 写入 `buffer[OFFSET_CDATA]`，紧接着 `commitTransaction()` 持久化 master，然后 `dispatchInner` 返回，`handleOpenSecureChannel` 调 `secureChannel.wrap` **就地加密**该 buffer。中间窗口 ~10 µs 内 seed 是明文。

APDU buffer 是 transient RAM，掉电即清，且 SC wrap 用 PKCS5 paded ciphertext **覆写** seed。SC 已建立意味着对端持有正确密钥，不会读取 raw buffer。

**修复建议**：无。当前实现满足 MEAP-5 §"GENERATE_SEED" 的"raw seed returned once via SC"语义。

**其他子项**：

- `blindBasePoint` 用拒绝采样保证 r ∈ [1, p)，单次拒绝率 ≈ 20/2²⁵⁵ ≈ 2⁻²⁵⁰，期望循环 1.0000... 次。✓
- 第 162-165 注释 "Reset the base point and re-blind it so the second scalar ladder runs on a coordinate trajectory uncorrelated with the first" —— 关键防御：A 计算和 R 计算用独立盲值。✓
- `S = (r + k·s) mod ℓ` 用 `Bignat.mult`(变时间) + `Bignat.mod`(变时间)。但这两个值在签名输出后立即公开（k 通过 R_enc/A_enc/M 重算可得，s 是签名一部分）—— MEAP-6 §SCA 的"post-emergence"论证适用。✓

---

## `PinManager.java`

**摘要**：MEAP-3 PIN/PUK。`OwnerPIN` 后端，包含 setup/verify/change/unblock/wipe。Wipe 用 `0xFF` scrub buffer 驱动一次写穿后重建 `OwnerPIN` 实例。

### Finding A-13 — wipeInTx 的 try-catch swallow [S3 — Low]

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\PinManager.java:200-210`

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\PinManager.java:199-213
Util.arrayFillNonAtomic(scrub, (short) 0, Constants.PUK_MAX_LEN, (byte) 0xFF);
try {
    pin.update(scrub, (short) 0, Constants.PIN_MAX_LEN);
} catch (Exception ignored) {
    // Scrub is best-effort; re-instantiation below still provides JC-level invalidation.
}
try {
    puk.update(scrub, (short) 0, Constants.PUK_MAX_LEN);
} catch (Exception ignored) {
    // Same fallback rationale as the PIN scrub.
}
this.pin = new OwnerPIN(Constants.PIN_RETRY_LIMIT, Constants.PIN_MAX_LEN);
this.puk = new OwnerPIN(Constants.PUK_RETRY_LIMIT, Constants.PUK_MAX_LEN);
this.provisioned[0] = 0;
```

**判定**：S3。注释说"best-effort"但若 `OwnerPIN.update` 抛异常 (silicon 错误)，scrub 写不进去；只剩"重建 OwnerPIN 引用"作兜底，**而 JC 规范不保证旧 OwnerPIN 持有的 EEPROM 单元被立即清零**。一些 silicon 把 OwnerPIN 内部缓冲区与 GC 关联，可能保留 PIN hash 残留直到下次 GC。

实际威胁：物理 die-probing。在已确定的纯软件威胁模型外。但既然代码已经在做 best-effort scrub，吞掉异常等于把"我尝试过"变成"我没成功"，没有对调用方可见的失败信号。

**修复建议**：把异常重抛为 `SW_UNSUPPORTED_FEATURE` 让上层放弃 commit；或至少在 `provisioned[0] = 0` 之外增加一个 `scrub_failed_flag`，下次启动检测到时阻止 SETUP（强制 reset-to-factory）。代价 1 字节 EEPROM。

---

## `MasterSeed.java`

**摘要**：BIP-39 seed 持久化 + 双 HMAC 衍生 (BIP-32 secp256k1 master + SLIP-10 ed25519 master)。`importSeed` / `generateSeed` / 两个 `copy*MasterTo` / `wipe`.

### Finding A-12 — `copy*MasterTo` 是 public，可被滥用 [S3 — Low]

**位置**：

- `@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\MasterSeed.java:218-221`
- `@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\MasterSeed.java:227-230`

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\MasterSeed.java:218-230
public void copyBip32MasterTo(byte[] dst, short dstOff) {
    requireSeeded();
    Util.arrayCopyNonAtomic(bip32Material, (short) 0, dst, dstOff, MASTER_LEN);
}

public void copySlip10MasterTo(byte[] dst, short dstOff) {
    requireSeeded();
    Util.arrayCopyNonAtomic(slip10Material, (short) 0, dst, dstOff, MASTER_LEN);
}
```

**判定**：S3。这两个方法是 `public`，包内任意类（含 PKI / SC / authentikey）都能拿到 master key 副本。当前只有 `Bip32.walkPathToLeaf` 与 `Slip10.walkPath` 调用它们，并且 dst 都是 transient scratch；但 Java 没有"caller 必须用 transient buffer"的强约束 —— 一行 `masterSeed.copyBip32MasterTo(persistentBuf, 0)` 就能把 master 写到 EEPROM。

**修复建议**：把可见性收窄到 **package-private**（去掉 `public` 关键字）。Java 默认包级，已经满足"applet 包内调用"的需求；JC 上 host 不能直接调 Java 方法，所以可见性收窄不影响 wire 行为。零成本。

---

## `Secp256k1.java`

**摘要**：secp256k1 (SEC 2 v2.0 §2.4.1) 曲线参数 + `setCurveParameters` 助手。所有参数打包成单 `byte[] PARAMS = p ‖ a ‖ b ‖ n ‖ G(uncompressed)`，258 字节。

**Findings**：无。常量值与 SECG 规范完全一致；`MeowlAppletTest.authentikeyIsCompressed` + `SchnorrK1Test` + `EcdsaK1Test` 间接 pin 这些值（任何参数错误都会让所有签名 host-side 验证失败）。

---

## `Bignat.java`

**摘要**：多精度大整数。可变时间内核 `add/sub/mult/mod/lessThan/isZero` 与常时间助手 `condSubInPlace/condAddInPlace/ctLessThan/ctIsZero`。`mod` 改编自 Toporin Satochip Bignat（GPL-2 → AGPL-3 升级合规）。

### Finding A-16 — `Bignat.mod` 的可变时间属性会泄漏 Schnorr e·d 的 timing [**S2 — Medium**]

**位置**：

- `Bignat.mod` 实现：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Bignat.java:149-241`
- Schnorr 调用点：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Schnorr.java:213, 230-236`

**判定**：S2。

`Bignat.mod` 的内层 `while (!shiftLesser(...))` 循环次数取决于 `dividend / divisor` 的具体比特模式 —— 严格变时间。

调用点风险评估：

| 调用点 | 输入秘密性 | 影响 |
| --- | --- | --- |
| `Field25519.mul/sqr` | 操作数中至少一个被 Coron 投影盲化 | 由 `randomizeProjective` 遮蔽，**实际安全** |
| `Schnorr` 行 230：`(k + e·d) mod n` | k 来自 aux randomness（每次新鲜），e 是公开挑战，d 是秘密 | **e 公开 + k 新鲜** ⇒ 即便定时泄漏 e·d 的 bit pattern，攻击者也只能学到 (e·d mod n) 的 bit 而非 d 单独的 bit。BUT： |
| `Ed25519` 行 183：`(k·s) mod ℓ` | k 来自 SHA-512(R‖A‖M)（公开后），s 是秘密 | "Post-emergence" 论证：s 已经决定了已发布的签名，timing 不会带来比签名本身更多的信息 |

但 Schnorr 的论证有缺陷：

> e = tagged_hash("BIP0340/challenge", R.x ‖ P.x ‖ m) 是**公开**值（host 也能算），而 d 是**秘密**且**跨签名稳定**。每次签同一 path，d 不变；每次签 e 不同。Bignat.mod 对 (e·d) 的处理时间因 e 而异，但**对 d 的依赖**会通过多次 (e_i, T_i) 样本的统计被抽出。

实际可利用性受**接口端 ~5 ms PCSC jitter** 削弱，针对单卡的统计攻击需要数千次签名以"平均掉"jitter。MEAP-6 §"Threat model" 把此场景标为 out-of-scope（"strong physical adversary with sub-millisecond timing precision"），并在 §6.3 中跟踪 v2 的 limb-radix `Field25519` 重写（顺带也会改善 `Bignat.mod`）。

**修复建议**：v1 内不修；以下三种长期方案择一：

1. **常时间长除法**：实现 Barrett reduction 或 Montgomery 形式（代价 ~150 行 + 性能下降 30-50%）。
2. **盲化 Schnorr 的 e·d**：把 e 也乘以一个随机 r，再除回去 → `(k + e·d) = (k + r·e·d)/r mod n`（代价 ~3 个额外 32 字节 mul + 一个 modular inverse，~20% 性能损失）。
3. **Limb-radix-2²⁶ 重写**：v2 路线。

短期内：在 `Bignat.java` 的 javadoc 顶部追加一段"Schnorr e·d 的 timing 反推到 d 在 sub-ms 攻击者下可行"的明确警告，让 v2 路线工作有更强 motivation。

---

## `SecureChannel.java`

**摘要**：MEAP-2 SC 完整实现。ECDH (`ALG_EC_SVDP_DH_PLAIN_XY`) → HKDF-SHA-256 → AES-256-CBC + HMAC-SHA-256/16-byte tag。Encrypt-then-MAC，IV 单调严格增。

### Finding A-08 — `unwrap` 在 IV 不单调时立即 reset() [S3 — Low]

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\SecureChannel.java:318-323`

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\SecureChannel.java:318-323
// Replay defense before MAC verification: reject non-monotonic IVs cheaply. IV bytes are
// public, so a non-constant-time compare is fine.
if (compare16(apduBuffer, ivOffset, lastInboundIv, (short) 0) <= 0) {
    reset();
    ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
}
```

**判定**：S3 — DoS/UX 边界 case。任何抓到合法 envelope 的人都可以重放它来强制对端 SC 重置，触发整个 host 端重新握手（再消耗一对 ECDH + HKDF）。攻击者**没有** key 仍能让对端被动消耗资源。

**实际威胁**：典型 PCSC reader 抓不到 USB-CCID 链路的应用层流量（它在 reader-内部）；NFC 链路更易被抓。即使被抓到，DoS 损失只是一次 ~150 ms 的握手，没有实际破坏。

**修复建议**：把 reset 推迟到 MAC 验证之后 —— 这样未持密钥的攻击者无法触发 reset，只能让卡耗费 ~5 ms 验 MAC 后拒绝。仍是 DoS 但成本对称。

```java
// 修改后
if (compare16(...) <= 0) {
    ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);  // 不 reset
}
// MAC 验证 ...
if (!ConstantTime.equals(...)) {
    reset();   // 只有验过 MAC 后失败才 reset
    ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
}
```

但要注意：MAC 失败必然 reset（防 oracle），IV 失败"不 reset"会被批评为"为了不 DoS 弱化了协议"。最佳做法是把这条挂在 issue tracker 让作者决定权衡。

---

### Finding A-09 — outboundCounter 无溢出保护 [S4 — Info]

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\SecureChannel.java:399-407`

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\SecureChannel.java:399-407
private void incrementCounter() {
    for (short i = (short) (Constants.SC_BLOCK_LEN - 1); i >= 0; i--) {
        short next = (short) ((outboundCounter[i] & 0xFF) + 1);
        outboundCounter[i] = (byte) next;
        if (next <= 0xFF) {
            return;
        }
    }
}
```

**判定**：S4。计数器 16 字节，理论极限 2¹²⁸ 次 wrap。一次 SC session 寿命 = 一次 select + 不被 deselect 期间 = 数分钟 NFC 操作 ≈ 数千次 APDU 远低于 2¹²⁸。但 wrap 后 counter 退回全 0，下一条 outbound IV 会与第一条相同 —— **如果对端 host 端不重放检查（卡端只检查 inbound 单调），同一个 (key, IV) 会被 AES-CBC 重用，泄露明文 XOR**。

**修复建议**：在 wrap 后抛 `SW_SECURE_CHANNEL_FAILED` 强制 host 重新握手。代价 4 行代码。

---

## `Edwards25519.java`

**摘要**：edwards25519 群运算。扩展射影坐标 (X,Y,Z,T)，`add-2008-hwcd-3` (9M) + `dbl-2008-hwcd` (3S+4M)，常时间 double-and-always-add 标量乘 (256-bit)，Coron 投影盲化。

**关键代码点（标量乘）**：

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Edwards25519.java:447-463
for (short i = (short) 255; i >= 0; i--) {
    pointDouble(out, outOff, out, outOff, scratch, scratchOff);

    short byteIdx = (short) (31 - (i >> 3));
    short bitInByte = (short) (i & 7);
    short bit = (short) ((scalar[(short) (scalarOff + byteIdx)] >>> bitInByte) & 1);
    byte mask = (byte) -bit;

    setIdentity(scratch, addendOff);
    conditionalCopy(scratch, addendOff, in, inOff, scratch, addendOff, POINT_LEN, mask);

    pointAdd(out, outOff, out, outOff, scratch, addendOff, scratch, scratchOff);
}
```

**Findings**：无。

- 256 个 bit 全部走完，每个 iter 都做 `pointDouble` + `pointAdd`（即使加 identity）。✓
- `conditionalCopy` 用 mask 选择，无分支。✓
- `pointAdd(R, R, identity)` 不退化（验算 X3=4X1Z1, Y3=4Y1Z1, Z3=4Z1², T3=4X1Y1 → 仿射 = R）。✓
- `BASE_X` / `BASE_Y` / `BASE_T` 与 RFC 8032 §5.1.4 一致，`BASE_T = BASE_X · BASE_Y mod p` 预计算（手算可验）。
- `Edwards25519Test` (20 966 字节) 用 BC oracle 比对所有运算 + 加 RFC 8032 vector 1/2 cross-check。

---

## `Authentikey.java`

**摘要**：长生命周期 secp256k1 设备身份密钥对。`new KeyPair(public, private).genKeyPair()` 在 install 时生成；rt-to-factory 保留（MEAP-4）。`writeCompressedPubkeyTo` 做 SEC 1 §2.3.3 压缩。

### Finding A-11 — Authentikey 用持久 (EEPROM) 私钥 [S4 — Info]

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Authentikey.java:26-29`

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Authentikey.java:25-37
public Authentikey() {
    this.privateKey =
            (ECPrivateKey)
                    KeyBuilder.buildKey(
                            KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    this.publicKey =
            (ECPublicKey)
                    KeyBuilder.buildKey(
                            KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
    Secp256k1.setCurveParameters(this.privateKey);
    Secp256k1.setCurveParameters(this.publicKey);

    new KeyPair(this.publicKey, this.privateKey).genKeyPair();
}
```

**判定**：S4 / 设计明确。Authentikey 必须跨 reset/power-cycle 持久（MEAP-4 §"authentikey survives reset"），所以必须落 EEPROM。这是 secure element 的常规做法，安全性依赖 silicon 的 EEPROM 保护。

**修复建议**：无。但建议在 javadoc 加一行"private key lives in EEPROM permanently; SCA threat model assumes EAL 5+ silicon"使审计者一目了然。

---

## `MeowlApplet.java`

**摘要**：APDU 路由 + 16 个 inner handler + 5 个 outer handler。491 LOC，applet 中最大文件。`SHARED_SCRATCH_LEN = 1056` 字节单例 transient（按 Ed25519 上限定）+ `INNER_SCRATCH_LEN = 128` 用于摘要分阶。

**关键架构观察**：

- 4 个 sign handler (`handleSignEcdsaK1` / `handleSignSchnorrK1` / `handleSignEd25519` / `handleSignPkiCsr`) 都用 `try { ... } finally { wipe innerScratch }` 包住，覆盖任何异常路径。✓
- `handleSetup` / `handleImportSeed` / `handleGenerateSeed` 都把 `pinManager.setupInTx` / `state.transitionToInTx` / `masterSeed.importSeed` 包在单一 `JCSystem.beginTransaction()` / `commitTransaction()` 块内。一致。✓
- `wipe()` 实现 `WipeTrigger`：`secureChannel.reset()`（SC 是 transient，事务外）→ 单事务包 PIN/PKI/seed/state 四个持久 wipe。✓

**Findings**：本节内的 cross-cut findings (A-14, A-15) 已分别记在 PkiManager / Ed25519 节。无文件级独立 finding。

---

## 等级直方图

```text
S0 (Blocker)     | 0
S1 (High)        | 0
S2 (Medium)      | 2  (A-01 Schnorr 奇偶分支, A-16 Bignat.mod 变时间)
S3 (Low)         | 4  (A-02 Schnorr carry, A-08 SC reset-on-IV-fail, A-12 master copy public, A-13 PIN scrub swallow)
S4 (Info)        | 8  (A-03, A-09, A-10, A-11, A-14, A-15, A-19, A-20)
```

无 S0/S1 finding 意味着 **applet 在当前威胁模型下没有阻止主网发布的代码缺陷**。两个 S2 都是已记录的 SCA 防御纵深问题，文档与实现轻微漂移（详见 [`05-side-channels.md`](./05-side-channels.md)）。
