# 03 — Wire 协议审计

<!-- SPDX-FileCopyrightText: 2026 meowl.social contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

ISO 7816-4 APDU、TLV 编码、Secure Channel 信封格式与状态字契约的审计。Findings 编号 `W-XX`，与 `A-XX` 互引。

## 1. APDU 命令矩阵

由 `Constants.java` 与 `MeowlApplet.dispatch*` 联合定义：

| INS | 名称 | CLA | P1/P2 | C-Data | R-Data | SW | 路径 | 状态门 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `0xA0` | GET_INFO | `0x80` | 00 | — | TLV blob | 9000 | outer | any |
| `0xA1` | OPEN_SECURE_CHANNEL | `0x80` | 00 | host_eph_pubkey (65) | card_eph_pubkey (65) ‖ sig | 9000 | outer | any |
| `0xA2` | CLOSE_SECURE_CHANNEL | `0x80` | 00 | — | — | 9000 | outer | any |
| `0xA3` | RESET_TO_FACTORY | `0x80` | 00 | — | — | 0x6F00+n / 0x6FFF | outer | any |
| `0xA4` | EXPORT_PKI_PUBKEY | `0x80` | 00 | — | compressed pubkey (33) | 9000 | inner (SC required) | any |
| `0xA5` | EXPORT_PKI_CERT | `0x80` | 00 | offset (2) ‖ len (2) | cert window | 9000 | inner | ≥ PERSONALIZED |
| `0xB0` | SIGN_PKI_CSR | `0x80` | 00 | digest (32) | DER ECDSA sig | 9000 | inner | UNINITIALIZED |
| `0xB1` | IMPORT_PKI_CERT | `0x80` | P1=INIT/WRITE/FINALIZE | varies | — | 9000 | inner | UNINITIALIZED |
| `0xB2` | LOCK_PKI | `0x80` | 00 | — | — | 9000 | inner | UNINITIALIZED → PERSONALIZED |
| `0xC0` | SETUP | `0x80` | 00 | TLV(PIN, PUK) | — | 9000 | inner | PERSONALIZED → SETUP_DONE |
| `0xC1` | VERIFY_PIN | `0x80` | 00 | PIN | — | 9000 / 0x63Cn | inner | ≥ SETUP_DONE |
| `0xC2` | CHANGE_PIN | `0x80` | 00 | TLV(old, new) | — | 9000 | inner | PIN verified |
| `0xC3` | CHANGE_PUK | `0x80` | 00 | TLV(old_puk, new_puk) | — | 9000 | inner | PIN verified |
| `0xC4` | UNBLOCK_PIN | `0x80` | 00 | TLV(PUK, new_pin) | — | 9000 | inner | PIN blocked + PUK 仍有 |
| `0xD0` | IMPORT_SEED | `0x80` | 00 | seed (16-64) | — | 9000 | inner | SETUP_DONE → SEEDED, PIN verified |
| `0xD1` | GENERATE_SEED | `0x80` | 00 | — | seed (64) | 9000 | inner | SETUP_DONE → SEEDED, PIN verified |
| `0xE0` | EXPORT_XPUB | `0x80` | 00 | curve (1) ‖ depth (1) ‖ path | xpub | 9000 | inner | SEEDED, PIN verified |
| `0xE1` | SIGN_ECDSA_K1 | `0x80` | 00 | path ‖ digest (32) | r ‖ s (64) | 9000 | inner | SEEDED, PIN verified |
| `0xE2` | SIGN_SCHNORR_K1 | `0x80` | 00 | path ‖ digest (32) | sig (64) | 9000 | inner | SEEDED, PIN verified |
| `0xE3` | SIGN_ED25519 | `0x80` | 00 | path ‖ message (≤256) | sig (64) | 9000 | inner | SEEDED, PIN verified |

CLA = `0x80` 是 ISO 7816 "proprietary" 类，与所有标准 GP 命令不冲突。

### Findings

无 finding：命令矩阵完整、ISO 兼容、状态门无遗漏。

---

## 2. TLV 编码（`ApduTlv.java`）

### 编码规则（applet 简化的 BER-TLV）

```text
+--------+-----------+--------------+
| Tag(1) | Length(1) | Value(0-255) |
+--------+-----------+--------------+
```

- 单字节 tag（0x01-0xFE）；
- 单字节 length（0-0xFF）；
- value 长度 ≤ 255。

### 不支持的 BER 特性

| 特性 | 支持 | 理由 |
| --- | --- | --- |
| 多字节 tag (high tag form) | ❌ | applet 命名空间不需要 31+ tag |
| 长形长度 (>= 0x80) | ❌ | value 永不 > 255 |
| 嵌套 constructed TLV | ❌ | 平铺即可 |
| 大端 vs 小端 | 大端 | ISO 7816 标准 |

### Tag 命名空间（`Constants.java` 行 124-138）

| Tag | 用途 | 出现位置 |
| --- | --- | --- |
| `0x01` | PIN value | SETUP, CHANGE_PIN, UNBLOCK_PIN |
| `0x02` | PUK value | SETUP, CHANGE_PUK, UNBLOCK_PIN |
| `0x03` | PIN_OLD | CHANGE_PIN |
| `0x04` | PUK_OLD | CHANGE_PUK |
| `0x10` | xpub_path | EXPORT_XPUB |
| `0x11` | sign_path | SIGN_* |
| `0x12` | sign_digest | SIGN_ECDSA_K1 / SIGN_SCHNORR_K1 |
| `0x13` | sign_message | SIGN_ED25519 |
| `0x20` | info_protocol_version | GET_INFO |
| `0x21` | info_applet_version | GET_INFO |
| `0x22` | info_capabilities | GET_INFO |
| `0x23` | info_lifecycle | GET_INFO |
| `0x24` | info_pin_tries_remaining | GET_INFO |
| `0x25` | info_puk_tries_remaining | GET_INFO |

Tag 数值不重叠 ✓。`MeowlAppletTest.getInfoIncludesAllTlvFields` pin 了 GET_INFO 的所有 tag（包括 PROTOCOL_VERSION = 0x0100, APPLET_VERSION = 0x0001）。

### Finding W-01 — `finishReserved` 不验证总长 [S4 — Info]

详见 [`01-applet-files.md`](./01-applet-files.md#finding-a-19---finishreserved-不验证-dst-总长-s4--info)（编号 A-19）。

---

## 3. Secure Channel 信封格式

### 物理结构

```text
+---------+--------------------+----------+
| IV (16) | Ciphertext (16k+P) | MAC (16) |
+---------+--------------------+----------+
```

- IV：单调递增（详见 §3.2）；
- Ciphertext：AES-256-CBC + PKCS5 padding，长度是 16 字节倍数；
- MAC：HMAC-SHA-256 over (IV ‖ Ciphertext)，截断到前 16 字节。

### 3.1 IV 派生（`SecureChannel.java:388-407`）

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\SecureChannel.java:386-396
private void deriveOutboundIv(byte[] dst, short dstOff) {
    incrementCounter();
    for (short i = 0; i < Constants.SC_BLOCK_LEN; i++) {
        dst[(short) (dstOff + i)] =
                (byte) (ivBase[i] ^ outboundCounter[i]);
    }
}
```

- 客户端计数器 (host) 与卡端计数器 (card outbound) 各自独立。
- IV = `IV_base XOR counter`，其中 `IV_base` 是 HKDF 派生的 16 字节，`counter` 是 16 字节大端整数。
- **同一会话内 IV 永不重复**，前提是 counter 不 wrap（**A-09**）。

### 3.2 IV 单调性检查（unwrap 路径）

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\SecureChannel.java:317-323
// Replay defense before MAC verification: reject non-monotonic IVs cheaply. IV bytes are
// public, so a non-constant-time compare is fine.
if (compare16(apduBuffer, ivOffset, lastInboundIv, (short) 0) <= 0) {
    reset();
    ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
}
```

- 卡端用 `lastInboundIv` 跟踪上一条已接受的 host IV。
- 任何 IV ≤ lastInboundIv 都立即拒绝（重放防御）。
- **A-08**：在 MAC 之前 reset，给重放者一个 DoS 杠杆。

### 3.3 MAC 验证（`SecureChannel.java:340-352`）

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

- HMAC 计算覆盖 `(IV ‖ ciphertext)`，**未**包含明文长度（PKCS5 padding 自包含）。
- 比较用 `ConstantTime.equals`（OR-fold，无早退）。
- MAC 失败 → reset + 抛错 → 防 padding oracle。✓

### 3.4 解密与解填（`Cipher.ALG_AES_CBC_PKCS5`）

平台自带 PKCS5 padding 验证。padding 错误会抛 `CryptoException`，被 `MeowlApplet.process` 包成 `SW_UNKNOWN`（0x6F00）。**关键**：MAC 在 decrypt 之前已经验证，所以攻击者不能用 PKCS5 oracle —— `A-08` 仅是"DoS 重置 SC"，没有 padding oracle 暴露。

### 3.5 wrap 流程（`SecureChannel.java:359-380`）

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\SecureChannel.java:357-380
public short wrap(byte[] apduBuffer, short plaintextOffset, short plaintextLen) {
    requireOpen();
    deriveOutboundIv(apduBuffer, (short) 0);
    Cipher c = Cipher.getInstance(Cipher.ALG_AES_CBC_NOPAD ... ALG_AES_CBC_PKCS5);
    c.init(encKey, Cipher.MODE_ENCRYPT, apduBuffer, (short) 0, Constants.SC_BLOCK_LEN);
    short cipherLen = c.doFinal(apduBuffer, plaintextOffset, plaintextLen,
                                 apduBuffer, Constants.SC_BLOCK_LEN);
    short cipherEnd = (short) (Constants.SC_BLOCK_LEN + cipherLen);
    hmac.sign(apduBuffer, (short) 0, cipherEnd, apduBuffer, cipherEnd);
    return (short) (cipherEnd + Constants.SC_MAC_LEN);
}
```

- **就地加密**：plaintext 在 outBuf 被 ciphertext 覆写。
- 顺序：IV 派生 → AES-CBC encrypt → HMAC over (IV ‖ ciphertext) → 输出 IV ‖ ciphertext ‖ MAC。
- 这就是 **Encrypt-then-MAC** 范式，符合 NIST SP 800-38C / RFC 7366 推荐。

### Findings

- **W-02 [S3]**：见 [`01-applet-files.md`](./01-applet-files.md) 的 A-08（IV 不单调时 reset 立即触发）。
- **W-03 [S4]**：见 A-09（counter wrap 后 (key, IV) 重用）。

---

## 4. 状态字契约（`Constants.java`）

### 标准 ISO 7816-4 范围

| SW | 含义 | 触发位置 |
| --- | --- | --- |
| `0x9000` | 成功 | 所有正常路径 |
| `0x6700` | wrong length | `Bounds.requireCapacity` 失败、TLV 解析越界 |
| `0x6982` | conditions of use not satisfied | 状态机违规、未提供 PIN、未 seeded |
| `0x6985` | conditions not satisfied | applet 内部一致性 |
| `0x69F0` | auth blocked | PIN/PUK 计数器耗尽 |
| `0x6A82` | file not found | （未使用） |
| `0x6A86` | wrong P1/P2 | INS 不识别的子操作 |
| `0x6E00` | CLA not supported | non-0x80 类 |
| `0x6D00` | INS not supported | 未知 INS |
| `0x6F00` | unknown error | 全局 catch-all |
| `0x6FFF` | feature unsupported | platform crypto 缺失 |

### 自定义范围

| SW | 含义 | 触发 |
| --- | --- | --- |
| `0x63Cn` | PIN 还剩 n 次重试 | VERIFY_PIN 失败 |
| `0x6F00+n` (n=1..3) | RTF 倒计数还剩 n 次 | RESET_TO_FACTORY 中间步 |
| `0x6F00` | RTF 完成（最后一次） | 倒计数到 0 |
| `0x6FF0` | secure channel failed | SC 握手失败 / unwrap 失败 |
| `0x6FF1` | lifecycle invalid | 状态转移非法 |

ISO 7816-4 §5.1.5 把 `0x63Cn` 标准化为 PIN retry counter 形式，正好用满 4 bit nibble。`MeowlAppletTest.verifyPinFailureExposesRetryCounter` pin 了这条契约。

### Findings

无 finding。状态字契约清晰，与 ISO 7816-4 兼容。

---

## 5. 路径编码（HD 派生）

### 编码格式（`SIGN_*` / `EXPORT_XPUB` 的 path 段）

```text
+----------+----------+
| depth(1) | path(4×) |
+----------+----------+

path[i] = uint32 大端，最高位为 1 ⇒ hardened
```

- depth ∈ [0, 8]（`Constants.HD_PATH_MAX_DEPTH`）
- path 总长 = 4 × depth
- HD 派生 ISO 7816-4 子格式：`HARDENED_MASK = 0x80000000`（高字节 = 0x80）

### 路径示例

```text
m/44'/0'/0'/0/0  →  depth=5, path=
  0x8000002C 0x80000000 0x80000000 0x00000000 0x00000000
```

### Findings

无。`HdDerivationTest.bip32WellKnownVector` 用 BIP-32 §"Test vectors" 的 5 条向量交叉验证。

---

## 6. 协议总评

### 强项

1. **简化 BER-TLV** + 单字节 tag/length —— 解析复杂度 O(1)，攻击面小。
2. **CLA = 0x80** 与 GP/ISO 命令完全分隔。
3. **Encrypt-then-MAC** + 严格 IV 单调 + MAC 失败强制 reset。
4. **PIN retry counter 在 SW 中暴露** —— ISO 标准做法。
5. **三步 chunked import** (PKI cert) —— 处理大 payload 时 APDU buffer 限制的标准策略。

### 弱项

1. **A-08 / W-02 [S3]**：IV 重放防御与 MAC 验证的顺序导致 DoS 杠杆。修复成本：3 行代码。
2. **A-09 / W-03 [S4]**：outboundCounter 缺 wrap 保护。修复成本：4 行代码。
3. **A-19 [S4]**：`finishReserved` 缺总长检查。修复成本：1 行代码。

无 S0/S1 级别 wire 协议问题。
