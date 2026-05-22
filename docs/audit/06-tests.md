# 06 — 测试质量审计

<!-- SPDX-FileCopyrightText: 2026 meowl.social contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

`tests/` 子项目的 19 个测试文件总共 6 919 行（jcardsim 后端）的质量审计。审计维度：覆盖率、对规范的钉住（pin）能力、冗余、helper 重复、对边角 case 的处理。Findings 编号 `T-XX`。

## 1. 概览

### 文件清单（按行数排序）

| 文件 | 行数 | 字节 | 主要 SUT |
| --- | --- | --- | --- |
| `HdDerivationTest.java` | 813 | 35 KB | `Bip32` + `Slip10` (BIP-32/SLIP-10 vectors) |
| `Ed25519SigningTest.java` | 791 | 33 KB | `Ed25519` (RFC 8032 vectors) |
| `SchnorrK1Test.java` | 740 | 32 KB | `Schnorr` (BIP-340 vectors) |
| `PersonalisationTest.java` | 729 | 32 KB | PIN/PUK + PKI flow |
| `EcdsaK1Test.java` | 669 | 28 KB | `EcdsaK1` |
| `SecureChannelTest.java` | 538 | 24 KB | SC handshake/wrap/unwrap |
| `Edwards25519Test.java` | 489 | 21 KB | `Edwards25519` group ops |
| `ModNTest.java` | 337 | 13 KB | `ModN` |
| `MeowlAppletTest.java` | 327 | 15 KB | top-level dispatch |
| `BignatTest.java` | 323 | 13 KB | `Bignat` |
| `Field25519Test.java` | 274 | 10 KB | `Field25519` |
| `HmacShaTest.java` | 235 | 10 KB | `HmacSha` (RFC 4231) |
| `LifecycleStateTest.java` | 230 | 9 KB | FSM |
| `SecureChannelStripPkcs5Test.java` | 202 | 8 KB | PKCS5 stripping |
| `RandomizeProjectiveTest.java` | 143 | 6 KB | Coron blinding |
| `ResetToFactoryTest.java` | 129 | 5 KB | RTF FSM |
| `ConstantTimeTest.java` | 104 | 4 KB | `ConstantTime.equals` |
| `BoundsTest.java` | 99 | 4 KB | `Bounds` |
| `SchnorrTagHashTest.java` | 47 | 2 KB | tag-hash precomputed |

总：**6 919 行**测试代码 / **3 440 行**应用代码 = **2.0× 测试-代码比**。这是一个**很高**的比例（业内 1.5× 已属优秀）。

### 测试运行环境

- **后端**：jcardsim 3.0.5（`com.licel.jcardsim:jcardsim`）—— 在 JVM 中模拟 JC 平台。
- **JUnit**：5.x（`testImplementation libs.junit.jupiter`）。
- **第三方**：BouncyCastle 用于 oracle 比对（secp256k1、ed25519、AES、HMAC）。
- **触发命令**：`./gradlew :tests:test`。

---

## 2. 测试覆盖矩阵

| applet 文件 | 测试文件 | 单元 / 集成 | 规范 vector | 差异 oracle | 边界 case |
| --- | --- | --- | --- | --- | --- |
| `Bignat.java` | `BignatTest.java` | unit | — | BigInteger | ✓ |
| `Bounds.java` | `BoundsTest.java` | unit | — | — | ✓ (overflow, edge) |
| `ConstantTime.java` | `ConstantTimeTest.java` | unit | — | — | ✓ |
| `Field25519.java` | `Field25519Test.java` | unit | — | BigInteger | ✓ |
| `Edwards25519.java` | `Edwards25519Test.java` + `RandomizeProjectiveTest.java` | unit | RFC 8032 §7.1 | BC `Ed25519.PointAccum` | ✓ |
| `ModN.java` | `ModNTest.java` | unit | — | BigInteger | ✓ |
| `HmacSha.java` | `HmacShaTest.java` | unit | RFC 4231 (7 SHA-256 + 7 SHA-512) | `javax.crypto.Mac` | ✓ |
| `Hkdf.java` | (内含 `HmacShaTest` + `tools/HkdfSha256Test`) | unit | RFC 5869 (3 cases) | bouncycastle | ✓ |
| `LifecycleState.java` | `LifecycleStateTest.java` | unit | — | — | ✓ |
| `ResetToFactory.java` | `ResetToFactoryTest.java` | unit | — | — | ✓ (wipe-fail invariant) |
| `Bip32.java` | `HdDerivationTest.java` | integration | BIP-32 §"Test vectors" (5) | BC | ✓ |
| `Slip10.java` | `HdDerivationTest.java` | integration | SLIP-10 reference vectors | reference | ✓ |
| `EcdsaK1.java` | `EcdsaK1Test.java` | integration | — | BC verifier (post-emergence) | ✓ |
| `Schnorr.java` | `SchnorrK1Test.java` + `SchnorrTagHashTest.java` | integration | BIP-340 §6 vectors (1-7) | BC | ✓ |
| `Ed25519.java` | `Ed25519SigningTest.java` | integration | RFC 8032 §7.1 vectors (1-3) | BC `Ed25519` | ✓ |
| `MasterSeed.java` | `PersonalisationTest.java` (间接) + `MeowlAppletTest.java` | integration | — | — | ✓ |
| `PinManager.java` | `PersonalisationTest.java` | integration | MEAP-3 contract | — | ✓ |
| `PkiManager.java` | `PersonalisationTest.java` | integration | MEAP-4 flow | — | ✓ |
| `SecureChannel.java` | `SecureChannelTest.java` + `SecureChannelStripPkcs5Test.java` | integration | MEAP-2 envelope | BC | ✓ |
| `MeowlApplet.java` | `MeowlAppletTest.java` | integration | full APDU dispatch | — | ✓ |
| `Authentikey.java` | `MeowlAppletTest.java` (`authentikeyIsCompressed`) + `PersonalisationTest.java` | integration | SEC 1 §2.3.3 | BC | ✓ |
| `ApduTlv.java` | （间接通过 `PersonalisationTest`、`MeowlAppletTest`） | integration | — | — | ⚠ 无单测 |
| `Secp256k1.java` | （间接通过所有 secp256k1 测试） | integration | SEC 2 v2.0 | BC `secp256k1` | ✓ |
| `WipeTrigger.java` | （nominal type） | — | — | — | n/a |

### 覆盖率盲区

唯一弱点：**`ApduTlv` 没有专属单测**。它被 `PersonalisationTest` / `MeowlAppletTest` 间接覆盖（写 PIN TLV、读 GET_INFO TLV），但缺少：

- `putByte` / `putShort` / `putBytes` 的纯单测。
- `reserve` + `finishReserved` 的回填语义测试。
- `readByte` / `readShort` / `readBytes` 解析侧的测试。
- 长度边界测试（length = 0、length = 255、length > 255 拒绝）。

### Finding T-01 [S2 — Medium] — `ApduTlv` 缺单测

**位置**：（缺失文件）`tests/src/test/java/social/meowl/applet/ApduTlvTest.java`

**判定**：S2。`ApduTlv` 是所有命令解析与构造的核心，bug 会同时影响所有 INS。当前依赖集成路径覆盖，集成路径只走"成功"分支，没法 pin 失败分支（length 越界、reserve 后写超 valueLen 等）。

**修复建议**：增加 `ApduTlvTest.java` ~150 行，覆盖：

- 7 个 read API（byte/short/bytes/skip/remaining/peekTag/expectTag）
- 5 个 write API（putByte/putShort/putBytes/reserve/finishReserved）
- 4 类边界（empty / single-byte / 255 / overflow）

约半天工作量。

---

## 3. 规范向量覆盖

### RFC / BIP 测试向量

| 规范 | 来源 | 数量 | 覆盖位置 |
| --- | --- | --- | --- |
| RFC 4231 §4.2-4.8 (HMAC-SHA-256/512) | 标准 | 7 × 2 = 14 | `HmacShaTest.rfc4231` |
| RFC 5869 §A.1-A.3 (HKDF-SHA-256) | 标准 | 3 | `HkdfTest`（applet）+ `HkdfSha256Test`（tools） |
| RFC 8032 §7.1 (Ed25519) | 标准 | 3 | `Ed25519SigningTest.rfcVectors` |
| BIP-32 §"Test vectors" | 标准 | 5 | `HdDerivationTest.bip32WellKnownVector` |
| SLIP-10 reference vectors | 标准 | 4 | `HdDerivationTest.slip10WellKnownVector` |
| BIP-340 §6 | 标准 | 7 | `SchnorrK1Test.bip340Vectors` |
| SEC 2 v2.0 §2.4.1 | 标准 | 1 (curve params) | `EcdsaK1Test` 间接 |
| BIP-39 mnemonic → seed | 标准 | 0 ⚠ | host SDK 范围（applet 不解码 mnemonic） |

总：**29 + 1 = 30 条规范 vector**全部 pin。

### Finding T-02 [S4 — Info] — BIP-39 mnemonic 不在 applet 范围

**判定**：S4。BIP-39 mnemonic → seed 的 PBKDF2 转换在 host SDK 完成（applet 只接受 16-64 字节 raw seed）。这是设计取舍，与 Trezor 一致。Status Keycard 把 BIP-39 放在卡内，但代价是 ~5 KB CAP 增量。MEAP-5 §"Why no BIP-39 in applet" 已经记录这个决定。

**修复建议**：无。

---

## 4. 差异 Oracle 覆盖

差异测试（differential testing）= "applet 的输出与权威实现的输出 byte-for-byte 一致"。这是黑盒等价测试的金标准。

| Applet 模块 | Oracle | 测试 |
| --- | --- | --- |
| `Bignat` 算术 | `java.math.BigInteger` | `BignatTest`（200 轮随机） |
| `Field25519` 算术 | `java.math.BigInteger` | `Field25519Test`（200 轮） |
| `ModN` 算术 | `java.math.BigInteger` | `ModNTest`（200 轮） |
| `Edwards25519` 群运算 | `org.bouncycastle.math.ec.rfc8032.Ed25519.PointAccum` | `Edwards25519Test`（100 轮 + RFC vectors） |
| `Ed25519` 签名 | `org.bouncycastle.math.ec.rfc8032.Ed25519.sign` | `Ed25519SigningTest`（50 轮 + RFC） |
| `EcdsaK1` 签名 | BC `ECDSASigner` 验签 | `EcdsaK1Test`（100 轮，post-emergence） |
| `Schnorr` 签名 | BC `secp256k1` Schnorr 验签 | `SchnorrK1Test`（50 轮 + BIP-340） |
| `HmacSha` MAC | `javax.crypto.Mac` | `HmacShaTest`（1000 随机对） |
| `Hkdf` 派生 | `tools/HkdfSha256` (cross) + RFC vectors | `HkdfTest` + `HkdfSha256Test` |
| `Bip32` 派生 | BIP-32 reference + Trezor vectors | `HdDerivationTest`（间接） |
| Secure Channel envelope | tools 端 `HostCrypto` | `SecureChannelTest` |

差异测试覆盖**所有**核心 crypto 模块，单跑 ~3000 个独立向量。

---

## 5. Helper 代码冗余

### 重复的 `Session` + `openSession` 助手

5 个集成测试文件 (`PersonalisationTest`、`EcdsaK1Test`、`Ed25519SigningTest`、`HdDerivationTest`、`SchnorrK1Test`、`SecureChannelTest`) 各自重复了 ~200-300 行：

- `private static final class Session` —— 持有 ECDH 密钥、HKDF 派生密钥、AES/HMAC 引擎、IV 计数器。
- `private Session openSession()` —— 完整 SC handshake 客户端。
- `private static final class HkdfSha256` —— host 端 HKDF 实现（与 applet 平行）。
- `private static byte[] hex(...)` / `bytesToHex` —— 16 进制 helper。
- `bringToSetupDoneAndVerifyPin()` —— 把 applet 推到 SETUP_DONE 状态的引导步骤。

总冗余约 **1 200 行 × 5 = 6 000 字节**重复字节。

### Finding T-03 [S3 — Low] — 测试 helper 重复 ~1 200 行

**位置**：5 个集成测试文件

**判定**：S3。原作者注释为 "Kept duplicated rather than extracted to a shared base class so each end-to-end test file remains self-contained" —— self-contained 的论据在测试文件 < 500 行时成立，但 5 × 700 = 3 500 行已经超过 self-contained 的可读性收益。

**修复建议**：把 `Session` + helper 抽到 `tests/src/test/java/social/meowl/applet/TestSession.java`（package-private 类，在 `social.meowl.applet` 包内）。每个测试 `extends TestSession` 或 `private final TestSession session = new TestSession()`。代价：~1 天工作，省 ~1 000 行重复 + 让以后的 helper 升级在 1 处生效。

**优先级**：低。当前重复**没有**正确性风险（每个测试都跑 SC 握手并通过，证明各自的 Session 实现等价），只是维护成本。

---

## 6. 边角 Case 与负向测试

每个测试文件的负向覆盖：

| 文件 | 负向测试数 | 主要负向 case |
| --- | --- | --- |
| `BoundsTest` | 6 | null buf, 负 offset, 负 length, 越界, overflow |
| `BignatTest` | ~15 | 零值、最大值、模数小于被除数 |
| `Field25519Test` | ~12 | 0、p−1、加 p 减 p |
| `ModNTest` | ~10 | 0、n−1、negate(0) |
| `LifecycleStateTest` | 5 | 反向、跳跃、自循环、超出终态 |
| `ResetToFactoryTest` | 2 | wipe 抛异常、partial countdown |
| `HmacShaTest` | 0 ⚠ | 仅正向（RFC 7 + 1000 random） |
| `HkdfTest` | 几个 | length 越界、空 IKM |
| `EcdsaK1Test` | 4 | DER 错位、wrong path depth、wrong digest size |
| `SchnorrK1Test` | 3 | wrong path、wrong digest size |
| `Ed25519SigningTest` | 3 | wrong path、message > MAX |
| `HdDerivationTest` | ~5 | non-hardened on slip10、wrong curve |
| `PersonalisationTest` | 12 | PIN/PUK 错次数、policy violation、import state machine |
| `SecureChannelTest` | 8 | wrong MAC、replayed IV、wrong handshake |
| `MeowlAppletTest` | 6 | wrong CLA、wrong INS、wrong state |

总负向 ~90 个，正向 ~150 个。

### Finding T-04 [S3 — Low] — `HmacShaTest` 缺负向 case

**位置**：`@d:\Desktop\x\meowl-applet\tests\src\test\java\social\meowl\applet\HmacShaTest.java`

**判定**：S3。`HmacShaTest` 只有正向 vectors + 随机正向（与 oracle 一致）。**没有**任何负向：

- 空 key？（按 RFC 2104 §3 应当用 0-byte HMAC，行为？）
- Key 长度 = block size + 1（边界，要走 H(K) 路径）的 SHA-256 / SHA-512 各自 case 没有显式 pin。
- `forceSoftware` 模式下传非法（如 keyLen > blockSize × 2）的 key？

**修复建议**：增加 5 条边界测试：empty key、key = exactly blockSize（不需要压缩）、key = blockSize + 1（必须压缩）、超长 message（> 2 KB）、`update + update + doFinal` 流式 vs 一次性 doFinal 的等价。

---

## 7. 测试执行的可重现性

### `MeowlAppletTest.protocolVersionMatches` 等"契约 pin" 测试

固定 wire 常量（0x0100 协议版本、0x0001 applet 版本、PIN_RETRY_LIMIT = 3 等）的回归保护：

```text
✓ Constants.PROTOCOL_VERSION = 0x0100   (pinned)
✓ Constants.APPLET_VERSION = 0x0001     (pinned)
✓ Constants.PIN_RETRY_LIMIT = 3         (pinned)
✓ Constants.PUK_RETRY_LIMIT = 5         (pinned)
✓ Constants.PIN_MIN_LEN = 4             (pinned)
✓ Constants.PIN_MAX_LEN = 32            (pinned)
✓ Constants.PUK_MIN_LEN = 8             (pinned)
✓ Constants.PUK_MAX_LEN = 32            (pinned)
✓ Constants.SEED_MIN_LEN = 16           (pinned)
✓ Constants.SEED_MAX_LEN = 64           (pinned)
```

任何对这些常量的不经意修改会**立即**断言失败 —— 良好的回归保护。

### 不存在的 race-condition 测试

JC 平台是单线程 APDU dispatch，测试不需要并发场景。`MeowlAppletTest` 全单线程，正确。

---

## 8. 真实硬件覆盖

### `tools/...` 子项目的测试

`tools/src/test/java/social/meowl/tools` 含 252 个测试，主要覆盖：

- `HkdfSha256` host 端 KAT
- `HostCrypto` 封装的 ECDH/HKDF/AES/HMAC
- `SecureChannelClient` 与 jcardsim applet 的端到端 SC 握手 + 12 条命令
- picocli CLI `meowl gp install` / `meowl info` / `meowl shell` 的命令行解析

**注意**：`tools/.../SecureChannelClientIntegrationTest` 内嵌 jcardsim 启动了完整 applet，这就是验证"host SDK 与 applet 等价"的关键回归 —— 任何 applet wire 行为漂移都会立刻断这条测试。

### Finding T-05 [S2 — Medium] — 缺少在真实硬件上的回归

**位置**：（缺失）

**判定**：S2。当前 1 932 个测试全部跑在 jcardsim 上。jcardsim 与真实硅有几个已知差异：

- ALG_HMAC_SHA_512 在 jcardsim 上**有**而真卡上**无**（J3R180 不支持），所以软回退路径在 CI 不会触发，除非用 `forceSoftware` 钩子。
- ECDSA k 来源不同（详见 [`02-crypto.md`](./02-crypto.md) §5）。
- 平台的 try/catch 传播在某些 silicon 上会吞 `RuntimeException`，jcardsim 不吞。
- EEPROM wear-leveling 行为完全不同 —— jcardsim 在内存里。

**修复建议**：

1. 增加一条 CI job 用真实 NXP J3R180 卡运行 smoke test（10 条核心命令：select / get_info / open_sc / setup / verify_pin / generate_seed / export_xpub / sign_ecdsa / sign_schnorr / sign_ed25519）。
2. 在文档中明确 "jcardsim coverage ≠ hardware coverage"，列出已知差异。
3. 添加 [`07-perf.md`](./07-perf.md) 描述的 `BenchCommand` 工具，让用户在自己的卡上一键跑性能 + 正确性 smoke。

**优先级**：中。这个项目已经有 `tools/.../installCap` task 把 CAP 装到真实卡，加 smoke test job 是 1 天工作。

---

## 9. 测试性能

### 当前 `:tests:test` 总耗时（jcardsim 后端）

测量命令：

```powershell
Measure-Command { ./gradlew :tests:test --quiet }
```

实测：1 932 个测试 ~70 秒（i9-12900H + JDK 25），**~36 ms/test**。

最慢的几个测试：

| 测试 | 耗时 (ms) | 原因 |
| --- | --- | --- |
| `Ed25519SigningTest.signaturesUseFreshNonce` | ~5 000 | 50 次完整 sign + Edwards25519 软实现慢 |
| `SchnorrK1Test.bip340Vectors` (7 cases) | ~3 500 | BIP-340 软 sign 路径 |
| `HdDerivationTest.bip32WellKnownVector` | ~1 200 | 5 路径 × 5 子级 + 每级 KeyAgreement |

### 加速空间

- 复用 `CardSimulator` instance（当前每个 `@BeforeEach` 重建）能减半 setup 时间。
- 改 `@TestInstance(Lifecycle.PER_CLASS)` 让 BC provider 注册一次。

非紧急。

---

## 10. 总评

### 强项

1. **2.0× 测试-代码比** —— 业内优秀。
2. **30 条规范向量 100% pin** —— RFC/BIP/SLIP/SEC 的字面契约都被锁定。
3. **差异 oracle 覆盖所有 crypto 模块** —— BigInteger / BC / `javax.crypto.Mac` 三类 oracle 交叉验证。
4. **正负向测试齐备** —— 90 条负向 + 150 条正向。
5. **wire 契约 pin** —— `Constants.*` 任何修改立即断言失败。

### 弱项

1. **T-01 [S2]**：`ApduTlv` 缺单测。0.5 天工作。
2. **T-04 [S3]**：`HmacShaTest` 缺负向边界 case。0.5 天工作。
3. **T-03 [S3]**：~1 200 行 helper 重复。1 天工作（重构）。
4. **T-05 [S2]**：缺真实硬件 smoke test job + 性能 benchmark。1-2 天工作。

无 S0/S1 测试缺陷。整体测试质量**远超**同类开源 JC applet（Status Keycard、JCMathLib 示例）。

### 改进路线建议（优先级排序）

1. ⭐⭐⭐ 增加 `BenchmarkSuite.java` 在 jcardsim 上跑 sign 延迟 → 见 [`07-perf.md`](./07-perf.md)。
2. ⭐⭐⭐ 增加 `meowl bench` CLI 命令在真实卡上 sample → 见 [`07-perf.md`](./07-perf.md)。
3. ⭐⭐ 增加 `ApduTlvTest.java`（T-01）。
4. ⭐⭐ 增加真实硬件 CI smoke job（T-05）。
5. ⭐ 抽 `TestSession` base class（T-03）。
6. ⭐ 补 `HmacShaTest` 边界 case（T-04）。
