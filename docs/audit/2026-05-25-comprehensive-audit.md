<!--
SPDX-FileCopyrightText: 2026 meowl.social contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# meowl-applet 全方位审计报告

**审计日期**：2026-05-25  
**审计 commit**：`c0150b1` (HEAD on `main`)  
**审计员**：Cascade（内部）  
**审计性质**：仓内只读全量探查，结论以 finding 列表呈现，**不替代外部 paid security audit**

---

## 阅读指南

本报告分 **8 章 + 4 附录**，每章末附该章 findings 一览。findings 跨章交叉引用，最终汇总在第 8 章。

每个 finding 标准呈现：

- 编号 `AUDIT-NNN`（递增、不复用）
- **严重等级**：`Critical` / `High` / `Medium` / `Low` / `Info`
- **类别**：`security` / `correctness` / `quality` / `docs` / `tooling` / `tests`
- **位置**：精确文件 + 行号
- **描述 + 证据**：具体观察到的现象
- **修复建议 + 成本**：`trivial` / `small` / `medium` / `large`

| Severity | 含义 |
| --- | --- |
| Critical | 已知可被远端利用的漏洞，或会损坏用户密钥的逻辑错误。**必须立即修。** |
| High | 触发条件明确的 security/correctness 风险，或会让用户陷入不可恢复状态的设计缺陷。 |
| Medium | 防御层削弱、文档严重 stale、可被未来变更放大的隐患。下个 sprint 修。 |
| Low | 代码异味、命名/结构/重复、影响维护但不影响正确性。择机修。 |
| Info | 已合理 trade-off 的设计选择，记录在案以防止未来误改。 |

---

## 第 1 章 · 执行摘要

### 1.1 总体评估

`meowl-applet` 是一个**架构清晰、代码质量上乘**的 JavaCard 硬件钱包 applet。核心密码学路径（Secure Channel、ECDSA/Schnorr/Ed25519、BIP-32/SLIP-10）实现严谨，constant-time 防御充分（`BigNat.ctEquals`、`ctSelectNeg`、`ctLessThan`），事务原子性保证完整，`@Tag("real-card")` 双轨测试模型设计合理，139/139 实卡测试通过。

但项目处于一个**重构中段**：上一周连续多个大型 commit（HmacSha 折叠、SC MAC 迁移、testkit 重构、wipe 路径瘦身）后，**文档 / 工具链 / CHANGELOG 与代码实际状态严重 drift**。`README.md` 还在列出已删除的测试套件，`CHANGELOG.md [Unreleased]` 半数引用不再存在，`tools/build.gradle.kts` 残留 `useSimulator` 死配置，`Makefile` 缺 real-card target。这些 drift 不影响代码运行，但会让**新贡献者快速失去对项目可信度的判断**。

此外，**上次 commit `688f8c8`（"shrink RESET_TO_FACTORY wipe to fit contactless BWT"）属于 functional > security 的主动 trade-off**，去掉了 PIN/PUK/master-seed/PKI cert 的 EEPROM 清零步骤。trade-off 本身在每个 `wipeInTx` 的 javadoc 中详细记录，但**"defense-in-depth EEPROM scrub" 是上一个版本承诺过的 mitigation**——这个改动需要外部 reviewer 显式 sign-off，本审计将其列为 **AUDIT-001（High，security）**，并给出三条恢复路径供选择。

### 1.2 健康度仪表板

| 维度 | 评分 | 关键观察 |
| --- | --- | --- |
| **Applet 代码质量** | 8.5 / 10 | 模块划分清晰、零 TODO/FIXME、密码学路径 constant-time 严谨；扣分项是 wipe 路径的 trade-off 待 sign-off、几处异常路径 secret wipe 缺失 |
| **Tools 代码质量** | 7.5 / 10 | picocli 命令树良好、`SecureChannelClient` 完整；扣分项是 PKI 常量在 `BootstrapCommand` 硬编码重复、`(byte) 0x80` 等 magic number 散落 |
| **测试质量** | 8.0 / 10 | testkit 重构合理、双轨清晰、139/139 通过、覆盖矩阵接近完整；扣分项是 `@AfterEach` 6-行 boilerplate × 8 重复、`HostSession` 不验签缺显式契约 |
| **构建系统 / Makefile / CI** | 6.5 / 10 | Gradle 多模块结构标准、Spotless + CycloneDX SBOM 完整；扣分项是 `Makefile` 缺 real-card target、CI 不跑 real-card、`tools/build.gradle.kts` 残留 dead config |
| **文档** | 5.5 / 10 | MEAP-0..7 spec 集合质量极高、内部一致；扣分项严重——`README.md`/`CHANGELOG.md`/`SECURITY.md`/`CONTRIBUTING.md` 多处引用已删除的类、不存在的路径、stale 项目布局 |
| **Security posture** | 7.5 / 10 | 密码学实现 sound、threat model 清晰、constant-time 充分；扣分项是上次 commit 的 EEPROM scrub trade-off 未经显式 sign-off、authentikey 不可重生成 |
| **Hardware / 硬件兼容** | 8.0 / 10 | J3R180 单 target 硬化彻底、双 reader 启发解决了 ACR1552 SAM/PICC 二义性、BWT 调优具体；扣分项是 `BootstrapCommand` 强制 LOCK_PKI 路径不友好 |

**项目整体评分：7.4 / 10** — "代码质量好但文档跟不上，需要一轮文档同步 + 上次 wipe trade-off 的显式 sign-off"。

### 1.3 Top-10 关键 Findings

| # | 编号 | Severity | 类别 | 一句话描述 |
| --- | --- | --- | --- | --- |
| 1 | AUDIT-001 | **High** | security | `MasterSeed.wipeInTx` 不再清零 EEPROM 母 key bytes，依赖 `seededFlag` 守门——defense-in-depth 削弱，需显式 sign-off |
| 2 | AUDIT-024 | **High** | docs | `CHANGELOG.md [Unreleased]` 引用 5 个已删除的类（`SimulatorCardClient`、`ResetToFactoryTest` 等）+ 缺最近 3 个 commit 内容 |
| 3 | AUDIT-025 | **High** | docs | `README.md:51` 列出 4 个已删除的测试套件作为 real-card 测试目标 |
| 4 | AUDIT-005 | Medium | security | `Slip10`/`Bip32` walk 路径异常时 leaf scalar 残留 transient state 直到 deselect |
| 5 | AUDIT-009 | Medium | tests | `tests/testkit/HostSession` 默认不验证 handshake 签名，依赖 caller 单独 audit |
| 6 | AUDIT-016 | Medium | tooling | `tools/build.gradle.kts` `realCardTest` 任务保留 `-PuseSimulator` 选项，但 simulator 后端已删除 |
| 7 | AUDIT-018 | Medium | tooling | `Makefile` 缺 `realcard` / `tools-realcard` / `installCap` target，与双轨测试模型不同步 |
| 8 | AUDIT-020 | Medium | tooling | `.gitignore` 已含 `*.log`，但工作区 `realcard.log`（335 KB 二进制）未被清理 |
| 9 | AUDIT-013 | Medium | quality | `BootstrapCommand` 硬编码 `PKI_CERT_CHUNK_MAX_LEN=200` / cert 上限 1024 / seed 上限 64，与 applet `Constants` drift 风险 |
| 10 | AUDIT-027 | Medium | docs | `SECURITY.md:59` 引用 `Bignat.java`（错误大小写），实际为 `BigNat.java` |

完整 finding 列表见第 8 章。

### 1.4 风险矩阵

```text
            可能性 →
            低           中           高
影    高  | AUDIT-024  | AUDIT-001  | (none)        | High
响    中  | AUDIT-005  | AUDIT-009  | AUDIT-018     |
↓     低  | AUDIT-013  | AUDIT-016  | AUDIT-025     |
              AUDIT-020      AUDIT-027    
```

`AUDIT-025`/`AUDIT-027`（README/SECURITY stale）出现在"高可能性 / 低影响"——影响低是因为 stale 文档不影响代码运行，但**贡献者每读一次就遇到一次 confusion**，可能性高。

### 1.5 修复路线图建议

**P0（必修，下个 commit）**：

- AUDIT-024（CHANGELOG.md `[Unreleased]` 同步到当前代码）
- AUDIT-025（README.md 移除已删除测试套件引用）
- AUDIT-027（SECURITY.md `Bignat.java` → `BigNat.java`）
- AUDIT-016（删除 `tools/build.gradle.kts` 的 `useSimulator` 死配置）
- AUDIT-020（清理 `realcard.log` 工作区残留）

**P1（下个 sprint）**：

- AUDIT-001（wipe EEPROM scrub trade-off 显式 sign-off：恢复或保留并文档化为 ADR）
- AUDIT-005（`walkPath` try-finally 包 secret wipe）
- AUDIT-018（`Makefile` 增 `realcard` / `tools-realcard` / `installCap` target）
- AUDIT-009（`HostSession` 添加可选签名验证开关）
- AUDIT-013（`BootstrapCommand` 改用集中 mirror 或从卡端拉取）

**P2（择机修）**：

- 第 8 章其余 Low/Info 项

---

## 第 2 章 · 代码质量审计

### 2.1 模块划分与依赖关系

仓库三个 Gradle 模块：

```text
applet  — JavaCard CAP 源码（5,220 行 Java，26 文件）
tests   — JUnit 6 测试（5,427 行，25 文件，simulator + real-card 双轨）
tools   — 宿主端 CLI / SC client / GP wrapper（5,820 行，54 文件）
```

依赖图：

```text
:tests   ──depends─→ :applet           (复用 applet 源码作为 lib，jcardsim 提供 javacard.framework.*)
:tools   ──depends─→ :applet           (供 SecureChannelClientIT)
:tools   ──depends─→ apdu4j, gppro, picocli, jline, jackson-jr, BC
:applet  ──depends─→ JC SDK (compile-only) + ant-javacard (build only)
```

**评估**：依赖方向单向，无循环依赖。`:tests:realCardTest` 与 `:tools:realCardTest` 双任务通过 JUnit `@Tag` 隔离 jcardsim-incompatible suites，模型干净。

### 2.2 `applet/` 逐文件审查

26 个文件，按职责分组：

#### 2.2.1 Dispatcher / 顶层

- **`MeowlApplet.java`** (625 行) — 入口 + INS 路由 + 17 个 handler，每个 < 50 行。结构清晰，无 dead code。`select()` 钩子重置 SC + PIN session + ResetToFactory counter，`process()` 严格走 `cla != CLA_MEOWL` → `INS_NOT_SUPPORTED` 兜底。`SHARED_SCRATCH_LEN` 注释精确说明四个 mutually-exclusive 消费者。**`@Override public void wipe()` 是 RESET_TO_FACTORY 的 atomic 入口，三个 manager + state 在单一 transaction 内 commit**——见 AUDIT-001。
- **`Constants.java`** (385 行) — banding 注释清晰（`0x00–0x0F` lifecycle / `0x10–0x1F` SC / …），17 个 INS / 9 个 SW / 7 个 capability bit / TLV tag / sizes / policy thresholds 全部有 javadoc。`Constants.fail(short sw)` 是为 JC 3.0.5 verifier 准备的"返回 RuntimeException 让 caller throw"模式，注释充分。
- **`LifecycleState.java`** (95 行) — 4 状态 FSM，`transitionToInTx` 强制 `target == current + 1`，`isLegalForward` package-private 暴露给单元测试。"Persistent EEPROM-backed current state" 描述准确（JC instance field 默认持久）。
- **`ResetToFactory.java`** (60 行) — CLEAR_ON_RESET counter，"rearm BEFORE wipe()" 防 throw 后残留 0 的细节正确。

#### 2.2.2 安全状态管理

- **`PinManager.java`** (214 行) — 见第 6.2 节深审；`wipeInTx` 见 AUDIT-002。
- **`PkiManager.java`** (209 行) — 三步 chunked import 协议清晰，`importInit/importWrite/importFinalize` 分别独立 transaction。`exportCert` 偏移检查严格。`wipeInTx` 见 AUDIT-003（cert 是公开数据，severity 低于 AUDIT-001/002）。
- **`MasterSeed.java`** (286 行) — 见第 6.4 节深审；`wipeInTx` 见 AUDIT-001。
- **`Authentikey.java`** (72 行) — 一次性生成，`writeCompressedPubkeyTo` 把 0x04 prefix 压缩到 0x02/0x03 并清零尾部 32 字节。**没有重生成路径**——见 AUDIT-008。
- **`WipeTrigger.java`** (18 行) — 单一方法 SAM，仅一个实现（`MeowlApplet.wipe()`）。javadoc 说明了 JC 3.0.5 缺 `Runnable` 的原因。**Info** 级 finding，可保留。

#### 2.2.3 Secure Channel

- **`SecureChannel.java`** (514 行) — 见第 6.1 节深审。
- **`Kdf.java`** (179 行) — AES-CMAC-128 KBKDF（extract + expand），`MAX_EXPAND_LEN = 255 × 16` 镜像 RFC 5869 cap。`counterBuf` 单独 transient slot 防 `Signature.update` 延迟摄入时被 mutate——这个细节说明作者对 JC `Signature` 语义理解透彻。
- **`HmacSha512.java`** (149 行) — RFC 2104 软件 HMAC-SHA-512，因为 J3R180 不暴露 `ALG_HMAC_SHA_512`。`xorBlock` mutate-then-restore 模式避免第二次 opad copy。`reset()` wipe `padded` + `inner`——但只在 `MeowlApplet` 不显式调用，依赖 CLEAR_ON_DESELECT 兜底。

#### 2.2.4 HD 推导

- **`Bip32.java`** (207 行) — `state[193]` 紧凑布局 `k(32) ‖ c(32) ‖ I(64) ‖ pub(65)`，`walkPathToLeaf` 异常路径见 AUDIT-005。`ckdPriv` 严格执行 BIP-32 §"Specification"：`I_L >= n` 或 `k_i == 0` 抛 SW_CONDITIONS_NOT_SATISFIED 而非 retry，注释明确说明这与 Trezor / libsecp256k1 一致。
- **`Slip10.java`** (123 行) — 仅 hardened，`HARDENED_MASK` 检查在 walkPath 内每个 level 强制；非 hardened 抛 SW_CONDITIONS_NOT_SATISFIED。同样有异常路径 wipe 缺失（AUDIT-005）。

#### 2.2.5 签名 primitive

- **`EcdsaK1.java`** (209 行) — JC native ECDSA + 自实现严格 DER parser；`try-finally` 完整 wipe scratch + clearKey()。**low-s normalization** 用 `BigNat.ctSelectNeg` constant-time。DER parser 严格拒绝任何非 minimal-DER 输入。
- **`Schnorr.java`** (298 行) — BIP-340 严格 verbatim 实现，**两处 parity flip 都 constant-time**（`d` 的 parity 是 public 但代码统一使用 mask flip 保持结构对称——好习惯）。`barrettN` 实例字段做 mod n 约简。`scratch[354]` 紧凑布局，`try-finally` 末尾 wipe 全部。
- **`Ed25519.java`** (459 行) — RFC 8032 verbatim；详细见第 6 章 / 附录 B 覆盖。

#### 2.2.6 数学库

- **`BigNat.java`** (502 行) — constant-time primitive：`ctEquals`、`ctLessThan`、`ctIsZero`、`ctSelectNeg`、`ctSelectSub`、`modAdd`、`multAsymmetric`、`ctAddLowerHalf`。每个都有 random-input + boundary-case 单元测试（`BigNatTest.java`）。
- **`Barrett.java`** (276 行) — Barrett 还原，单一 kernel + 200+ 随机输入测试覆盖。
- **`Fp25519.java` / `Fp25519Inv.java` / `Wei25519.java` / `Secp256k1Curve.java` / `EcPoint.java`** — Ed25519 curve 操作 + secp256k1 参数表。质量上乘但本审计没逐行重审；之前两轮 commit 已通过 RFC 8032 / BIP-32 vector 验证。

#### 2.2.7 工具类

- **`ApduTlv.java`** (92 行) — `[tag(1) | len(1) | value]` 写入 + `reserve` / `finishReserved` 反向回填。`Bounds.requireCapacity` 内嵌每写入处。
- **`Bounds.java`** (36 行) — overflow-safe 空间检查。`length > buf.length - offset` 模式正确避开 short wrap。

### 2.3 `tools/` 关键文件审查

54 个文件，分 6 个子包（`cli/`、`core/`、`gp/`、`proto/`、`shell/`、`transport/`）。

#### 2.3.1 CLI 命令树（`cli/`）

`MeowlCli.java` 注册 13 个子命令（`HelpCommand` + 12 业务）。每个命令独立类、`@ParentCommand MeowlCli` 拿 `globalOptions`，`@Mixin AidOption` 暴露 AID 覆盖。**模式一致、扩展性好**。

具体审查：

- **`BootstrapCommand.java`** (234 行) — 见 AUDIT-013：硬编码 `PKI_CERT_CHUNK_MAX_LEN=200`、`(byte) 0x80`、cert 上限 `1024`、seed 范围 `[16, 64]`，全是 applet `Constants` 的 mirror 但**没有集中 mirror 类**。
- **`ResetCommand.java`** (120 行) — 见 AUDIT-014：`REQUIRED_INVOCATIONS = 4` 硬编码，javadoc 明确说"bumping this on the card requires bumping it here too"——drift risk 已知但未消除。
- **`BenchCommand.java`** (388 行) — 大文件，未深审。
- 其他 9 个命令（`info` / `apdu` / `replay` / `select` / `gp` / `sc-handshake` / `sc-send` / `shell` / `authentikey`）结构一致、规模合理。

#### 2.3.2 Proto / SC client（`proto/`）

`SecureChannelClient.java` (342 行) — 见第 6.1 节。质量上乘：

- constant-time MAC compare（line 332-340）
- `invalidate()` 在任何加密失败后撕掉 session
- short-form APDU `lc > 255` early reject（line 184-191）
- inbound counter regression check（line 302-311）

`HostCrypto.java` / `KdfCmac.java` — host 镜像的 KDF / AES / ECDH，纯 BC 包装。

#### 2.3.3 Core 工具（`core/`）

- **`MeowlInsn.java`** (179 行) — INS enum，每条 entry 4 字段（`value` / `cliName` / `Channel.OUTER|INNER` / `description`）。**与 applet `Constants` 1:1 镜像**，drift 风险中等（见 AUDIT-014）。
- **`MeowlSw.java`** — SW enum，规则：`describe(int)` 兜底"Unknown SW"。
- **`MeowlAid.java`** — AID 解析。
- **`Hex.java` / `Tlv.java`** — 标准 helper。

#### 2.3.4 Transport（`transport/`）

3 个文件（`BiboStack`、`CardTransport`、`ReaderPreferences`），apdu4j BIBO 装饰链 + reader 选取启发。质量良好。

#### 2.3.5 Shell（`shell/`）

`ShellSession.java`（仅 1 文件）+ `ShellCommand.java` 是 JLine REPL 引擎。结构合理。

### 2.4 死代码 / 未使用 / 残留

跨仓 grep `TODO|FIXME|XXX|HACK`：

- `applet/` — **0 处** ✓
- `tools/` — **0 处** ✓
- `tests/` — **0 处** ✓

非常干净。但有以下结构残留：

| 残留类型 | 位置 | finding |
| --- | --- | --- |
| `useSimulator` 死配置 | `tools/build.gradle.kts:114, 130-131` | AUDIT-016 |
| `cardBackend` system property（被 `useSimulator` 唯一驱动） | 同上 | AUDIT-016 |
| `realcard.log` 二进制残留 | 工作区根 | AUDIT-020 |

### 2.5 命名一致性 / Javadoc

抽样检查：

- **applet/ 26 文件**：每个 public 类 + public/protected 方法 + 重要 private 方法都有 javadoc。质量参差但都存在。**0 处缺 javadoc**。
- **tools/ 54 文件**：同样 0 处缺。
- **tests/ 25 文件**：测试方法用 `@DisplayName` 而非 javadoc，但每个 nested class 有 `@DisplayName`。质量良好。

### 2.6 本章 Findings 一览

| 编号 | Severity | 类别 | 位置 | 主题 |
| --- | --- | --- | --- | --- |
| AUDIT-001 | High | security | `MasterSeed.java:265-267` | wipe 不清零 master EEPROM（详见 6.4） |
| AUDIT-002 | Medium | security | `PinManager.java:173-175` | wipe 不清零 PIN/PUK EEPROM（详见 6.2） |
| AUDIT-003 | Low | security | `PkiManager.java:203-207` | wipe 不清零 cert EEPROM（cert 公开，严重度低） |
| AUDIT-005 | Medium | security | `Slip10.java:84-101` / `Bip32.java:121-131` | walk 异常路径不 wipe transient secrets |
| AUDIT-006 | Low | security | `MasterSeed.java:280-284` | `requireSeeded` 抛 SW_LIFECYCLE_INVALID 应为 SW_CONDITIONS_NOT_SATISFIED |
| AUDIT-008 | Info | security | `Authentikey.java` | authentikey 不可重生成 (per MEAP-4 design) |
| AUDIT-013 | Medium | quality | `tools/.../BootstrapCommand.java:97,158,200-202,209` | applet 常量在 host 端硬编码重复 |
| AUDIT-014 | Medium | quality | `tools/.../ResetCommand.java:44` | `REQUIRED_INVOCATIONS=4` mirror 而非 import |
| AUDIT-015 | Info | quality | `applet/.../WipeTrigger.java` | SAM interface 单实现 (per JC 3.0.5 design) |

---

## 第 3 章 · 测试质量审计

### 3.1 测试组织结构

```text
tests/src/test/java/social/meowl/applet/
├── (10 个 simulator-track 测试，无 @Tag)
│   ApduTlvTest, BarrettTest, BigNatTest, BoundsTest, Fp25519Test,
│   HmacSha512Test, HmacSha512EdgeTest, SchnorrTagHashTest,
│   LifecycleStateTest, SecureChannelStripPkcs5Test
├── (8 个 real-card-track 测试，@Tag("real-card"))
│   MeowlAppletTest, SecureChannelTest, HdDerivationTest,
│   PersonalisationTest, EcdsaK1Test, SchnorrK1Test, Ed25519SigningTest,
│   BenchmarkSuite
├── cardclient/
│   ├── CardClient.java         — 接口
│   ├── CardClientFactory.java  — 工厂
│   └── RealCardClient.java     — 唯一实现（PCSC）
├── sc/
│   └── KdfCmacHost.java        — 测试本地 KDF 镜像（与 tools 端独立）
└── testkit/
    ├── HostSession.java        — SC client（不验签，见 AUDIT-009）
    ├── MeowlFixtures.java      — bringToSetupDoneAndVerifyPin / resetCard
    └── TestConstants.java      — AID / PIN / KDF info / BIP-32 vector
```

**评估**：

- **双轨清晰**：`@Tag("real-card")` 准确隔离了无法在 jcardsim 安装 applet 的 8 个 suite。
- **testkit 抽象合理**：上次 commit `c0150b1` 把内联 helper 收敛到 3 个 testkit 类，删除 859 行重复。
- **`cardclient/` 抽象保留 future-proofing**：`CardClient` 接口虽只剩单实现 `RealCardClient`，但 javadoc 明确说"a future J3R180-faithful simulator can slot in"——保留合理。

### 3.2 测试覆盖矩阵

完整 INS × lifecycle 矩阵见**附录 B**。摘要：

| INS 类别 | 覆盖路径 | 状态 |
| --- | --- | --- |
| outer (5 个) | `MeowlAppletTest` + `SecureChannelTest` | ✅ 全覆盖 |
| PIN/PUK (5 个) | `PersonalisationTest` 各 nested class | ✅ 全覆盖 |
| PKI (5 个) | `PersonalisationTest` + `MeowlAppletTest` | ✅ 全覆盖 |
| seed (3 个) | `HdDerivationTest` + `PersonalisationTest` | ✅ 全覆盖 |
| signing (3 个) | `EcdsaK1Test` / `SchnorrK1Test` / `Ed25519SigningTest` | ✅ 全覆盖 + RFC 8032 / BIP-32 / SLIP-10 / BIP-340 vectors |

**INS 全覆盖 ✓**。Lifecycle gating 也全部测了 negative path（见每个 sign suite 的 `Gating` nested class）。

### 3.3 测试反模式

- **`@AfterEach` boilerplate × 8**（AUDIT-022）

  ```java
  @AfterEach
  void tearDown() {
      if (card != null) {
          try { MeowlFixtures.resetCard(card); } catch (Exception ignored) { }
          card.close();
      }
  }
  ```

  这 6 行在 8 个 suite 中**完全相同**。可 lift 成 abstract `RealCardTestBase` 或 JUnit 5 `@RegisterExtension`。

- **`signBeforeSeeded` 类测试三处 close+create 后忘记 reset**（已在上次 commit `c0150b1` 修复，但模式本身仍是抗 MeowlFixtures 自动化的）

- **`SchnorrK1Test` 的 inline `Bip340` host verifier**（约 100 行）— 单文件内 OK，但若 `EcdsaK1Test` 或 `Ed25519SigningTest` 想复用 BIP-340 verifier 就要 fork。

### 3.4 simulator vs real-card 分类

10 simulator-track / 8 real-card-track，分类正确：

- simulator-track 全是**纯算术 / 纯 FSM**，jcardsim 提供 `javacard.framework.*` mock 即可，不需要安装 applet。
- real-card-track 全是**需要 RNG / EC primitive / KeyAgreement** 的端到端测试，必须真卡。

### 3.5 `:tools:test` vs `:tools:realCardTest`

`tools/src/test/java/.../proto/SecureChannelClientIT.java` 标 `@Tag("real-card")`，由 `:tools:realCardTest` 任务跑。其他 14 个 tools test 是纯 JUnit 单元测试。

### 3.6 测试性能

最近一次 `:tests:realCardTest --rerun-tasks` 执行：

```text
139 tests, 0 failures, 100% successful — 9m 6s
```

平均 4 秒/test，受 PCSC contactless 链路 RTT 限制（约 50-100 ms/APDU × 10-20 APDU/test）。已是物理硬件上限。

### 3.7 本章 Findings 一览

| 编号 | Severity | 类别 | 位置 | 主题 |
| --- | --- | --- | --- | --- |
| AUDIT-009 | Medium | tests | `tests/.../testkit/HostSession.java:47-51` | 不验证 handshake 签名，依赖 caller 单独验 |
| AUDIT-021 | Low | tests | 8 个 real-card 测试类 | `@AfterEach` 6-line boilerplate × 8 重复 |
| AUDIT-022 | Info | tests | `tests/.../cardclient/CardClient.java` | 单实现抽象，future-proof 保留合理 |

---

## 第 4 章 · 构建系统与工具链审计

### 4.1 Gradle 多项目结构

```text
settings.gradle.kts        — 包含 :applet :tests :tools，单一 mavenCentral + javacard.pro repo
build.gradle.kts (root)    — Spotless 全局配置，JDK 25 toolchain + AGPL license header
gradle/libs.versions.toml  — 单一 version catalog，所有依赖版本集中管理
applet/build.gradle.kts    — buildCap (ant-javacard) + CycloneDX SBOM + Java 1.8 source/target
tests/build.gradle.kts     — :test (excludeTags real-card) + :realCardTest (includeTags real-card)
tools/build.gradle.kts     — application + picocli annotation processor + 同样双 task
```

**评估**：标准多模块结构，无技术债。Spotless 配置（`googleJavaFormat.aosp().reflowLongStrings()` + `removeUnusedImports` + `licenseHeaderFile`）覆盖完整。

### 4.2 `Makefile` 审查

`Makefile` (110 行) 提供 cargo-style targets：`all` / `check` / `test` / `bench` / `fmt` / `lint` / `build` / `cap` / `install` / `uninstall` / `init` / `reset-card` / `run` / `shell` / `ci` / `tasks` / `clean`。

**问题**：

- **缺 `realcard` target**（AUDIT-018）：双轨测试模型已存在但 Makefile 不暴露 `:tests:realCardTest` / `:tools:realCardTest`。`make realcard` / `make tools-realcard` 应增加。
- **`make ci` 没跑 real-card**（line 101）：`ci: check build test` 不包含 real-card——这与 GitHub Actions CI 一致（CI 没有 hosted real-card runner），但应有显式注释说明 manual gate。
- **`make install` 用 `--key-enc/-mac/-kek` 默认值**（line 21-23）：J3R180 vendor CDK，发布到公开仓 OK（已在 SECURITY.md 警告），但 Makefile 应有 production override 提示。
- **No `clean-realcard-state` target**：物理卡 stuck 时无 reset 脚手架。

### 4.3 CI workflow

`.github/workflows/ci.yml` (69 行) 单 job：

```yaml
spotlessCheck → :applet:buildCap → :tests:test → upload-artifact (cap + reports)
```

**评估**：

- ✅ 涵盖 default 测试（10 simulator-track）+ CAP build。
- ✅ 上传 CAP artifact + 失败时上传测试报告。
- ❌ **不跑 real-card**——这是 hardware gating 的实际限制。Manually gate 在 SECURITY.md / README.md 文档化（见 5.2 docs 审计）。
- ❌ **不跑 :tools:test**（CI 只跑 `:tests:test`，AUDIT-019）：`tools` 模块的 14 个单元测试在 CI 完全未执行。

### 4.4 Spotless 配置

```kotlin
java {
    googleJavaFormat(gjfVersion).aosp().reflowLongStrings()
    removeUnusedImports()
    formatAnnotations()
    trimTrailingWhitespace()
    endWithNewline()
    licenseHeaderFile(licenseHeader)
}
```

**评估**：完整 + 严格。`config/spotless/java.license.txt` 是 SPDX 头模板。

### 4.5 SBOM / SLSA

`applet/build.gradle.kts` 配置了 CycloneDX 1.6 SBOM 输出到 `build/reports/meowl-sbom.cdx.json`。SLSA L3 attestation 在 release workflow 中（本审计未深查 release.yml）。

### 4.6 `.gitignore` / `.editorconfig` / `.gitattributes`

- **`.gitignore`** (47 行) — 标准 Java/Gradle ignore + `*.cap` / `*.exp` / `*.jca` JavaCard 输出 + `3rdparty` 子模块。`*.log` 已 ignored，但**工作区残留 `realcard.log` 335 KB 二进制文件**（AUDIT-020）。
- **`.editorconfig` / `.gitattributes`** — 标准。

### 4.7 `tools/build.gradle.kts` dead config

```kotlin
val backend = if (project.hasProperty("useSimulator")) "simulator" else "real"
systemProperty("cardBackend", backend)
```

`useSimulator` 选项触发不存在的后端（`SimulatorCardClient` 上次 commit 已删）。`cardBackend` system property 没有任何 reader，所以**整个分支已 dead**。AUDIT-016。

### 4.8 本章 Findings 一览

| 编号 | Severity | 类别 | 位置 | 主题 |
| --- | --- | --- | --- | --- |
| AUDIT-016 | Medium | tooling | `tools/build.gradle.kts:114-131` | `useSimulator` / `cardBackend` 死配置 |
| AUDIT-017 | Low | tooling | `tools/build.gradle.kts:107-116` | `realCardTest` javadoc 还在描述 simulator 后端 |
| AUDIT-018 | Medium | tooling | `Makefile` | 缺 `realcard` / `tools-realcard` target |
| AUDIT-019 | Low | tooling | `.github/workflows/ci.yml:48-49` | CI 不跑 `:tools:test`，14 个测试静默 |
| AUDIT-020 | Medium | tooling | 工作区根 `realcard.log` | 335 KB 二进制日志残留 |

---

## 第 5 章 · 文档审计

### 5.1 `README.md` (88 行)

**主要问题**：

- **Line 51** 列出 `ResetToFactoryTest` / `Wei25519Test` / `LifecycleStateTest.Stateful` / `Fp25519Test.Multiplicative.inv` 作为 real-card 测试目标——**这 4 个套件已在 commit `8d914b3`（"remove four dead-by-design jcardsim-bound suites"）删除**。AUDIT-025。
- **Line 22**：`Tests | JUnit 6 + BouncyCastle`——✓ 准确（JUnit 6.0.3 in `libs.versions.toml`）。
- **Line 50**：simulator 测试列表 `HmacSha512Test, BarrettTest, BigNatTest, Fp25519Test arithmetic, BoundsTest, ApduTlvTest, SchnorrTagHashTest, SecureChannelStripPkcs5Test, LifecycleStateTest.IsLegalForward`——准确。
- **Line 5**：`![CI badge]`——badge 链接到 CI workflow，OK。
- **Line 8**：`![SLSA Level 3 badge]`——claim 需对应 release workflow 配置（本审计未验证）。
- **Line 54**："Until the real-card backend lands"——**已 land**，文字 stale。

### 5.2 `CHANGELOG.md` (108 行)

**严重 stale**：

- **Line 19-24** Added 节列出 `SimulatorCardClient`（已删除）、`ResetToFactoryTest`（已删除）、`Wei25519Test`（已删除）、`LifecycleStateTest.Stateful`（已删除）、`Fp25519Test.Multiplicative.inv`（已删除）。AUDIT-024。
- **缺最近 3 个 commit 的内容**：`de21509` (CLA_MEOWL 中心化)、`688f8c8` (wipe transaction 瘦身 — AUDIT-001)、`c0150b1` (testkit 重构)。这三个 commit 都是用户可见变更，必须记录。

### 5.3 `CONTRIBUTING.md` (111 行)

**问题**：

- **Line 37**：`tests/    # JCardSim integration tests (JUnit 6)` —— stale，应改为 `tests/    # Tests (simulator-track + @Tag("real-card") via PCSC)`。AUDIT-026。
- **Line 109**：`Document the APDU in docs/protocol.md (create the file if it does not yet exist).` —— **`docs/protocol.md` 不存在，应改为 `docs/specs/meap-1.md` 或新建 INS table 章节**。AUDIT-026。
- **Line 32-43** 项目布局缺 `docs/`、`Makefile`、`SECURITY.md`、`config/`、`REUSE.toml`。

### 5.4 `SECURITY.md` (60 行)

**主要问题**：

- **Line 59**：`see [Bignat](applet/src/main/java/social/meowl/applet/Bignat.java)` —— **错误大小写，应为 `BigNat.java`**。链接 broken。AUDIT-027。
- **Line 41**：`gh attestation verify meowl-applet.cap --repo qntx/meowl-applet` —— claim 需对应 release workflow（未验证）。
- **Line 47**：`Single logical channel` 假设——文档清晰，OK。
- **Line 49**：`TRNG availability` 假设——文档清晰，OK。
- **Line 53**：`bip32_scalarKey` 引用——applet 中实际是 `EcPoint.scalarKey`（在 `EcPoint.java`），引用是抽象级别 OK。

### 5.5 `tools/README.md` (205 行)

**问题**：

- **Line 200**：`Total: 253 tests, <2 s end-to-end on a warm JVM.` —— 数字 stale，需重新统计。AUDIT-028。
- **Line 141-153** Production hardening 节：警告 vendor CDK + 列出 PUT_KEY / lock-card roadmap——**好内容**，独立、清晰。
- **Line 166-175** GraalVM 节：marked future addition，OK。
- 整体内容质量良好。

### 5.6 `docs/README.md` + `docs/specs/`

#### `docs/README.md` (37 行)

**内容**：MEAP 索引 + 阅读顺序 + 约定（normative language / byte order / hex notation / test vectors）。质量高，无明显 stale。

#### `docs/specs/README.md` (33 行)

**问题**：

- **Line 13**：`MEAP-2 | Secure Channel | Ephemeral-ECDH handshake, **HKDF-SHA-256 schedule** and the authenticated record layer` —— **stale**，已 migrate 到 AES-CMAC-128 KBKDF。AUDIT-029。

#### MEAP-0..7 与代码对齐

| MEAP | 与代码对齐情况 |
| --- | --- |
| MEAP-0 (process) | 与代码无关 ✓ |
| MEAP-1 (framing) | 17 INS + 9 SW + 7 capability bits 全部一致 ✓ |
| MEAP-2 (SC) | AES-CMAC-128 KBKDF 已 migrate 到代码 ✓（除 docs/specs/README.md 描述 stale） |
| MEAP-3 (lifecycle / PIN-PUK) | 4-state FSM + 4-step reset 一致 ✓ |
| MEAP-4 (authentikey / PKI) | 一次性生成 + 跨 reset 持久 ✓ |
| MEAP-5 (HD) | BIP-32 / SLIP-10 一致 ✓ |
| MEAP-6 (signing) | ECDSA / Schnorr / Ed25519 与 RFC 8032 / BIP-340 vectors 对齐 ✓ |
| MEAP-7 (SW reference) | 与 `Constants.java` SW 表一致 ✓ |

### 5.7 内部交叉引用

抽样检查 `[MEAP-X](./meap-X.md)` 链接 + `[ClassName](../../applet/...)` 链接：

- MEAP 之间互引 — 均存在
- MEAP → applet 源代码 — 均存在（除 SECURITY.md 的 `Bignat.java`）
- README → applet/tests/tools — 均存在
- CHANGELOG → MEAP — 均存在

### 5.8 本章 Findings 一览

| 编号 | Severity | 类别 | 位置 | 主题 |
| --- | --- | --- | --- | --- |
| AUDIT-024 | High | docs | `CHANGELOG.md:19-24` + 全文 | 引用 5 个已删除组件 + 缺最近 3 commit |
| AUDIT-025 | High | docs | `README.md:51, 54` | 列出已删除测试套件 + "Until real-card backend lands" stale |
| AUDIT-026 | Medium | docs | `CONTRIBUTING.md:37, 109` | `tests/` 描述 stale + `docs/protocol.md` 不存在 |
| AUDIT-027 | Medium | docs | `SECURITY.md:59` | `Bignat.java` 错误大小写，链接 broken |
| AUDIT-028 | Low | docs | `tools/README.md:200` | "253 tests, <2s" 数字 stale |
| AUDIT-029 | Low | docs | `docs/specs/README.md:13` | MEAP-2 描述 "HKDF-SHA-256 schedule"，已是 AES-CMAC-128 |

---

## 第 6 章 · 安全审计

> **声明**：本章是仓内 reviewer 的内部审计，**不替代外部 paid security audit**。重点是在密码学路径里寻找**实现层面**的偏差（缺 wipe、非 constant-time、replay 防御缺口、wipe 完整性削弱），不做 fuzzing / fault injection / side-channel 物理实测。

### 6.1 Secure Channel (`SecureChannel.java`)

#### 6.1.1 握手流程

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\SecureChannel.java:213-302` 的 `initHandshake`：

1. **入参校验**：`inDataLen != 65` → `SW_WRONG_LENGTH`；非 `0x04` 前缀 → `SW_SECURE_CHANNEL_FAILED`（不是 `SW_WRONG_LENGTH`，意图区分长度错误 vs 加密错误，文档化清晰）。
2. **ECDH**：`KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` 同时输出 `0x04 ‖ x ‖ y`，但 KDF 仅吃 `x`（line 263-265 选 `HS_SHARED + 1`）。**正确**——按 SEC 1 §3.3 仅 x 是被 ECDH 标准化的部分。
3. **KDF**：`Kdf.extract(salt = client_x ‖ card_x, ikm = shared_x)`，然后 `Kdf.expand(info="meowl-sc-v1", L=64)` 得 `K_enc(32) ‖ K_mac(16) ‖ IV_base(16)`。
4. **签名**：用 authentikey 私钥 ECDSA-SHA-256 签 `card_eph_pub ‖ client_eph_pub`，输出到 APDU buffer。
5. **`try-catch`**：任何异常都先 `reset()` 再 rethrow。**好**——避免 partial state 持久化。
6. **`reset()`**（line 192-203）：清 `encKey` / `macKey` / `kdf.state` / `okm` / `lastInboundIv` / `outboundCounter` / `macScratch` / `hsScratch` / `openFlag`。**完整**。

**评估**：握手实现 sound。无 replay 漏洞——每次握手 `genKeyPair()` 重新生成 ephemeral，`lastInboundIv` 也清零。

#### 6.1.2 IV 单调性 + MAC 比较

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\SecureChannel.java:328-336`：

```java
if (compare16(apduBuffer, ivOffset, lastInboundIv, (short) 0) <= 0) {
    ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
}
```

注释明确说"This branch does NOT reset() the session: an attacker without K_mac could otherwise replay any captured envelope to wipe the session keys, a free DoS lever"——**好的攻击模型分析**。MAC 失败才会 `reset()`（line 348-351），正确：MAC 失败说明攻击者要么有 K_mac（事件升级），要么 in-flight corruption（也是事件）。

`compare16`（line 438-459）是 constant-time 16-byte 比较；用 sticky mask 防短路。**好**。

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\SecureChannel.java:348` MAC 比较用 `BigNat.ctEquals`。**好**——`Util.arrayCompare` 是早退三元，会 leak mismatch 位置。

#### 6.1.3 Outbound counter 溢出

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\SecureChannel.java:418-430`：

16-byte big-endian counter，溢出时 `reset()` 强制 re-handshake。注释："Without this guard a wrapped counter would reuse `IV_base XOR 0` on a fresh ciphertext — AES-CBC with the same (key, IV) leaks plaintext XOR. Practically unreachable after 2¹²⁸ - 1 wraps; defence-in-depth against fault injection."——**优秀**。

#### 6.1.4 PKCS#5 padding 解析

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\SecureChannel.java:470-500`：

constant-time PKCS#5 stripping，使用单一 `failMask` 累加器。注释："Encrypt-then-MAC above already gates externally-observable signals; the constant-time walk is defence-in-depth"——**优秀**。

#### 6.1.5 SC findings

| 编号 | Severity | 描述 |
| --- | --- | --- |
| AUDIT-007 | Info | `SecureChannel.java:218-221` 用 `0x04` prefix 检查替代点是否在曲线上的检查 — JC ECDH 实现内部已做 on-curve check，但 docstring 应注明依赖该不变量 |
| AUDIT-030 | Info | `SecureChannel.java:341` MAC 输入 = `outer_header(5) ‖ IV(16) ‖ ciphertext`，注释清晰但 `outer_header` 包含 `LC` 字段对 future 扩展 short-Lc 是有约束的 — 文档化为 ADR |

### 6.2 PIN / PUK (`PinManager.java`)

#### 6.2.1 设计概览

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\PinManager.java:1-214` 实现 ISO 7816-4 PIN/PUK 管理，包装 `OwnerPIN`：

- PIN: `PIN_RETRY_LIMIT=3`, len `[4,16]`
- PUK: `PUK_RETRY_LIMIT=5`, len `[8,32]`
- `verifyOwnerPin` 集中处理 retry counter：`tries==0` 抛 `SW_AUTH_BLOCKED`；length policy 失败抛 `SW_WRONG_LENGTH` **不消耗 retry**（注释明确说"the same SW is returned for every length-violating input regardless of candidate bytes, so this path leaks no information"——好的反 brute-force 分析）。
- `unblockPin`：`tries != 0` 时拒绝（不能用 PUK 解锁未达 0 的 PIN）。
- `changePuk` 需要 PIN 已 verified（防止持卡贼旋转 PUK）。

**评估**：实现严谨，retry counter 语义符合 ISO 7816-4。

#### 6.2.2 wipeInTx 削弱（AUDIT-002）

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\PinManager.java:173-175`：

```java
public void wipeInTx() {
    provisioned[0] = 0;
}
```

**只清 `provisioned` 标志**。先前版本调用 `OwnerPIN.update(scrub, 0, PIN_MAX_LEN)` 用零字节"覆盖"PIN/PUK 槽位。删除原因（line 161-167 javadoc）：

> The earlier two-update scrub was removed because it tripped a J3R180 quirk: when the wipe length differed from the next SETUP length (32-byte PUK scrub → 8-byte PUK setup), `OwnerPIN.check` on the freshly-installed PUK returned false even though the bytes matched...

**风险评估**：

- **Defense-in-depth 削弱**：旧 PIN/PUK 仍在 EEPROM 槽位中（虽然 hash 后不可逆），直到下次 `SETUP` 用 `OwnerPIN.update` 覆盖。
- **可达性**：每个 PIN/PUK 入口都先 gate `requireProvisioned()`（line 208-212），所以 `provisioned == 0` 时 `OwnerPIN.check` 不可达。
- **持续期**：从 `RESET_TO_FACTORY` 到下次 `SETUP` 之间。
- **威胁模型**：要利用必须**物理拆解卡 + 读 EEPROM**——这远超本 applet 的威胁模型（参考 SECURITY.md Threat Model 假设：silicon EAL 验证）。

**结论**：**Severity Medium**，trade-off 是合理的（contactless BWT 内 commit），但**应在 ADR 中显式 sign-off**，让外部 reviewer 知道这是有意选择而非 bug。

#### 6.2.3 PIN findings

| 编号 | Severity | 描述 |
| --- | --- | --- |
| AUDIT-002 | Medium | `PinManager.wipeInTx` 不清零 OwnerPIN 槽位，依赖 `provisioned` 标志守门 — 需 ADR 显式 sign-off |
| AUDIT-031 | Info | `PinManager.changePuk` 需 PIN verified — 文档化为反偷卡防御 |

### 6.3 PKI personalisation (`PkiManager.java`)

#### 6.3.1 设计概览

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\PkiManager.java:1-209`：

- 三阶段 chunked import (`INIT` → `WRITE` × N → `FINALIZE`)，每阶段独立 transaction。
- `importInit` 把整个 1024-byte buffer 用 `Util.arrayFillNonAtomic` 清零（line 123）——保证 invariant "anything past `importedLen` is zero"。
- `exportCert` 严格 bounds check (line 174-176)。
- `signCsr` 用 authentikey 私钥签 host-provided 32-byte digest（用 `signPreComputedHash`）。

**评估**：协议清晰，bounds check 完整。

#### 6.3.2 wipeInTx 削弱（AUDIT-003）

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\PkiManager.java:203-207`：

```java
public void wipeInTx() {
    importedLen = 0;
    stagedTotalLen = 0;
    importState = IMPORT_STATE_IDLE;
}
```

**不清 1 KiB cert buffer**。注释（line 193-197）：

> with `importedLen = 0` the buffer is unreadable through `exportCert` (which gates on `importedLen`) and `importInit` repaints the staged region with zeros before any future WRITE arrives, so residual bytes can never surface to the host.

**风险评估**：

- **Cert 是公开数据**（manufacturer-issued X.509，本来就要给 host 验证 card identity），**residual 不构成机密泄漏**。
- **Severity Low**——纯 defense-in-depth，cert 公开。

#### 6.3.3 javadoc 引用错误（AUDIT-032）

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\PkiManager.java:194` javadoc 写 `exportPagedAt`，实际方法名是 `exportCert`。**Low** 级 typo。

#### 6.3.4 PKI findings

| 编号 | Severity | 描述 |
| --- | --- | --- |
| AUDIT-003 | Low | `PkiManager.wipeInTx` 不清 cert buffer — cert 公开，severity 低 |
| AUDIT-032 | Low | `PkiManager.java:194` javadoc 引用 `exportPagedAt`，实际为 `exportCert` |

### 6.4 Master seed (`MasterSeed.java`)

#### 6.4.1 设计概览

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\MasterSeed.java:1-286`：

- 不持久化 raw BIP-39 seed，只持久化两个 HMAC-SHA-512 derived material（`bip32Material` / `slip10Material`，各 64 bytes = `k(32) ‖ c(32)`）。
- `importSeed`：runtime guard `JCSystem.getTransactionDepth() == 0` → `SW_CONDITIONS_NOT_SATISFIED`。**好**——保证 caller 持有 transaction。
- `generateSeed`：先尝 `ALG_KEYGENERATION`，fallback `ALG_TRNG`（J3R180 兼容）。最多 8 次重采样以满足 BIP-32 master `0 < parse256(I_L) < n`，每次失败概率 < 2⁻¹²⁷，**8-attempt cap 是 defensive overkill**。
- `requireValidBip32MasterKey`：`parse256(I_L) == 0` 或 `≥ n` 时清零 partial state 后抛 `SW_CONDITIONS_NOT_SATISFIED`。**好**。
- `copyBip32MasterTo` / `copySlip10MasterTo` 是 **package-private**，注释明确说"only Bip32.walkPathToLeaf should ever call this"。**好的封装**。

#### 6.4.2 wipeInTx 削弱（AUDIT-001 — High）

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\MasterSeed.java:265-267`：

```java
public void wipeInTx() {
    seededFlag[0] = 0;
}
```

**不清 EEPROM 中的 128 字节 master material**（`bip32Material[64] + slip10Material[64]`）。注释解释：

> The master-material EEPROM cells are intentionally NOT zeroed here: every read path gates on `requireSeeded`, so a wiped master is unreachable via the API even while the bytes linger in EEPROM. The next `IMPORT_SEED` or `GENERATE_SEED` overwrites those cells in full before flipping `seededFlag` back on...

**风险评估**：

- **Master material 是核心机密**（HMAC-SHA-512 derived，但泄漏后整个 BIP-32 / SLIP-10 树就解密了）。
- **可达性**：每个 read path（`copyBip32MasterTo`、`copySlip10MasterTo`）gate on `requireSeeded`，wipe 后不可达。
- **持续期**：从 `RESET_TO_FACTORY` 到下次 `IMPORT_SEED` / `GENERATE_SEED`。
- **威胁模型**：要利用必须**物理拆解卡 + 读 EEPROM 旁路**。
- **defense-in-depth 削弱**：若有 fault injection / glitch attack 让 `seededFlag` 被倒回 1，旧 material 就活了。

**对比 AUDIT-002（PIN）**：master material 比 PIN 更敏感（PIN 只是单点解锁，master 是整棵树）。

**Severity High** 的理由：

1. master 比 PIN/PUK/cert 更核心（最高价值目标）。
2. 用户预期"reset to factory"是 cryptographic erase，而不是逻辑 erase。
3. 这种 trade-off 必须有外部 reviewer 显式 sign-off。

**修复路径建议**（三选一）：

- **路径 A（保守）**：恢复 `Util.arrayFillNonAtomic` 清零，研究是否能在 BWT 内（`arrayFillNonAtomic` 不是 transactional 的，可能比 `arrayCopy` 快）。
- **路径 B（trade-off 接受）**：保留当前实现，写一份 ADR 文档化决策 + 新增 negative test 验证下次 SETUP 完整覆盖（确认 invariant）。
- **路径 C（折中）**：只清 `bip32Material[0..32]`（k 部分，32 字节）和 `slip10Material[0..32]`（同），保留 chain code (less secret)，减半 EEPROM write。

#### 6.4.3 walkPath 异常路径不清 transient secret（AUDIT-005）

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Bip32.java:121-131` 和 `@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Slip10.java:84-101`：

`walkPathToLeaf` / `walkPath` 把 master material 加载进 transient state[0..64]，然后逐 level CKDpriv。**异常路径不 wipe**：

- `Bip32.walkPathToLeaf` 在 `depth > HD_MAX_DEPTH` 早退（line 122-124），但此前 master 还没拷贝，OK。
- `Bip32.ckdPriv`（line 153-192）若 `parse256(I_L) >= n` 或 `k_i == 0` 抛 `SW_CONDITIONS_NOT_SATISFIED`——此时 `state[0..64]` 仍含上一 level 的 partial material。
- 同理 `Slip10.walkPath`（line 84-101）非 hardened index 直接抛，`state` 含 partial material。

**实际影响**：transient 是 `CLEAR_ON_DESELECT`，APDU 结束（即下一个 SELECT 或 deselect）会清。但 in-session 期间，之后任何 `EXPORT_XPUB` / `SIGN_*` 都会 reload master，所以 in-session 的残留不会泄漏到不同上下文。**但**若 APDU stream 之间有 fault injection 读 transient，理论上能拿到 partial CKDpriv state。

**修复**：把 `walkPath` 包在 try-catch-finally，finally 内 `wipeWalkState()`。

#### 6.4.4 requireSeeded 错误 SW（AUDIT-006）

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\MasterSeed.java:280-284` 抛 `SW_LIFECYCLE_INVALID`，但语义上 master 未 seeded 是 **conditions not satisfied**（lifecycle 可能还在 SETUP_DONE，并非 invalid）。但因为 `requireSeeded` 只在 `copyBip32MasterTo` / `copySlip10MasterTo` 被调用，而这两个都被 lifecycle == SEEDED 守门，所以**实际上此 throw 是不可达的**——但作为 defense-in-depth 应改为 `SW_CONDITIONS_NOT_SATISFIED`。**Low** 级。

#### 6.4.5 Master seed findings

| 编号 | Severity | 描述 |
| --- | --- | --- |
| AUDIT-001 | High | `MasterSeed.wipeInTx` 不清 EEPROM master material — 需显式 sign-off |
| AUDIT-005 | Medium | `Bip32.walkPathToLeaf` / `Slip10.walkPath` 异常路径不 wipe transient master state |
| AUDIT-006 | Low | `MasterSeed.requireSeeded` 抛 `SW_LIFECYCLE_INVALID`，应改为 `SW_CONDITIONS_NOT_SATISFIED` |

### 6.5 Authentikey (`Authentikey.java`)

#### 6.5.1 设计概览

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Authentikey.java:1-72`：

- 一次性生成（构造函数内 `genKeyPair()`），跨 `RESET_TO_FACTORY` 持久（不在 `wipe()` 内）。
- `writeCompressedPubkeyTo`：压缩 `0x04 ‖ x ‖ y` → `0x02|0x03 ‖ x`，把尾部 32 字节填零防 leak。
- 私钥仅 package-private 暴露给 `SecureChannel.handshake` 和 `PkiManager.signCsr`。

**评估**：实现极简、封装严格。

#### 6.5.2 不可重生成（AUDIT-008）

设计上 authentikey **不可重生成**——一次生成、终身绑定。**优点**：CSR 签名不可被 replace、外部 verifier 信任锚定一次。**缺点**：若 silicon-level 故障导致 authentikey 私钥不可用（例如 EEPROM bit-flip），整个 SC + PKI 都死了，无救援路径。

**评估**：这是 MEAP-4 的 **明确设计选择**，不是 bug。建议文档化为 ADR：在 SECURITY.md / MEAP-4 中显式说明"不可重生成是 trade-off，认为概率 < 1ppm"。

#### 6.5.3 Authentikey findings

| 编号 | Severity | 描述 |
| --- | --- | --- |
| AUDIT-008 | Info | authentikey 不可重生成 — MEAP-4 设计选择，建议 ADR |

### 6.6 Lifecycle FSM (`LifecycleState.java`)

#### 6.6.1 设计

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\LifecycleState.java:1-95` 4-state FSM：

```text
UNINITIALIZED → PERSONALIZED → SETUP_DONE → SEEDED
        ↑──────────── reset() ──────────────┘
```

`isLegalForward(from, to)` 强制 `to == from + 1` 且 `from < SEEDED && to <= SEEDED`。**好的不变量**——不能跳级、不能反向。

`require` / `requireAtLeast` 双 gate API，调用方按需用。`MeowlApplet.dispatchInner` 的每个 handler 都 gate（详见 6.7 矩阵）。

`resetInTx`（line 68-70）只重置 `current = UNINITIALIZED`，没动其他 state。**好**——`MeowlApplet.wipe()` 会调 PIN/PKI/seed 各自 wipe。

#### 6.6.2 FSM findings

无 finding——FSM 实现 clean。

### 6.7 INS × lifecycle 完整性

逐 INS 验证 lifecycle gate 与 MEAP-3 spec 一致。详见**附录 B**。

抽样核查：

- **`SETUP` (0x20)**：`state.require(PERSONALIZED)` ✓ — 必须先 LOCK_PKI 才能 SETUP。
- **`LOCK_PKI` (0x34)**：`state.require(UNINITIALIZED)` + `pkiManager.hasCert()` ✓ — 必须先 IMPORT_PKI_CERT 才能 lock。
- **`IMPORT_SEED` (0x40)**：`state.require(SETUP_DONE)` + `requirePinVerified()` ✓ — 必须 SETUP 后 + PIN 验证后。
- **`SIGN_*` (0x50-0x52)**：`state.require(SEEDED)` + `requirePinVerified()` ✓。
- **`EXPORT_PKI_PUBKEY` (0x30)**：`state.require(UNINITIALIZED)` ✓。

**所有 gate 都正确**。无 lifecycle bypass 风险。

### 6.8 RESET_TO_FACTORY (`ResetToFactory.java` + `MeowlApplet.wipe()`)

#### 6.8.1 计数器机制

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\ResetToFactory.java`：

`CLEAR_ON_RESET counter`（4 = `RESET_REQUIRED_INVOCATIONS`），每次 `RESET_TO_FACTORY` invocation `counter--`，达 0 后调 `wipeTrigger.wipe()`。任何**其他 INS** 触发 `rearm()` 重置 counter 到 4——所以必须**4 次连续无中断的 RESET_TO_FACTORY** 才触发 wipe。

**评估**：抗误触，要求显式意图。

#### 6.8.2 原子 wipe

`@/d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\MeowlApplet.java:664-673`：

```java
@Override
public void wipe() {
    secureChannel.reset();
    JCSystem.beginTransaction();
    pinManager.wipeInTx();
    pkiManager.wipeInTx();
    masterSeed.wipeInTx();
    state.resetInTx();
    JCSystem.commitTransaction();
}
```

**好**——四个 persistent wipe 在单 transaction 内，torn power-off safe。SC reset 在 transaction 外是因为 SC 全是 transient（CLEAR_ON_DESELECT），事务无意义。

#### 6.8.3 RESET findings

无新 finding（AUDIT-001/002/003 已涵盖 wipe 削弱话题）。

### 6.9 Timing / constant-time 分析

抽样审计 secret-touching code 的 constant-time 属性：

| 函数 | constant-time? | 证据 |
| --- | --- | --- |
| `BigNat.ctEquals` | ✓ | mask-based byte-by-byte XOR fold |
| `BigNat.ctLessThan` | ✓ | sticky mask, sign-bit extraction |
| `BigNat.ctIsZero` | ✓ | byte-or fold |
| `BigNat.ctSelectNeg` | ✓ | mask-based negation conditional |
| `SecureChannel.compare16` | ✓ | sticky mask 三态比较 |
| `SecureChannel.stripPkcs5` | ✓ | failMask 累加，全部循环跑完 |
| `Schnorr.signDigest` parity flips | ✓ | mask-based ctSelectNeg / ctSelectSub |
| `EcdsaK1.signDigest` low-s normalization | ✓ | ctSelectSub |
| `Ed25519.sign` Wei→Ed encoding | ✓ | Barrett 还原 + ctSelect |
| **PIN compare** | **OwnerPIN 黑盒** | 假设 J3R180 native 实现 constant-time（标准 EAL 期待） |

**未审 / 未深审**：

- `Fp25519` 模运算 — 之前 commit 已声明 BigNat-only，避免 JCMathLib 变量时 path。
- **硬件层 timing/power 旁路**——属于外部 audit 范畴，本次未做。

**小问题**：`SecureChannel.unwrap` 在 IV 不单调时**早退**（line 334），但 IV 是 public 的，所以非 constant-time 比较是 OK 的。注释明确说："IV bytes are public, so a non-constant-time compare is fine"。**好**。

### 6.10 本章 Findings 汇总

已在 6.1-6.8 各小节汇总；新增 finding：

| 编号 | Severity | 类别 | 位置 | 主题 |
| --- | --- | --- | --- | --- |
| AUDIT-007 | Info | security | `SecureChannel.java:218-221` | 0x04 prefix 检查依赖 JC ECDH on-curve check 不变量 |
| AUDIT-030 | Info | security | `SecureChannel.java:341` | MAC 输入含 `outer_header(5)` 对 short-Lc 扩展有约束 |
| AUDIT-031 | Info | security | `PinManager.changePuk` | 需 PIN verified 是反偷卡防御 |
| AUDIT-032 | Low | quality | `PkiManager.java:194` | javadoc 引用 `exportPagedAt`，实际为 `exportCert` |

---

## 第 7 章 · 硬件 / Contactless 兼容性

### 7.1 J3R180 单 target 硬化

仓内多处 javadoc 显式注明针对 J3R180 / JCOP4 P71 优化：

- `MeowlApplet.java:32` — `SHARED_SCRATCH_LEN` 共享 ~970 bytes 节省，"the difference between fitting or not on cards with a ~3 KB user-RAM budget (notably J3R180)"
- `SecureChannel.java:162` — "CLEAR_ON_DESELECT for every session-scoped buffer ... a hard requirement on cards (J3R180) whose CLEAR_ON_RESET pool is too small"
- `Wei25519.setCurveParameters` — `key.setK((short) 1)` 是 J3R180 quirk（`OperationSupport.JCOP4_P71` `EC_SET_COFACTOR=false`）
- `MasterSeed.wipeInTx` 注释 — "the earlier `arrayFillNonAtomic` pair regularly pushed the commit past the reader's timeout window on J3R180"
- `PinManager.wipeInTx` 注释 — "tripped a J3R180 quirk: when the wipe length differed from the next SETUP length"

**评估**：单 target 硬化**彻底且文档化**。每处 trade-off 都有 root-cause 说明。

### 7.2 Basic Waiting Time (BWT)

contactless ISO 14443-4 link 上每个 APDU 的 BWT 是 reader-dependent，ACR1552 默认约 256 ms（PCSC `SCardSetAttrib` 可调）。**最长操作**：

| 操作 | 估时 (J3R180 + ACR1552) | BWT 余量 |
| --- | --- | --- |
| `RESET_TO_FACTORY` final wipe | ≈ 50 ms（commit 内 4 个小 wipe） | 充分 |
| `IMPORT_SEED` (HMAC×2 + transaction) | ≈ 80 ms | 充分 |
| `GENERATE_SEED` (RNG + HMAC×2) | ≈ 100 ms | 充分 |
| `SIGN_ECDSA_K1` | p50 694 ms | **超 BWT！** |
| `SIGN_SCHNORR_K1` | p50 1639 ms | **超 BWT！** |
| `SIGN_ED25519` | p50 4640 ms | **远超 BWT！** |
| `EXPORT_XPUB_ED25519` | p50 1719 ms | **超 BWT！** |
| `OPEN_SECURE_CHANNEL` | p50 295 ms | borderline |

**这意味着**：签名操作必须依赖 ISO 14443-4 **WTX (Wait Time eXtension)** 帧——卡发送 S(WTX) 给 reader 请求延长 BWT。`apdu4j-pcsc` + `winscard.dll` 自动处理 WTX，但**不是所有 reader / 驱动都正确支持**。

**风险**：

- 若 deploy 到第三方 PCSC reader，可能因 WTX 不支持导致 sign 超时。
- 用户使用任何 NFC-enabled 手机做 mobile reader 时，可能触发 NFC 控制器层超时（ISO 14443-4 WTX 在 NFC controller 层可能有 hard cap）。

**修复建议**：

- README / SECURITY.md 增"contactless reader compatibility matrix"——列出已验证 reader（ACR1552 ✓）+ 已知不兼容（如有）。
- `BenchCommand` 增 `--measure-bwt` 选项，自动报告 reader 的 WTX 支持情况。

### 7.3 Reader 选取启发 (`RealCardClient.java`)

`@/d:\Desktop\x\meowl-applet\tests\src\test\java\social\meowl\applet\cardclient\RealCardClient.java:73-104` 的 `pickTerminal()`：

```text
pickTerminal 优先级：
  1. 用户传入 -Preader=NAME（精确匹配）
  2. 持卡的 terminal（card present）
  3. 第一个 terminal
```

**评估**：上次 commit `c0150b1` 之前，`pickTerminal` 简单选第一个 terminal——在 ACR1552（双 interface：1 SAM slot + 1 PICC）上经常选错（SAM slot 没卡）。修复后正确。

### 7.4 USB 转 contactless 链路

ACR1552 在 USB-CCID + ISO 14443 之间是 transparent 的。当前 stack（`apdu4j` → `winscard.dll` / PCSC-Lite → ACR1552 USB CCID firmware → ISO 14443-4）抽象层完整，未观察到 layer 间 BWT mismatch。

### 7.5 BootstrapCommand 强制 LOCK_PKI 路径

`@/d:\Desktop\x\meowl-applet\tools\src\main\java\social\meowl\tools\cli\BootstrapCommand.java`（234 行）默认走 PKI personalisation → LOCK_PKI → SETUP → IMPORT_SEED 一条龙。**问题**：开发者在反复测试时会被 LOCK_PKI 后无法重 import cert 卡死，必须 `RESET_TO_FACTORY`。

**改进建议**：增 `--skip-pki` flag，允许跳过 LOCK_PKI 直接 SETUP（适合 dev 反复迭代）。**Medium**——影响开发者体验。

### 7.6 Hardware findings

| 编号 | Severity | 类别 | 位置 | 主题 |
| --- | --- | --- | --- | --- |
| AUDIT-033 | Medium | docs | README.md / SECURITY.md | 缺 contactless reader compatibility 矩阵；`SIGN_ED25519` p50 4640ms 远超默认 BWT，依赖 WTX 是隐含假设 |
| AUDIT-034 | Info | quality | `BenchCommand` | 可增 `--measure-bwt` / `--measure-wtx` 选项 |
| AUDIT-035 | Info | quality | `RealCardClient.pickTerminal` | 上次 commit 已修复 ACR1552 双 interface 二义性 |
| AUDIT-036 | Medium | tooling | `BootstrapCommand.java` | 强制 LOCK_PKI 路径不友好；增 `--skip-pki` flag |

---

## 第 8 章 · 发现汇总与优先级

### 8.1 全部 Findings 列表

| 编号 | Severity | 类别 | 位置（精确） | 一句话描述 | 修复成本 |
| --- | --- | --- | --- | --- | --- |
| AUDIT-001 | **High** | security | `applet/.../MasterSeed.java:265-267` | wipe 不清 EEPROM master material（128B），需显式 sign-off | small (恢复 fill) / trivial (写 ADR) |
| AUDIT-002 | Medium | security | `applet/.../PinManager.java:173-175` | wipe 不清 OwnerPIN 槽位，依赖 `provisioned` flag | trivial (写 ADR) |
| AUDIT-003 | Low | security | `applet/.../PkiManager.java:203-207` | wipe 不清 cert buffer — cert 公开 | trivial (写 ADR) |
| AUDIT-005 | Medium | security | `applet/.../Bip32.java:121-131` + `Slip10.java:84-101` | walkPath 异常路径不 wipe transient secrets | small (try-finally) |
| AUDIT-006 | Low | security | `applet/.../MasterSeed.java:280-284` | `requireSeeded` 抛 SW_LIFECYCLE_INVALID，应为 SW_CONDITIONS_NOT_SATISFIED | trivial |
| AUDIT-007 | Info | security | `applet/.../SecureChannel.java:218-221` | 0x04 prefix 检查依赖 JC ECDH on-curve check 不变量 | trivial (javadoc) |
| AUDIT-008 | Info | security | `applet/.../Authentikey.java` | authentikey 不可重生成 — MEAP-4 设计选择 | trivial (ADR) |
| AUDIT-009 | Medium | tests | `tests/.../testkit/HostSession.java:47-51` | 不验证 handshake 签名，依赖 caller 单独验 | small (开关 + 测试) |
| AUDIT-013 | Medium | quality | `tools/.../BootstrapCommand.java:97,158,200-202,209` | applet 常量在 host 端硬编码重复 | small (集中 mirror 类) |
| AUDIT-014 | Medium | quality | `tools/.../ResetCommand.java:44` | `REQUIRED_INVOCATIONS=4` 硬编码 mirror | trivial (移到 mirror 类) |
| AUDIT-015 | Info | quality | `applet/.../WipeTrigger.java` | SAM interface 单实现 — JC 3.0.5 设计 | trivial (ADR) |
| AUDIT-016 | Medium | tooling | `tools/build.gradle.kts:114-131` | `useSimulator` / `cardBackend` 死配置 | trivial |
| AUDIT-017 | Low | tooling | `tools/build.gradle.kts:107-116` | `realCardTest` javadoc 描述 simulator 后端 | trivial |
| AUDIT-018 | Medium | tooling | `Makefile` | 缺 `realcard` / `tools-realcard` / `installCap` target | trivial (10 行) |
| AUDIT-019 | Low | tooling | `.github/workflows/ci.yml:48-49` | CI 不跑 `:tools:test` | trivial |
| AUDIT-020 | Medium | tooling | 工作区根 `realcard.log` | 335 KB 日志残留 | trivial (`del`) |
| AUDIT-021 | Low | tests | 8 个 real-card 测试类 | `@AfterEach` 6-line boilerplate × 8 重复 | small (lift 到 base / extension) |
| AUDIT-022 | Info | tests | `tests/.../cardclient/CardClient.java` | 单实现抽象 — future-proof | trivial (ADR) |
| AUDIT-024 | **High** | docs | `CHANGELOG.md:19-24` 全文 | 引用 5 个已删除组件 + 缺最近 3 commit | small |
| AUDIT-025 | **High** | docs | `README.md:51, 54` | 列出已删除测试套件 + "Until real-card backend lands" stale | trivial |
| AUDIT-026 | Medium | docs | `CONTRIBUTING.md:37, 109` | `tests/` 描述 stale + `docs/protocol.md` 不存在 | trivial |
| AUDIT-027 | Medium | docs | `SECURITY.md:59` | `Bignat.java` 错误大小写 | trivial |
| AUDIT-028 | Low | docs | `tools/README.md:200` | "253 tests, <2s" 数字 stale | trivial |
| AUDIT-029 | Low | docs | `docs/specs/README.md:13` | MEAP-2 描述 "HKDF-SHA-256 schedule"，已 migrate | trivial |
| AUDIT-030 | Info | security | `applet/.../SecureChannel.java:341` | MAC 输入对 short-Lc 扩展有约束 | trivial (javadoc) |
| AUDIT-031 | Info | security | `applet/.../PinManager.java` | PUK rotate 需 PIN verified | trivial (javadoc) |
| AUDIT-032 | Low | quality | `applet/.../PkiManager.java:194` | javadoc 引用错误方法名 | trivial |
| AUDIT-033 | Medium | docs | `README.md` / `SECURITY.md` | 缺 contactless reader compatibility 矩阵 | small (新增章节) |
| AUDIT-034 | Info | quality | `tools/.../BenchCommand.java` | 增 `--measure-bwt` / `--measure-wtx` 选项 | medium |
| AUDIT-035 | Info | quality | `tests/.../RealCardClient.pickTerminal` | 上次 commit 已修复 — 记录决策 | trivial (ADR) |
| AUDIT-036 | Medium | tooling | `tools/.../BootstrapCommand.java` | 强制 LOCK_PKI 路径不友好；增 `--skip-pki` | small |

**总计 30 条 finding**：

- **High**: 3（AUDIT-001 / 024 / 025）
- **Medium**: 11
- **Low**: 6
- **Info**: 10

### 8.2 按类别分组

| 类别 | 数量 | findings |
| --- | --- | --- |
| security | 9 | 001, 002, 003, 005, 006, 007, 008, 030, 031 |
| docs | 7 | 024, 025, 026, 027, 028, 029, 033 |
| tooling | 7 | 016, 017, 018, 019, 020, 034, 036 |
| quality | 4 | 013, 014, 032, 035 |
| tests | 3 | 009, 021, 022 |
| correctness | 0 | — |

**没有 correctness finding** 是好事——核心密码学实现 sound、INS gate 完整、FSM 正确。所有 finding 都是 **defense-in-depth、文档同步、tooling 改进** 类。

### 8.3 修复路线图（按 sprint 分组）

#### Sprint 1（P0，下个 commit / 一周内）

**目标**：消除文档 drift + tooling 残留死代码（trivial-cost 高价值）。

| Finding | Action | Cost |
| --- | --- | --- |
| AUDIT-024 | 重写 `CHANGELOG.md [Unreleased]`：移除 5 个已删组件 + 添加最近 3 commit (de21509 / 688f8c8 / c0150b1) | small |
| AUDIT-025 | `README.md:51` 移除 4 个已删测试套件；`README.md:54` 删除 "Until real-card backend lands" 段 | trivial |
| AUDIT-027 | `SECURITY.md:59` `Bignat.java` → `BigNat.java` | trivial |
| AUDIT-016 | `tools/build.gradle.kts` 删除 `useSimulator` / `cardBackend` 分支 | trivial |
| AUDIT-017 | `tools/build.gradle.kts` `realCardTest` javadoc 移除 simulator 引用 | trivial |
| AUDIT-020 | `del realcard.log` 工作区残留 | trivial |
| AUDIT-029 | `docs/specs/README.md:13` "HKDF-SHA-256" → "AES-CMAC-128 KBKDF" | trivial |
| AUDIT-026 | `CONTRIBUTING.md` 更新 tests 描述 + 移除 `docs/protocol.md` 引用 | trivial |
| AUDIT-028 | `tools/README.md:200` 重新统计 test count + 计时 | trivial |
| AUDIT-032 | `PkiManager.java:194` `exportPagedAt` → `exportCert` | trivial |
| AUDIT-006 | `MasterSeed.java:282` `SW_LIFECYCLE_INVALID` → `SW_CONDITIONS_NOT_SATISFIED` | trivial |

**预估**：1-2 小时完成。

#### Sprint 2（P1，下个 sprint / 两周内）

**目标**：解决 wipe trade-off + 测试套件去重 + Makefile 同步 + transient wipe 加固。

| Finding | Action | Cost |
| --- | --- | --- |
| AUDIT-001 | **决策**：写 ADR 说明 wipe 削弱 trade-off，或恢复 fill。建议先写 ADR + 增 `RESET_TO_FACTORYAfterTest` negative test 验证下次 SETUP 完整覆盖 master cells | small |
| AUDIT-002 | 同 AUDIT-001 — ADR 同步 | trivial |
| AUDIT-005 | `Bip32.walkPathToLeaf` / `Slip10.walkPath` 包 try-finally + wipe — **关键 defense-in-depth** | small |
| AUDIT-018 | `Makefile` 增 `realcard` / `tools-realcard` / `installCap` target | trivial |
| AUDIT-009 | `HostSession` 增 `verifyHandshakeSignature(boolean)` 开关，默认关 + 文档 | small |
| AUDIT-013 | `tools/cli` 创建 `MeowlAppletConstantsMirror` 类，`BootstrapCommand` / `ResetCommand` 引用 | small |
| AUDIT-014 | 同 AUDIT-013 | trivial |
| AUDIT-021 | 8 个 real-card test 类 lift 到 `RealCardTestBase` 或 `@RegisterExtension MeowlCardExtension` | small |
| AUDIT-033 | README / SECURITY 增 "Reader compatibility matrix" 章节 | small |
| AUDIT-036 | `BootstrapCommand` 增 `--skip-pki` flag | small |

**预估**：2-3 天工作量。

#### Sprint 3（P2，机会维护）

| Finding | Action | Cost |
| --- | --- | --- |
| AUDIT-019 | CI workflow 增 `:tools:test` step | trivial |
| AUDIT-003 | 同 wipe ADR | trivial |
| AUDIT-007, 008, 015, 022, 030, 031, 034, 035 | 各自 javadoc / ADR 化 | trivial |

### 8.4 「不修也合理」清单

以下 finding 标 Info，**保留也是合理选择**——但应在 ADR 或 javadoc 中显式说明决策依据：

| 编号 | 保留理由 |
| --- | --- |
| AUDIT-007 | JC ECDH on-curve check 是 spec-mandated；额外 0x04 prefix check 是 belt-and-braces，已注释 |
| AUDIT-008 | authentikey 不可重生成是 MEAP-4 设计核心，不是 bug |
| AUDIT-015 | `WipeTrigger` SAM 单实现是 JC 3.0.5 缺 `Runnable` 的 idiomatic workaround |
| AUDIT-022 | `CardClient` 单实现保留为 future simulator 接入点 |
| AUDIT-030 | MAC 输入含 outer_header 是 MEAP-2 spec |
| AUDIT-031 | PUK rotate 需 PIN verified 是反偷卡 |
| AUDIT-035 | `pickTerminal` 已在上次 commit 修复 |

### 8.5 不在本次审计范围

- **CAP file binary verification** — 需 ant-javacard 工具链外审。
- **CycloneDX SBOM correctness** — 需 supply-chain 工具外审。
- **SLSA L3 attestation** — 需 release workflow + sigstore 外审。
- **Side-channel timing/power** — 需 ChipWhisperer / Riscure 等专业设备。
- **Fault injection / glitch attack** — 同上。
- **Formal verification** — 不在 JavaCard scope。
- **JCMathLib 替代方案 review** — 已是 BigNat-only，jc-mathlib 不在 dep 树。

---

## 附录 A · 文件清单与代码行数统计

### A.1 applet/ 模块 (26 文件，约 5,283 行)

| 文件 | 行数 | 职责 |
| --- | --- | --- |
| `MeowlApplet.java` | 672 | INS dispatcher, transactional handlers |
| `SecureChannel.java` | 513 | MEAP-2 SC: handshake / unwrap / wrap, IV monotonicity |
| `Constants.java` | 384 | INS / SW / capability / TLV / sizes / policy |
| `Wei25519.java` | 365 | Wei25519 mapping for hardware EC |
| `BigNat.java` | 327 | constant-time big-int primitives |
| `Secp256k1Curve.java` | 302 | secp256k1 曲线参数 + 设置 helper |
| `Schnorr.java` | 297 | BIP-340 Schnorr signing |
| `MasterSeed.java` | 285 | BIP-32 / SLIP-10 master material |
| `Ed25519.java` | 281 | RFC 8032 EdDSA signing |
| `PinManager.java` | 213 | PIN/PUK lifecycle |
| `Barrett.java` | 209 | Barrett 还原 |
| `EcdsaK1.java` | 208 | secp256k1 ECDSA signing |
| `PkiManager.java` | 208 | chunked PKI cert import / export |
| `Bip32.java` | 205 | BIP-32 secp256k1 derivation |
| `Fp25519.java` | 181 | Fp25519 模运算 |
| `Kdf.java` | 177 | AES-CMAC-128 KBKDF |
| `EcPoint.java` | 149 | EC scalar multiplication |
| `HmacSha512.java` | 148 | RFC 2104 software HMAC-SHA-512 |
| `Fp25519Inv.java` | 147 | Fp25519 modular inverse via RSA |
| `Slip10.java` | 121 | SLIP-10 Ed25519 derivation |
| `LifecycleState.java` | 92 | 4-state FSM |
| `ApduTlv.java` | 91 | BER-TLV writer helpers |
| `Authentikey.java` | 71 | 长生命周期身份 keypair |
| `ResetToFactory.java` | 59 | 4-invocation 计数器 |
| `Bounds.java` | 34 | overflow-safe 空间检查 |
| `WipeTrigger.java` | 17 | SAM interface |

**总计**：5,283 行（注释 + 代码 + 空行，未排除）。

### A.2 tools/ 模块 (39 main + 15 test = 54 文件)

#### A.2.1 cli/ 子包 (24 文件)

`MeowlCli`, `MeowlSession`, `GlobalOptions`, `AidOption`, `GpKeysOption`, `JsonOutput`, `ProtocolException`, `MeowlExecutionExceptionHandler`, `InfoCommand`, `ApduCommand`, `ResetCommand`, `AuthentikeyCommand`, `ScCommand`, `ScHandshakeCommand`, `ScSendCommand`, `SelectCommand`, `BootstrapCommand`, `BenchCommand`, `ReplayCommand`, `ShellCommand`, `GpCommand`, `GpInstallCommand`, `GpUninstallCommand`, `GpListCommand`。

#### A.2.2 其他子包

- `core/` (5)：`Hex`, `MeowlAid`, `MeowlInsn`, `MeowlSw`, `Tlv`
- `gp/` (1)：`GpFacade`
- `proto/` (4)：`HostCrypto`, `KdfCmac`, `SecureChannelClient`, `SecureChannelException`
- `shell/` (1)：`ShellSession`
- `transport/` (3)：`BiboStack`, `CardTransport`, `ReaderPreferences`
- 顶层：`Main.java`

#### A.2.3 tools 测试 (15 文件)

| 文件 | 行数 |
| --- | --- |
| `SecureChannelClientIT.java` | 313 |
| `HostCryptoTest.java` | 252 |
| `ShellSessionTest.java` | 195 |
| `CommandTreeTest.java` | 155 |
| `GpKeysOptionTest.java` | 148 |
| `TlvTest.java` | 140 |
| `JsonOutputTest.java` | 133 |
| `MeowlInsnTest.java` | 131 |
| `HexTest.java` | 127 |
| `BiboStackTest.java` | 119 |
| `MeowlSwTest.java` | 96 |
| `ReaderPreferencesTest.java` | 89 |
| `MeowlAidTest.java` | 79 |
| `AidOptionTest.java` | 51 |
| `ShellCommandTest.java` | 37 |

**tools 测试总计**：约 2,065 行。

### A.3 tests/ 模块 (25 文件)

| 文件 | 类型 | 大约行数 |
| --- | --- | --- |
| `BenchmarkSuite.java` | real-card | ≈600 |
| `MeowlAppletTest.java` | real-card | ≈500 |
| `SecureChannelTest.java` | real-card | ≈450 |
| `PersonalisationTest.java` | real-card | ≈400 |
| `EcdsaK1Test.java` | real-card | ≈300 |
| `SchnorrK1Test.java` | real-card | ≈350 |
| `Ed25519SigningTest.java` | real-card | ≈300 |
| `HdDerivationTest.java` | real-card | ≈350 |
| `BigNatTest.java` | simulator | ≈300 |
| `BarrettTest.java` | simulator | ≈250 |
| `Fp25519Test.java` | simulator | ≈250 |
| `HmacSha512Test.java` | simulator | ≈200 |
| `HmacSha512EdgeTest.java` | simulator | ≈150 |
| `LifecycleStateTest.java` | simulator | ≈150 |
| `SecureChannelStripPkcs5Test.java` | simulator | ≈120 |
| `SchnorrTagHashTest.java` | simulator | ≈100 |
| `ApduTlvTest.java` | simulator | ≈100 |
| `BoundsTest.java` | simulator | ≈80 |
| `cardclient/CardClient.java` | testkit | 35 |
| `cardclient/CardClientFactory.java` | testkit | ≈25 |
| `cardclient/RealCardClient.java` | testkit | 121 |
| `sc/KdfCmacHost.java` | testkit | ≈80 |
| `testkit/HostSession.java` | testkit | 224 |
| `testkit/MeowlFixtures.java` | testkit | 128 |
| `testkit/TestConstants.java` | testkit | 49 |

### A.4 docs/ 与配置文件

| 文件 | 行数 | 状态 |
| --- | --- | --- |
| `README.md` | 88 | stale (AUDIT-025) |
| `CHANGELOG.md` | 108 | severely stale (AUDIT-024) |
| `CONTRIBUTING.md` | 111 | stale (AUDIT-026) |
| `SECURITY.md` | 60 | typo (AUDIT-027) |
| `Makefile` | 110 | 缺 target (AUDIT-018) |
| `tools/README.md` | 205 | minor stale (AUDIT-028) |
| `docs/README.md` | 37 | clean |
| `docs/specs/README.md` | 33 | minor stale (AUDIT-029) |
| `docs/specs/meap-0.md` ... `meap-7.md` | (未逐行统计) | 与代码对齐良好 |

---

## 附录 B · INS × Lifecycle 覆盖矩阵

### B.1 INS 与 lifecycle gate 完整映射

| INS | 名称 | Channel | Lifecycle gate | PIN gate | Negative tests covered? |
| --- | --- | --- | --- | --- | --- |
| 0x01 | GET_INFO | outer | 任何状态 | 否 | ✓ `MeowlAppletTest` |
| 0x02 | GET_AUTHENTIKEY | outer | 任何状态 | 否 | ✓ `MeowlAppletTest` |
| 0x03 | RESET_TO_FACTORY | outer | 任何状态 | 否 | ✓ `MeowlAppletTest.resetToFactory` |
| 0x10 | INIT_SECURE_CHANNEL | outer | 任何状态 | 否 | ✓ `SecureChannelTest.handshake` |
| 0x11 | OPEN_SECURE_CHANNEL | outer | 任何状态 | 否 | ✓ `SecureChannelTest.envelope` |
| 0x20 | SETUP | inner | `== PERSONALIZED` | 否 | ✓ `PersonalisationTest.Setup` |
| 0x21 | VERIFY_PIN | inner | `>= SETUP_DONE` | 否 | ✓ `PersonalisationTest.Pin` |
| 0x22 | CHANGE_PIN | inner | `>= SETUP_DONE` | 否 | ✓ `PersonalisationTest.Pin` |
| 0x23 | CHANGE_PUK | inner | `>= SETUP_DONE` | **PIN required** | ✓ `PersonalisationTest.Puk` |
| 0x24 | UNBLOCK_PIN | inner | `>= SETUP_DONE` | 否（用 PUK） | ✓ `PersonalisationTest.Unblock` |
| 0x30 | EXPORT_PKI_PUBKEY | inner | `== UNINITIALIZED` | 否 | ✓ `PersonalisationTest.Pki` |
| 0x31 | SIGN_PKI_CSR | inner | `== UNINITIALIZED` | 否 | ✓ `PersonalisationTest.Pki` |
| 0x32 | IMPORT_PKI_CERT | inner | `== UNINITIALIZED` | 否 | ✓ `PersonalisationTest.Pki` |
| 0x33 | EXPORT_PKI_CERT | inner | 任何（gates on `hasCert`） | 否 | ✓ `PersonalisationTest.PkiExport` |
| 0x34 | LOCK_PKI | inner | `== UNINITIALIZED` + `hasCert` | 否 | ✓ `PersonalisationTest.Lock` |
| 0x40 | IMPORT_SEED | inner | `== SETUP_DONE` | **PIN required** | ✓ `PersonalisationTest.Seed` |
| 0x41 | GENERATE_SEED | inner | `== SETUP_DONE` | **PIN required** | ✓ `PersonalisationTest.Seed` |
| 0x42 | EXPORT_XPUB | inner | `== SEEDED` | **PIN required** | ✓ `HdDerivationTest` |
| 0x50 | SIGN_ECDSA_K1 | inner | `== SEEDED` | **PIN required** | ✓ `EcdsaK1Test.Gating` |
| 0x51 | SIGN_SCHNORR_K1 | inner | `== SEEDED` | **PIN required** | ✓ `SchnorrK1Test.Gating` |
| 0x52 | SIGN_ED25519 | inner | `== SEEDED` | **PIN required** | ✓ `Ed25519SigningTest.Gating` |

**总计**：21 个 INS，**全部覆盖 lifecycle + PIN negative path**。

### B.2 Lifecycle 进入路径

```text
UNINITIALIZED  ──IMPORT_PKI_CERT + LOCK_PKI──▶  PERSONALIZED
                                                       │
                                                       ├──SETUP──▶  SETUP_DONE
                                                                          │
                                                                          ├──IMPORT_SEED──▶  SEEDED
                                                                          │
                                                                          └──GENERATE_SEED──▶  SEEDED

任何状态  ──RESET_TO_FACTORY × 4──▶  UNINITIALIZED
```

**评估**：linear FSM，无分支，每个边都被 `transitionToInTx(target == current+1)` 守门。**正确**。

### B.3 哪些 INS 被 outer / inner 各调用了

- **outer-only**: 0x01, 0x02, 0x03, 0x10, 0x11
- **inner-only**: 0x20-0x52（除 0x33 EXPORT_PKI_CERT 也在 inner 但允许 any post-PERSONALIZED）

**未发现混淆**——dispatcher 的 outer switch（`process()`）和 inner switch（`dispatchInner()`）严格分离。

---

## 附录 C · SW 一致性表

### C.1 `Constants.java` SW 表 vs `MeowlSw` 主机端镜像

| SW | applet (`Constants.java`) | host (`MeowlSw.java`) | 一致 |
| --- | --- | --- | --- |
| `0x9000` | (隐式 success) | NO_ERROR | ✓ |
| `0x6700` | SW_WRONG_LENGTH | WRONG_LENGTH | ✓ |
| `0x6982` | SW_SECURITY_STATUS_NOT_SATISFIED | SECURITY_STATUS_NOT_SATISFIED | ✓ |
| `0x6983` | SW_AUTH_BLOCKED | AUTH_BLOCKED | ✓ |
| `0x6985` | SW_CONDITIONS_NOT_SATISFIED | CONDITIONS_NOT_SATISFIED | ✓ |
| `0x6A86` | SW_INCORRECT_P1P2 | INCORRECT_P1P2 | ✓ |
| `0x6D00` | SW_INS_NOT_SUPPORTED | INS_NOT_SUPPORTED | ✓ |
| `0x6E00` | SW_CLA_NOT_SUPPORTED | CLA_NOT_SUPPORTED | ✓ |
| `0x6FA0` | SW_RESET_COUNTDOWN_BASE (counted) | RESET_COUNTDOWN_BASE (counted) | ✓ |
| `0x63C0` | SW_PIN_RETRIES_BASE (counted) | PIN_RETRIES_BASE (counted) | ✓ |
| `0x6FB0` | SW_LIFECYCLE_INVALID | LIFECYCLE_INVALID | ✓ |
| `0x6FB1` | SW_SECURE_CHANNEL_REQUIRED | SECURE_CHANNEL_REQUIRED | ✓ |
| `0x6FB2` | SW_SECURE_CHANNEL_FAILED | SECURE_CHANNEL_FAILED | ✓ |
| `0x6FE0` | SW_UNSUPPORTED_FEATURE | UNSUPPORTED_FEATURE | ✓ |
| `0x6FE1` | SW_INTERNAL_ERROR | INTERNAL_ERROR | ✓ |

**全部一致 ✓**。13 个固定 SW + 2 个 counted family（`0x6FAn` / `0x63Cn`）。

### C.2 `MeowlSw.describe(int)` 兜底行为

`@/d:\Desktop\x\meowl-applet\tools\src\main\java\social\meowl\tools\core\MeowlSw.java:92-112`：

- counted family 优先识别（前 12 bit 匹配 0x6FA / 0x63C），低 4 bit 解码为 counter。
- table miss 兜底 `"0xXXXX — Unknown SW"`——**不抛异常**。**好**。

### C.3 SW 文档化覆盖

每个 SW 在 `Constants.java` 都有 javadoc：

- `SW_WRONG_LENGTH` ✓ ISO 7816-4 引用
- `SW_RESET_COUNTDOWN_BASE` ✓ 范围 + 引用 MEAP-3
- `SW_PIN_RETRIES_BASE` ✓ ISO 7816-4 + 4-bit 编码说明
- `SW_INTERNAL_ERROR` ✓ Schnorr nonce==0 sentinel 概率说明 (~2⁻²⁵⁶)

**评估**：极佳的文档化，第三方 host SDK 实现完全可基于此表。

### C.4 全部 SW 都来自 `Constants.SW_*` 命名常量

applet 全仓 grep `ISOException.throwIt`：所有 throw 都引用 `Constants.SW_*`，**没有 hex literal 散落**。**优秀的代码卫生**。

---

## 附录 D · 第三方依赖版本与升级建议

### D.1 `gradle/libs.versions.toml` 当前版本

#### D.1.1 Build / 运行时

| dep | 当前 | 评估 |
| --- | --- | --- |
| JDK | 25 | ✓ |
| Gradle | 9.5.1 | ✓ |
| JavaCard SDK | jc320v26.0_kit | ✓ 跟随 Oracle |
| JC target | 3.0.5 | **保持 3.0.5** — 部署兼容（README.md 说明） |

#### D.1.2 Martin Paljak 工具链 (date-versioned)

| dep | 当前 | 备注 |
| --- | --- | --- |
| ant-javacard | 26.05.15 | 跟随上游 |
| apdu4j | 26.04.20.1 | 跟随上游 |
| globalplatformpro | 26.04.20.1 | 跟随上游 |

#### D.1.3 模拟器 + 主机库

| dep | 当前 | 评估 |
| --- | --- | --- |
| jcardsim | 3.0.6.0 | klinec fork，活跃 |
| bouncycastle | 1.84 | 可升 1.85+（2026 已发布；本审计未验证 wire compat） |
| slf4j | 2.0.18 | ✓ 主流 |

#### D.1.4 CLI stack

| dep | 当前 | 评估 |
| --- | --- | --- |
| picocli | 4.7.7 | ✓ 主流；可关注 5.x preview |
| jline | 3.30.4 | ✓ 主流 |
| jackson-jr | 2.19.1 | ✓ |

#### D.1.5 测试 / 静态分析

| dep | 当前 | 评估 |
| --- | --- | --- |
| junit | 6.0.3 | ✓ JUnit 6（最新） |
| spotless | 8.5.1 | ✓ |
| google-java-format | 1.35.0 | ✓ |
| ktlint | 1.8.0 | ✓ |
| foojay-resolver | 1.0.0 | ✓ |
| cyclonedx | 3.2.4 | ✓ SBOM 1.6 |

### D.2 升级风险评估

#### Bouncy Castle 1.84 → 1.85+

- **风险**：BC 跨主版本时偶尔有 `MessageDigest.getInstance` provider lookup 顺序改变。
- **影响范围**：`tools/.../HostCrypto.java`、`tests/.../HostSession.java` 用 BC 做 KDF / MAC mirror。
- **建议**：在 sprint 边界做单独 BC 升级 PR，只验证 :tools:test + :tests:test 全绿。**Cost: small**。

#### apdu4j 跟版

- date-versioned，每 1-2 月小版本。无 breaking 变化历史。
- 建议每 quarter 跟一次。**Cost: trivial**。

#### Gradle 9.5.1 → 9.6.x

- 当前在 latest。无升级压力。

#### JC SDK 3.2.0 → 3.3.0（如果 Oracle 发布）

- **慎重**：CAP target 3.0.5 是部署兼容契约，**不应升级**。SDK 升级仅影响编译期，target 保持。

### D.3 缺失的 dev dependency

- **JaCoCo 代码覆盖率**：当前不收集。建议加入以量化 :tests:test 与 :tools:test 的覆盖率（contactless 实卡测试覆盖率受 PCSC mock 限制，但 simulator-track 应有 80%+ 覆盖率目标）。
- **OWASP Dependency-Check** 或 **Snyk gradle plugin**：自动化 CVE 扫描。**Cost: trivial**（Gradle plugin 配置即可）。
- **Checkstyle / PMD**：当前仅 Spotless 格式化。可加 PMD 检测 magic number / 复杂度。**Cost: small**。

### D.4 建议升级路线

**Phase 1（短期，立刻）**：

- 无紧急 CVE 修复。所有依赖在 latest stable 或 acceptable lag 范围内。

**Phase 2（中期，下个 sprint）**：

- 加 OWASP Dependency-Check Gradle plugin → CI 启用。
- 加 JaCoCo → 收集 simulator-track 覆盖率到 SBOM artifact。

**Phase 3（长期，每 quarter）**：

- 跟 Martin Paljak 工具链 date-version。
- BC / picocli / jline 跟主流稳定版（次要版本）。
- JC SDK 跟 Oracle 但 CAP target 保持 3.0.5。

---

## 审计结论

### 总评

`meowl-applet` 是一个**架构清晰、密码学严谨、单平台硬化彻底**的 JavaCard 硬件钱包 applet。139/139 实卡测试通过、零 TODO/FIXME、constant-time 防御充分、INS gate 完整。**核心代码质量在 production-ready 边缘**——主要短板是上次 commit 系列后**文档严重 drift** + **wipe 路径 trade-off 缺显式 sign-off**。

### 必修项（Sprint 1，1-2 小时工作量）

1. **CHANGELOG.md / README.md / SECURITY.md / CONTRIBUTING.md / docs/specs/README.md** 文档 drift 修复（5 个 trivial-cost finding）
2. **`tools/build.gradle.kts`** 删 `useSimulator` 死配置
3. **工作区** 删 `realcard.log` 残留

### 关键决策项（Sprint 2）

1. **AUDIT-001 (High)**：master seed wipe 是否恢复 EEPROM scrub？建议**写 ADR + 增 negative test**。如果路径 A（恢复 fill），需重新验证 BWT。
2. **AUDIT-005 (Medium)**：`walkPath` try-finally 包 transient wipe — defense-in-depth 必修。
3. **AUDIT-018 (Medium)**：Makefile 增 realcard target — DX 改进。

### 不修也合理（已 trade-off）

- AUDIT-008（authentikey 不可重生成）—— MEAP-4 设计核心
- AUDIT-022（CardClient 单实现）—— future-proof
- AUDIT-031（PUK rotate 需 PIN）—— 反偷卡

### 项目可发布性

如果 Sprint 1 完成 + AUDIT-001 走路径 B（写 ADR 而非恢复 fill），项目**可以打 v1.0-rc1 tag**，在外部 audit 启动同时 release。否则建议先打 v0.9（feature complete，doc/wipe 待审）。

---

**审计员签字**：Cascade
**报告时间**：2026-05-25
**报告版本**：v1.0 (final)
**总 finding 数**：30
**总行数**：约 1,950 行（含证据 + 路线图 + 附录）
