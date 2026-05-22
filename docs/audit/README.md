# meowl-applet 审计报告

<!--
SPDX-FileCopyrightText: 2026 meowl.social contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

本目录是对 `meowl-applet` 进行的一次全面审计的产出物，覆盖 25 个 applet 源文件、19 个测试文件、tools/ 工具集，以及 jcardsim + 真实硬件双轨基准测试。报告于 2026-05 完成；审计版本对应 git `HEAD`（构建 CAP `meowl-applet.cap` = 117 645 字节，on-card-loaded = 17 359 字节）。

## 目录索引

| # | 文件 | 内容 |
| --- | --- | --- |
| 0 | [`00-overview.md`](./00-overview.md) | Executive summary、等级直方图、TOP10 critical findings、生产就绪度结论 |
| 1 | [`01-applet-files.md`](./01-applet-files.md) | applet 25 个 `.java` 文件**逐文件**审计（每文件一节，定位、判定、依据、修复建议） |
| 2 | [`02-crypto.md`](./02-crypto.md) | 横切：Bignat / Field25519 / Edwards25519 / Schnorr / Ed25519 / EcdsaK1 / Bip32 / Slip10 / Hkdf / HmacSha vs RFC/BIP，对照 3rdparty |
| 3 | [`03-wire-protocol.md`](./03-wire-protocol.md) | APDU / TLV / Secure Channel envelope / IV / MAC / replay defense |
| 4 | [`04-lifecycle.md`](./04-lifecycle.md) | 四态 FSM、reset-to-factory 原子性、PIN/PUK/seed/PKI lifecycle |
| 5 | [`05-side-channels.md`](./05-side-channels.md) | constant-time 检查、projective blinding、RNG 源、scratch 擦除、padding-oracle |
| 6 | [`06-tests.md`](./06-tests.md) | 测试质量：覆盖率、假测试、冗余、helper 重复、F-tag 回归映射 |
| 7 | [`07-perf.md`](./07-perf.md) | 实测：CAP 字节分布、RAM 占用、sign 延迟（jcardsim p50/p95/p99 + 真实硬件 p50/p95/p99） |

## 严重程度（Severity）等级定义

每条 finding 必须挂上下面五档之一：

| 等级 | 含义 | 处理时限 |
| --- | --- | --- |
| **S0 — Blocker** | 立即可被攻击者利用（密钥/seed 泄露、签名伪造、Secure Channel 绕过、bricking）；阻止主网发布 | 必须修复后才发版 |
| **S1 — High** | 在合理威胁模型下严重削弱安全保证（实际定时旁路、缺失的密钥销毁、状态机绕过、协议失配） | 1 个发版周期内修复 |
| **S2 — Medium** | 偏离规范但缺乏直接利用（防御纵深、错误码不规范、RNG 回退路径不优、测试盲区） | 计划内修复，可与新功能合批 |
| **S3 — Low** | 代码质量、可读性、注释/文档与实现的微小漂移、minor 性能问题 | 机会性修复 |
| **S4 — Info** | 设计取舍记录、未利用的 attack surface 提示、未来 v2 路线参考 | 仅记录，不必动手 |

## Finding 编号约定

`A-XX` — applet 源码 finding，跨章节稳定（例如 `A-07` 可能在 `01` `02` `05` 三处都被引用）。
`T-XX` — 测试质量 finding。
`P-XX` — 性能 / 资源 finding。
`W-XX` — wire / 协议 finding。

## 审计范围与边界

**在范围内：**

- `applet/src/main/java/social/meowl/applet/` 全部 25 个 Java 源文件。
- `tests/src/test/java/social/meowl/applet/` 全部 19 个测试文件（覆盖率与质量）。
- `tools/src/main/java/social/meowl/tools/` 中与协议正确性相关的客户端（`SecureChannelClient`、`HostCrypto`、`HkdfSha256`）。
- jcardsim 基准实测，CAP 静态分析，RAM 静态预算。

**不在范围内：**

- 平台底层：JC 3.0.5 native crypto 的实现质量、J3R180 silicon 的 SCA/FA 抗性。
- 第三方依赖：jcardsim、ant-javacard、apdu4j、BouncyCastle 自身的 CVE。
- 物理 / 故障注入攻击（FA、glitching）—— 这是 silicon 厂商的 EAL 5+ 评估范围，本文不对其作出断言。
- 供应链 / 构建系统的 SLSA 等级评估。

## 复现性

每条 finding 都附 `@/path/to/file.java:line` 引用；代码评估对应的 commit 是 `git rev-parse HEAD`（审计开始时锁定）。基准测试的复现命令见 [`07-perf.md`](./07-perf.md) 顶部。

## Finding 状态追踪

| Finding | 严重度 | 状态 | 关闭于 |
| --- | --- | --- | --- |
| **A-01** | S2 | ✅ **RESOLVED** | PR-1 — `Schnorr` 改用 `ModN.negateModConditional(mask)` |
| **A-02** | S3 | ✅ **RESOLVED** | PR-1 — `Schnorr` 改用 `Bignat.addLowerHalfCt` 常时 carry |
| A-03 | S4 | OPEN | (info, no action planned) |
| **A-08** | S3 | ✅ **RESOLVED** | PR-1 — `SecureChannel.unwrap` 不在 stale-IV 时 reset() |
| **A-09** | S4 | ✅ **RESOLVED** | PR-1 — `SecureChannel.incrementCounter` 检 wrap 并 tear down |
| A-10 | S4 | OPEN | (info) |
| A-11 | S4 | OPEN | (info / design intent) |
| **A-12** | S3 | ✅ **RESOLVED** | PR-1 — `MasterSeed.copy*MasterTo` 改 package-private |
| **A-13** | S3 | ✅ **RESOLVED** | PR-1 — `PinManager.wipeInTx` 不再吞 scrub 异常 |
| A-14 | S4 | OPEN | (info / threat-model documented) |
| A-15 | S4 | OPEN | (info / wrap covers exposure window) |
| A-16 | S2 | OPEN | **PR-3/PR-4 范围** (Bignat.mod limb-radix 重写) |
| **A-19** | S4 | ✅ **RESOLVED** | PR-1 — `ApduTlv.finishReserved` 增加 dst 容量检查 |
| A-20 | S4 | OPEN | (info / Path index is public) |
| **A-21** | S3 | ✅ **RESOLVED** | PR-1 — `Bip32.ckdPriv` javadoc 明示偏离 BIP-32 字面规定的设计取舍 |
| T-01 | T | ✅ **RESOLVED** | PR-1 — 新增 `ApduTlvTest` |
| T-03 | T | OPEN | **PR-5 范围** (`TestSession` 抽象) |
| T-04 | T | ✅ **RESOLVED** | PR-1 — 新增 `HmacShaEdgeTest` |
| T-05 | T | OPEN | **PR-5 范围** (hardware-smoke.yml CI) |
| P-02 | P | OPEN | **PR-3/PR-4 范围** (Field25519/Edwards25519 优化) |

性能基线 JSON 落在 [`perf-baselines/`](./perf-baselines/)，每个 PR 产出一份独立文件。
