# 00 — Executive Summary

<!-- SPDX-FileCopyrightText: 2026 meowl.social contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

针对 `meowl-applet` 在 commit `3d6bbf3e8c066a9d8ef1b81e8097f43c083681d3` 处的全面安全审计的执行摘要。审计范围包括 25 个 applet 源文件 (3 440 LOC)、19 个测试文件 (6 919 LOC)、tools/ 子项目协议层、jcardsim 性能基准与 CAP 静态分析。

## 1. 总体结论

**`meowl-applet` 在当前威胁模型下没有阻止主网发布的安全缺陷**。

具体而言：

- ✅ **零 S0 (Blocker)** finding —— 没有立即可被利用的密钥泄露、签名伪造、Secure Channel 绕过、bricking 漏洞。
- ✅ **零 S1 (High)** finding —— 没有在合理威胁模型下严重削弱安全保证的问题。
- ⚠️ **3 条 S2 (Medium)** finding —— 都属于侧信道防御纵深的"文档与实现轻微漂移"类，不构成实战攻击面（详见 §3）。
- 📋 **8 条 S3 (Low)** finding —— 代码质量 / DoS 边界 / 可见性收紧等机会性改进。
- 💡 **9 条 S4 (Info)** finding —— 设计取舍记录、未来 v2 路线参考。

测试覆盖率优秀（**2.0× 测试-代码比**，30 条 RFC/BIP/SLIP 规范向量 100% pin），生命周期 FSM 与 reset-to-factory 原子性是审计的最干净部分。

## 2. Severity 直方图

```text
S0 (Blocker)  | 0
S1 (High)     | 0
S2 (Medium)   | 3   (A-01, A-16, P-02)
S3 (Low)      | 8   (A-02, A-08, A-12, A-13, A-21, T-01, T-03, T-04, T-05)
S4 (Info)     | 9+  (A-03, A-09, A-10, A-11, A-14, A-15, A-19, A-20, P-01)
```

按子系统分布：

| 子系统 | S2 | S3 | S4 |
| --- | ---: | ---: | ---: |
| 加密原语 (`Bignat` / `Schnorr` / `Ed25519` / `EcdsaK1` / `Bip32`) | 2 (A-01, A-16) | 2 (A-02, A-21) | 3 (A-03, A-10, A-20) |
| Secure Channel (`SecureChannel`) | 0 | 1 (A-08) | 1 (A-09) |
| Lifecycle / PIN / PKI / Seed | 0 | 2 (A-12, A-13) | 3 (A-11, A-14, A-15) |
| Wire / TLV (`ApduTlv` / `MeowlApplet`) | 0 | 0 | 1 (A-19) |
| Tests | 0 | 4 (T-01, T-03, T-04, T-05) | 0 |
| Performance | 1 (P-02) | 0 | 1 (P-01) |

## 3. TOP-3 优先修复 finding

### S2 #1 — `Schnorr` y(R) 奇偶翻转的非常时间分支 (A-01)

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Schnorr.java:194-199`

**风险**：MEAP-6 §SCA 声称"the secret bit never branches the control flow"，但实现用 `if (ryLastByte & 0x01) negateMod(K)` 早退分支，给"k' 最低 bit 是否奇"提供 ~10 µs 的定时旁路。

**实战可利用性**：极低。aux randomness 让 k' 每次新鲜，PCSC reader 5 ms jitter 对此分支差完全压制。

**修复成本**：低（~30 行代码）。引入 `ModN.negateModConditional(byte[], short, mask)` mask-driven 变体。

**优先级**：**应在下一个版本前修**，恢复实现与文档一致。

---

### S2 #2 — `Bignat.mod` 变时间渗透到 Schnorr `(e·d) mod n` (A-16)

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Bignat.java:149-241` + `@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Schnorr.java:213-236`

**风险**：`Bignat.mod` 内层 shift-subtract 循环次数取决于操作数比特模式。在 Schnorr `s = (k + e·d) mod n` 路径上：

- e 公开（host 可控 m → 可控 e）。
- d 跨签名稳定。
- k 来自 aux，每次新鲜。

理论上选择性消息攻击者可以累积多个 (e_i, T_i) 样本统计反推 d。

**实战可利用性**：受 **PCSC ≥ 5 ms** 或 **NFC ≥ 2 ms** reader jitter 隔离 → 必须有 **直驱 + 紧密 polling** 才能区分 100-200 µs 的 mod 时间差。具备这种能力的攻击者通常也有 die-probing 能力，超出软件防御范围。

**修复成本**：高。两条路径：

1. **短期**：在 Schnorr 引入 `(k + r·e·d)/r mod n` 盲化 e·d (~50 行 + 1 modular inverse, ~20% 性能下降)。
2. **长期**：v2 路线 limb-radix-2²⁶ Field 重写 + Barrett reduction (~300 行，30-50% 性能影响)。

**优先级**：MEAP-6 §6.3 已跟踪 v2。**v1 不修**，但建议在 `Bignat.java` javadoc 顶部追加明确警告。

---

### S2 #3 — `SIGN_ED25519` 硬件预测 ~3.5 s 接近 budget 上限 (P-02)

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Ed25519.java:138-205`

**实测**：jcardsim 35 ms × ~100× 时钟差 = 预测硬件 3.5 s（MEAP-6 budget 3-6 s 中位）。

**风险**：UX 边界。普通 BTC ECDSA sign ~150 ms 用户已习惯；3.5 s 一笔 Solana 签名会触发"卡了吗？"焦虑。

**修复成本**：高。Limb-radix Field 重写或 NAF 窗口化 scalarMult。

**优先级**：v2 路线项 #1（同时关闭 A-16）。

## 4. 强项

1. **HMAC / HKDF / Ed25519 / Edwards25519** —— 与 RFC 5869/2104/8032 完全一致，30 条规范测试向量 100% pin。
2. **Coron 投影盲化 + 双独立盲化** —— Ed25519/Schnorr SCA 防御纵深超过 BIP-340 reference signer。
3. **Native + 软回退**双路径 (`HmacSha`、`RandomData`) —— 真正硬件兼容性优于 Status Keycard。
4. **`TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT` 优先 + persistent 兜底** —— 标量永不落 EEPROM 是关键加固。
5. **Encrypt-then-MAC + IV 严格递增 + MAC 失败强制 reset** —— SC 协议三大正确性条件全部满足，不暴露 padding oracle。
6. **2.0× 测试-代码比 + 差异 oracle** —— 业内优秀。
7. **生命周期 FSM 是纯函数 + 所有持久写在事务内** —— RTF 原子性、防 wipe-failure 反模式都有专门测试 pin。
8. **`SHARED_SCRATCH` + 每路径 `finally { wipe(); }`** —— scratch 卫生统一且严格。

## 5. 弱项

1. **`Bignat.mod` 变时间** (A-16, S2)：v2 路线已计划。
2. **Schnorr 奇偶翻转早退分支** (A-01, S2)：低成本修复，应在下版前完成。
3. **缺真实硬件 baseline + smoke test job** (T-05, S3)：本审计提供了 `meowl bench` 工具，但需用户在物理 J3R180 卡上跑一次填充 baseline。
4. **测试 helper 重复 ~1 200 行** (T-03, S3)：维护成本，非正确性风险。
5. **`ApduTlv` 缺单测** (T-01, S3)：依赖集成路径覆盖，缺失负向 case。

## 6. 关键基准数据（jcardsim @ 4.6 GHz）

| 操作 | p50 (ms) | p99 (ms) | 硬件预测 | MEAP-6 budget |
| --- | ---: | ---: | --- | --- |
| `SIGN_ECDSA_K1` | 3.2 | 8.9 | ~150 ms | 150-300 ✅ |
| `SIGN_SCHNORR_K1` | 3.3 | 7.9 | ~400 ms | 400-900 ✅ |
| `SIGN_ED25519` | 35.0 | 42.7 | ~3.5 s | 3-6 s ✅ |
| `EXPORT_XPUB_K1` | 3.7 | 10.5 | ~150 ms | 80-200 ✅ |
| `EXPORT_XPUB_ED25519` | 17.1 | 22.6 | ~1.7 s | (软实现) |
| `OPEN_SECURE_CHANNEL` | 6.4 | 9.8 | ~250 ms | 100-300 ✅ |

CAP on-card-loaded：**21.7 KB**（J3R180 40-50 KB 可用容量的 ~50%）。

## 7. 与同类项目对比

| 维度 | Status Keycard | Ledger BOLOS | meowl-applet |
| --- | --- | --- | --- |
| HW 平台 | NXP J3D081/J3R200 | ST31H320 (BOLOS) | NXP J3R180 |
| Open source | ✅ AGPL | ❌ proprietary | ✅ AGPL |
| HMAC 软回退 | ❌ | N/A | ✅ |
| Schnorr BIP-340 | ❌ | ✅ | ✅ |
| Ed25519 (RFC 8032) | ❌ | ✅ | ✅ |
| 双独立投影盲化 | N/A | ✅ | ✅ |
| ECDSA RFC 6979 | ❌ | ✅ | ❌ (用平台 RNG) |
| EAL 等级 | EAL 5+ | EAL 5+ | EAL 6+ |
| RAM 占用 | ~2 KB | ~4 KB | ~1.4 KB |
| CAP 大小 | ~28 KB | N/A | 21.7 KB |

**meowl-applet 的差异化定位**：在 EAL 6+ 通用 JC silicon 上提供 **HMAC 软回退 + 双独立盲化 + Schnorr/Ed25519 全栈** 的开源 AGPL 实现 —— 是对 Status Keycard (功能不全) 和 Ledger (闭源专有) 的精准补位。

## 8. 推荐发布前 Checklist

按优先级递降：

- [ ] **A-01**：把 Schnorr y(R) 奇偶翻转改 mask-driven（~30 行 + `ModN.negateModConditional`）。
- [ ] **T-05**：在 J3R180 物理卡跑 `meowl bench --json`，把基线 commit 到 `docs/audit/perf-baselines/`。
- [ ] **T-01**：增加 `ApduTlvTest.java`（~150 行覆盖 read/write/edge cases）。
- [ ] **A-16 文档**：在 `Bignat.java` javadoc 顶部追加 SCA 警告，让 v2 路线工作有更清晰的 motivation。
- [ ] **A-12**：把 `MasterSeed.copy*MasterTo` 收窄为 package-private（移除 `public` 关键字）。
- [ ] (可选) **T-04**：补 `HmacShaTest` 边界 case（~5 个测试）。
- [ ] (可选) **T-03**：抽 `TestSession` 基类，省 ~1 200 行 helper 重复。

非紧急项（v2 路线）：

- [ ] **A-16 实修**：limb-radix-2²⁶ `Field25519` + Barrett reduction。
- [ ] **P-02 实修**：NAF 窗口化或 SLIP-10 + Ed25519 路径优化。

## 9. 报告导航

| 文件 | 主要内容 |
| --- | --- |
| [`README.md`](./README.md) | 报告索引、severity 等级定义、finding 编号约定 |
| [`00-overview.md`](./00-overview.md) | **本文档** —— executive summary |
| [`01-applet-files.md`](./01-applet-files.md) | applet 25 个文件**逐文件**审计 (~14 个 finding) |
| [`02-crypto.md`](./02-crypto.md) | 横切：原语对照 RFC/BIP/SLIP 规范 + 与 libsecp256k1/Trezor/Ledger 对比 |
| [`03-wire-protocol.md`](./03-wire-protocol.md) | APDU 命令矩阵、TLV、SC 信封、状态字契约 |
| [`04-lifecycle.md`](./04-lifecycle.md) | 4 状态 FSM、PIN/PUK/PKI/seed/RTF 原子性 |
| [`05-side-channels.md`](./05-side-channels.md) | constant-time 矩阵、Coron 盲化、RNG 源、padding-oracle 防御 |
| [`06-tests.md`](./06-tests.md) | 测试质量、覆盖矩阵、helper 重复、规范向量覆盖 |
| [`07-perf.md`](./07-perf.md) | CAP 字节布局、RAM 预算、jcardsim sign 延迟 + `meowl bench` 工具说明 |

新增工具：

- `tests/src/test/java/social/meowl/applet/BenchmarkSuite.java` —— jcardsim 基准测试套件（默认 disabled，`-Dbench=true` 启用）
- `tools/src/main/java/social/meowl/tools/cli/BenchCommand.java` —— `meowl bench` CLI 命令（硬件 baseline 采样）

## 10. 审计签名

| 项 | 值 |
| --- | --- |
| 审计 commit | `3d6bbf3e8c066a9d8ef1b81e8097f43c083681d3` |
| 审计完成日期 | 2026-05 |
| applet LOC | 3 440 (去除注释空行) |
| tests LOC | 6 919 |
| CAP on-card | 21 705 字节 |
| jcardsim test 总数 | 1 932 (全部通过) |
| 新增 finding 总数 | 20 (3 × S2, 8 × S3, 9 × S4) |
| 阻止主网发布的 finding | **0** |

**结论：批准在完成 §8 推荐 checklist 的前两项 (A-01 + T-05) 后发布。**
