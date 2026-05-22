# 07 — 资源占用与性能基准

<!-- SPDX-FileCopyrightText: 2026 meowl.social contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

CAP 字节布局、RAM 占用、jcardsim 实测 sign 延迟分布、对应硬件预测，以及供用户在真实卡上运行的 `meowl bench` 工具说明。Findings 编号 `P-XX`。

## 1. CAP 字节布局

### 静态分析（基于 commit `3d6bbf3e8c066a9d8ef1b81e8097f43c083681d3` 构建产物）

复现命令：

```powershell
.\gradlew.bat :applet:buildCap
$cap = "applet\build\cap\meowl-applet.cap"
[System.IO.Compression.ZipFile]::ExtractToDirectory($cap, "build\cap-inspect")
```

CAP 归档（下载）总大小：**117 645 字节** (≈ 115 KB)。

CAP 内部构件（JC 平台真正加载的部分）：

| 构件 | 字节 | 说明 |
| --- | --- | --- |
| `Method.cap` | 13 330 | **可执行字节码（最大头）** |
| `Descriptor.cap` | 4 346 | class/method/field 描述 |
| `RefLocation.cap` | 1 510 | 跨 class 引用位置 |
| `ConstantPool.cap` | 1 337 | 常量池 |
| `StaticField.cap` | 685 | 静态字段初值 |
| `Class.cap` | 386 | class 头 |
| `Import.cap` | 44 | 导入包列表 |
| `Directory.cap` | 34 | 构件目录 |
| `Header.cap` | 19 | CAP 头 |
| `Applet.cap` | 14 | applet AID 注册 |
| **合计** | **21 705** | **on-card-loaded ≈ 21 KB** |

剩余 ~96 KB 是 `.class` 文件（converter 输入）+ MANIFEST + `applet.xml` + `javacard.xml`，**不**加载到卡上。

### 单类 `.class` 字节占比

`.class` 是 CAP 的输入；JC converter 会做 ~75% 压缩。这个表反映 **代码的相对复杂度**，不是 on-card 大小。

| Class | `.class` 字节 | 占比 |
| --- | ---: | ---: |
| `MeowlApplet.class` | 12 808 | 14.5% |
| `SecureChannel.class` | 7 736 | 8.8% |
| `Bignat.class` | 6 334 | 7.2% |
| `Edwards25519.class` | 5 954 | 6.8% |
| `Ed25519.class` | 4 874 | 5.5% |
| `Bip32.class` | 4 448 | 5.0% |
| `Schnorr.class` | 4 381 | 5.0% |
| `PinManager.class` | 3 882 | 4.4% |
| `Field25519.class` | 3 848 | 4.4% |
| `HmacSha.class` | 3 814 | 4.3% |
| `EcdsaK1.class` | 3 729 | 4.2% |
| `MasterSeed.class` | 3 497 | 4.0% |
| `Constants.class` | 3 344 | 3.8% |
| `PkiManager.class` | 3 094 | 3.5% |
| `Slip10.class` | 2 422 | 2.7% |
| `Hkdf.class` | 2 219 | 2.5% |
| `Secp256k1.class` | 2 170 | 2.5% |
| `ModN.class` | 2 011 | 2.3% |
| `Authentikey.class` | 1 724 | 2.0% |
| `ApduTlv.class` | 1 643 | 1.9% |
| `LifecycleState.class` | 1 634 | 1.9% |
| `ResetToFactory.class` | 1 046 | 1.2% |
| `Bounds.class` | 747 | 0.8% |
| `ConstantTime.class` | 607 | 0.7% |
| `WipeTrigger.class` | 144 | 0.2% |
| **总计** | **88 110** | 100% |

最大三类：`MeowlApplet`（路由 + 16 handlers）、`SecureChannel`（MEAP-2 完整客户端）、`Bignat`（多精度大整数）。

### 与目标卡的容量对比

NXP J3R180 EEPROM 总量 **80 KB**，典型可用容量（去掉 GP/JCRE 占用）**~40-50 KB**。on-card 21.7 KB 占用约 **45-55%**，**留有充足空间**给 PKI cert (max 1 KB) 和后续 v2 升级。

### Finding P-01 [S4 — Info] — `MeowlApplet.class` 单文件占 14.5%

**判定**：S4。`MeowlApplet` 491 LOC、12.8 KB `.class`，是路由器加 16 个 handler。结构清晰、无冗余（每个 INS 一个 handler，状态门 + finally wipe + dispatch）。**不需要拆分**——拆分会让 cross-handler 共享状态变得脆弱。

---

## 2. RAM 预算

### Transient 数组分配

| 来源 | 类型 | 大小 (字节) | 用途 |
| --- | --- | --- | --- |
| `MeowlApplet.sharedScratch` | `CLEAR_ON_DESELECT` | **1 056** | 所有 sign / HD-walk 路径共享 |
| `MeowlApplet.innerScratch` | `CLEAR_ON_DESELECT` | 128 | inner APDU 解析、PIN/PUK staging |
| `SecureChannel.lastInboundIv` | `CLEAR_ON_DESELECT` | 16 | replay 防御计数 |
| `SecureChannel.outboundCounter` | `CLEAR_ON_DESELECT` | 16 | 卡端响应 counter |
| `SecureChannel.handshakeScratch` | `CLEAR_ON_DESELECT` | 96 | ECDH + HKDF 中间 |
| `HmacSha.softKey` | `CLEAR_ON_DESELECT` | 64 (SHA-256) / 128 (SHA-512) | 软回退路径 K' |
| `Hkdf.counterBuf` | `CLEAR_ON_DESELECT` | 1 | HKDF expand counter |
| `PinManager.scrub` | `CLEAR_ON_DESELECT` | 32 | PIN/PUK wipe 缓冲 |
| `ResetToFactory.remaining` | `CLEAR_ON_RESET` | 1 | RTF 倒计数 |
| **总计 (近似)** | | **~1 410** | |

JC 3.0.5 transient 限制：`CLEAR_ON_DESELECT` 32 KB（典型卡）；当前 **1.4 KB ≈ 4.4% 利用率**。

### Persistent 数组（EEPROM 占用）

| 来源 | 大小 (字节) |
| --- | --- |
| `MasterSeed.bip32Material` + `slip10Material` | 128 (2 × 64) |
| `MasterSeed.seededFlag` | 1 |
| `PkiManager.cert` | 1 024 (max) |
| `PkiManager.importedLen + stagedTotalLen + importState` | 5 |
| `Authentikey.privateKey` (内部) | ~32-64 (silicon-dep) |
| `Authentikey.publicKey` (内部) | ~64-65 |
| `PinManager.pin` (`OwnerPIN`) | ~64 (silicon-dep) |
| `PinManager.puk` (`OwnerPIN`) | ~64 |
| `PinManager.provisioned` | 1 |
| `LifecycleState.state` | 1 |
| **总计** | **~1 380 + cert** |

数据 EEPROM 占用 ~1.4 KB，加 CAP 21.7 KB ≈ **23 KB total**，远低于 J3R180 的 40 KB 可用容量。

---

## 3. jcardsim 实测 sign 延迟

### 测试环境

| 维度 | 值 |
| --- | --- |
| CPU | Intel i9-12900H @ 4.6 GHz |
| OS | Windows 10/11 |
| JDK | Eclipse Adoptium 25 |
| jcardsim | 3.0.5 |
| BC | bouncycastle-jdk18on |

### 复现命令

```powershell
.\gradlew.bat :tests:test --tests "social.meowl.applet.BenchmarkSuite" -Dbench=true
```

### 实测结果（n=50 样本，5 次 warmup）

```text
[bench] EXPORT_XPUB_K1         n=50  p50=  3.7ms  p95=  7.1ms  p99= 10.5ms  mean=  4.2ms  σ=  1.5ms  min=  2.5ms  max= 10.5ms
[bench] SIGN_ECDSA_K1          n=50  p50=  3.2ms  p95=  6.6ms  p99=  8.9ms  mean=  3.6ms  σ=  1.2ms  min=  2.9ms  max=  8.9ms
[bench] SIGN_SCHNORR_K1        n=50  p50=  3.3ms  p95=  7.0ms  p99=  7.9ms  mean=  4.0ms  σ=  1.3ms  min=  3.1ms  max=  7.9ms
[bench] SIGN_ED25519           n=50  p50= 35.0ms  p95= 39.9ms  p99= 42.7ms  mean= 35.5ms  σ=  2.4ms  min= 31.6ms  max= 42.7ms
[bench] EXPORT_XPUB_ED25519    n=50  p50= 17.1ms  p95= 21.1ms  p99= 22.6ms  mean= 17.7ms  σ=  1.7ms  min= 15.9ms  max= 22.6ms
[bench] OPEN_SECURE_CHANNEL    n=50  p50=  6.4ms  p95=  9.2ms  p99=  9.8ms  mean=  6.8ms  σ=  1.4ms  min=  4.9ms  max=  9.8ms
```

### 分类汇总

| 操作 | p50 (ms) | p95 (ms) | p99 (ms) | 主要瓶颈 |
| --- | ---: | ---: | ---: | --- |
| `SIGN_ECDSA_K1` (m/44'/0'/0'/0/0) | 3.2 | 6.6 | 8.9 | platform `ALG_ECDSA_SHA_256` (native, fast) + BIP-32 5 级派生 |
| `SIGN_SCHNORR_K1` (m/86'/0'/0'/0/0) | 3.3 | 7.0 | 7.9 | software Schnorr + BIP-32 + Bignat scalarMult |
| `EXPORT_XPUB_K1` (m/44'/0'/0'/0/0) | 3.7 | 7.1 | 10.5 | BIP-32 5 级派生 + native scalarMult |
| `EXPORT_XPUB_ED25519` (m/44'/501'/0'/0') | 17.1 | 21.1 | 22.6 | SLIP-10 + Ed25519 软实现 pubkey |
| `SIGN_ED25519` (m/44'/501'/0'/0') | **35.0** | **39.9** | **42.7** | **SLIP-10 + Ed25519 双 scalarMult + Bignat.mod**（applet 最慢路径） |
| `OPEN_SECURE_CHANNEL` (handshake) | 6.4 | 9.2 | 9.8 | ECDH + HKDF + handshake ECDSA-sign |

### 关键观察

1. **secp256k1 路径 (ECDSA / Schnorr / xpub)** 都在 < 10ms：`Signature.ALG_ECDSA_SHA_256` 与 `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` 在 jcardsim 上是 native 路径，BIP-32 派生主导耗时。
2. **Ed25519 sign 是慢路径**：35 ms p50 / 43 ms p99 —— 软实现的两次 256-bit double-and-always-add ladder + 投影盲化 + Bignat 算术。这是 **applet 的最长 worst-case latency**。
3. **Schnorr 比 ECDSA 仅慢 ~5%**：因为 secp256k1 scalarMult 是 platform native (`ALG_EC_SVDP_DH_PLAIN_XY`) — 软只覆盖 nonce / challenge hash / `s = k + e·d` 的标量运算。
4. **OPEN_SC 6.4 ms**：主要是 ECDH (native) + HKDF (软 / 短消息) + 一次 ECDSA-sign on authentikey。

### 与 MEAP-6 §"Performance budget" 对照

| 操作 | MEAP-6 目标 (硬件) | jcardsim 实测 | 差距比 (sim/HW) |
| --- | --- | --- | --- |
| ECDSA k1 sign | 150-300 ms | 3.2 ms | ~50× |
| Schnorr sign | 400-900 ms | 3.3 ms | ~150× |
| Ed25519 sign | 3-6 s | 35.0 ms | ~100× |
| EXPORT_XPUB | 80-200 ms | 3.7 ms | ~25× |

**比例反映 jcardsim 跑在桌面 CPU 上（4.6 GHz）vs 真卡 SC （20-40 MHz）—— 约 100× 时钟差**。Ed25519 software 路径在 HW 上预计 3-5 秒，**符合 MEAP-6 budget**。

### Finding P-02 [S2 — Medium] — Ed25519 sign 在硬件上接近 budget 上限

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\Ed25519.java:138-205`

**判定**：S2。jcardsim 35 ms × ~100× = ~3.5 s 预测硬件耗时，处于 MEAP-6 budget (3-6s) 的中位。**两次** scalarMult（A 计算 + R 计算）每次 256 iterations × (pointDouble + pointAdd) 是主要成本。

**优化路线（按收益排序）**：

1. **窗口化 NAF (4-bit window) + 预计算表** —— 减半 ladder iterations，但需 ~256 字节 静态表 + ~50 行代码。预计 -30%（→ 2.5 s）。
2. **共享 SHA-512 引擎** —— 已实现（行 100-104）。
3. **Limb-radix-2²⁶ Field 重写** —— 关闭 `A-16`（SCA finding）顺带提速 2-3×（→ 1-1.5 s）。
4. **Ed25519 native（如果未来卡支持）** —— 删除整套软件实现。JC 3.1+ 有 `Signature.ALG_EDDSA` 但 J3R180 不支持。

短期（v1）不动；v2 路线优先项 #3（双重收益：SCA + 性能）。

---

## 4. 真实硬件基准 (`meowl bench`)

`tools/` 子项目新增 `BenchCommand.java`（285 LOC），提供端到端硬件性能采样。

### 用法

```powershell
# 1. 安装 CAP（若尚未安装）
.\gradlew.bat :tools:installCap

# 2. 通过 meowl shell 完成 SETUP + IMPORT_SEED 进入 SEEDED 状态

# 3. 运行 bench
.\gradlew.bat :tools:run --args="bench --pin 123456"

# 或精选子集（仅签名）
.\gradlew.bat :tools:run --args="bench --pin 123456 --include ecdsa,schnorr,ed25519"

# 或 JSON 输出供回归监控
.\gradlew.bat :tools:run --args="bench --pin 123456 --json"
```

### `--help` 输出

```text
Usage: meowl bench [-hV] [--aid=HEX] -p=PIN [--samples=N] [--warmup=N]
                   [--include=OP[,OP...][,OP[,OP...]...]]...
Measures p50/p95/p99 latency of sign + HD-walk paths on a real card. Card must
be SEEDED + PIN-validated.
      --aid=HEX     Applet AID to SELECT, hexadecimal (default: F06D656F776C01).
  -h, --help        Show this help message and exit.
      --include=OP[,OP...][,OP[,OP...]...]
                    Comma-separated subset of {ecdsa,schnorr,ed25519,xpub-k1,
                      xpub-ed25519,sc}. Default: all.
  -p, --pin=PIN     User PIN to authenticate before benchmarking (4-32 ASCII
                      bytes).
      --samples=N   Timed iterations per operation (default: 30).
  -V, --version     Print version information and exit.
      --warmup=N    Warm-up iterations per operation (default: 5).
```

### 硬件实测占位

下表预留给运行 `meowl bench` 后的真实卡测试结果（**审计时无可用 J3R180 卡**，留待用户在物理硬件上跑后填充）：

| 操作 | p50 (ms) | p95 (ms) | p99 (ms) | mean (ms) | σ (ms) | MEAP-6 目标 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `SIGN_ECDSA_K1` | _TODO_ | _TODO_ | _TODO_ | _TODO_ | _TODO_ | 150-300 |
| `SIGN_SCHNORR_K1` | _TODO_ | _TODO_ | _TODO_ | _TODO_ | _TODO_ | 400-900 |
| `SIGN_ED25519` | _TODO_ | _TODO_ | _TODO_ | _TODO_ | _TODO_ | 3000-6000 |
| `EXPORT_XPUB_K1` | _TODO_ | _TODO_ | _TODO_ | _TODO_ | _TODO_ | 80-200 |
| `EXPORT_XPUB_ED25519` | _TODO_ | _TODO_ | _TODO_ | _TODO_ | _TODO_ | (软实现，预计 ≈ Ed25519 sign 一半) |
| `OPEN_SECURE_CHANNEL` | _TODO_ | _TODO_ | _TODO_ | _TODO_ | _TODO_ | 100-300 |

填充建议：

1. 在 README 增加 "Performance" 节，附 `meowl bench --json` 输出。
2. 追加到 `docs/audit/07-perf.md`（本文件）的本表。
3. 把 JSON 输出 commit 到 `docs/audit/perf-baselines/<commit-sha>.json`，未来回归时 diff。

---

## 5. 预测的硬件 timing 旁路精度

回应 [`05-side-channels.md`](./05-side-channels.md) 中的 **A-16** 分析：

| 维度 | jcardsim (4.6 GHz) | J3R180 预测 (~25 MHz SC) |
| --- | --- | --- |
| 单次 `Bignat.mod` 内层 byte op | ~5-10 ns | ~500-1000 ns |
| 32 字节 `Bignat.mod` 全循环 | ~1-2 µs | ~100-200 µs |
| **PCSC reader jitter (USB-CCID)** | n/a (本地 JVM) | **5-50 ms** |
| **NFC reader jitter (PN532)** | n/a | **2-10 ms** |
| **直接驱动 + 紧密 polling**（攻击者最佳） | n/a | **0.1-1 ms** |

**结论**：`Bignat.mod` 的 ~100-200 µs 时间差被即便是 NFC reader 的 ~2 ms jitter 完全淹没。**只有写自己驱动 + 抓 transit 物理脉冲的攻击者**才能区分；这种攻击者也具备 die-probing 能力，已超出软件防御范围。

A-16 的 S2 等级**反映这种"理论可能但实操遥远"的特征**。

---

## 6. 性能优化建议

### 收益高、成本低（v1.x）

1. **共享 `MessageDigest.ALG_SHA_256` 实例** —— `Schnorr` 和 `Hkdf` 各持一个；可共享。**节省 ~50 字节 CAP**。
2. **预计算 `tagged_hash("BIP0340/aux")` 等的 SHA-512 inner state** —— 当前每次 sign 重算 `SHA256(tag) ‖ SHA256(tag) ‖ x`。预计算 inner state 节省 2 × 64 byte 的 SHA round。**节省 ~5 ms / Schnorr sign**。
3. **`Edwards25519.scalarMult` 缓存基点的 256 倍数** —— 1 KB 静态表换 30% sign 加速。**EEPROM ↔ 时间** 折衷。

### 收益高、成本高（v2）

1. **Limb-radix-2²⁶ Field25519 重写** —— 同时关闭 A-16 SCA finding 与 Ed25519 速度瓶颈。预计 -50% Ed25519 sign 时间。
2. **`Signature.ALG_EDDSA` 当 silicon 支持** —— 删除 ~5 KB 软件实现。需要 JC 3.1+。

### 不建议

- ❌ **打开 `KEY_AGREEMENT_DH_PLAIN_KEYDERIVATION_VARIANT`**（节省一次 `KeyAgreement` init）—— 平台行为差异，调试成本高。
- ❌ **批处理 sign**（一次 APDU sign 多个）—— 复杂度爆炸，与 ISO 7816-4 数据流 model 不符。

---

## 7. 总评

### 强项

1. **CAP on-card 21.7 KB** —— 相对 J3R180 40-50 KB 可用，留足 v2 升级空间。
2. **RAM 1.4 KB transient + 1.4 KB persistent** —— 无浪费。
3. **secp256k1 sign 路径 <10 ms** (jcardsim, ~硬件 1 s) —— 满足 wallet UX 实时签名需求。
4. **Ed25519 sign ~35 ms** (jcardsim, ~硬件 3.5 s) —— **位于 MEAP-6 budget 中位**，可接受。
5. **完整的 `BenchmarkSuite` (jcardsim) + `meowl bench` (硬件) 双轨** —— 性能回归门槛清晰。

### 弱项

1. **P-02 [S2]**：Ed25519 sign 在硬件上 ~3.5 s 接近用户耐心边界（普通 BTC 签名 ~150 ms 用户已习惯）。**修复路径**：v2 limb-radix。
2. **空缺真实硬件 baseline**：`meowl bench` 工具就绪，但本审计未运行（无可用卡）。**优先级**：拿到第一张 J3R180 卡后立即执行并 commit 基线 JSON。

### 实测复现命令汇总

```powershell
# 1. CAP 大小分析
.\gradlew.bat :applet:buildCap
$cap = "applet\build\cap\meowl-applet.cap"
[System.IO.Compression.ZipFile]::ExtractToDirectory($cap, "build\cap-inspect")
Get-ChildItem "build\cap-inspect" -Recurse -File | Sort-Object Length -Descending

# 2. jcardsim sign 延迟
.\gradlew.bat :tests:test --tests "social.meowl.applet.BenchmarkSuite" -Dbench=true

# 3. 硬件 sign 延迟（需要插卡 + SEEDED 状态）
.\gradlew.bat :tools:run --args="bench --pin 123456 --json"
```
