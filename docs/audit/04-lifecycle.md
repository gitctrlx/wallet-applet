# 04 — 生命周期与状态机审计

<!-- SPDX-FileCopyrightText: 2026 meowl.social contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

`LifecycleState` 四态 FSM、PIN/PUK 状态、PKI 状态、master seed 状态、reset-to-factory 原子性的审计。

## 1. 状态机定义

### 四态 FSM（`LifecycleState.java`）

```text
UNINITIALIZED ──[LOCK_PKI]──→ PERSONALIZED ──[SETUP]──→ SETUP_DONE ──[IMPORT_SEED|GENERATE_SEED]──→ SEEDED
       ▲                                                                                               │
       └──────────────────────[RESET_TO_FACTORY × 4]─────────────────────────────────────────────────┘
```

| 状态 | 字节值 | 进入触发 | 退出触发 |
| --- | --- | --- | --- |
| `UNINITIALIZED` | `0x00` | install / RTF | LOCK_PKI |
| `PERSONALIZED` | `0x01` | LOCK_PKI | SETUP |
| `SETUP_DONE` | `0x02` | SETUP | IMPORT_SEED / GENERATE_SEED |
| `SEEDED` | `0x03` | IMPORT_SEED / GENERATE_SEED | RTF |

### 转移规则（`LifecycleState.isLegalForward`）

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\LifecycleState.java:38-46
public static boolean isLegalForward(byte from, byte to) {
    return (from == UNINITIALIZED && to == PERSONALIZED)
            || (from == PERSONALIZED && to == SETUP_DONE)
            || (from == SETUP_DONE && to == SEEDED);
}
```

- 仅允许相邻**前进**（`from → from+1`）。
- 自循环、回退、跳跃皆非法 → `SW_LIFECYCLE_INVALID`（`0x6FF1`）。
- `LifecycleStateTest.{adjacentForwardLegal, selfTransitionIllegal, backwardIllegal, skippingIllegal, pastTerminalIllegal}` 全覆盖。

---

## 2. 命令与状态门

| 命令 | 允许的进入态 | 副作用 |
| --- | --- | --- |
| GET_INFO | any | — |
| RESET_TO_FACTORY | any | RTF 倒计时 / 终态 wipe → UNINITIALIZED |
| OPEN/CLOSE_SECURE_CHANNEL | any | session 状态 |
| EXPORT_PKI_PUBKEY | any | — |
| EXPORT_PKI_CERT | ≥ PERSONALIZED | — |
| **SIGN_PKI_CSR** | UNINITIALIZED | 用 authentikey 签 host-supplied digest |
| **IMPORT_PKI_CERT** | UNINITIALIZED | EEPROM 写入 |
| **LOCK_PKI** | UNINITIALIZED → PERSONALIZED | 锁定 PKI cert |
| SETUP | PERSONALIZED → SETUP_DONE | install PIN/PUK |
| VERIFY_PIN | ≥ SETUP_DONE | session validated |
| CHANGE_PIN / CHANGE_PUK / UNBLOCK_PIN | PIN flow | rotate stored PIN/PUK |
| IMPORT_SEED / GENERATE_SEED | SETUP_DONE + PIN verified → SEEDED | install master seed |
| EXPORT_XPUB / SIGN_* | SEEDED + PIN verified | HD 派生 + 签名 |

---

## 3. PIN/PUK 状态

### `PinManager` 后端

- `OwnerPIN pin` (`PIN_RETRY_LIMIT = 3`, `PIN_MAX_LEN = 32`)
- `OwnerPIN puk` (`PUK_RETRY_LIMIT = 5`, `PUK_MAX_LEN = 32`)
- `provisioned[1]`：1 字节 EEPROM 标志，`!= 0` 表示 SETUP 已运行。

### Session validation

- `pin.isValidated()` 由 JC OwnerPIN 平台维护。
- `clearSession()` 在 `MeowlApplet.select` 中调用 → 每次 `SELECT` 重置已验证状态。
- `pin.reset()` 在 `OwnerPIN.update` 时自动触发。

### 重试计数器语义

| 命令 | 失败时计数器消耗 | 失败 SW |
| --- | --- | --- |
| VERIFY_PIN | 是 | `0x63Cn` (n = 剩余次数) |
| VERIFY_PIN（已 blocked） | 不消耗 | `0x69F0` |
| VERIFY_PIN（长度错） | **不消耗** ⚠ | `0x6700` |
| CHANGE_PIN（旧 PIN 错） | 是（旧 PIN check 走 verifyPin） | `0x63Cn` |
| CHANGE_PIN（新 PIN 政策错） | **不消耗** | `0x6700` |
| CHANGE_PUK（旧 PUK 错） | 是（PUK） | `0x63Cn` |
| UNBLOCK_PIN（PUK 错） | 是（PUK） | `0x63Cn` |
| UNBLOCK_PIN（新 PIN 政策错） | **是**（per `docs/specs/meap-3.md`） | `0x6700` |

### Findings

- **L-01 [S2]**：`verifyPin` 长度错不消耗计数器。这是 _by design_：长度错是 host 端协议失误，不是猜测 PIN。但这意味着攻击者可以无限发送 `length=0` 不消耗计数器 —— 不会泄露 PIN。
  - **判定**：S4 / 设计明确。`PinManagerTest.verifyPinLengthErrorDoesNotConsumeRetry` pin 这条契约。

无 actionable finding。

---

## 4. PKI 状态

### 三步 chunked import 状态机（`PkiManager.java`）

```text
IMPORT_STATE_IDLE ──[INIT]──→ IMPORT_STATE_STAGED ──[FINALIZE]──→ IMPORT_STATE_IDLE (with importedLen > 0)
                                  │
                                  └──[WRITE × N]──→ (still STAGED)
```

- `INIT`：声明 `totalLen`，归零整个 `cert[]`，`importState ← STAGED`。
- `WRITE`：在 `[0, totalLen)` 内写片段。要求 `importState == STAGED`。
- `FINALIZE`：`importedLen ← stagedTotalLen`，`importState ← IDLE`。

### 锁定（LOCK_PKI）

- `LifecycleState.transitionToInTx(PERSONALIZED)`。
- 之后 `SIGN_PKI_CSR` / `IMPORT_PKI_CERT` 都因状态门 (UNINITIALIZED) 拒绝。
- `EXPORT_PKI_PUBKEY` / `EXPORT_PKI_CERT` 仍可用。

### 跨 RTF 的持久性

| 字段 | RTF 后 |
| --- | --- |
| `cert[]` | 清零 |
| `importedLen` / `stagedTotalLen` / `importState` | 重置 |
| **authentikey 私钥** | **保留**（MEAP-4 §"authentikey survives reset"） |

### Finding A-14（重述）

`SIGN_PKI_CSR` 在 UNINITIALIZED 阶段不需要 PIN，授权完全依赖 SC 握手（依赖 manufacturer 的 ECDH 密钥控制）。Severity S4 / 设计明确。详见 [`01-applet-files.md`](./01-applet-files.md#finding-a-14--uninitialized-阶段的-sign_pki_csr-仅由-sc-保护-s4--info)。

---

## 5. Master seed 状态

### `MasterSeed` 后端

- `bip32Material[64]` (EEPROM)：`k_master(32) ‖ c_master(32)` for secp256k1。
- `slip10Material[64]` (EEPROM)：同上 for ed25519。
- `seededFlag[1]`：1 字节 EEPROM。

### 进入 SEEDED 状态的两条路径

| 命令 | 数据流 | seed 来源 |
| --- | --- | --- |
| IMPORT_SEED | host → seed → applet → HMAC × 2 → master | host 持有 |
| GENERATE_SEED | applet → CSPRNG seed → applet → HMAC × 2 → master + emit seed back to host (via SC) | 卡上 |

### 不变性

- `importSeed` / `generateSeed` 都强制 `JCSystem.getTransactionDepth() != 0`（行 106-108、144-146）—— 调用方必须握有事务。
- `seededFlag[0] = 1` 在事务内最后才设置 → 半成品状态不可见。
- `requireValidBip32MasterKey` 在事务内拒绝 `parse256(I_L) == 0 || ≥ n`（概率 < 2⁻¹²⁷）。

### Finding A-15（重述）

GENERATE_SEED 在 SC wrap 前 seed 明文驻 APDU buffer ~10 µs。Severity S4 / 设计明确。详见 [`01-applet-files.md`](./01-applet-files.md)。

---

## 6. Reset-to-Factory 原子性

### 触发链（`MeowlApplet.handleResetToFactory` + `ResetToFactory`）

```text
RTF #1 → SW = 0x6F00 + 3 (倒计数 3)
RTF #2 → SW = 0x6F00 + 2 (倒计数 2)
RTF #3 → SW = 0x6F00 + 1 (倒计数 1)
RTF #4 → 倒计数到 0 → 重置计数器 → wipe() → SW = 0x6FFF
```

`Constants.RESET_REQUIRED_INVOCATIONS = 4`，`SW_RESET_COUNTDOWN_BASE = 0x6F00`。

### Wipe 顺序（`MeowlApplet.wipe()`）

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\MeowlApplet.java:482-499
public void wipe() {
    secureChannel.reset();   // transient, 事务外 OK
    JCSystem.beginTransaction();
    try {
        pinManager.wipeInTx();
        pkiManager.wipeInTx();
        masterSeed.wipeInTx();
        state.resetInTx();
        resetCountdown.rearm();   // 也在事务内？检查
        JCSystem.commitTransaction();
    } catch (RuntimeException e) {
        JCSystem.abortTransaction();
        throw e;
    }
}
```

- **PIN/PKI/seed/lifecycle/RTF counter** 全部在**单个**事务内提交 → 全成功或全回滚。
- **authentikey** 不在 wipe 列表内 —— 由设计明示。

### 防 wipe 中失败的反模式

`ResetToFactory.recordInvocation`（`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\ResetToFactory.java:30-47`）在 step→0 时**先重置计数器再调 wipe**：

```@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\ResetToFactory.java:30-47
public void recordInvocation(WipeTrigger trigger) {
    byte step = (byte) (remaining[0] - 1);
    if (step > 0) {
        remaining[0] = step;
        ISOException.throwIt((short) (Constants.SW_RESET_COUNTDOWN_BASE + step));
    }
    // step == 0 — terminal step. Rearm BEFORE wipe so a wipe() exception cannot
    // leave remaining[0] at zero and emit a spurious 0x6FFF on the next call.
    remaining[0] = Constants.RESET_REQUIRED_INVOCATIONS;
    trigger.wipe();
    ISOException.throwIt(Constants.SW_RESET_COUNTDOWN_BASE);
}
```

`ResetToFactoryTest.wipeExceptionDoesNotCorruptCounter` pin 这个反模式：模拟 `wipe()` 抛 `RuntimeException`，验证 `remaining[0]` 已被 rearm 到 4 而非 0。

### Findings

无。RTF 实现的原子性（事务）、防失败语义（先 rearm 再 wipe）、单点入口（仅 INS_RESET_TO_FACTORY 路径）都齐备。

---

## 7. 跨命令的状态依赖

### Session-scoped 依赖

| 命令 | 依赖 | 实现位置 |
| --- | --- | --- |
| SIGN_* | `pin.isValidated()` | `MeowlApplet` 各 sign handler 入口 |
| IMPORT_SEED / GENERATE_SEED | 同上 | handleImportSeed / handleGenerateSeed |
| EXPORT_XPUB | 同上 | handleExportXpub |
| CHANGE_PIN | `pin.isValidated()` (旧 PIN 通过) | PinManager |

### 跨 select 持久化

- `select()` 调 `clearSession()` → `pin.reset()` → 必须重新 VERIFY_PIN。
- SC 是 transient（CLEAR_ON_DESELECT）→ 必须重新 OPEN_SECURE_CHANNEL。

### Finding L-02 [S4 — Info] — Session 标志在 RTF 后被 select 自然清

**位置**：`@d:\Desktop\x\meowl-applet\applet\src\main\java\social\meowl\applet\MeowlApplet.java:117-120`

`select()` 在 RTF 触发的 `wipe()` **之后**也会被调一次（如果 host 重连）。`clearSession()` 已经在 RTF wipe 之前由 `pinManager.wipeInTx()` 隐式触发（重建 OwnerPIN 实例自然 reset）。但若 host 不重连立刻 select，session validated 标志仍可能在 EEPROM 内残留 —— 这是一个 wipe → 下一次 select 之间的窗口。

**判定**：S4。`OwnerPIN` 的 `isValidated()` 实际上是 transient bit，`new OwnerPIN()` 重建会重置；`pinManager.wipeInTx()` 重建实例。所以 wipe 后立即下一条命令也会因 `provisioned[0] == 0` 被拒。

**修复建议**：无。当前已正确。

---

## 8. 总评

### 强项

1. **FSM 是纯函数 + 状态字段集中**（`LifecycleState`）—— 测试容易，规范清晰。
2. **所有持久写都在事务内** —— `PinManager.setupInTx`、`MasterSeed.importSeed/generateSeed`、`PkiManager.importInit/Write/Finalize`、`MeowlApplet.wipe()`。
3. **RTF 原子性** —— PIN/PKI/seed/state/counter 全部在单事务内，全成功或全回滚。
4. **Wipe 防失败** —— rearm 在 wipe 之前，避免 wipe 失败导致 counter 卡零。

### 弱项

无 actionable finding。状态机与生命周期是审计中最干净的部分。

### 单条信息级提示

- **A-14**：`SIGN_PKI_CSR` 在 UNINITIALIZED 阶段不需要 PIN，依赖 SC 握手 —— 需要在 README 或 javadoc 顶部更显式地说明 manufacturer-only 的威胁模型。
