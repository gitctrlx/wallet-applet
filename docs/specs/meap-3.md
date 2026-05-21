---
meap: 3
title: Lifecycle, PIN/PUK and reset-to-factory
description: Four-state lifecycle FSM, single PIN/PUK authentication policy, three authorisation rules and the multi-step reset-to-factory primitive.
status: Final
type: Standards Track
category: Wire
created: 2026-05-19
requires: [1, 2]
author: meowl.social contributors
---

# MEAP-3: Lifecycle, PIN/PUK and reset-to-factory

## Abstract

This MEAP specifies the four-state lifecycle finite-state machine that gates every command, the single-PIN single-PUK authentication policy that gates every sensitive command after personalisation, and the multi-step reset-to-factory primitive that returns the card to its initial state without erasing the long-lived `authentikey`. Together these three mechanisms determine **when** any given INS is allowed to run, given the card's current configuration and the current Secure Channel session.

## Motivation

A hardware-wallet applet has hard ordering constraints between its commands: the manufacturer must personalise the card before the user can set their PIN, the user must set their PIN before they can load a seed, and the user must load a seed before they can sign anything. Encoding those constraints in implicit per-command checks would scatter authority logic throughout the codebase and make it impossible to audit which command runs when. MEAP-3 instead exposes a single explicit FSM and a single explicit PIN session flag, and pins each INS's gate to one of three discrete authorisation rules.

The reset primitive presents a separate concern. A single APDU that wipes the seed would be a denial-of-service primitive trivially exploitable by any wire attacker with momentary contact (a tap-and-grab NFC terminal, an unattended USB host) — the user loses their entire wallet to a single forged byte sequence. Reset must therefore be deliberate, multi-step, and recoverable from honest mistakes.

## Specification

### Lifecycle FSM

A conforming applet MUST implement a 4-state lifecycle FSM with a strictly linear forward path and a single retrograde edge that collapses to the initial state:

```text
                                                                           reset-to-factory
                  ┌────────────────────────────────────────────────────────────────────────┐
                  │                                                                       │
                  ▼                                                                       │
        ┌─────────────────┐  PKI  ┌───────────────┐  SETUP  ┌────────────┐  IMPORT_SEED   │
        │ UNINITIALIZED   ├──lock─▶ PERSONALIZED  ├────────▶ SETUP_DONE  ├──────or────────┘
        │     0x00        │       │     0x01      │         │    0x02    │  GENERATE_SEED
        └─────────────────┘       └───────────────┘         └────────────┘
                                                                  │
                                                                  ▼
                                                           ┌────────────┐
                                                           │   SEEDED   │
                                                           │    0x03    │
                                                           └────────────┘
```

State byte encoding (TLV value of `TAG_LIFECYCLE_STATE` per [MEAP-1](./meap-1.md)):

| Byte | Mnemonic | Meaning |
| ---- | -------- | ------- |
| `0x00` | `UNINITIALIZED` | Fresh applet instance. The `authentikey` exists per [MEAP-4](./meap-4.md); no PKI cert, no PIN, no seed. |
| `0x01` | `PERSONALIZED` | Manufacturer PKI flow has completed and the manufacturer certificate is locked into EEPROM. |
| `0x02` | `SETUP_DONE` | User has installed PIN and PUK. No seed loaded. |
| `0x03` | `SEEDED` | Master seed loaded; HD derivation and signing are available. |

A conforming applet MUST advance the state via `transitionTo` only along the four legal forward edges, and MUST collapse to `UNINITIALIZED` only via the reset path. Any attempted forward transition that does not match the legal edge above MUST raise `6FB0` (lifecycle invalid). The applet MUST NOT expose any APDU that triggers a non-monotonic forward jump.

The current state byte is exposed verbatim through `GET_INFO`'s `TAG_LIFECYCLE_STATE` so that hosts can drive personalisation and setup deterministically without polling for command-specific error codes.

### PIN / PUK policy

A conforming applet MUST implement exactly one PIN and one PUK, both backed by JavaCard's `OwnerPIN`. The single PIN gates every sensitive inner-band command except those listed under *No-auth rule* below. The single PUK only unblocks the PIN; it has no other authority.

#### Length and retry policy

| Credential | Min length | Max length | Default retry counter |
| ---------- | ---------- | ---------- | --------------------- |
| PIN        | 4 bytes    | 16 bytes   | 3                     |
| PUK        | 8 bytes    | 32 bytes   | 5                     |

A conforming applet MUST NOT enforce a charset on either credential — the host wallet MAY impose ASCII or UTF-8 constraints in its own UI but the card treats both as opaque byte strings. A conforming host SHOULD generate the PUK from a CSPRNG and SHOULD encourage the user to back it up alongside the seed.

#### `SETUP` (INS `0x20`)

Provisions PIN and PUK in a single atomic transaction. Reachable in state `PERSONALIZED`; transitions to `SETUP_DONE` on success.

Inner data layout:

```text
[pin_len(1)] [pin(pin_len)] [puk_len(1)] [puk(puk_len)]
```

A conforming applet MUST verify `pin_len ∈ [4, 16]` and `puk_len ∈ [8, 32]` and reject any other length with `6700`. The four mutations (install PIN, install PUK, set the *provisioned* internal flag, advance lifecycle) MUST commit inside a single `JCSystem.beginTransaction()` / `commitTransaction()` block; a torn power-off mid-transaction MUST leave the card in `PERSONALIZED` rather than in any intermediate state.

A conforming applet MUST reject `SETUP` in any state other than `PERSONALIZED` with `6985` (conditions of use not satisfied). A second `SETUP` after `SETUP_DONE` is therefore impossible without a prior `RESET_TO_FACTORY`.

#### `VERIFY_PIN` (INS `0x21`)

Sets the session-scoped `pin_verified` flag if the supplied PIN matches the stored PIN. Reachable in any state ≥ `SETUP_DONE`.

Inner data: the PIN bytes verbatim (no length prefix; the card uses the data field length).

Status words:

| Outcome | Status word |
| ------- | ----------- |
| Correct PIN | `9000` |
| Wrong PIN, `n ∈ {1, 2}` retries remain | `63C` ‖ `n` |
| Wrong PIN, retry counter exhausted | `6983` (auth blocked) |
| Length outside `[4, 16]` | `6700` (does NOT consume a retry) |
| Lifecycle gate violation | `6FB0` |

A conforming applet MUST NOT consume a retry on a length-violating `VERIFY_PIN`: a constant `6700` carries no information about the PIN, so a host bug that sends an over-length PIN must not brick the card. This rule is enforced by the reference implementation and asserted by `PersonalisationTest`.

A conforming applet MUST clear the `pin_verified` flag on every event that closes the Secure Channel session: `select()`, `INIT_SECURE_CHANNEL` re-handshake, `RESET_TO_FACTORY` completion, or any cryptographic failure in the record layer (per [MEAP-2 §Session lifecycle](./meap-2.md)).

#### `CHANGE_PIN` (INS `0x22`)

Rotates the PIN. Reachable in any state ≥ `SETUP_DONE`.

Inner data layout:

```text
[old_pin_len(1)] [old_pin(old_pin_len)] [new_pin_len(1)] [new_pin(new_pin_len)]
```

The handler MUST verify `old_pin` against the stored PIN inline (the *self-verify rule* of *Authorisation rules* below); a stale `pin_verified` flag from a prior `VERIFY_PIN` is **not** sufficient. A conforming host SHOULD treat the card as the source of truth for PIN-rotation auth even if it cached a recent `VERIFY_PIN` success.

#### `CHANGE_PUK` (INS `0x23`)

Rotates the PUK. Reachable in any state ≥ `SETUP_DONE`.

Inner data layout: identical to `CHANGE_PIN` but for PUK.

The handler MUST verify the supplied old PUK against the stored PUK inline, **and** MUST require the `pin_verified` flag from a prior `VERIFY_PIN` in the same Secure Channel session. The double-gate is deliberate: a stolen card whose PIN is unknown to the attacker must not be hijackable by rotating the PUK. This is the *session-verify rule + self-verify rule combined* (see *Authorisation rules*).

#### `UNBLOCK_PIN` (INS `0x24`)

Unblocks the PIN counter using the PUK and installs a fresh PIN. Reachable in any state ≥ `SETUP_DONE`.

Inner data layout:

```text
[puk_len(1)] [puk(puk_len)] [new_pin_len(1)] [new_pin(new_pin_len)]
```

A conforming applet MUST verify the supplied PUK against the stored PUK and consume one PUK retry **regardless of whether the new-PIN candidate satisfies the length policy**: an attempt to unblock with a malformed new PIN is a wasted PUK attempt. Exhausting the PUK retry counter MUST permanently brick the card (status `6983` thereafter; no further `UNBLOCK_PIN` is ever accepted).

### Authorisation rules

Every gated INS MUST follow exactly one of three rules:

- **Self-verify rule** — the command's own data field carries the credential and the handler verifies it inline. The card does NOT consult the session `pin_verified` flag. Used by `CHANGE_PIN` and `UNBLOCK_PIN`.
- **Session-verify rule** — the handler checks `pin_verified` (i.e. a prior successful `VERIFY_PIN` in the *same* Secure Channel session). Used by `CHANGE_PUK`, `IMPORT_SEED`, `GENERATE_SEED`, `EXPORT_XPUB` and every signing INS.
- **No-auth rule** — the command does not require PIN authorisation. Used by `GET_INFO`, `GET_AUTHENTIKEY`, `RESET_TO_FACTORY`, `INIT_SECURE_CHANNEL`, `OPEN_SECURE_CHANNEL` (the envelope itself), and the PKI-personalisation INSes (`EXPORT_PKI_PUBKEY`, `SIGN_PKI_CSR`, `IMPORT_PKI_CERT`, `EXPORT_PKI_CERT`, `LOCK_PKI`) which run before the user PIN exists.

A conforming applet MUST allocate every new INS to exactly one of these rules; it MUST NOT invent a fourth rule (per-command counter, per-INS PIN slot, ACL bitmask) without a successor MEAP that supersedes this one.

### `RESET_TO_FACTORY` (INS `0x03`, outer-frame)

A conforming applet MUST implement a multi-step reset trigger:

- An internal `remaining` counter starts at **4** on every applet `select()` and is set back to 4 by **every non-`RESET_TO_FACTORY` APDU** (including outer-frame APDUs and any `OPEN_SECURE_CHANNEL` envelope, regardless of the inner INS or its outcome).
- Each `RESET_TO_FACTORY` APDU decrements `remaining` by 1.
- After the decrement, the applet emits status word `0x6FA0 + remaining`. The first three invocations therefore return `0x6FA3`, `0x6FA2`, `0x6FA1` in succession. The fourth invocation triggers the wipe and returns `0x6FA0` (the *reset-done* code; see [MEAP-7](./meap-7.md)).

`RESET_TO_FACTORY` carries no inner data. P1, P2 and LC MUST be `0x00`; the applet MUST NOT inspect them.

A conforming applet MUST perform the wipe as follows, in atomic order:

1. Zeroise the master seed (BIP-32 master `k_master(32) ‖ c_master(32)` and SLIP-10 master, per [MEAP-5](./meap-5.md)).
2. Clear the *seeded* flag.
3. Clear PIN and PUK material and counters.
4. Clear the manufacturer certificate (if any).
5. Tear down the Secure Channel (`K_enc`, `K_mac`, `IV_base`, `last_inbound_IV`, `pin_verified`).
6. Reset the lifecycle FSM to `UNINITIALIZED`.

A conforming applet MUST preserve the `authentikey` keypair across the wipe per [MEAP-4](./meap-4.md). Step 6 is the only retrograde lifecycle transition this MEAP allows.

A conforming host SHOULD render the countdown to the user in a confirmation UI ("3 more confirmations needed to wipe the card"). The status-word encoding gives the host the remaining count without any extra round-trip.

### Status words owned by this MEAP

| Status word | Meaning |
| ----------- | ------- |
| `9000` | success |
| `6700` | wrong length |
| `6982` | security status not satisfied — Secure Channel not open or `pin_verified` not set when required |
| `6983` | auth blocked — PIN retry counter exhausted, or PUK retry counter exhausted |
| `6985` | conditions of use not satisfied — lifecycle FSM forbids this command in the current state |
| `63Cn` | wrong PIN, `n` retries remain (`n ∈ {0..2}`; `n = 0` is reported as `6983` instead) |
| `6FA0` | reset done — final invocation triggered the wipe |
| `6FA1`–`6FA3` | reset countdown — `n` more `RESET_TO_FACTORY` APDUs needed |
| `6FB0` | lifecycle invalid — illegal forward transition or wrong-state command |

The complete status-word reference is [MEAP-7](./meap-7.md).

## Rationale

### One PIN, one PUK

The MUSCLE framework that Satochip inherits supports up to eight PIN and eight PUK slots with per-slot ACL bitmasks. In practice Satochip uses only slot 0 for everything. The complexity of the multi-slot model buys nothing for a personal hardware wallet — every sensitive command is gated by the same single PIN — and exposes more state than it secures (each unused slot is a counter the firmware must maintain across power loss). MEAP-3 therefore specifies exactly one PIN and one PUK; the resulting authority logic is a few lines and trivially auditable.

### Three authorisation rules

Naïve designs pin every gate to the session-verify rule (i.e. `pin_verified` controls everything after `VERIFY_PIN`). That is wrong for two flows:

- `CHANGE_PIN` cannot use the session flag because if the attacker stole the card *after* the user verified their PIN, the session flag would already be set and the attacker could rotate the PIN to one only they know. The self-verify rule forces the attacker to know the current PIN.
- `CHANGE_PUK` cannot use only the self-verify rule because the PUK alone is not sufficient authority to rotate the PUK (an attacker who steals the card and the PUK could rotate the PUK before the user notices). Combining the self-verify rule on the old PUK with the session-verify rule on `pin_verified` raises the bar to "attacker knows current PUK *and* current PIN", which matches the intuitive trust model.

Encoding this distinction as three explicit rules rather than ad-hoc per-INS checks makes the gate matrix auditable in one table.

### Multi-step reset

Satochip's [original specification](https://github.com/Toporin/SatochipApplet) requires `RESET_TO_FACTORY` four times consecutively. MEAP-3 keeps this design unchanged: the threat model — drive-by NFC, momentary unattended access — is unchanged in 2026, and four invocations strikes the right balance between defeating brief contact and not punishing an honest user who fat-fingers one or two presses. Each non-reset INS rearms the counter, so an honest user just needs to send any other APDU to undo a stray reset attempt.

### `authentikey` survives reset

The `authentikey` is the card's stable identity ([MEAP-4](./meap-4.md)). Wiping it on reset would mint a new card identity at every wipe, breaking any client-side TOFU pin and breaking the manufacturer PKI's notion of "this card". Reset should make the card *forget the user* but keep being the same physical card; preserving `authentikey` is what implements that.

### Atomic `SETUP`

A previous draft of the personalisation flow committed PIN install, PUK install, the *provisioned* flag and the lifecycle advance in two transactions. A torn power-off between them could leave the card in a state where `VERIFY_PIN` was gated out by the FSM (still `PERSONALIZED`) but `SETUP` was rejected by the *provisioned* flag (already true) — bricking the card without recourse short of `RESET_TO_FACTORY`. The single-transaction rule in this MEAP closes that hazard; the regression is asserted by `PersonalisationTest`.

## Backwards Compatibility

N/A — v1.0 greenfield.

## Test Vectors

Reproducible vectors require an attacker model where the host can control time and the applet's state across power cycles. The reference test class `PersonalisationTest` exercises the invariants:

- A fresh applet starts in `UNINITIALIZED`. `GET_INFO`'s `TAG_LIFECYCLE_STATE` is `0x00`.
- `SETUP` is rejected with `6985` until the PKI flow completes and the FSM enters `PERSONALIZED`.
- A successful `SETUP` advances to `SETUP_DONE` and a fresh `VERIFY_PIN` returns `9000`.
- A `VERIFY_PIN` with under-length data returns `6700` and does NOT decrement the retry counter.
- Three wrong-PIN `VERIFY_PIN` calls return `63C2`, `63C1`, `6983` in succession; the fourth call returns `6983` regardless of input.
- After three wrong PINs, `UNBLOCK_PIN` with the correct PUK and a length-policy-compliant new PIN succeeds; an `UNBLOCK_PIN` with a length-violating new PIN consumes a PUK retry and returns `6700`.
- Three `RESET_TO_FACTORY` APDUs return `6FA3`, `6FA2`, `6FA1`. Sending any other APDU rearms the counter; another `RESET_TO_FACTORY` again returns `6FA3`. A fourth consecutive `RESET_TO_FACTORY` returns `6FA0` and the next `GET_INFO` shows `TAG_LIFECYCLE_STATE = 0x00` while `TAG_AUTHENTIKEY_PUBKEY` is unchanged.

## Reference Implementation

- Lifecycle FSM: [`LifecycleState`](../../applet/src/main/java/social/meowl/applet/LifecycleState.java).
- PIN / PUK manager: [`PinManager`](../../applet/src/main/java/social/meowl/applet/PinManager.java).
- Reset trigger: [`ResetToFactory`](../../applet/src/main/java/social/meowl/applet/ResetToFactory.java) and the `wipe()` callback in [`MeowlApplet`](../../applet/src/main/java/social/meowl/applet/MeowlApplet.java).
- Reference test class: [`PersonalisationTest`](../../tests/src/test/java/social/meowl/applet/PersonalisationTest.java) for `SETUP` / `VERIFY_PIN` / `CHANGE_PIN` / `CHANGE_PUK` / `UNBLOCK_PIN`; [`MeowlAppletTest`](../../tests/src/test/java/social/meowl/applet/MeowlAppletTest.java) for the outer-frame `RESET_TO_FACTORY` countdown; [`LifecycleStateTest`](../../tests/src/test/java/social/meowl/applet/LifecycleStateTest.java) for the FSM forward-edge predicate.

## Security Considerations

### Brute-force surface

The PIN retry counter is 3. An attacker with sustained physical access can submit at most three guesses before the card blocks; combined with the PUK's 5-attempt counter (gated on the same physical access), the brute-force surface is at most 15 sequential guesses. For PINs of even 4 digits (10⁴ candidates) this is far too small to meaningfully threaten a randomly chosen PIN. Hosts SHOULD encourage users to choose at least 6-digit PINs and SHOULD reject obviously weak choices (`123456`, `000000`, etc.) at the UI layer.

### `OwnerPIN.check` timing

The JavaCard 3.x specification does NOT document `OwnerPIN.check` as constant-time. A timing side channel on `check` would in principle leak whether the first byte of the candidate matches the first byte of the stored PIN, accelerating brute-force. We accept this residual leak because the bounded retry counter (3 attempts then permanent block) reduces the attacker's signal-to-noise ratio below any usable level: the attacker would have to recover the PIN from at most three `check` calls with timing variance dwarfed by the secure-element clock noise. Future implementations MAY layer a constant-time wrapper over `check`; the reference implementation does not.

### Reset as DoS

Even with the four-step countdown, a sufficiently determined attacker with sustained contact-interface access can still wipe the card. This is unavoidable without a physical confirmation button on the device; MEAP-3's design only deters drive-by attacks, not patient ones. Users who deploy meowl cards in adversarial physical environments SHOULD enclose them in tamper-evident packaging or use them in conjunction with an external confirmation device.

### PIN-flag scope

Tying `pin_verified` to the Secure Channel session (rather than to the lifetime of the applet) means an attacker who steals an authenticated card cannot use a side channel to keep the card "alive" past the host's deselect. The card's deselect is **not** something the attacker can prevent; even a contactless tap of a different applet AID forces deselect, and the card vacates the PIN flag in the same atomic action that it tears down the Secure Channel session.

## Copyright

This document is licensed under the AGPL-3.0-or-later licence the rest of the project uses; see [LICENSE](../../LICENSE).
