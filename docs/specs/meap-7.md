---
meap: 7
title: Status-word reference
description: Single-source enumeration of every two-byte status word a conforming applet may emit, with triggering conditions and owning MEAP per code.
status: Final
type: Standards Track
category: Wire
created: 2026-05-19
requires: [1]
author: meowl.social contributors
---

# MEAP-7: Status-word reference

## Abstract

This MEAP enumerates every two-byte status word (SW) a conforming applet may emit, the precise triggering condition for each, and the MEAP that owns the wire path on which the status word can occur. It is a single-source lookup table — every other MEAP references this MEAP rather than redefining its own status-word table — so host SDKs and auditors can reason about the entire failure surface from one document.

## Motivation

A multi-MEAP specification spreads status-word definitions across multiple files. Without a consolidated table, host SDKs end up implementing a switch / dispatch on `(INS, SW)` tuples reverse-engineered from each MEAP's *Negative path* section, with subtle disagreements between MEAPs (does `6700` mean "data field too short" or "data field wrong length"? does the answer depend on the INS?). MEAP-7 fixes the table once and for all: every status word has exactly one definition, every triggering condition cites a single normative source, and every host SDK can build its dispatch off the table directly.

## Specification

### Reading the table

| Column | Meaning |
| ------ | ------- |
| **SW** | The two-byte status word, in `SW1 SW2` hex form. |
| **Mnemonic** | The constant name in [`Constants`](../../applet/src/main/java/social/meowl/applet/Constants.java). |
| **Source** | The standard or document the value originates from. |
| **Triggering condition** | What the card MUST emit this status word for. Conditions are grouped by INS where the status word's interpretation depends on context. |
| **MEAP** | The MEAP that defines the wire path. |

Where a status word's low byte carries a payload (e.g. `63Cn` for PIN retries, `6FAn` for reset countdown), the payload-bearing bits are notated with a lowercase letter and explained in the *Triggering condition* column.

### Standard ISO 7816-4 status words

| SW | Mnemonic | Source | Triggering condition | MEAP |
| -- | -------- | ------ | -------------------- | ---- |
| `9000` | (no constant) | ISO 7816-4 | Successful execution. The response data field, if any, is the payload defined by the corresponding MEAP. Hosts MUST treat any other status word as a failure. | all |
| `63Cn` | `SW_PIN_RETRIES_BASE + n` | ISO 7816-4 | `VERIFY_PIN`, `CHANGE_PIN` or `UNBLOCK_PIN` failed authentication; `n ∈ {1, 2}` retries remain. The card transitions to `6983` once `n` would otherwise drop to 0. | [3](./meap-3.md) |
| `6700` | `SW_WRONG_LENGTH` | ISO 7816-4 | Data field length does not match the layout the INS requires. Specifically: ECDSA / Schnorr inner data length ≠ `1 + 4·depth + 32`; Ed25519 inner data length < `1 + 4·depth`; `EXPORT_XPUB` inner data length ≠ `2 + 4·depth`; `IMPORT_SEED` `seed_len ∉ [16, 64]`; `SETUP` PIN/PUK lengths outside policy; `VERIFY_PIN` length outside `[4, 16]` (does NOT consume a retry); `IMPORT_PKI_CERT` chunk parameters out of range; the Secure Channel envelope shorter than the minimum `IV + 1 block + MAC = 48` bytes. | [1](./meap-1.md), [2](./meap-2.md), [3](./meap-3.md), [4](./meap-4.md), [5](./meap-5.md), [6](./meap-6.md) |
| `6982` | `SW_SECURITY_STATUS_NOT_SATISFIED` | ISO 7816-4 | The command requires `pin_verified` to be true and it is not. Hosts MUST run `VERIFY_PIN` inside the current Secure Channel session and retry. | [3](./meap-3.md), [5](./meap-5.md), [6](./meap-6.md) |
| `6983` | `SW_AUTH_BLOCKED` | ISO 7816-4 | PIN retry counter exhausted (host must `UNBLOCK_PIN` with the PUK), OR PUK retry counter exhausted (card is permanently bricked). The two conditions return the same code; hosts can disambiguate via the lifecycle FSM and prior request history. | [3](./meap-3.md) |
| `6985` | `SW_CONDITIONS_NOT_SATISFIED` | ISO 7816-4 | Lifecycle FSM forbids the command in the current state, OR `LOCK_PKI` called without a committed certificate, OR `IMPORT_PKI_CERT(WRITE)` / `(FINALIZE)` called before a successful `(INIT)`, OR seed validity check failed (master-key or per-child), OR a SLIP-10 path index has the hardened bit clear. | [3](./meap-3.md), [4](./meap-4.md), [5](./meap-5.md) |
| `6A86` | `SW_INCORRECT_P1P2` | ISO 7816-4 | `IMPORT_PKI_CERT` P1 not in `{0x00, 0x01, 0x02}`, OR `EXPORT_XPUB` curve byte not in `{0x00, 0x01}`. | [4](./meap-4.md), [5](./meap-5.md) |
| `6D00` | `SW_INS_NOT_SUPPORTED` | ISO 7816-4 | INS not implemented at the frame it was sent on. Specifically: any inner-band INS sent at the outer frame; any unallocated INS at either frame. | [1](./meap-1.md) |
| `6E00` | `SW_CLA_NOT_SUPPORTED` | ISO 7816-4 | CLA byte ≠ `0x80`. | [1](./meap-1.md) |

### Applet-private extensions in the `6Fxx` range

The `6Fxx` range is reserved by ISO 7816-4 for application-defined errors. The card uses three sub-bands:

- `6FA0`–`6FAF` — reset-to-factory countdown.
- `6FB0`–`6FBF` — lifecycle and Secure Channel state errors.
- `6FE0`–`6FEF` — implementation / silicon errors.

| SW | Mnemonic | Triggering condition | MEAP |
| -- | -------- | -------------------- | ---- |
| `6FA0` | `SW_RESET_COUNTDOWN_BASE + 0` | The fourth consecutive `RESET_TO_FACTORY` invocation; the wipe has been performed. The next `GET_INFO` shows lifecycle `UNINITIALIZED` with the `authentikey` preserved. Often referred to as *reset-done*. | [3](./meap-3.md) |
| `6FA1` | `SW_RESET_COUNTDOWN_BASE + 1` | Three consecutive `RESET_TO_FACTORY` invocations have been received; one more is required to trigger the wipe. | [3](./meap-3.md) |
| `6FA2` | `SW_RESET_COUNTDOWN_BASE + 2` | Two consecutive `RESET_TO_FACTORY` invocations have been received. | [3](./meap-3.md) |
| `6FA3` | `SW_RESET_COUNTDOWN_BASE + 3` | One `RESET_TO_FACTORY` invocation has been received; the counter starts at 4 on every applet `select()` and is rearmed by every non-`RESET_TO_FACTORY` APDU. | [3](./meap-3.md) |
| `6FB0` | `SW_LIFECYCLE_INVALID` | Lifecycle FSM forbids this transition or the command's state-precondition is not met. Examples: a non-`SETUP` command in `PERSONALIZED`; `IMPORT_SEED` outside `SETUP_DONE`; `EXPORT_XPUB` outside `SEEDED`; an illegal forward edge passed to `transitionTo`. | [3](./meap-3.md), [5](./meap-5.md), [6](./meap-6.md) |
| `6FB1` | `SW_SECURE_CHANNEL_REQUIRED` | An inner-band INS was reached without a currently-open Secure Channel. The host MUST `INIT_SECURE_CHANNEL` and retry. | [2](./meap-2.md) |
| `6FB2` | `SW_SECURE_CHANNEL_FAILED` | An ECDH or HKDF or signature step in `INIT_SECURE_CHANNEL` produced a non-recoverable cryptographic failure, OR an `OPEN_SECURE_CHANNEL` envelope failed replay / MAC / padding verification, OR the inbound `IV` did not strictly exceed the previous `last_inbound_IV`. | [2](./meap-2.md) |
| `6FE0` | `SW_UNSUPPORTED_FEATURE` | A required JavaCard feature is not advertised by the platform (e.g. `Signature.ALG_HMAC_SHA_512` at applet `install`), OR the JC native ECDSA returned a non-conformant DER signature. | [1](./meap-1.md), [5](./meap-5.md), [6](./meap-6.md) |
| `6FE1` | `SW_INTERNAL_ERROR` | A should-never-happen sentinel. Specifically: the BIP-340 tagged-hash output reduced to zero mod `n` during Schnorr signing — BIP-340 mandates failing the signature in that case; the probability is ≈ `2⁻²⁵⁶`. Hosts SHOULD treat as transient and retry; subsequent calls draw fresh aux randomness and will not collide with overwhelming probability. | [6](./meap-6.md) |

### Encoding rules

- A conforming applet MUST emit the status word as the last two bytes of every APDU response, big-endian (`SW1 SW2`).
- The reset-countdown range `6FAn` MUST be returned exactly as `0x6FA0 + remaining` with `remaining ∈ [0, 4]`. The applet MUST NOT use lower-nibble values of `6FAn` outside `[0, 4]`; future MEAPs MAY allocate them but this revision does not.
- The PIN-retry range `63Cn` MUST be returned exactly as `0x63C0 + remaining` with `remaining ∈ {1, 2}`. The card transitions to `6983` once `remaining` would drop to `0`; it does NOT emit `63C0`.
- A conforming applet MUST NOT emit any other `6Fxx` value than those listed above. A future MEAP MAY allocate further values; until that MEAP exists, hosts MAY treat unknown `6Fxx` as a hard error and refuse to process the card.

### Error-code stability

Every status word in this table is **frozen**. A successor MEAP MAY add new status words but MUST NOT change the meaning, scope or value of any existing one. This is the core stability guarantee MEAP-7 makes to host SDK authors: a host that dispatches on `0x6FB2` today will dispatch on the same condition forever.

## Rationale

### Three-band `6Fxx` allocation

Sub-banding the `6Fxx` range by purpose lets a reader of the status word identify the failure category at a glance:

- `6FAn` — temporal / progress (reset countdown).
- `6FBn` — lifecycle / channel state.
- `6FEn` — silicon / implementation.

The bands `6FCn` and `6FDn` remain unallocated for forward expansion (e.g. a future fingerprint-template band, a future audit-log band).

### Why `63Cn` for PIN retries, not `6Fxx`

`63Cn` is the ISO 7816-4 standard encoding for "wrong PIN, `n` retries remain". Every smartcard library on the host side knows how to decode it. Inventing a meowl-private encoding would be hostile.

### Why `6983` for both PIN-blocked and PUK-blocked

ISO 7816-4 defines `6983` as "Authentication method blocked". The card uses the same status word for both PIN-blocked (recoverable via `UNBLOCK_PIN`) and PUK-blocked (terminal). Hosts disambiguate via the lifecycle FSM and prior request history; the card cannot disambiguate without exposing more state than `6983` itself permits, and inventing two separate codes would just shift the disambiguation problem to the wire (a host facing `6FB3` "PUK blocked" would still need to know whether the card is recoverable).

### Why `6700` rather than INS-specific length codes

ISO 7816-4 has more granular length codes (`6CXX` for "wrong Le, expected XX bytes"; `67XX` for various length-related sub-codes). MEAP-7 uses only the generic `6700` because the granularity is not actionable: a host that sees `6700` already knows from the INS spec what the expected length is, and a sub-code does not change what the host has to do (re-encode the data field per the INS layout). The simplification eliminates whole categories of subtle disagreements between MEAP authors.

### `6FE1` is a should-never-happen sentinel

`6FE1` is documented for completeness but a conforming applet should never emit it in normal operation. Its existence is purely defensive: BIP-340's spec mandates failing if the tagged-hash output reduces to zero, and a card without a sentinel for that case would have to silently produce an invalid signature. The probability is well below any practical concern, but the wire MUST have a code for it.

## Backwards Compatibility

N/A — v1.0 greenfield.

## Test Vectors

The reference test suite covers every status word in the table:

| SW | Test class / test |
| -- | ----------------- |
| `9000` | every test class — every successful happy-path assertion |
| `63Cn` | [`PersonalisationTest.Pin.wrongPinReturnsRetriesBase`](../../tests/src/test/java/social/meowl/applet/PersonalisationTest.java) |
| `6700` | every test class' negative-path nested class (`*Negative` / `*Gating`) |
| `6982` | [`HdDerivationTest.HdGating.exportXpubRequiresPin`](../../tests/src/test/java/social/meowl/applet/HdDerivationTest.java); [`EcdsaK1Test.Gating.signRequiresPin`](../../tests/src/test/java/social/meowl/applet/EcdsaK1Test.java); analogous tests in [`SchnorrK1Test`](../../tests/src/test/java/social/meowl/applet/SchnorrK1Test.java), [`Ed25519SigningTest`](../../tests/src/test/java/social/meowl/applet/Ed25519SigningTest.java) |
| `6983` | [`PersonalisationTest.Pin.exhaustingRetriesBlocksPin`](../../tests/src/test/java/social/meowl/applet/PersonalisationTest.java) |
| `6985` | [`PersonalisationTest.Pki.lockPkiWithoutCertFails`](../../tests/src/test/java/social/meowl/applet/PersonalisationTest.java); [`HdDerivationTest.SeedInstall.invalidMasterKey`](../../tests/src/test/java/social/meowl/applet/HdDerivationTest.java) |
| `6A86` | [`HdDerivationTest.ExportXpubNegative.unknownCurveByte`](../../tests/src/test/java/social/meowl/applet/HdDerivationTest.java); [`Ed25519SigningTest.Negative.nonHardenedRejected`](../../tests/src/test/java/social/meowl/applet/Ed25519SigningTest.java) |
| `6D00` | [`MeowlAppletTest.Routing.unknownInsAtOuterFrame`](../../tests/src/test/java/social/meowl/applet/MeowlAppletTest.java) |
| `6E00` | [`MeowlAppletTest.Routing.wrongClaRejected`](../../tests/src/test/java/social/meowl/applet/MeowlAppletTest.java) |
| `6FA0`–`6FA3` | [`MeowlAppletTest.ResetToFactory`](../../tests/src/test/java/social/meowl/applet/MeowlAppletTest.java) — pins each of the four countdown values |
| `6FB0` | [`HdDerivationTest.HdGating.exportBeforeSeeded`](../../tests/src/test/java/social/meowl/applet/HdDerivationTest.java); analogous tests for the signing primitives |
| `6FB1` | [`SecureChannelTest.openSecureChannelWithoutHandshake`](../../tests/src/test/java/social/meowl/applet/SecureChannelTest.java) |
| `6FB2` | [`SecureChannelTest`](../../tests/src/test/java/social/meowl/applet/SecureChannelTest.java) — covers tampered MAC, replayed IV, modified ciphertext, malformed padding |

`6FE0` and `6FE1` are not exercised in the test suite because their triggering conditions cannot be reached from a conforming JC implementation (they would require a non-conformant silicon DER output for `6FE0` or a SHA-256 collision for `6FE1`). Their wire encoding is asserted statically by the constants table in [`Constants.java`](../../applet/src/main/java/social/meowl/applet/Constants.java).

## Reference Implementation

- Status-word constants: [`Constants`](../../applet/src/main/java/social/meowl/applet/Constants.java) — every named mnemonic in the tables above corresponds to a declaration in this file. The bare `9000` success code is written verbatim at each call site rather than via a constant.
- Reference test classes: enumerated in *Test Vectors* above.

## Security Considerations

### Information leakage through status words

Every status word the card emits is observable on the wire (the outer frame is unencrypted; the inner frame is encrypted but the outer status word is plaintext, per [MEAP-2 §Outbound](./meap-2.md)). A wire attacker can therefore distinguish "wrong PIN" (`63Cn`) from "PIN blocked" (`6983`) from "lifecycle invalid" (`6FB0`) etc. without breaking the Secure Channel. This is acceptable because the same information is recoverable from the lifecycle FSM (which `GET_INFO` exposes unauthenticated by design — see [MEAP-1 §`GET_INFO` payload](./meap-1.md)) and from the PIN retry counter (which the user already had to know to drive the wallet).

A status word MUST NOT carry an inferable secret. Specifically:

- `63Cn` carries the retry counter `n`, which is public per [MEAP-3](./meap-3.md).
- `6FAn` carries the reset countdown, which is public per [MEAP-3](./meap-3.md).
- No status word carries any byte of any cryptographic secret (PIN, PUK, seed, scalar) directly or by inference.

### Failure-mode obscurity

Concentrating all status words in a single MEAP means an attacker reading the spec immediately knows every code the card might emit. This is intentional. Security through obscurity has no place in a hardware-wallet protocol; the security comes from the cryptographic primitives the wire defends, not from the wire itself being mysterious. A host SDK that handles all enumerated status words gracefully is more robust than one that handles only the codes it has empirically observed.

## Copyright

This document is licensed under the AGPL-3.0-or-later licence the rest of the project uses; see [LICENSE](../../LICENSE).
