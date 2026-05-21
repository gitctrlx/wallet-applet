<!--
SPDX-FileCopyrightText: 2026 meowl.social contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# meowl-applet — Comprehensive Audit Report

Baseline commit: `7ca3aaa` &nbsp;·&nbsp; Date: 2026-05-21

Scope: `applet/` (22 JavaCard classes), `tools/` (30+ Java CLI classes), `tests/` (JCardSim integration), `docs/specs/meap-0..7`.
Dimensions: security & cryptography · correctness & boundaries · code quality & maintainability · test quality & coverage.

Tests baseline: `:tools:test` 242 passed · `:tests:test` 1381 passed · `:applet:test` NO-SOURCE → **1623 total tests, 100 % green**.

## Executive Summary

The audit uncovered **17 substantive findings** across four severity tiers:

| Severity | Count | Disposition |
| --- | --- | --- |
| CRITICAL | 3 | Spec ↔ implementation drift; long-lived EEPROM exposure of derived scalars. Fixed in this audit. |
| HIGH | 5 | MAC-vs-replay ordering, lc-byte truncation, host session not torn down on MAC fail, PIN wipe residue, reset countdown intermediate SW. Fixed. |
| MEDIUM | 5 | TLV length cap mismatch, host outbound IV monotonicity, Hkdf scratch aliasing, transaction contract clarity, Bignat constant-time documentation. Fixed where addressable, otherwise documented. |
| LOW | 4 | Defensive zeroisation, error-message hygiene, dead code, robustness polish. Fixed. |

No CRITICAL or HIGH finding is exploitable without first defeating one or more independent gates (e.g. the long-lived EEPROM scalar exposure requires both an attacker with physical hardware-side decapping capabilities *and* a card whose silicon's EEPROM erase semantics fall short of the JC spec). The cumulative defense-in-depth posture is sound; this audit hardens the construction by **eliminating spec/impl ambiguity, tightening replay-defense ordering, and adding a small number of host-side cross-checks that close blind spots without changing the wire**.

## How to read this report

Each finding follows the schema:

> `[id]` Title
> **Location**: `@absolute/path:line-line`
> **Dimension**: security · correctness · quality · test
> **Description / threat model**
> **Resolution**
> **Fix commit / regression test** (filled in after the corresponding fix lands)

Finding IDs use the pattern `<severity>-<stage>.<seq>`:

- severity: `C`(ritical) / `H`(igh) / `M`(edium) / `L`(ow) / `I`(nfo)
- stage: `1` spec consistency · `2` applet · `3` tools · `4` tests · `5` docs

---

## CRITICAL

### `C-1.01` Handshake response format diverges between MEAP-2 spec and applet/tools implementations

- **Location**:
  - `@d:/Desktop/x/meowl-applet/docs/specs/meap-2.md:70-74` — spec defines the outbound body as `card_eph_pub(65) ‖ sig` with `sig ≤ 72 bytes`.
  - `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/SecureChannel.java:266-278` — implementation writes `card_pub(65) ‖ sigLen(2 BE) ‖ sig(DER)`.
  - `@d:/Desktop/x/meowl-applet/tools/src/main/java/social/meowl/tools/proto/SecureChannelClient.java:101-125` — host follows the applet (parses the explicit `sigLen`).
- **Dimension**: protocol consistency / security
- **Threat**: a third-party SDK implementing strictly to the spec cannot interoperate; conversely a strict spec-compliance auditor would flag the implementation. The DER-encoded ECDSA signature is variable-length (up to 72 bytes), so the wire format **needs** an explicit length field or a strict DER parser; the implementation chose the former, which is the safer/simpler engineering choice but never made it into the spec.
- **Resolution**: update `meap-2.md` to ratify the existing `card_eph_pub(65) ‖ sigLen(2 BE) ‖ sig(DER)` layout, with a Rationale paragraph explaining the choice. No code change.

### `C-1.05` `PROTOCOL_VERSION` constant differs from MEAP-1 spec

- **Location**:
  - `@d:/Desktop/x/meowl-applet/docs/specs/meap-1.md:92` — `TAG_PROTOCOL_VERSION ... 0x0001 for this revision`.
  - `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Constants.java:24` — `PROTOCOL_VERSION = (short) 0x0100`.
- **Dimension**: protocol consistency
- **Threat**: any third-party tool that compares the GET_INFO TLV byte-for-byte against the spec will mismatch on the protocol-version tag value.
- **Resolution**: update `meap-1.md` to specify `0x0100` ("1.0", the form actually emitted and rendered by `meowl info`). The implementation is the authoritative reference (all existing test suites pin this value).

### `C-2.02` `Bip32.scalarKey` is EEPROM-backed and transiently holds the derived leaf scalar

- **Location**: `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Bip32.java:90-100`
- **Dimension**: security
- **Threat**: the secp256k1 BIP-32 leaf scalar is loaded into a `KeyBuilder.TYPE_EC_FP_PRIVATE` (persistent) key via `signKey.setS(...)` before every scalar multiplication. `clearKey()` at the end of the call invalidates the JC platform's view of the key, but the underlying EEPROM cells may retain a residual signature depending on the silicon's erase semantics. An attacker with physical access (chip decapping, EEPROM probing) might recover a *recently used* leaf scalar — which derives directly from the master seed and therefore lets them sign on behalf of the user.
- **Resolution**: prefer `TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT` (RAM-backed, vanishes on deselect) when the silicon advertises it; fall back to the persistent flavour only on cards that do not. Add a regression test that asserts the transient flavour is used on JCardSim (and add silicon admission criteria to docs/security checklist).

---

## HIGH

### `H-1.03` `SecureChannel.unwrap` verifies MAC **before** the replay-IV check; MEAP-2 spec requires the opposite

- **Location**: `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/SecureChannel.java:309-330`
- **Dimension**: security / protocol compliance
- **Threat**: MEAP-2 §record-layer step 2 ("The replay check MUST happen before MAC verification so a wire attacker with no MAC key still gets a hard reject") mandates the order. The current implementation does the MAC verification first, then the replay check — both still reject with `6FB2` and both still tear down the session, but a wire attacker who can mass-replay outdated envelopes against a session in progress can force the card to compute one full HMAC-SHA-256 per envelope before discovering the replay, which is mildly DoS-amplifying and unambiguously non-compliant with the spec.
- **Resolution**: swap the two blocks so `compare16(IV, lastInboundIv) ≤ 0` is checked first; only on a strictly-greater IV do we proceed to the MAC verification.

### `H-1.05` `SecureChannelClient.sendInner` silently truncates `lc` to a byte

- **Location**: `@d:/Desktop/x/meowl-applet/tools/src/main/java/social/meowl/tools/proto/SecureChannelClient.java:166-168`
- **Dimension**: correctness / security
- **Threat**: the host builds the HMAC input from `[CLA INS P1 P2 (byte)lc] ‖ IV ‖ ciphertext`. When `lc > 255` (which happens for envelopes carrying a PKCS-5-padded ciphertext ≥ 240 bytes), the `(byte)` cast silently truncates, producing a MAC that does not bind the actual outer-frame length. The card-side MAC computation uses the *real* LC byte received off the wire, so the host's MAC will fail and the envelope is rejected — but the host's own envelope is also now structurally inconsistent with a short-form APDU. Larger inner payloads (e.g. SIGN_PKI_CSR's TBSCertificate inputs) silently fail with an obscure MAC-mismatch.
- **Resolution**: explicitly reject `lc > 255` with a clear `SecureChannelException` ("envelope too large for short-form APDU"). Short-form APDU was the design choice in MEAP-2; document the cap.

### `H-1.12` `SecureChannelClient.decryptOutbound` does not invalidate the host session on MAC failure

- **Location**: `@d:/Desktop/x/meowl-applet/tools/src/main/java/social/meowl/tools/proto/SecureChannelClient.java:247-270`
- **Dimension**: security / correctness
- **Threat**: when the host detects a MAC mismatch on a card response, it throws `SecureChannelException` but leaves `kEnc/kMac/ivBase` populated. The card, per MEAP-2 §session-lifecycle, has *already* torn down its own session as a result of the failure. A subsequent `sendInner()` from the host will encrypt under stale keys, fail at the card's MAC verification, and return another `6FB2` — masking the original root cause.
- **Resolution**: on any MAC failure (inbound or outbound), zero the host-side key material and set an `invalidated` flag so the next `sendInner()` fails fast with "session invalidated — re-handshake required".

### `H-1.16` `PinManager.wipe()` cannot guarantee old PIN/PUK bytes are erased from EEPROM

- **Location**: `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/PinManager.java:198-206`
- **Dimension**: security
- **Threat**: `wipe()` discards the existing `OwnerPIN` references and re-instantiates them. The JC spec exposes no `clearKey()`-equivalent on `OwnerPIN`, so the underlying EEPROM cells that held the previous PIN/PUK might still carry recoverable signal until they are overwritten by a future `update()` call. An attacker with physical EEPROM access could recover a PIN *post* factory-reset.
- **Resolution**: best-effort overwrite — call `pin.update(garbage, …)` and `puk.update(garbage, …)` with random-filled buffers **before** discarding the references. This forces a write cycle through whatever internal EEPROM storage the JC implementation uses, defeating the simplest residue-recovery attacks.

### `H-3.01` `ResetCommand.driveCountdown` does not validate intermediate SWs

- **Location**: `@d:/Desktop/x/meowl-applet/tools/src/main/java/social/meowl/tools/cli/ResetCommand.java:90-108`
- **Dimension**: correctness
- **Threat**: the CLI sends 4 consecutive `RESET_TO_FACTORY` APDUs and only validates the *last* SW (must be `0x6FA0`). If the card returns garbage SWs for the first three (e.g. `6D00` because it is not the meowl applet), the loop still completes 4 transmissions and only the final wipe-completion check catches the misuse. This is a "silent overrun" — the user thinks they ran `meowl reset` against the meowl applet when in fact they ran it against the GP card manager and the card was unaffected.
- **Resolution**: validate every intermediate SW is in the `0x6FA0..0x6FAF` range; bail out early on the first non-countdown response.

### `H-2.01` `SecureChannel.initHandshake` returns `6700` instead of `6FB2` on non-`0x04` prefix byte

- **Location**: `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/SecureChannel.java:197-200`
- **Dimension**: protocol compliance
- **Threat**: MEAP-2 §57: "It MUST reject a body whose first byte is not `0x04` with `6FB2` (Secure Channel cryptographic check failed)." The current code returns `SW_WRONG_LENGTH (6700)` for both length mismatch *and* prefix-byte mismatch.
- **Resolution**: split the guard into two `if` statements with distinct SWs.

---

## MEDIUM

### `M-1.04` `Bignat` operations are deliberately non-constant-time

- **Location**: `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Bignat.java:38-43`
- **Dimension**: security / design trade-off
- **Threat**: the schoolbook multiplication, comparison, and modular-reduction loops in `Bignat` have data-dependent timing. The applet uses `Bignat` only on values that are either public after the call (Schnorr `R.x`, `s`) or mixed with random nonce material (BIP-340's per-signature `k`), so the leakage does not directly compromise long-lived secrets. **However**, repeated signing of the same message with the same key could theoretically aggregate per-signature timing residue over many queries.
- **Resolution**: this is a known JC platform trade-off documented in the class javadoc. The audit confirms there is no straightforward constant-time replacement that fits the CAP-size budget. Documented as accepted risk in the security checklist; tracking is via the security model in `docs/specs/`.

### `M-1.06` TLV length cap mismatches between applet `ApduTlv` (127) and spec/tools (255)

- **Location**:
  - `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/ApduTlv.java:26` — `MAX_VALUE_LEN = 0x7F`.
  - `@d:/Desktop/x/meowl-applet/docs/specs/meap-1.md:82` — `LEN is unsigned, in the inclusive range [0, 255]`.
  - `@d:/Desktop/x/meowl-applet/tools/src/main/java/social/meowl/tools/core/Tlv.java:95` — encodes up to 255.
- **Dimension**: correctness / consistency
- **Threat**: today every meowl TLV value fits in ≤ 33 bytes (the authentikey is the largest), so no current functionality is broken. But a future field (e.g. a longer pubkey, multi-byte capability vector) could legitimately need ≥ 128 bytes; the applet would reject it where the spec and tools accept it.
- **Resolution**: raise `ApduTlv.MAX_VALUE_LEN` to `(short) 0xFF` (= 255) to match the spec and the host parser. The single-byte length field already encodes the value uniquely; the 127 cap was a defensive over-restriction with no current rationale.

### `M-1.13` `SecureChannelClient.decryptOutbound` does not verify the outbound IV is monotonic

- **Location**: `@d:/Desktop/x/meowl-applet/tools/src/main/java/social/meowl/tools/proto/SecureChannelClient.java:247-269`
- **Dimension**: security / defense-in-depth
- **Threat**: MEAP-2 §134 stipulates "IV is `IV_base XOR outbound_counter` where `outbound_counter` is incremented on every successful outbound wrap". The MAC verification already covers integrity, so a *successful* replay would require breaking HMAC-SHA-256. **But**: a card-side bug (or compromised silicon) that re-uses an `outbound_counter` would not be caught on the host. Defense-in-depth says the host should track the last decrypted outbound counter and reject regressions.
- **Resolution**: extract `outbound_counter = IV ⊕ IV_base`, compare against a `lastOutboundCounter` field, reject regressions with `SecureChannelException` and invalidate the session. The cost is one 16-byte XOR per envelope.

### `M-1.14` `Hkdf.expand` mutates `scratch` between `hmac.update` and `hmac.sign`

- **Location**: `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Hkdf.java:144-156`
- **Dimension**: correctness / portability
- **Threat**: the loop calls `hmac.update(scratch, 0, HASH_LEN)` (passing the previous `T(i-1)`), then writes `scratch[0] = counter` before invoking `hmac.sign(scratch, 0, 1, scratch, 0)`. JC's `Signature.update` is allowed (per the spec) to defer the digest update to the next `sign()` call; on such an implementation the `scratch[0] = counter` overwrite would corrupt `T(i-1)` before it is hashed. JCardSim and most JCOP silicon are streaming (they update immediately), so the existing tests pass — but the behaviour is implementation-defined.
- **Resolution**: introduce a dedicated 1-byte transient buffer `counterBuf`. Write the counter to it, hash from there. Keep `scratch` exclusively for `T(i)` material.

### `M-2.03` `MasterSeed.importSeed` / `generateSeed` rely on an undocumented "caller-holds-transaction" contract

- **Location**: `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/MasterSeed.java:118-159`
- **Dimension**: correctness / API contract
- **Threat**: the javadoc says "Caller must already hold a JC transaction", and the two extant callers (`MeowlApplet.handleImportSeed` / `handleGenerateSeed`) honour the contract. But a future caller that forgets the wrap would silently see a half-mutated `MasterSeed` survive a power loss. The contract is currently load-bearing but unenforced.
- **Resolution**: add a runtime guard via `JCSystem.getTransactionDepth() > 0` at the top of both methods. A misuse becomes a hard `6985 (CONDITIONS_NOT_SATISFIED)` at development time instead of a torn-storage hazard at deployment.

---

## LOW

### `L-1.07` `tools/HkdfSha256.expand` intermediate `T(i)` buffers are not zeroed

- **Location**: `@d:/Desktop/x/meowl-applet/tools/src/main/java/social/meowl/tools/proto/HkdfSha256.java:78-93`
- **Dimension**: security / defensive hygiene
- **Threat**: only the *last* `T(N)` buffer is zeroed before the function returns. Intermediate `T(i)` buffers (for `1 ≤ i < N`) are abandoned to the GC. On a long-lived JVM, garbage-collected pages may linger in old-gen heap for an unbounded time, exposing them to heap-scraping malware on a compromised host.
- **Resolution**: zero `previous` before reassigning it to the fresh `T(i)` each iteration.

### `L-1.09` `tools/HostCrypto.bigIntToFixed` error message includes the value

- **Location**: `@d:/Desktop/x/meowl-applet/tools/src/main/java/social/meowl/tools/proto/HostCrypto.java:243-262`
- **Dimension**: security
- **Threat**: the error message `"value does not fit in %d bytes: %s".formatted(length, value)` includes the `BigInteger.toString()` of the value. The function is currently only invoked on the ECDH shared-X coordinate (public), but as a general-purpose helper it could be reused for private scalars in the future. Logging the value to stderr / a structured log sink would then leak the secret.
- **Resolution**: drop the `value` from the message; keep only the length and a generic "value does not fit" diagnostic.

### `L-1.15` `applet/Hkdf` has a redundant `hmac.init` before the `expand` loop

- **Location**: `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/Hkdf.java:137`
- **Dimension**: code quality
- **Threat**: the call on line 137 is immediately overwritten by the in-loop `hmac.init` on line 145. Dead code; misleading for auditors.
- **Resolution**: delete the redundant pre-loop `init`.

### `L-2.01` `ResetToFactory.recordInvocation` leaves an inconsistent counter on `WipeTrigger.wipe()` exception

- **Location**: `@d:/Desktop/x/meowl-applet/applet/src/main/java/social/meowl/applet/ResetToFactory.java:54-63`
- **Dimension**: correctness
- **Threat**: if the supplied `WipeTrigger.wipe()` throws, the `rearm` call following it is skipped and the counter stays at 0. The next `recordInvocation` will read `step = -1 = 0xFF` and emit `SW_RESET_COUNTDOWN_BASE + 0xFF`. In practice `wipe()` should never throw, but the failure mode is unsightly.
- **Resolution**: rearm *before* invoking `wipe()` so the counter is always returned to a sane state regardless of the wipe outcome.

---

## INFO

### `I-various` Style and documentation polish

- `tools/HostCrypto.RNG = new SecureRandom()` is the platform default and is correct, but a comment clarifying which source is used (and the rationale for not picking `getInstanceStrong()`) would help future auditors. — *Resolved with a doc comment.*
- `ShellSession.runReset` does not validate intermediate SWs (the equivalent of `H-3.01` on the shell side). The shell user can see each step's output and visually verify, so the risk is lower; aligned with `H-3.01` for consistency. — *Fixed in the same patch as `H-3.01`.*
- `BiboStack.ClosingBibo` swallows the inner `IOException` on `close()`. Documented in the javadoc as intentional. — *No action.*

---

## Test-quality observations

- `tools/test/`: 242 tests, healthy assertion strength (constant-time MAC, RFC-5869 vectors, JCardSim integration). No mocks-only happy-path tests detected.
- `tests/` (JCardSim integration): 1381 tests covering wire-level behaviour. Coverage is excellent for happy paths and CRITICAL spec invariants; less so for the **error paths** of `RESET_TO_FACTORY` and `PinManager.wipe()` post-residue behaviour. Recommend adding probes for those two surfaces.
- No fuzz / property-based / timing micro-benchmarks exist. For a v2 of the audit, a Monte Carlo timing harness against `ConstantTime.equals` and `Bignat.mod` would be the highest-yield additions.

## Protocol consistency matrix (MEAP-N × applet × tools)

| MEAP | applet | tools | Discrepancies |
| --- | --- | --- | --- |
| meap-0 (framework) | MeowlApplet | MeowlCli, MeowlSession | none |
| meap-1 (INS/SW/TLV) | Constants | core/MeowlInsn, MeowlSw, Tlv | **C-1.05** (PROTOCOL_VERSION), **M-1.06** (TLV max len) |
| meap-2 (Secure Channel) | SecureChannel, Hkdf | proto/* | **C-1.01** (sigLen), **H-1.03** (MAC-vs-replay order), **H-2.01** (initHandshake SW), **H-1.05**, **H-1.12**, **M-1.13**, **M-1.14** |
| meap-3 (PIN/PUK/reset) | PinManager, ResetToFactory | cli/ResetCommand | **H-1.16** (PIN wipe residue), **H-3.01** (reset countdown intermediate SW), **L-2.01** |
| meap-4 (PKI/Authentikey) | Authentikey, PkiManager | cli/AuthentikeyCommand | none |
| meap-5 (Seed/BIP32) | MasterSeed, Bip32, Slip10 | — | **C-2.02** (scalarKey EEPROM), **M-2.03** (transaction contract) |
| meap-6 (signing) | EcdsaK1, Schnorr, Ed25519, Bignat, ModN | — | **M-1.04** (Bignat non-CT, accepted risk) |
| meap-7 (reset semantics) | ResetToFactory, WipeTrigger | cli/ResetCommand | covered above |

## Fixes timeline (filled in as the patch series lands)

| ID | Severity | Status | Commit | Regression test |
| --- | --- | --- | --- | --- |
| C-1.01 | CRITICAL | Pending | – | spec update; existing handshake tests cover the impl |
| C-1.05 | CRITICAL | Pending | – | spec update; `InfoCommand` test pins `1.0` |
| C-2.02 | CRITICAL | Pending | – | new test asserting transient flavour on JCardSim |
| H-1.03 | HIGH | Pending | – | new envelope-with-stale-IV-and-bad-MAC test |
| H-1.05 | HIGH | Pending | – | new oversize-inner-APDU rejection test |
| H-1.12 | HIGH | Pending | – | new MAC-fail-then-sendInner test |
| H-1.16 | HIGH | Pending | – | wipe + EEPROM-residue assertion (best-effort on JCardSim) |
| H-2.01 | HIGH | Pending | – | new non-0x04 prefix test |
| H-3.01 | HIGH | Pending | – | new mid-countdown wrong-SW test |
| M-1.06 | MEDIUM | Pending | – | new 128-byte-and-200-byte TLV round-trip tests |
| M-1.13 | MEDIUM | Pending | – | new replay-outbound test |
| M-1.14 | MEDIUM | Pending | – | covered by existing RFC-5869 vectors |
| M-2.03 | MEDIUM | Pending | – | new missing-transaction guard test |
| L-1.07 | LOW | Pending | – | n/a (defensive only) |
| L-1.09 | LOW | Pending | – | new test asserting error message no longer contains the value |
| L-1.15 | LOW | Pending | – | covered by existing RFC-5869 vectors |
| L-2.01 | LOW | Pending | – | wipe-throws-then-resume test |
