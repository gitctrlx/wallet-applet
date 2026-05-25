<!--
SPDX-FileCopyrightText: 2026 meowl.social contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# ADR-002 — Secure Channel uses AES-CMAC-128 KBKDF, not HKDF-SHA-256

- **Status**: Accepted
- **Date**: 2026-05-25
- **Author(s)**: meowl.social contributors
- **Touches**: `applet/src/main/java/social/meowl/applet/SecureChannel.java`, `applet/src/main/java/social/meowl/applet/Kdf.java`, `tools/src/main/java/social/meowl/tools/sc/KdfCmac.java`, `docs/specs/meap-2.md`

## Context

MEAP-2 needs a Secure Channel KDF and record-layer MAC. The earlier MEAP-2 draft (pre-Phase-1) used HKDF-SHA-256 + truncated HMAC-SHA-256. That worked end-to-end but cost ~13 KiB of CAP space (HMAC-SHA-256 software engine + HKDF Extract/Expand + helper truncation). On a J3R180 with bounded CAP budget this is significant.

NXP J3R180 has a native AES-CMAC engine (verified via the JCAlgTest profile pinned in `3rdparty/`). Using it directly removes the SHA-256 software engine entirely, replacing it with a thin CMAC-based KBKDF (NIST SP 800-108 feedback mode).

## Options considered

### Option A — Keep HKDF-SHA-256

Stay with the earlier design for compatibility and well-understood security analysis.

- **Pros**: Standard, broadly studied; existing host SDKs implement HKDF natively.
- **Cons**: 13 KiB CAP overhead on J3R180; no native silicon acceleration; brings a SHA-256 software engine that nothing else needs.

### Option B — AES-CMAC-128 KBKDF + AES-CMAC-128 record-layer MAC

Use NIST SP 800-108 feedback-mode KBKDF over AES-CMAC-128 for both extract and expand, and AES-CMAC-128 for the MAC field.

- **Pros**: Drops 10.22 % of CAP size (≈13 KiB); silicon-accelerated CMAC; one MAC primitive handles both KDF and record layer; 128-bit forgery resistance equals truncated HMAC-SHA-256-128.
- **Cons**: BREAKING CHANGE to MEAP-2 for any external host SDK; KBKDF is less battle-tested in IoT contexts than HKDF (but is a NIST-approved construction).

### Option C — Skip the Secure Channel entirely

Lean on PCSC-T1 + GP SCP02/03 for confidentiality.

- **Pros**: Zero applet code; reuses ecosystem.
- **Cons**: GP SCP requires CardManager keys we don't ship in production; couples privacy guarantees to the GP card lifecycle; no NFC story.

## Decision

**Option B**. The Secure Channel uses AES-CMAC-128 KBKDF (NIST SP 800-108 feedback mode) for both Extract and Expand, and AES-CMAC-128 for the record-layer MAC. The wire envelope is `[CLA INS P1 P2 LC] ‖ IV(16) ‖ ciphertext ‖ MAC(16)`. Keying material is `K_enc(32) ‖ K_mac(16) ‖ IV_base(16)` = 64 bytes (down from 80).

The `meowl-sc-v1` info label is reused; a future SC revision MUST allocate a fresh label.

## Consequences

### Positive

- CAP size drops by 13,128 bytes (10.22 %), recovered for future protocol features.
- J3R180 native CMAC instruction is exercised; KDF and record-layer MAC share one cryptographic primitive.
- 128-bit forgery resistance is preserved (matches the prior 16-byte truncated HMAC-SHA-256 exactly).

### Negative / accepted residual risk

- Any external host SDK written against the HKDF-SHA-256 design needs to be reimplemented. We considered this an acceptable cost because there were no production external SDKs at the time of cutover; the only canonical host implementations live in this repo (`tools/SecureChannelClient`, `tests/KdfCmacHost`).
- AES-CMAC-128 KBKDF has fewer published cryptanalysis papers than HKDF, though it is a NIST SP 800-108 construction with formal security proof.

### Mitigations and follow-ups

- Byte-for-byte test vectors live in `tests/KdfCmacHost.java`, ensuring the host and applet KDF implementations cannot drift.
- Real-card verification (`:tests:realCardTest --tests SecureChannelTest`) is the canonical correctness gate; jcardsim does not exercise the silicon-native CMAC.
- A future SC revision (MEAP-2 v2) MUST use a different `info` label; the v1 label is permanently bound to this construction.

## References

- `docs/specs/meap-2.md` — MEAP-2 specification
- `applet/src/main/java/social/meowl/applet/Kdf.java`
- `tools/src/main/java/social/meowl/tools/sc/KdfCmac.java`
- NIST SP 800-108 — Recommendation for Key Derivation Using Pseudorandom Functions
- RFC 4493 — The AES-CMAC Algorithm
- RFC 5869 — HKDF (the option we left behind)
