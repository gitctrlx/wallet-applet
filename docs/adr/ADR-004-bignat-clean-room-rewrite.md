<!--
SPDX-FileCopyrightText: 2026 meowl.social contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# ADR-004 — BigNat will be clean-room rewritten to drop GPL upstream attribution

- **Status**: Proposed
- **Date**: 2026-05-25
- **Author(s)**: meowl.social contributors
- **Touches**: `applet/src/main/java/social/meowl/applet/BigNat.java`, `REUSE.toml`
- **Closes audit findings**: NEWAUDIT-014 (file-name typo), follow-up clean-up of the GPL provenance chain

## Context

`BigNat.java` is the project's constant-time big-integer primitive: `ctEquals`, `ctLessThan`, `ctIsZero`, `ctSelectAdd`, `ctSelectSub`, `ctSelectNeg`, `addMod`, `subMod`, `multAsymmetric`, `ctAddLowerHalf`. Roughly 327 lines.

The current implementation is annotated in `REUSE.toml` as derived from Toporin's Satochip Biginteger (GPL-2.0-or-later), which itself derives from the Radboud University OV-chip 2.0 project (GPL-2.0-or-later). The GPLv2-or-later upgrade clause lets us re-license to AGPL-3.0-or-later, which is what we have done — but the attribution chain still has to be honoured.

Two pressure points motivate a rewrite:

1. **License clarity.** Each downstream re-distributor of CAP source has to inspect the REUSE metadata, traverse the GPLv2-or-later upgrade clause, and convince themselves the AGPL claim is sound. A clean-room implementation eliminates that branch of the analysis. We become the sole copyright holder of every line in the applet.
2. **Audit ergonomics.** v2 audit `NEWAUDIT-014` exposed that the current REUSE entry mis-spells the path (`Bignat.java` vs `BigNat.java`), so SPDX tools were silently skipping the upstream attribution. That is being fixed in Phase 0 mechanically, but the longer-term answer is to remove the upstream attribution entirely.

The functions in question are textbook constant-time idioms: sticky-mask comparison, two's-complement add-with-carry, schoolbook 16×16 → 32 multiplication. The math is public-domain mathematics; nothing in `BigNat` is a non-obvious cryptographic invention deserving of patent or trade-secret protection. The clean-room cost is moderate (a few engineer-days plus thorough RFC vector tests) and the long-term maintainability benefit is significant.

## Options considered

### Option A — Keep the current implementation, fix only the REUSE typo

- **Pros**: Zero risk; ship today; only a one-byte file-name fix.
- **Cons**: Permanent GPL upstream chain; downstream license analysis remains non-trivial; a future contributor accidentally re-introducing the typo silently breaks attribution again.

### Option B — Clean-room rewrite

Have an engineer who has not read Toporin / OV-chip 2.0 source write a fresh implementation from the public-domain algorithms (Knuth TAOCP Vol. 2 §4.3.1, Handbook of Applied Cryptography §14, RFC 8032 / 7748 reference behaviour). Verify byte-for-byte against `java.math.BigInteger` over 1000+ random inputs (jqwik) plus the existing RFC-vector suite.

- **Pros**: Single AGPL-3.0-or-later copyright; REUSE metadata simplifies to the project-wide template; future audits do not have to think about upstream chain.
- **Cons**: Engineering cost ~1 week (3-4 days writing, 2-3 days verifying); non-zero risk of subtly mis-implementing constant-time semantics; must keep legacy implementation under `.bak` until verification is complete to allow side-by-side regression checks.

### Option C — Replace BigNat with `javacard.framework.Util` + JC 3.1 BigNumber

JC 3.1 ships a `BigNumber` class with constant-time semantics promised by the spec.

- **Pros**: Zero implementation work; spec-blessed primitive.
- **Cons**: Requires JC 3.1 target, contradicting [ADR-003](./ADR-003-cap-target-jc-3.0.5.md). Locks out J3R180 fleet. Dead end until we move off 3.0.5.

## Decision

**Option B**. Phase 1 of the Q2-2026 refactor (`C:\Users\gitct\.windsurf\plans\comprehensive-refactor-de728f.md`) executes a clean-room rewrite of `BigNat.java`. Acceptance gates:

1. Existing `BigNatTest.java` passes verbatim (no test relaxation).
2. New jqwik fuzzing (Phase 3 wiring) compares each `BigNat` operation byte-for-byte against `java.math.BigInteger` over 1000+ random inputs.
3. `BarrettTest.java` (200+ random inputs) still passes — Barrett's hot path bottoms out in `BigNat.multAsymmetric`, so this is the ground-truth integration test.
4. CAP size delta ≤ ±2 % (not a primary goal, but a sanity check on accidental complexity creep).

When all four gates green, the legacy implementation is deleted from the working tree and `REUSE.toml` simplifies to a single entry covering all applet sources under the project-wide AGPL header.

## Consequences

### Positive

- `REUSE.toml` collapses; downstream license review is trivial.
- One fewer historical GPL chain to keep straight in audits.
- The clean-room process forces a re-derivation of constant-time semantics, which catches latent assumptions baked into the upstream code.

### Negative / accepted residual risk

- Engineering time (~1 week) that does not produce new user-facing functionality.
- Non-zero risk of regression if the four acceptance gates miss a corner case. Mitigated by retaining the legacy file under `.bak` until Phase 6 closeout.

### Mitigations and follow-ups

- Side-by-side fuzz: a temporary test `BigNatLegacyParityTest` runs every operation through both implementations on identical inputs and asserts byte equality. Removed once the legacy file is deleted.
- ADR closeout: when the rewrite lands, this ADR's status flips from `Proposed` to `Accepted` and references the merge commit.
- If acceptance gates fail and we cannot resolve within budget, we fall back to Option A and document the abandoned attempt in a new ADR rather than silently rolling back.

## References

- `applet/src/main/java/social/meowl/applet/BigNat.java`
- `REUSE.toml` — current upstream attribution
- `docs/audit/2026-05-25-comprehensive-audit-v2-supplement.md` — NEWAUDIT-014
- `C:\Users\gitct\.windsurf\plans\comprehensive-refactor-de728f.md` — Phase 1 schedule
- Knuth, *The Art of Computer Programming* Vol. 2, §4.3.1 (Multiple-precision arithmetic)
- A. Menezes, P. van Oorschot, S. Vanstone, *Handbook of Applied Cryptography*, §14
