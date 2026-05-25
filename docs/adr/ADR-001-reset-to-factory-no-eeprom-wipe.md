<!--
SPDX-FileCopyrightText: 2026 meowl.social contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# ADR-001 — Reset-to-factory does not bulk-wipe EEPROM

- **Status**: Accepted
- **Date**: 2026-05-25
- **Author(s)**: meowl.social contributors
- **Touches**: `applet/src/main/java/social/meowl/applet/MasterSeed.java`, `applet/src/main/java/social/meowl/applet/PinManager.java`, `applet/src/main/java/social/meowl/applet/PkiManager.java`, `applet/src/main/java/social/meowl/applet/MeowlApplet.java`
- **Closes audit findings**: AUDIT-001

## Context

`RESET_TO_FACTORY` must clear every secret bound to the previous owner so a re-personalised card cannot leak the prior seed, PIN, PUK or BIP-32 derivation material. The naïve implementation wipes every persistent byte that ever held a secret in one transaction.

Two hardware constraints make the naïve approach hostile:

- **Block waiting time (BWT)** on contactless ISO/IEC 14443. A J3R180 in NFC mode has roughly 1.5 s of useful BWT before the host PCD aborts the transaction. A 64-byte seed wipe + 32-byte PIN scrub + 32-byte PUK scrub + 1024-byte cert wipe + lifecycle/auth-fail counter writes, all inside a single `JCSystem.beginTransaction()`, repeatedly tripped the BWT on real silicon during the post-Phase-1 audit window.
- **EEPROM endurance**. Each row rewrite consumes a wear cycle. Bulk-wiping every reset path (especially the 1 KiB cert buffer) on every test run accelerates wear noticeably during integration testing.

Additionally, `OwnerPIN.update` exhibited a J3R180-specific quirk where wiping with a length different from the next `SETUP` length caused subsequent `OwnerPIN.check` to fail despite matching bytes (see `PinManager.wipeInTx` javadoc). The earlier "scrub-then-update" approach was abandoned for that reason.

`AUDIT-001` flagged this as a defense-in-depth hole: a card that is reset but then re-deselected (no follow-up `SETUP` / `IMPORT_SEED`) leaves prior secret bytes physically resident in EEPROM until the next provisioning write, which physical memory readout could in principle recover.

## Options considered

### Option A — Bulk-wipe everything in one transaction

Walk every persistent byte that ever held a secret on every `RESET_TO_FACTORY`.

- **Pros**: Defense-in-depth maximised; no residual bytes survive the reset.
- **Cons**: BWT-bound on contactless; wear-cycle hostile; tripped by the J3R180 OwnerPIN quirk above.

### Option B — Logical wipe + invariant on next provisioning

Zero only the bookkeeping (PIN-provisioned flag, `MasterSeed.seedLen`, `PkiManager.importedLen`, `LifecycleState`) and rely on the invariant *the next `SETUP` / `IMPORT_SEED` / `IMPORT_PKI_CERT` fully overwrites the affected cells before the host can read them*. The bookkeeping gates every read API (`requireProvisioned`, `requireSeeded`, `hasCert`), so logically the prior bytes are unreadable.

- **Pros**: Single-shot atomic reset commits within BWT; no extra wear; sidesteps the OwnerPIN quirk.
- **Cons**: Residual bytes physically present until next write; relies on caller invariants that future contributors must not break.

### Option C — Incremental scrub across multiple APDUs

Spread the wipe over several APDUs so each commits within BWT individually.

- **Pros**: Gets the wipe done on contactless without violating BWT.
- **Cons**: Reset is no longer atomic; partial-wipe state needs new SW codes; complicates the lifecycle state machine; new attack surface (interrupted-reset states).

## Decision

**Option B**. `RESET_TO_FACTORY` performs a logical wipe inside a single transaction (`MeowlApplet.wipe()` calls `MasterSeed.wipeInTx`, `PinManager.wipeInTx`, `PkiManager.wipeInTx`, `LifecycleState.transitionToInTx(UNINITIALIZED)`) and the next provisioning command is contractually required to repaint the cells.

This decision is the one that lets us run the existing reset loop end-to-end on contactless without BWT timeouts, preserves the OwnerPIN.check invariant on J3R180, and keeps the wipe atomic — properties Options A and C cannot deliver simultaneously.

## Consequences

### Positive

- Reset commits within BWT on contactless J3R180.
- No surprise OwnerPIN.check failures after `UNBLOCK_PIN` / `CHANGE_PUK`.
- EEPROM wear is bounded to the cells actually rewritten on next provisioning.

### Negative / accepted residual risk

- After `RESET_TO_FACTORY` and **before** the next `SETUP` / `IMPORT_SEED` / `IMPORT_PKI_CERT`, the prior owner's secret bytes physically remain in EEPROM. Recovery requires either a logic flaw exposing those cells (gated by `requireProvisioned` / `requireSeeded` / `hasCert`) or invasive physical memory readout (decapping). Both are out of scope for our threat model.

### Mitigations and follow-ups

- Every read API gates on the bookkeeping flags. Bypassing those flags is a Critical-severity bug, not a routine one.
- A regression test (`ResetToFactoryInvariantTest`, planned in Phase 3 of the Q2-2026 refactor) exercises `IMPORT_SEED(seedA)` → reset × 4 → `IMPORT_SEED(seedB, shorter)` → derivation must not reveal seedA. The test inspects the simulator's persistent buffer to confirm the new write fully covers the old.
- This ADR should be revisited if (a) we move off J3R180 to silicon with different BWT / OwnerPIN behaviour, or (b) the threat model adds physical-memory-readout adversaries.

## References

- `docs/audit/2026-05-25-comprehensive-audit.md` — AUDIT-001
- `applet/src/main/java/social/meowl/applet/MasterSeed.java` — `wipeInTx` javadoc
- `applet/src/main/java/social/meowl/applet/PinManager.java` — `wipeInTx` javadoc (the OwnerPIN quirk note)
- `applet/src/main/java/social/meowl/applet/PkiManager.java` — `wipeInTx` javadoc (cert buffer rationale)
- ISO/IEC 14443-4 §7.2 — BWT semantics
