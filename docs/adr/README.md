<!--
SPDX-FileCopyrightText: 2026 meowl.social contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Architecture Decision Records

This directory tracks **why** the meowl-applet codebase looks the way it does. Each ADR captures a single decision: the context that forced it, the alternatives considered, the decision itself, and the consequences accepted.

ADRs are append-only — when a decision is revisited, write a new ADR that *supersedes* the old one and link both ways. Never edit a superseded ADR's outcome; the historical record matters.

The format follows [Michael Nygard's classic template](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions); a fillable copy lives in [`template.md`](./template.md).

## Conventions

- **File name**: `ADR-NNN-kebab-case-title.md` where `NNN` is a zero-padded incrementing integer.
- **Status lifecycle**: `Proposed` → `Accepted` → (optionally) `Deprecated` / `Superseded by ADR-MMM`.
- **Cross-links**: every ADR that touches code MUST point at the affected files using repository-absolute paths so a reviewer can jump straight to the implementation.
- **Audit traceability**: when an ADR closes a finding from `docs/audit/`, cite the finding ID (e.g. `AUDIT-001`, `NEWAUDIT-014`) in the *Context* section.

## Index

| ID | Title | Status | Touches |
| --- | --- | --- | --- |
| [ADR-001](./ADR-001-reset-to-factory-no-eeprom-wipe.md) | Reset-to-factory does not bulk-wipe EEPROM | Accepted | `MasterSeed`, `PinManager`, `PkiManager`, `MeowlApplet.wipe` |
| [ADR-002](./ADR-002-secure-channel-aes-cmac-kdf.md) | Secure Channel uses AES-CMAC-128 KBKDF, not HKDF-SHA-256 | Accepted | `SecureChannel`, `Kdf`, `MEAP-2` |
| [ADR-003](./ADR-003-cap-target-jc-3.0.5.md) | CAP file targets JavaCard 3.0.5, built with JCDK v26.0 | Accepted | `applet/build.gradle.kts`, `gradle/libs.versions.toml` |
| [ADR-004](./ADR-004-bignat-clean-room-rewrite.md) | BigNat will be clean-room rewritten to drop GPL upstream attribution | Proposed | `BigNat`, `REUSE.toml` |

## When to write a new ADR

Write one when any of these is true:

- A choice between two viable implementations is being made and reviewers will ask "why did we go with X?"
- A workaround is being added because of a hardware / silicon / SDK quirk and future maintainers will want to revisit it.
- A trade-off is being accepted (security vs. footprint, atomicity vs. BWT, simplicity vs. flexibility) — record the trade so the next maintainer doesn't unwind it accidentally.
- An audit finding is being deliberately deferred or accepted as a residual risk — the ADR is the durable record that closes the finding.
