# Architecture Decision Records

This directory stores the **Architecture Decision Records (ADRs)** that document every architecturally-significant decision in `meowl-applet`. Each ADR is an immutable record: once accepted, it is never edited in place — superseding decisions add a new ADR that references and supersedes the older one.

The format follows Michael Nygard's lightweight ADR template (Context → Decision → Consequences). Records are numbered sequentially and named `NNNN-kebab-title.md`.

## Index

| ID | Title | Status |
| --- | --- | --- |
| [ADR-0001](./0001-standalone-hardware-wallet-positioning.md) | Standalone hardware-wallet positioning (not a host-side backend) | Accepted |
| [ADR-0002](./0002-cla-and-greenfield-protocol.md) | CLA = `0x80` and greenfield wire protocol | Accepted |
| [ADR-0003](./0003-curves-and-signing-primitives.md) | Curves = secp256k1 + Ed25519; primitives = ECDSA, BIP-340 Schnorr, EdDSA | Accepted |
| [ADR-0004](./0004-secure-channel-cipher-suite.md) | Secure Channel cipher suite: AES-256-GCM (primary) / AES-256-CBC + HMAC-SHA256 (fallback) | Accepted |
| [ADR-0005](./0005-authentikey-lifecycle.md) | Authentikey is generated at `install` and survives reset-to-factory | Accepted |
| [ADR-0006](./0006-pin-policy.md) | Single PIN + single PUK with bounded retries | Accepted |
| [ADR-0007](./0007-card-only-signs-hashes.md) | Card signs hashes only — transaction parsing stays off-card | Accepted |
| [ADR-0008](./0008-reset-to-factory-multi-step.md) | Reset-to-factory requires N consecutive un-interleaved INS to trigger | Accepted |

## Conventions

- **Status**: `Proposed` → `Accepted` → (possibly) `Superseded by ADR-NNNN`
- **Date**: ISO-8601 (`YYYY-MM-DD`) on the line under the title
- **Immutability**: only `Status` and back-references may be edited after acceptance
- **Cross-references**: use relative links like `[ADR-0001](./0001-foo.md)`
