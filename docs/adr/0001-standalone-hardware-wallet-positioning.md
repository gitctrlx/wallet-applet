# ADR-0001: Standalone hardware-wallet positioning

Date: 2026-05-18

## Status

Accepted

## Context

`meowl-applet` could plausibly fit any of three product slots:

1. A **standalone hardware wallet** like Satochip, Ledger, Trezor, Keystone, where the secure element owns the entire private-key lifetime.
2. A **co-signer** in an MPC / threshold scheme, where the card holds one share of a key split across multiple devices.
3. A **host-side backend**, where the card is a co-processor that an external Rust/Go wallet drives turn-by-turn.

These three slots have radically different APDU surfaces, security models, and host-side tooling. The two Rust projects under `3rdparty/` — `kobe` (HD derivation) and `signer` (transaction signing) — could superficially read as host-side, which has caused confusion.

## Decision

**`meowl-applet` is a standalone hardware-wallet applet, in the same product slot as Satochip.**

Concretely:

- The master seed lives **only** inside the secure element. It is generated or imported through APDUs, never exported in plaintext.
- All BIP-32 secp256k1 and SLIP-10 Ed25519 derivation runs **on-card**. The host never sees a non-public child key.
- All ECDSA / BIP-340 Schnorr / Ed25519 signing runs **on-card**. The host receives signatures, never private keys.
- The host is responsible for everything that does **not** touch private keys: BIP-39 mnemonic handling at recovery time, derivation-path decisions, public-key → address encoding, transaction construction, preimage hashing, UI, and network broadcast.

`kobe` and `signer` are **reference implementations** used by `meowl-applet` only for:

1. **Design inspiration** — how to abstract twelve chains over two curves.
2. **CI Known-Answer Tests** — the same mnemonic + path is fed to `kobe` (ground truth) and to the on-card BIP-32 derivation; the resulting xpubs must match bit-for-bit.
3. **A future, optional host SDK** — post-v1.0, `kobe`/`signer` may be re-targeted to replace their local `Zeroizing<SecretKey>` with APDU calls to a `meowl` card. v1.0 does not do this work.

`kobe` and `signer` are **not** runtime or build-time dependencies of the applet.

## Consequences

### Positive

- Aligns with the entire hardware-wallet industry's standard split. Anyone reviewing the design (auditors, users, integrators) immediately understands the trust boundary.
- Frees the applet to use the most defensible cryptographic primitives at every layer, without inheriting any external tool's interface.
- Makes "private keys never leave the card" a literal, testable invariant rather than a marketing claim.

### Negative

- The card cannot offload heavy work to the host; everything from BIP-32 derivation to RFC 6979 nonce generation must run within the JavaCard runtime's memory and timing envelope.
- A separate host client must exist to drive the card. We bootstrap one in `tools/` and may eventually publish a `kobe`-flavoured SDK.

### Neutral

- Forces a clean APDU surface — see [ADR-0002](./0002-cla-and-greenfield-protocol.md) — instead of inheriting Satochip's MUSCLE-derived legacy.
