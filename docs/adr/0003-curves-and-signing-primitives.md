# ADR-0003: Two curves, three signing primitives

Date: 2026-05-18

## Status

Accepted

## Context

A multi-chain hardware wallet must decide which elliptic curves and signature schemes to implement. Naively each chain could demand a different primitive, but the reference Rust toolkit `kobe` (which covers twelve major chains) shows the field collapses to a small set:

| Chain family | Curve | Signature scheme | Derivation |
| --- | --- | --- | --- |
| Bitcoin (legacy / SegWit), EVM, Cosmos, Tron, Filecoin, Spark, XRPL | secp256k1 | ECDSA | BIP-32 |
| Bitcoin Taproot, Nostr | secp256k1 | BIP-340 Schnorr (optional Taproot tweak) | BIP-32 + BIP-86 / NIP-06 |
| Solana, Sui, TON, Aptos | Ed25519 | EdDSA (Ed25519) | SLIP-10 |

That is **two curves and three signature schemes** to cover all twelve chains. P-256 / secp256r1 is occasionally requested for PassKeys / WebAuthn but those are not blockchain use cases and can wait for a later release.

## Decision

The card v1.0 implements exactly:

1. **secp256k1 ECDSA** signing over a 32-byte digest, with a deterministic RFC 6979 nonce and a 1-byte public-key-recovery suffix. Derivation: full BIP-32 (hardened and non-hardened children).
2. **secp256k1 BIP-340 Schnorr** signing. P2 of the APDU selects whether to apply a Taproot tweak (BIP-86 path) or skip the tweak (NIP-06 / Nostr path). Derivation: same BIP-32 tree as ECDSA.
3. **Ed25519 EdDSA** signing per RFC 8032 (no PureEdDSA / Ed25519ph variants). Derivation: SLIP-10 with **hardened-only** children (the SLIP-10 standard forbids non-hardened derivation on Ed25519).

The card does **not** implement:

- secp256r1 / P-256, BLS12-381, ristretto25519, sr25519, or any other curve.
- Any post-quantum scheme (deferred until a NIST PQC standard ships and JavaCard kits expose a tested primitive).
- ECDH on Ed25519 (the X25519 / Curve25519 transform is a separate primitive and not required by any covered chain).

## Consequences

### Positive

- **Coverage:** twelve major chains and their ecosystem standards (BIP-340, BIP-86, NIP-06, SLIP-10) are all signed natively on-card with no host-side fallback.
- **Surface area:** three signing INS opcodes (`SIGN_ECDSA_K1`, `SIGN_SCHNORR_K1`, `SIGN_ED25519`) make the audit surface small.
- **Memory:** only two curve-parameter constant blocks need to live in EEPROM/Flash.

### Negative

- **Ed25519 software path:** the JavaCard 3.0.5 API does not expose native Ed25519. A constant-time RFC 8032 implementation will live in `crypto/Ed25519.java`. Expected cost: ~250–400 ms per signature on typical SE silicon, which is acceptable.
- **No P-256:** PassKeys / WebAuthn / X.509 client-cert flows are out of scope for v1.0. A future ADR may add it once a use case appears.

### Neutral

- Chains that use the same curve as Bitcoin but different message-construction conventions (Cosmos ADR-036, EVM EIP-191, XRPL `STX\0` prefix, Sui Blake2b intent) are entirely handled by the host before the 32-byte hash hits the card. The card never needs to know which chain it is signing for.
