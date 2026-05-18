# ADR-0007: Card signs hashes only

Date: 2026-05-18

## Status

Accepted

## Context

A signing card has three possible interfaces with the outside world:

1. **Full transaction parser** — the host sends a serialised transaction; the card parses fields, checks invariants, displays them to the user (impossible without a screen), and signs internally derived sighashes. Ledger and Trezor work this way because they have screens.
2. **Sighash signer** — the host computes the chain-specific sighash and the card just signs 32 bytes with a chosen derived key.
3. **Raw signer** — the card signs any 32-byte input with any keyslot, regardless of provenance.

Screenless cards (Yubikey-form-factor, NFC cards) cannot reasonably parse a Bitcoin transaction because they cannot show the user what is being signed before the signature exists. Satochip ships a 21 KB `Transaction.java` to parse legacy Bitcoin transactions on-card, and the result is unused once you accept that there is no display: the parsed fields are simply hashed and signed, which is functionally identical to signing a host-computed hash.

## Decision

- The card exposes only sighash-style signing primitives (`SIGN_ECDSA`, `SIGN_SCHNORR`, `SIGN_ED25519`).
- The host **must** compute the chain-specific preimage hash before invoking the card:
  - Bitcoin: BIP-143 / BIP-341 sighash, depending on script type.
  - EVM: Keccak-256 of RLP-encoded transaction or EIP-191 / EIP-712 prefix.
  - Solana: SHA-512 inside Ed25519 (host need only supply the message body — Ed25519 hashes internally).
  - Cosmos: SHA-256 of canonical ADR-036 / Amino bytes.
  - XRPL: SHA-512 truncated, prefixed by `STX\0`.
  - Sui: Blake2b of intent-prefixed bytes.
  - Nostr: SHA-256 of the canonical event JSON.
- The card does **not** ship a transaction parser for any chain.
- A future ADR may revisit this if we ship a card variant with a display; for screenless v1.0 the constraint is firm.

## Consequences

### Positive

- The applet code base shrinks by tens of KB. No `Transaction.java`, no PSBT decoder, no RLP / SCALE / Borsh parser.
- The card's signing-side audit surface is uniform across all twelve supported chains: input is always 32 bytes (Ed25519 takes raw message but the trust model is identical).
- New chains can be added on the host without any firmware change as long as they use one of the three signing primitives.

### Negative

- **Blind signing risk:** without a display, the user has no on-device visual confirmation of what the card is signing. This is a known property of screenless cards and a UX concern owned by the host wallet (which should refuse to forward suspicious payloads).
- The host bears more responsibility. We accept this and produce a reference host (`tools/`) plus, eventually, hardened bindings via `kobe` / `signer` (see [ADR-0001](./0001-standalone-hardware-wallet-positioning.md)).

### Neutral

- This is the natural fit for the JavaCard 3.0.5 memory budget; trying to put per-chain parsers on-card would inflate the CAP file past the limits of many low-cost SE silicon products.
