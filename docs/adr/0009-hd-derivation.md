# ADR-0009: HD derivation — BIP-32 secp256k1 + SLIP-10 Ed25519

Date: 2026-05-18

## Status

Accepted

## Context

The card must derive child keys from a single master seed so that one BIP-39 mnemonic backs every supported chain (per [ADR-0003](./0003-curves-and-signing-primitives.md): secp256k1 for Bitcoin/EVM/Cosmos/Tron/Filecoin/Spark/XRPL/Nostr, Ed25519 for Solana/Sui/TON/Aptos). Two standards apply:

- **BIP-32** ([bitcoin/bips/bip-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)) for secp256k1, supporting both hardened (`i ≥ 2³¹`) and non-hardened children.
- **SLIP-10** ([satoshilabs/slips/slip-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)) for Ed25519, supporting hardened children only (per spec).

Both standards depend on HMAC-SHA-512. JCAlgTest's 112-card survey shows `Signature.ALG_HMAC_SHA_512` natively available on 45/112 cards (40%) and on every modern JCOP3/JCOP4 family member we target.

## Decision

### Storage

A single persistent `MasterSeed` holds the BIP-32 and SLIP-10 master material side-by-side:

```text
bip32  k_master(32) ‖ c_master(32)     // I_L ‖ I_R from HMAC-SHA-512("Bitcoin seed", seed)
slip10 k_master(32) ‖ c_master(32)     // I_L ‖ I_R from HMAC-SHA-512("ed25519 seed", seed)
seeded_flag(1)                          // != 0 once import or generation has succeeded
```

The raw input seed is processed at import time and immediately overwritten; the card persists only the derived master material.

### `IMPORT_SEED` (INS `0x40`)

- Reachable in state `SETUP_DONE` (i.e. PIN is set; `pinManager.isPinVerified()` is required).
- Data: `[seedLen(1), seed(seedLen)]` with `16 ≤ seedLen ≤ 64` per BIP-32 §"Master key generation".
- Computes both HMAC-SHA-512 chains atomically, commits the master material, advances lifecycle to `SEEDED`.

### `GENERATE_SEED` (INS `0x41`)

- Reachable in state `SETUP_DONE`, PIN verified.
- Card generates a 64-byte seed via `RandomData.ALG_KEYGENERATION` (or `ALG_TRNG` fallback), runs the two HMAC-SHA-512 chains, and **returns the raw seed bytes to the host as the response**. The host renders the seed (typically via BIP-39 mnemonic) for the user to back up. This is the only APDU that ever exposes raw seed material; any subsequent attempt to export it fails.

### `EXPORT_XPUB` (INS `0x42`)

- Reachable in state `SEEDED`, PIN verified.
- Data: `[curve(1), depth(1), path(4 × depth, big-endian)]` where `curve = 0x00` (secp256k1) or `0x01` (Ed25519). `depth ≤ MAX_DEPTH = 8`.
- For secp256k1: returns `[compressed_pubkey(33) ‖ chain_code(32)]`. The host then constructs the BIP-32 78-byte serialised xpub if needed.
- For Ed25519 in Phase 4: returns `chain_code(32)` only. Public key computation requires Ed25519 scalar multiplication which is implemented along with the signing primitive in Phase 5; until then `[33-byte zero pubkey || chain_code]` is **not** returned to avoid suggesting a usable pubkey.

### Derivation primitives

- `HMAC-SHA-512` via `Signature.ALG_HMAC_SHA_512`. If the silicon does not advertise the algorithm at install time, the applet refuses to install on that card (no software fallback in v1.0).
- `serP(point(k_par))` (non-hardened secp256k1) via `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` with the parent private key as init and {@code G} (the curve base point) as the input public key. The output is `0x04 ‖ x ‖ y`; we compress to `serP` form per SEC 1 §2.3.3.
- 256-bit modular addition mod n (for `k_i = (parse256(I_L) + k_par) mod n`) via a small custom `ModN` helper that performs add-with-carry and a conditional `−n`. See implementation notes in `Bip32.java`.
- Per BIP-32 §"Private parent key → private child key", if `parse256(I_L) ≥ n` or the resulting `k_i = 0` we **fail the derivation** (return `SW_CONDITIONS_NOT_SATISFIED`) rather than silently incrementing `i`; the probability of either condition is `~2⁻¹²⁷` and our host SDK can pick a different `i` if it ever happens.

### Test vectors

- BIP-32 official vectors 1, 2, 3, 4 (`bip-0032.mediawiki`).
- SLIP-10 official Ed25519 vectors 1 and 2 (`slip-0010.md`).
- Cross-check secp256k1 against `kobe` (`m/44'/60'/0'/0/0` for EVM, `m/84'/0'/0'/0/0` for BTC SegWit).

## Consequences

### Positive

- Single master seed; one mnemonic backs every chain meowl supports.
- The most common BIP-32 paths (BIP-44/49/84/86 BTC, EVM `m/44'/60'/0'/0/i`, BIP-86 Taproot, NIP-06 Nostr) all work because we implement both hardened and non-hardened derivation for secp256k1.
- SLIP-10 Ed25519 hardened-only is exactly what Solana/Sui/TON/Aptos expect.
- Master material in EEPROM is 128 bytes; the seed never appears in EEPROM after import.

### Negative

- Cards lacking `Signature.ALG_HMAC_SHA_512` cannot run the applet. JCAlgTest places this at ~40% of the surveyed population, but modern JCOP3/JCOP4 (our primary target) all support it. We do not implement a software HMAC-SHA-512 fallback in v1.0; a future ADR may add one for broader silicon coverage.
- The custom `ModN` implementation, although ~100 lines and constant-time-correct for its inputs (the reduction does either `0` or `1` subtraction depending on a carry/compare result that depends only on `k_par + I_L`), is bespoke cryptographic code and warrants its own audit and KAT regression test set.

### Neutral

- `EXPORT_XPUB` for Ed25519 is partial in Phase 4 (chain code only). Phase 5 closes this when it implements Ed25519 signing.
