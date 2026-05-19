---
meap: 5
title: Hierarchical-deterministic key derivation
status: Final
type: Standards Track
category: Crypto
created: 2026-05-19
requires: [1, 2, 3]
author: meowl.social contributors
---

# MEAP-5: Hierarchical-deterministic key derivation

## Abstract

This MEAP specifies the on-card hierarchical-deterministic (HD) key derivation. A single master seed feeds two parallel HD trees: BIP-32 over secp256k1 (for Bitcoin / EVM / Cosmos / Tron / Filecoin / Spark / XRPL / Nostr) and SLIP-10 hardened-only over Ed25519 (for Solana / Sui / TON / Aptos). Three INSes — `IMPORT_SEED`, `GENERATE_SEED`, `EXPORT_XPUB` — cover the full lifecycle from seed loading through child public-key export. The master seed lives only inside the secure element; only public material crosses the wire after `GENERATE_SEED`'s one-shot return.

## Motivation

A multi-chain hardware wallet has a hard requirement: one BIP-39 mnemonic (or any 16–64 byte master seed) MUST back every supported chain. The wallet ecosystem has converged on two standards:

- **BIP-32** ([bitcoin/bips/bip-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)) over secp256k1, supporting both hardened (`i ≥ 2³¹`) and non-hardened children. Used by every chain whose private-key arithmetic lives on secp256k1.
- **SLIP-10** ([satoshilabs/slips/slip-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)) over Ed25519, supporting hardened children only (the SLIP-10 spec forbids non-hardened derivation on Ed25519 because the curve does not admit the non-hardened formula's `parse256(I_L) + k_par mod n` step in a sound way).

Both standards depend on HMAC-SHA-512. JCAlgTest's 112-card population survey shows `Signature.ALG_HMAC_SHA_512` natively available on 45/112 cards (40%) and on every modern JCOP3 / JCOP4 family member meowl targets. Implementing the derivation on-card is therefore feasible without a software HMAC fallback.

The derivation MUST also enforce the validity invariants both standards require — `parse256(I_L) < n` at the master and at every child node — to defeat the very small fraction of seeds that would otherwise produce an invalid key.

## Specification

### Master seed storage

A conforming applet MUST persist the master keying material in two parallel BIP-32-style chains, each `k_master(32) ‖ c_master(32)`:

```text
bip32_master   = HMAC-SHA-512("Bitcoin seed", seed)     ; 64 bytes, k_BIP32 ‖ c_BIP32
slip10_master  = HMAC-SHA-512("ed25519 seed", seed)     ; 64 bytes, k_SLIP10 ‖ c_SLIP10
seeded_flag    = 0x00 (unseeded) or 0x01 (seeded)
```

The applet MUST process the input seed at import time, derive both chains, and **immediately overwrite** any in-memory copy of the raw seed. The card MUST persist only the derived master material; it MUST NOT persist the raw seed.

### `IMPORT_SEED` (INS `0x40`)

Loads a host-supplied master seed. Reachable in `SETUP_DONE`; transitions to `SEEDED` on success.

Inner data layout:

```text
[seed_len(1)] [seed(seed_len)]
```

A conforming applet MUST verify `seed_len ∈ [16, 64]` per BIP-32 §"Master key generation" (256 to 512 bits) and reject any other length with `6700`. The handler then:

1. Computes `bip32_master` and `slip10_master` from the seed.
2. Validates `0 < parse256(k_BIP32) < n` per BIP-32 master-key rule (see *Master-key validity check* below). On failure: rejects with `6985` (conditions of use not satisfied) — the host SHOULD discard this seed and retry.
3. Persists both chains and the `seeded_flag` atomically inside a `JCSystem.beginTransaction` block.
4. Advances the lifecycle FSM to `SEEDED` (in the same transaction).
5. Overwrites the inbound seed bytes in the APDU buffer before returning.

A conforming applet MUST require `pin_verified` (per [MEAP-3 §Authorisation rules](./meap-3.md), session-verify rule) before accepting `IMPORT_SEED`.

### `GENERATE_SEED` (INS `0x41`)

The card itself draws a 64-byte CSPRNG seed and runs both HMAC-SHA-512 chains. The raw seed is returned **once** as the response so the host can render a BIP-39 mnemonic for the user to back up.

Inner data: empty.
Inner response: `[seed(64)]`.

A conforming applet MUST:

- Be reachable only in `SETUP_DONE` with `pin_verified` true.
- Source 64 bytes from `RandomData.ALG_KEYGENERATION` (or the platform's strongest-available CSPRNG; `ALG_TRNG` is an acceptable fallback).
- Re-sample the seed if `parse256(k_BIP32)` lands outside `(0, n)`. The probability of any single draw failing is ≤ `2⁻¹²⁷` so a defensive cap (the reference implementation uses 8 attempts) prevents a malformed silicon RNG from spinning forever; on cap exhaustion the applet MUST reject with `6985`.
- Return the raw seed bytes verbatim **once**, in the response of this exact APDU. Subsequent calls MUST NOT export the seed in any form.
- Advance the lifecycle FSM to `SEEDED` atomically with the seed material persistence.

This is the **only** path by which a private key (the seed itself) ever leaves the card. The path exists because BIP-39 mnemonic backup is the only recovery model the wallet ecosystem supports for a lost device; the alternative — never exposing the seed — would mean a card breakage destroys the user's funds.

A host that calls `GENERATE_SEED` MUST capture the response, render it (typically via BIP-39 mnemonic encoding, optionally with a passphrase), and present it to the user for backup. The host MUST NOT log the seed bytes and SHOULD wipe its in-memory copy as soon as the user has confirmed the mnemonic.

### `EXPORT_XPUB` (INS `0x42`)

Derives a child node and returns its public material. Reachable in `SEEDED` with `pin_verified` true.

Inner data layout:

```text
[curve(1)] [depth(1)] [path(4 × depth, big-endian)]
```

Where:

- `curve = 0x00` (`CURVE_SECP256K1`) selects the BIP-32 secp256k1 tree; `curve = 0x01` (`CURVE_ED25519`) selects the SLIP-10 Ed25519 tree. Any other value MUST be rejected with `6A86`.
- `depth ∈ [0, 8]` (`HD_MAX_DEPTH = 8`). `depth = 0` requests the master node itself. Any larger value MUST be rejected with `6700`.
- Each path element is a 32-bit big-endian unsigned integer. The hardened bit is the most-significant bit (`0x80000000`).

The inner-data length MUST equal `2 + 4 × depth`; any mismatch MUST be rejected with `6700`.

#### secp256k1 (`curve = 0x00`)

The applet MUST walk the BIP-32 tree per [BIP-32 §"Private parent key → private child key"](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-ckd-functions) and emit:

```text
[compressed_pubkey(33)] [chain_code(32)]                  ; total 65 bytes
```

The compressed public key follows SEC1 §2.3.3 (`0x02 ‖ x` if `y` is even, else `0x03 ‖ x`).

#### Ed25519 (`curve = 0x01`)

The applet MUST walk the SLIP-10 hardened-only tree per [SLIP-10 §"Master key generation"](https://github.com/satoshilabs/slips/blob/master/slip-0010.md). Each path element MUST have the hardened bit set; any non-hardened index MUST be rejected with `6A86`.

The applet MUST emit the leaf public key in RFC 8032 §5.1.2 little-endian compressed form alongside the chain code:

```text
[pubkey(32)] [chain_code(32)]                             ; total 64 bytes
```

The 32-byte pubkey is computed by deriving the leaf private key per SLIP-10, then computing `A = s · B` where `s` is the clamped scalar per [RFC 8032 §5.1.5](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5) and `B` is the standard ed25519 base point. Encoding follows RFC 8032 §5.1.2: 32-byte little-endian `y` with bit 0 of `x` placed in the high bit of byte 31. See [MEAP-6](./meap-6.md) for the encoding details since the same routine produces the `R` in Ed25519 signatures.

### Derivation primitives

#### HMAC-SHA-512

A conforming applet MUST use `Signature.ALG_HMAC_SHA_512`. If the silicon does not advertise the algorithm at install time, the applet MUST refuse to install on that card; this MEAP does NOT specify a software HMAC-SHA-512 fallback in this revision (a future MEAP MAY add one for broader silicon coverage).

#### Non-hardened secp256k1 — `point(k_par)`

For non-hardened secp256k1 derivation the applet MUST compute `serP(point(k_par))` (the compressed encoding of `k_par · G`) by invoking `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` with the parent private key as the init key and the curve base point `G` as the input public key. The KA primitive returns the uncompressed encoding `0x04 ‖ x ‖ y`; the applet MUST compress to the SEC1 form before feeding it into the next HMAC-SHA-512.

#### Master-key validity check

After deriving `k_master = parse256(I_L)` from the seed (in either tree), the applet MUST verify `0 < k_master < n` (where `n` is the secp256k1 group order for the BIP-32 tree, or the ed25519 prime-subgroup order ℓ for the SLIP-10 tree). The check uses the `ModN` helper module on the BIP-32 path; SLIP-10 values are not subject to a `mod ℓ` check because SLIP-10's hardened-only walk never adds I_L to a parent key.

A conforming applet MUST reject `IMPORT_SEED` with `6985` if either master fails the validity check. For `GENERATE_SEED` the applet MUST resample (up to a defensive cap of 8 attempts) and return `6985` only if the cap is exhausted — this is a should-never-happen sentinel, not an expected error code in normal operation. The probability of a single random seed failing on the BIP-32 side is `1 − n/2²⁵⁶ ≈ 2⁻¹²⁸`.

#### Per-child validity check

For non-hardened BIP-32 derivation, the applet MUST compute `k_i = (parse256(I_L) + k_par) mod n` and reject the derivation with `6985` if either `parse256(I_L) ≥ n` or `k_i = 0`. The host SDK MAY pick a different `i` and retry.

The reference `ModN` helper performs the addition with carry, then a single conditional subtract of `n` if either the carry was set or the unreduced sum is `≥ n`. The `lessThan` predicate it relies on iterates byte-by-byte short-circuiting on the first decision; this is **not** constant-time but the inputs (`k_par + I_L`) are not directly attacker-controlled in a useful way (the attacker sees only `I_L`'s output through HMAC of unobserved internal state).

#### Scalar-key hygiene

The `ECPrivateKey` slot used for non-hardened EC scalar multiplication is EEPROM-backed on the cards we target (JC 3.0.5 does not universally support `TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT`). A conforming applet SHOULD compensate by calling `clearKey()` at the tail of every `derivePath` to scrub the leaf scalar from EEPROM. A conforming applet MUST install the curve parameters (the secp256k1 prime, generator, group order, cofactor) at the head of every public-key computation that follows a `clearKey()` because some implementations (notably JCardSim, and some JCOP profiles) treat `clearKey()` as a full reset that drops curve parameters.

### Negative-path status words

| Condition | Status word |
| --------- | ----------- |
| `seed_len ∉ [16, 64]` | `6700` |
| Seed produces invalid `k_master` (BIP-32) | `6985` |
| `GENERATE_SEED` exhausts the resample cap | `6985` |
| `depth > 8` | `6700` |
| Inner-data length mismatch (`!= 2 + 4 × depth`) | `6700` |
| Unknown `curve` byte | `6A86` |
| SLIP-10 path contains a non-hardened index | `6A86` |
| Per-child validity check fails (`k_i = 0` or `I_L ≥ n`) | `6985` |
| Lifecycle gate violation (e.g. `EXPORT_XPUB` before `SEEDED`) | `6FB0` |
| `pin_verified` not set | `6982` |

## Rationale

### One seed, two trees

BIP-39 / BIP-44 / SLIP-10 all expect a single 16–64 byte master seed to back every chain. A multi-chain wallet that asked the user for two mnemonics — one for Bitcoin-side chains, one for Ed25519-side chains — would be hostile to the user. The cost of the unified design is two parallel master-material persistence slots (128 bytes total in EEPROM); this is a trivial budget on every modern smart card.

### Hardened-only SLIP-10

The SLIP-10 spec forbids non-hardened Ed25519 derivation because the non-hardened formula `k_i = parse256(I_L) + k_par mod ℓ` does not preserve the curve's clamping bit pattern (`s[0] &= 248; s[31] &= 127; s[31] |= 64`). A non-hardened SLIP-10 implementation could in principle re-clamp at every step but no major Ed25519 wallet supports it; following the spec keeps meowl interoperable with Solana's `solana_sdk::derivation_path`, Sui's `@mysten/sui` SDK, TON's `tonweb` SDK and Aptos's `aptos_sdk`.

### `EXPORT_XPUB` returns chain code, not the full xpub

A BIP-32 xpub serialisation (78 bytes with the version, depth, parent fingerprint, child number, chain code and pubkey, all Base58Check-encoded) is the host's natural input format, but constructing it requires the parent fingerprint — which is `RIPEMD-160(SHA-256(parent_pubkey))[0..4]`. RIPEMD-160 is not on every JC silicon. Returning the (compressed pubkey, chain code) pair lets the host compute the parent fingerprint and the full xpub itself; this also lets the host expose deeper children without re-walking from the master.

### Why `GENERATE_SEED` returns the seed

A pure "card never reveals seed" design would mean the user has no recovery path if the card breaks. BIP-39 mnemonic backup is the only recovery model the wallet ecosystem supports, and it requires the user to have the seed bytes once. The single-shot return at generation time minimises the exposure: the seed crosses the Secure Channel exactly once, while the user is paying attention. After that, no APDU exposes it.

### Per-child validity check rejects rather than skips

BIP-32 §"Private parent key → private child key" specifies that if `k_i = 0` or `parse256(I_L) ≥ n`, "the resulting key is invalid, and one should proceed with the next value for `i`". MEAP-5 deliberately translates this into "the card returns `6985` and the host picks a different `i`". The card cannot silently increment `i` because:

- The host's path is what produces the user's deterministic address sequence. A silent increment would produce a different address than the host expected.
- The probability of triggering the check is below `2⁻¹²⁷`. A user encountering this on a randomly generated path is, in expectation, never. For pathological paths chosen by an attacker (which would still need to compute SHA-512 collisions), the host should observe the error and back off.

### Master-key validity check

BIP-32 §"Master key generation" specifies the same `0 < k_master < n` check at the root. We enforce it at `IMPORT_SEED` (host expected to discard the seed) and at `GENERATE_SEED` (card resamples); the failure probability is again below `2⁻¹²⁷`.

## Backwards Compatibility

N/A — v1.0 greenfield. A future MEAP that adds new derivation curves (e.g. BLS12-381 for Ethereum 2 staking) will declare itself dependent on this MEAP and extend the `curve` byte allocation.

## Test Vectors

The reference test class `HdDerivationTest` exercises the official BIP-32 and SLIP-10 vectors:

### BIP-32

- **Vector 1** seed `000102030405060708090a0b0c0d0e0f`. Master `xpub`, `m/0H`, `m/0H/1`, `m/0H/1/2H`, `m/0H/1/2H/2`, `m/0H/1/2H/2/1000000000`.
- **Vector 2** seed `fffcf9f6...`. Master and `m/0`, `m/0/2147483647H`, `m/0/2147483647H/1`, `m/0/2147483647H/1/2147483646H`, `m/0/2147483647H/1/2147483646H/2`. Tests the deepest mixed-hardened path.
- **Vector 3** seed `4b381541...`. Master and `m/0H`. Specifically chosen because the first hardened child's `I_L` has a leading-zero byte — a case any naïve "trim leading zero" implementation would mishandle.

### SLIP-10

- **Vector 1** (same seed as BIP-32 Vector 1). `m`, `m/0H`, `m/0H/1H`, `m/0H/1H/2H`, `m/0H/1H/2H/2H`, `m/0H/1H/2H/2H/1000000000H`.
- **Vector 2** seed `fffcf9f6...`. `m` and `m/0H`.

For each vector the response from `EXPORT_XPUB` must match the reference `(pubkey, chain_code)` tuple byte-for-byte. The reference test class re-runs all vectors through both the simulator and a host-side BIP-32 / SLIP-10 implementation (BouncyCastle for secp256k1, an inline SLIP-10 walker for Ed25519) and asserts equality.

### Negative path

`HdDerivationTest.ExportXpubNegative` covers:

- `depth > 8` → `6700`.
- Unknown curve byte → `6A86`.
- Truncated path (fewer bytes than `4 × depth`) → `6700`.
- Missing PIN session → `6982`.
- Missing seed (lifecycle ≠ `SEEDED`) → `6FB0`.
- SLIP-10 non-hardened index → `6A86`.

## Reference Implementation

- Master seed persistence: [`MasterSeed`](../../applet/src/main/java/social/meowl/applet/MasterSeed.java).
- BIP-32 walk and EC scalar multiplication: [`Bip32`](../../applet/src/main/java/social/meowl/applet/Bip32.java).
- SLIP-10 walk: [`Slip10`](../../applet/src/main/java/social/meowl/applet/Slip10.java).
- Modular helpers: [`ModN`](../../applet/src/main/java/social/meowl/applet/ModN.java).
- Reference test class: [`HdDerivationTest`](../../tests/src/test/java/social/meowl/applet/HdDerivationTest.java).

## Security Considerations

### Seed exposure

`GENERATE_SEED` is the single APDU through which seed material crosses the wire. Hosts MUST treat the returned 64 bytes as the highest-sensitivity data the protocol ever produces:

- The response MUST be displayed to the user only once, ideally on a secure local UI surface (not network-rendered).
- The host SHOULD wipe its in-memory copy as soon as the user confirms.
- The host MUST NOT log, screenshot, or back up the response automatically.

The Secure Channel protects the response on the wire; the host's hygiene is what protects it after.

### Validity-check non-constant-time `lessThan`

The `Bignat.lessThan` predicate the validity check relies on short-circuits on the first byte that differs. For random inputs (which the seed and the HMAC-SHA-512 outputs are) the timing leak is uniform — there is no useful side channel because the attacker would need to control the inputs to force a specific timing. The reference implementation accepts this leak; future revisions MAY harden the predicate to constant-time without changing the wire spec.

### EEPROM scalar-key hygiene

The `ECPrivateKey` slot used in non-hardened secp256k1 derivation is EEPROM-backed on cards lacking `TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT`. A conforming applet MUST `clearKey()` at the tail of every `derivePath` to scrub the leaf scalar; failure to do so leaves the most-recently-derived child scalar in EEPROM where a sufficiently invasive attacker (chip-decapping, flash-readout) could recover it. The reference implementation clears the slot and re-installs curve parameters at every entry to make the next derivation correct.

### Per-child failure leakage

Returning `6985` rather than silently incrementing `i` reveals to a wire-level observer that a specific derivation step failed. Since the failure probability is below `2⁻¹²⁷`, an observer never sees it in practice; the leak is theoretical only. A host that wants to hide this signal MAY pre-walk the path off-card with a host-side BIP-32 implementation; the on-card walk is then a redundant double-check.

## Copyright

This document is licensed under the AGPL-3.0-or-later licence the rest of the project uses; see [LICENSE](../../LICENSE).
