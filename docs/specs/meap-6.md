---
meap: 6
title: Signing primitives — ECDSA, Schnorr, EdDSA
description: secp256k1 ECDSA, BIP-340 Schnorr and RFC 8032 Ed25519 signing primitives sharing a hash-only invariant and a uniform 64-byte signature output.
status: Draft
type: Standards Track
category: Crypto
created: 2026-05-19
requires: [1, 2, 3, 5]
author: meowl.social contributors
---

# MEAP-6: Signing primitives — ECDSA, Schnorr, EdDSA

## Abstract

This MEAP specifies the three signing primitives the card exposes: ECDSA on secp256k1 (`SIGN_ECDSA_K1`), BIP-340 Schnorr on secp256k1 (`SIGN_SCHNORR_K1`), and Ed25519 EdDSA (`SIGN_ED25519`). Together these cover every chain in the supported set: secp256k1 ECDSA for Bitcoin / EVM / Cosmos / Tron / Filecoin / Spark / XRPL; BIP-340 Schnorr for Bitcoin Taproot and Nostr; Ed25519 for Solana / Sui / TON / Aptos. Each primitive is pinned end-to-end: input layout, output layout, nonce derivation, canonicalisation rules, and the host's responsibilities for any chain-specific framing the card does not perform.

## Motivation

Three concerns drive the signing-side wire design:

1. **Input shape.** Two of the three primitives sign a host-computed 32-byte digest (the card never parses transactions — see *Hash-only invariant* below). Ed25519 is the exception: RFC 8032 §5.1.6 hashes the message internally as part of the deterministic-nonce construction, and a pre-hashed input is a different signature scheme (Ed25519ph) that no mainnet chain actually uses. The wire must accommodate both layouts unambiguously.
2. **Output canonicalisation.** Bitcoin Core (since v0.11.0) and EIP-2 reject ECDSA signatures whose `s` value is in the upper half of `n`. Performing low-`s` normalisation on-card eliminates a class of host-side bugs and gives every Bitcoin/Ethereum host a mainnet-policy-compliant signature with no extra work. BIP-340 signatures are non-malleable by construction and MUST NOT be flipped.
3. **Nonce policy reality.** JavaCard 3.0.5 does not expose an RFC 6979 deterministic-nonce hook for ECDSA, so the on-silicon ECDSA path uses whatever nonce policy the platform's `Signature.ALG_ECDSA_SHA_256` exposes. BIP-340 Schnorr is implemented in software and uses the synthetic-nonce branch of BIP-340 §3.2 with TRNG-sourced aux randomness. Ed25519 is implemented in software per RFC 8032 §5.1.6 and is fully deterministic. The three primitives therefore have three different nonce regimes, each pinned by this MEAP.

## Specification

### Hash-only invariant

A conforming applet MUST sign **hashes only**, with one explicitly enumerated exception. Specifically:

- `SIGN_ECDSA_K1` accepts a 32-byte digest and signs it with `Signature.signPreComputedHash(...)`. The applet MUST NOT re-hash the digest.
- `SIGN_SCHNORR_K1` accepts a 32-byte digest and treats it as the BIP-340 message `m`. The applet MUST NOT re-hash the digest before computing the BIP-340 challenge.
- `SIGN_ED25519` accepts the **raw message** of arbitrary length because RFC 8032 §5.1.6 hashes the message internally. The card hashes the message twice as part of the algorithm itself (once for the ephemeral nonce `r`, once for the challenge `k`); a host that pre-hashed the message would produce a signature for a different message than the verifier expects.

The host is responsible for every chain-specific preimage construction:

- Bitcoin: BIP-143 / BIP-341 sighash, depending on script type.
- EVM: Keccak-256 of RLP-encoded transaction or EIP-191 / EIP-712 prefix.
- Cosmos: SHA-256 of canonical ADR-036 / Amino bytes.
- XRPL: SHA-512 truncated, prefixed by `STX\0`.
- Sui / TON / Aptos / Solana: Ed25519 takes the raw message (intent-prefixed in Sui, account-data-prefixed in Solana, etc., but the prefixing is host-side).
- Nostr: SHA-256 of the canonical event JSON.

The card never sees a chain identifier, never parses a transaction, and never re-derives a sighash on-card. This is intentional: the audit surface of the signing path is uniform across all twelve supported chains.

### Common inner-data layout (digest-input primitives)

`SIGN_ECDSA_K1` and `SIGN_SCHNORR_K1` share a single inner-data layout:

```text
[depth(1)] [path(4 × depth, BE)] [digest(32)]
```

Where `depth ≤ HD_MAX_DEPTH = 8` per [MEAP-5](./meap-5.md). The applet derives the leaf scalar at `path` from the BIP-32 master and signs `digest` with that scalar. The total inner data length MUST equal `1 + 4 × depth + 32`; any mismatch MUST be rejected with `6700`.

### `SIGN_ECDSA_K1` (INS `0x50`)

Signs a 32-byte digest with the secp256k1 leaf private scalar derived at `path`. Returns a fixed-length raw `r ‖ s` pair.

Inner data: as defined in *Common inner-data layout* above.

Inner response:

```text
[r(32)] [s(32)]                                            ; 64 bytes
```

Both components are 32-byte big-endian, zero-padded. `s` is **always** in the low half of `n`: a conforming applet MUST normalise `s` to `s ≤ ⌊n/2⌋` before emitting; if the underlying primitive returned an `s > ⌊n/2⌋`, the applet MUST replace `s` with `n − s`. No DER encoding, no length prefix, no recovery byte.

A conforming applet MUST:

1. Derive the BIP-32 leaf scalar via `Bip32.deriveLeafScalar`.
2. Install the scalar into a transient `ECPrivateKey` slot and run `Signature.signPreComputedHash(...)` with `Signature.ALG_ECDSA_SHA_256`.
3. Strictly parse the JC native DER output as `0x30 [seqLen] 0x02 [rLen] [r bytes] 0x02 [sLen] [s bytes]` with at most one leading `0x00` byte stripped from each integer (the DER sign byte for an integer whose top bit would otherwise look negative). Anything outside this exact shape — wrong tags, mismatched lengths, value width > 33 bytes — MUST raise `6FE0` (unsupported feature). The host cannot trigger this by varying its inputs; only a non-conformant card can.
4. Left-pad `r` and `s` to 32 bytes each and write them sequentially to the response buffer.
5. Compare `s` against the pre-computed `⌊n/2⌋` constant. If `s > ⌊n/2⌋`, replace `s` with `n − s`.

A conforming applet MUST require lifecycle `SEEDED` and `pin_verified`. It MUST clear the leaf scalar from the transient `ECPrivateKey` slot at the tail of the handler.

#### Nonce policy

A conforming applet MUST use the platform's native ECDSA nonce policy:

- **Real silicon** (JCOP3 / JCOP4 / NXP P71 / Infineon SLE78): the ECDSA primitive draws a fresh random `k` per signature from the card's TRNG (the same source that backs the `authentikey` and the `GENERATE_SEED` CSPRNG). Two signatures over the same digest at the same path yield different `r,s` bytes with overwhelming probability.
- **Simulator** (JCardSim or any environment whose `Signature.ALG_ECDSA_SHA_256` defaults to RFC 6979): the implementation may use deterministic nonces. Two signatures over the same digest at the same path may then be byte-for-byte identical.

Both behaviours are valid ECDSA per FIPS 186-4 §6.4 and per every chain in the supported set. A conforming applet MUST NOT install an external `k` to force RFC 6979 because doing so is impossible on JC 3.0.5 without re-implementing ECDSA in software, and the operational cost is not justified — a host that needs RFC 6979 reproducibility can compute it off-card from the seed itself (which the host owns post-`GENERATE_SEED` or post-`IMPORT_SEED`).

A conforming host MUST NOT assume determinism on either side; it MUST treat each signing call's `r,s` output as fresh.

#### Recovery byte

A conforming applet MUST NOT emit a recovery byte. Hosts that need `v` (Ethereum, Filecoin, EIP-712 wallets) recover it post-facto by trying both `v ∈ {0, 1}`, recovering a candidate pubkey from `(r, s, digest, v)`, and matching against the expected pubkey returned by a prior `EXPORT_XPUB`. Standard reference libraries (`bitcoinjs-lib`, `noble-curves`, `kobe`) do this in O(1) elliptic-curve operations.

The rationale for keeping `v` off-card: computing `v` on-card requires recovering the `R` point from `r`, which entails a modular square root over `F_p`. JC 3.0.5 provides no primitive for this, so an on-card implementation would have to fall back to Tonelli-Shanks or exploit `p ≡ 3 mod 4` (`r^((p+1)/4) mod p`) in user code, plus point arithmetic to compare candidates. The added code surface for one bit of information is not justified.

### `SIGN_SCHNORR_K1` (INS `0x51`)

Signs a 32-byte digest with the BIP-340 Schnorr scheme on the secp256k1 leaf scalar derived at `path`.

Inner data: as defined in *Common inner-data layout*.

Inner response:

```text
[bytes(R)(32)] [s(32)]                                     ; 64 bytes
```

Where `bytes(R)` is the 32-byte big-endian x-coordinate of `R = k · G` with **implicit even-`y`** (SEC1 §2.3.5 x-only form, as BIP-340 §2 specifies). The parity flip — picking `k ← n − k'` whenever the random `k' · G` lands on an odd-`y` point — is performed on-card per BIP-340 §3.2 step 6. A conforming host always sees an even-`y` `R` and reconstructs the point by lifting `bytes(R)` via BIP-340's `lift_x` algorithm.

`s` is in `[0, n)` per the BIP-340 sign algorithm; the low-`s` restriction is **not** part of BIP-340 (Schnorr is non-malleable by construction — the verification equation `s · G = R + e · P` admits a unique `s` for any fixed `(R, P, m)` once parity of `R` is fixed) so a conforming applet MUST emit `s` verbatim and MUST NOT flip it.

#### Nonce policy

A conforming applet MUST follow the **synthetic-nonce branch** of BIP-340 §3.2:

```text
aux  ← TRNG(32)
t    = bytes(d) ⊕ tagged_hash("BIP0340/aux", aux)
k'   = int(tagged_hash("BIP0340/nonce", t ‖ bytes(P) ‖ m)) mod n
```

Where `d` is the BIP-32 leaf scalar (after parity flip if needed), `P = d · G`, `m` is the 32-byte digest. The aux randomness `aux` is drawn from the same JC `RandomData.ALG_KEYGENERATION` (fallback `ALG_TRNG`) source as the master seed.

Signatures are therefore **non-deterministic on every platform, including JCardSim**: two signatures over the same `(path, digest)` differ in both `R` and `s` with overwhelming probability. BIP-340 §3.2 explicitly endorses this synthetic-nonce variant as the recommended default precisely because it adds fault-resistance over the pure-deterministic variant.

#### Even-`y` `R` enforcement

The parity flip of BIP-340 §3.2 step 6 (`k ← n − k'` whenever `y(k' · G)` is odd) MUST be performed on-card. A conforming host therefore reconstructs `R` by lifting `bytes(R)` to its even-`y` representative via BIP-340 §3.3 step 6 (`R = lift_x(int(r))`). No parity hint travels on the wire.

#### Implementation

A conforming applet implements Schnorr on top of [`BigNat`](../../applet/src/main/java/social/meowl/applet/BigNat.java) (multi-precision arithmetic), [`Barrett`](../../applet/src/main/java/social/meowl/applet/Barrett.java) (constant-time modular reduction over `n`) and `Bip32.scalarMultG`, which delegates to `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` for the two scalar-base multiplications (`P = d · G` and `R = k · G`). Tagged hashing follows BIP-340 §2 verbatim.

A conforming applet MUST emit `6FE1` (internal error) if the signing path produces a should-never-happen sentinel — most notably, if the tagged-hash output reduces to zero mod `n` during the challenge computation. BIP-340 mandates failing the signature in that case; the probability is ≈ `2⁻²⁵⁶` and is below any practical concern. A conforming host SHOULD treat `6FE1` as transient and retry; subsequent calls draw fresh aux randomness and will not collide with overwhelming probability.

### `SIGN_ED25519` (INS `0x52`)

Signs an arbitrary-length message with the Ed25519 leaf private key derived at `path`.

Inner data:

```text
[depth(1)] [path(4 × depth, BE)] [message(0..*)]
```

The message MAY be empty. The applet streams it through `MessageDigest.ALG_SHA_512` twice (once for the nonce hash, once for the challenge hash) directly from the APDU buffer. Total inner data length MUST be at least `1 + 4 × depth`; any shorter is `6700`.

Inner response:

```text
[R_enc(32)] [S_enc(32)]                                    ; 64 bytes
```

Following RFC 8032 §5.1.6 verbatim. `R_enc` is the compressed Edwards encoding of `R = r · B` per RFC 8032 §5.1.2 (32-byte little-endian `y` with the high bit of byte 31 carrying bit 0 of `x`). `S_enc` is the 32-byte little-endian encoding of `S = (r + k · s) mod ℓ`, where `ℓ = 2²⁵² + 27742317777372353535851937790883648493` is the ed25519 group order. The host MAY feed this 64-byte blob into any standards-compliant Ed25519 verifier without further framing (the reference test suite uses the JDK's `Signature.getInstance("Ed25519")` directly).

#### Nonce policy

Ed25519 is **fully deterministic** on every platform. A conforming applet MUST follow RFC 8032 §5.1.6 verbatim:

```text
h        = SHA-512(sk)                                     ; sk is the SLIP-10 leaf private key
s        = clamp(h[ 0..32))                                ; clamp = (s[0]&=248; s[31]&=127; s[31]|=64)
prefix   = h[32..64)
A        = s · B
A_enc    = encode(A)
r        = SHA-512(prefix ‖ M) mod ℓ
R        = r · B
R_enc    = encode(R)
k        = SHA-512(R_enc ‖ A_enc ‖ M) mod ℓ
S        = (r + k · s) mod ℓ
signature = R_enc ‖ encodeLE(S)
```

No RNG is consulted; two signatures over the same `(path, message)` are byte-for-byte identical, on silicon and on the simulator alike. This is the property mainnet Solana / Sui / TON / Aptos validators expect and is the reason the chain ecosystem standardised on Ed25519 over Schnorr for these networks.

#### Implementation

JavaCard 3.0.5's EC coprocessor accepts short-Weierstrass curves only; Ed25519's native group is twisted Edwards. A conforming applet MUST therefore route Ed25519 through a **Weierstrass-25519 bridge** rather than implementing the twisted-Edwards group law in software:

- **EC scalar multiplication** delegates to the hardware coprocessor via `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` against the Weierstrass form of curve25519 ([`Wei25519`](../../applet/src/main/java/social/meowl/applet/Wei25519.java)). Both `A = s · G` and `R = r · G` run on the coprocessor; no software scalar ladder is required.
- **Cofactor handling** uses the `(s/8) · (8 · G)` identity. The clamped Ed25519 scalar `s` satisfies `s ≡ 0 (mod 8)` and exceeds the Wei25519 subgroup order `ℓ` (which `ECPrivateKey.setS` rejects); reducing to `s/8` against the precomputed point `8 · G` produces the same product in one coprocessor call. `Ed25519.scalarMultByPrivateScalar` implements this.
- **Affine-Weierstrass → compressed-Edwards encoding** is performed by `Wei25519.encodeEdwards`, applying the curve isomorphism `(x_W, y_W) → (x_E, y_E)` and emitting the 32-byte little-endian `y_E ‖ x_E_parity_bit` form mandated by RFC 8032 §5.1.2. The encoding uses [`Fp25519`](../../applet/src/main/java/social/meowl/applet/Fp25519.java) for the field operations and [`Fp25519Inv`](../../applet/src/main/java/social/meowl/applet/Fp25519Inv.java) for the single modular inverse.
- **Scalar arithmetic mod ℓ** (`r + k · s mod ℓ` for the final `S` component) is performed in software via `BigNat.mult` followed by [`Barrett`](../../applet/src/main/java/social/meowl/applet/Barrett.java) reduction; the final mod-ℓ trim uses constant-time `BigNat.ctSelectSub`.

The signing pipeline uses a 609-byte `CLEAR_ON_DESELECT` scratch buffer that stages the expanded private key (`s`, prefix), three scalar slots (`r`, `k`, `S`), two SHA-512 digest outputs, the 65-byte Wei25519 affine-point staging area and a 288-byte encode-scratch workspace. `Ed25519.sign(...)` MUST wipe the entire buffer in a `finally` clause regardless of which code path threw.

#### Wire-budget note

The Ed25519 sign APDU's `message` field is variable-length, capped by the surrounding APDU framing. After the depth + path + Secure Channel overhead, a single short APDU comfortably accommodates messages up to ~225 bytes. Hosts that need to sign messages larger than that MUST use the chain's existing pre-hashing convention (Solana already wraps in a 32-byte transaction hash for cross-program invocation; Sui / TON / Aptos likewise); this is a wire-budget concern, not a protocol-correctness concern — the algorithm itself accepts arbitrary-length messages.

## Rationale

### Why fixed-length raw `r ‖ s` for ECDSA, not DER

DER-encoded `ECDSA-Sig-Value` (RFC 3279) is what `Signature.signPreComputedHash` returns natively, and it is what Bitcoin Core stores in the script. But it is **not** what most modern host SDKs want: noble-curves, BouncyCastle, secp256k1-rs and most chain-specific signers prefer raw `r ‖ s`. A 64-byte fixed-length output also matches the BIP-340 and Ed25519 outputs, giving a uniform 64-byte signing surface across all three primitives and trivialising the host SDK's response-parsing logic. The applet absorbs the DER parsing cost once; the wire then carries the canonical form every consumer wants.

### Why on-card low-`s` normalisation

Bitcoin Core (since v0.11.0) and EIP-2 (Ethereum Homestead) reject any ECDSA signature whose `s > ⌊n/2⌋` as non-canonical. Performing the flip on-card means every Bitcoin / Ethereum host sees a mainnet-policy-compliant signature with no extra work; performing it host-side would mean a buggy host could accidentally produce a mainnet-rejected signature from a perfectly valid card output. The cost on-card is one byte-string compare and one optional subtract, which is negligible.

BIP-340 Schnorr signatures are emphatically NOT subject to low-`s`: the scheme is malleability-free by construction (the verification equation admits a unique `s` for any fixed `(R, P, m)` once parity of `R` is fixed), and BIP-341 / Taproot validators reject any flip of `s` to `n − s` because that produces a different — and equally non-malleable — signature for the same message.

### Why on-card even-`y` `R` enforcement

The alternative (emitting a parity hint alongside `bytes(R)`) would let the host reconstruct `R` without `lift_x`. But the reconstruction is trivial in software and `lift_x` is what every BIP-340 verifier already implements; emitting a hint would just bloat the wire. Performing the flip on-card is also what BIP-340's reference signer does, so the wire output is bit-for-bit identical to any reference implementation.

### Why message-input for Ed25519

Pre-hashing the message to feed `SIGN_ED25519` would produce signatures that no Ed25519 verifier accepts — the signature would be over the hash, not over the message, and the verifier (which doesn't know the hash function the host applied) would compute its own SHA-512 of the hash and get a different challenge. The only way to produce a verifier-compatible Ed25519 signature is to feed the algorithm the raw message. RFC 8032 §5.1.6 hashes the message itself — the message IS the input.

This is the single principled exception to the hash-only invariant. Every chain in the supported Ed25519 set (Solana / Sui / TON / Aptos) uses RFC 8032 Ed25519 (not Ed25519ph), so the principled exception is also the practical one.

### Why deterministic Ed25519, non-deterministic Schnorr, mixed ECDSA

Three different stories for three different reasons:

- **Ed25519** is deterministic by RFC 8032 design — there is no nonce parameter to randomise. A "non-deterministic Ed25519" would be a different signature scheme; the chain ecosystem expects the standard one.
- **BIP-340 Schnorr** is recommended by BIP-340 §3.2 to be synthetic-nonce (TRNG-derived `aux` XOR'd with a deterministic mask). The synthetic-nonce variant adds fault-resistance over the pure-deterministic one; the cost is non-determinism in the signature, which BIP-340 itself accepts. Hosts that want pure-deterministic BIP-340 (`aux = 0x00..00`) for cross-card replay must sign in software with the seed they own.
- **ECDSA** uses whatever the platform exposes — random on silicon, deterministic on JCardSim — because installing an external `k` is not supported on JC 3.0.5 without a software ECDSA reimplementation. The deviation from a pure "deterministic RFC 6979" design is accepted because the cost (re-implementing ECDSA in software) is not justified and the reproducibility property is recoverable host-side.

### Software big-integer arithmetic (Schnorr and Ed25519)

JavaCard 3.0.5 does not expose a multi-precision integer type. The Schnorr signing path needs `s = (k + e · d) mod n` over secp256k1; the Ed25519 path needs `F_p`-field arithmetic over `p = 2²⁵⁵ − 19` and `(r + k · s) mod ℓ` scalar arithmetic over the ed25519 group order. The reference implementation lives in [`BigNat`](../../applet/src/main/java/social/meowl/applet/BigNat.java) (multi-precision unsigned arithmetic with constant-time conditional add/sub/negate primitives), [`Barrett`](../../applet/src/main/java/social/meowl/applet/Barrett.java) (constant-time Barrett reduction parameterised by the modulus), [`Fp25519`](../../applet/src/main/java/social/meowl/applet/Fp25519.java) and [`Fp25519Inv`](../../applet/src/main/java/social/meowl/applet/Fp25519Inv.java) (curve25519 field arithmetic with an RSA-engine-accelerated inversion fast path), and [`Wei25519`](../../applet/src/main/java/social/meowl/applet/Wei25519.java) (Weierstrass-25519 curve parameters and the Edwards isomorphism). Randomised cross-checks against `java.math.BigInteger` live in [`BigNatTest`](../../tests/src/test/java/social/meowl/applet/BigNatTest.java), [`Fp25519Test`](../../tests/src/test/java/social/meowl/applet/Fp25519Test.java) and [`Wei25519Test`](../../tests/src/test/java/social/meowl/applet/Wei25519Test.java); the Ed25519 pipeline is end-to-end-verified against the JDK's `Signature.getInstance("Ed25519")` in [`Ed25519SigningTest`](../../tests/src/test/java/social/meowl/applet/Ed25519SigningTest.java).

## Backwards Compatibility

N/A — no prior revision.

## Test Vectors

### `SIGN_ECDSA_K1`

Reproducible byte-level vectors are not pinned because the ECDSA nonce policy is platform-dependent. The reference test class [`EcdsaK1Test`](../../tests/src/test/java/social/meowl/applet/EcdsaK1Test.java) instead asserts the invariants:

1. The signature verifies against the BIP-32-derived public key that `EXPORT_XPUB` would return for the same path.
2. `s ≤ ⌊n/2⌋` (low-`s` normalisation invariant).
3. The signature DER-encodes-then-decodes back to the same `(r, s)` pair (round-trip property).

### `SIGN_SCHNORR_K1`

Reproducible byte-level vectors are not pinned because the synthetic-nonce policy means every signature has fresh aux randomness. The reference test class [`SchnorrK1Test`](../../tests/src/test/java/social/meowl/applet/SchnorrK1Test.java) asserts:

1. The signature verifies under a host-side BIP-340 reference verifier with the BIP-32-derived public key.
2. `bytes(R)` lifts to an even-`y` point.
3. `s ∈ [0, n)`.
4. The host-side BIP-340 verifier itself is sanity-checked against [BIP-340 official vector 0](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv).

### `SIGN_ED25519`

Ed25519 IS deterministic; byte-level vectors are pinned. [`Ed25519SigningTest.ByteForByte`](../../tests/src/test/java/social/meowl/applet/Ed25519SigningTest.java) cross-checks every card-produced signature byte-for-byte against an independently computed signature using:

- A host-side SLIP-10 walker (HMAC-SHA-512 over the seed), to materialise the same 32-byte leaf private key the card derives.
- The JDK's `Signature.getInstance("Ed25519")` signer (Java 15+) wrapped over the materialised leaf key.

The card's signature MUST equal the host's signature byte-for-byte at the master, at `m/0H`, at a 5-level deep hardened path, and over the empty message. RFC 8032 §7.1's `(sk, M) → signature` reference vectors are exercised through `EXPORT_XPUB`'s pubkey path in [`Edwards25519Test.rfc8032Test1` / `Test2`](../../tests/src/test/java/social/meowl/applet/Edwards25519Test.java) since the SLIP-10 derivation does not let an external test fix `sk`; the byte-for-byte invariant against the JDK signer closes the loop end-to-end.

### Negative path

Each test class additionally exercises:

- Lifecycle gate violation (state ≠ `SEEDED`) → `6FB0`.
- Missing PIN session → `6982`.
- Truncated path / wrong inner-data length → `6700`.
- `depth > 8` → `6700`.
- For `SIGN_ED25519`, SLIP-10 non-hardened index → `6985`.
- Tampered signature → host-side verifier rejects.

## Reference Implementation

- ECDSA signing: [`EcdsaK1`](../../applet/src/main/java/social/meowl/applet/EcdsaK1.java).
- Schnorr signing: [`Schnorr`](../../applet/src/main/java/social/meowl/applet/Schnorr.java).
- Ed25519 signing: [`Ed25519`](../../applet/src/main/java/social/meowl/applet/Ed25519.java).
- Weierstrass-25519 bridge and curve constants: [`Wei25519`](../../applet/src/main/java/social/meowl/applet/Wei25519.java).
- Curve25519 field arithmetic: [`Fp25519`](../../applet/src/main/java/social/meowl/applet/Fp25519.java), [`Fp25519Inv`](../../applet/src/main/java/social/meowl/applet/Fp25519Inv.java).
- Multi-precision arithmetic shared by Schnorr and Ed25519: [`BigNat`](../../applet/src/main/java/social/meowl/applet/BigNat.java).
- Constant-time Barrett reduction over `n` (secp256k1) and `ℓ` (ed25519): [`Barrett`](../../applet/src/main/java/social/meowl/applet/Barrett.java).
- EC scalar multiplication via the hardware coprocessor: [`EcPoint`](../../applet/src/main/java/social/meowl/applet/EcPoint.java).
- Reference test classes: [`EcdsaK1Test`](../../tests/src/test/java/social/meowl/applet/EcdsaK1Test.java), [`SchnorrK1Test`](../../tests/src/test/java/social/meowl/applet/SchnorrK1Test.java), [`SchnorrTagHashTest`](../../tests/src/test/java/social/meowl/applet/SchnorrTagHashTest.java), [`Ed25519SigningTest`](../../tests/src/test/java/social/meowl/applet/Ed25519SigningTest.java); plus unit-test classes for the underlying primitives: [`BigNatTest`](../../tests/src/test/java/social/meowl/applet/BigNatTest.java), [`Fp25519Test`](../../tests/src/test/java/social/meowl/applet/Fp25519Test.java), [`Wei25519Test`](../../tests/src/test/java/social/meowl/applet/Wei25519Test.java).

## Security Considerations

### Blind signing

Without a screen, the user has no on-device visual confirmation of what the card is signing. The card sees only a 32-byte digest (or, for Ed25519, the raw message) and signs whatever the host SDK feeds it. This is a known property of screenless cards and a UX concern owned by the host wallet, which:

- MUST display the transaction details to the user before computing the digest and forwarding it to the card.
- MUST refuse to forward suspicious payloads (e.g. unknown-script Bitcoin transactions, unknown-method EVM transactions, arbitrary EIP-191 messages).
- SHOULD use a chain-specific transaction-decoder library on the host side and present the decoded fields in human-readable form.

A future card variant with a display MAY implement a transaction parser; this MEAP does not anticipate that.

### Side channels in software primitives

The Schnorr and Ed25519 paths combine software big-integer arithmetic with EC scalar multiplication delegated to the hardware coprocessor. Constant-time precautions on the software side cover every operation that touches a private scalar or an ephemeral nonce:

- **MAC comparisons** in the Secure Channel use `BigNat.ctEquals` per [MEAP-2](./meap-2.md).
- **Mod-`n` / mod-`ℓ` ordering and zero tests** use `BigNat.ctLessThan` and `BigNat.ctIsZero`; conditional add / sub / negate use the mask-based helpers `BigNat.ctSelectAdd`, `BigNat.ctSelectSub` and `BigNat.ctSelectNeg`. Every byte of the operand is read on every call regardless of the secret bit.
- **Schnorr y-parity flips** (`d ← n − d` and `k ← n − k`) use `BigNat.ctSelectNeg`, mask-driven so the wall-clock is independent of the parity bit — the per-signature 1-bit oracle a branchful flip would expose is closed.
- **`s = (k + e · d) mod n`** in Schnorr and **`s = (r + k · s) mod ℓ`** in Ed25519 reduce their secret-derived dividends through `Barrett`, whose byte schedule is data-independent by construction (the reduction performs the full set of conditional subtracts regardless of where the borrow chain settles).
- **EC scalar multiplication** is performed by the hardware coprocessor (`KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`). Side-channel resistance at the EC layer therefore relies entirely on the underlying silicon's countermeasures (clock jitter, dummy operations, masked private keys); the applet adds no software point blinding above it.

The reference implementation does not claim full SCA resistance against lab-grade adversaries. Deployments where SCA is in scope MUST select silicon whose declared countermeasures defend the underlying JC primitives, and SHOULD prefer EAL 6+ certified platforms.

### Threat model

The threat model targets a **software-only adversary on the host**:

- **In scope.** Host-resident malware reading process memory; networked APIs probing the SDK; an attacker with full APDU traffic on the bus but no fine-grained timing oracle (typical PCSC reader jitter is 1–5 ms).
- **In scope.** Replay, MAC truncation, padding-oracle and key-confusion attacks on the Secure Channel — defended by MEAP-2 (Encrypt-then-MAC, strict IV monotonicity, session invalidation on first failure).
- **In scope.** A lost / stolen card whose attacker has only commodity reader hardware — defended by the PIN/PUK retry counter and the EAL 5+ Augmented certification of the underlying NXP J3R180.
- **Out of scope.** A *strong physical adversary* with sub-millisecond timing precision on the PCSC link, glitch-injection equipment, or invasive die probes. The hardware EC coprocessor is the only line of defence at that tier; deployments in this threat class SHOULD select EAL 6+ silicon with declared SCA countermeasures.
- **Out of scope.** Supply-chain attacks against the toolchain itself; defended at the build layer by SLSA L3 provenance and the CycloneDX SBOM published with each release.

### Performance budget

The numbers below are wall-clock budgets observed on a J3R180 SECID card running at ~32 MHz over a contact reader; NFC adds another ~50 ms of bus latency. Host SDKs SHOULD plan their UX timeouts around the *upper* bound of each range.

| INS | Operation | Typical | Notes |
| --- | --------- | ------- | ----- |
| `SIGN_ECDSA_K1` (0x50) | secp256k1 ECDSA | **150 – 300 ms** | Native `Signature.ALG_ECDSA_SHA_256`, dominated by EC scalar mul on the secure-element coprocessor. |
| `SIGN_SCHNORR_K1` (0x51) | BIP-340 Schnorr | **400 – 900 ms** | Two coprocessor scalar mults (`P = d·G`, `R = k·G`) interleaved with software `BigNat` + `Barrett` arithmetic for the challenge and `s` computation; three SHA-256 ingests for tagged-hash domain separation. |
| `SIGN_ED25519` (0x52) | RFC 8032 Ed25519 | **3 – 6 s** | Two coprocessor scalar mults via the Weierstrass-25519 bridge interleaved with two SHA-512 ingests, the `Wei25519.encodeEdwards` modular inversions and `Barrett`-mediated mod-`ℓ` reduction; message capped at ~222 bytes by the inner short-form LC. |
| `EXPORT_XPUB` (0x42) | One BIP-32 / SLIP-10 step | **80 – 200 ms** | Hardened: one HMAC-SHA-512. Non-hardened: one HMAC-SHA-512 + one EC point add via JC `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`. |

Ed25519 latency is dominated by the two `Wei25519.encodeEdwards` modular inversions (one per scalar mult); the RSA-engine fast path in `Fp25519Inv` (selected at install when the silicon advertises `Cipher.ALG_RSA_NOPAD` over a 512-bit modulus) shaves roughly 30 % vs. the software Fermat ladder fallback.

### Recovery byte cross-card replay

A signature `(r, s)` from card A under a digest computed by host A is valid only against the public key derived from card A's seed. An attacker who relays the digest to card B would receive a different signature under card B's public key — there is no replay attack at the signature level. Hosts MUST nevertheless ensure they bind the digest preimage to the intended chain context (e.g. include the chain ID in EVM EIP-155 sighashes) so that a signature for one chain cannot be replayed on another with a colliding preimage.

## Copyright

This document is licensed under the AGPL-3.0-or-later licence the rest of the project uses; see [LICENSE](../../LICENSE).
