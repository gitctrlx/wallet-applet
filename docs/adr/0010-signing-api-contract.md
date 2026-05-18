# ADR-0010: Signing API contract — output format, nonce policy, low-s normalisation

Date: 2026-05-18

## Status

Accepted

## Context

[ADR-0003](./0003-curves-and-signing-primitives.md) decided which curves and signature schemes the card implements (secp256k1 ECDSA, secp256k1 BIP-340 Schnorr, Ed25519 EdDSA). [ADR-0007](./0007-card-only-signs-hashes.md) decided that the card signs hashes only and never parses transactions. What ADR-0003 deliberately left open is the **wire-level contract** of every Phase 5 signing APDU: input layout, output layout, nonce derivation, canonicalisation. Phase 5A (ECDSA secp256k1) is the first of the three to ship, so the contract has to be pinned down before the host SDK is wired to it.

The relevant constraints:

- JavaCard 3.0.5 exposes `Signature.ALG_ECDSA_SHA_256` and `Signature.signPreComputedHash(...)`; the output is **DER-encoded** `ECDSA-Sig-Value` (RFC 3279 §2.2.3). The applet must parse this and decide how to surface it to the host.
- JavaCard 3.0.5 does **not** expose an RFC 6979 deterministic-nonce interface. The native ECDSA implementation draws a fresh random `k` per signature (typically via the card's TRNG, which is the same source we trust for the authentikey and the master seed). There is no portable way to install an external `k` short of reimplementing ECDSA in software.
- BIP-62 (Bitcoin Core policy, since v0.11.0) and EIP-2 (Ethereum Homestead) require **low-`s` canonical signatures**: any signature with `s > ⌊n/2⌋` is non-canonical and rejected by mainnet validators. Whether the host or the card performs the flip is an applet-side decision.
- The public-key recovery byte `v` (also called `recid`) is required by Ethereum-style transactions but is **not** part of the ECDSA-Sig-Value structure. Computing `v` on-card requires either a modular square root (to recover the `R` point from `r`) or two trial pubkey recoveries plus a comparison — both of which exceed the JC 3.0.5 primitive surface.

## Decision

### Wire layout

Every Phase 5 signing APDU shares the same inner data layout:

```text
[depth(1) | path(4*depth, BE) | digest(32)]
```

`depth ≤ HD_MAX_DEPTH = 8`. `digest` is exactly 32 bytes; the host is responsible for computing the chain-specific preimage hash (per ADR-0007).

The response of `SIGN_ECDSA_K1` is:

```text
[r(32) | s(32)]
```

`r` and `s` are big-endian, zero-padded to 32 bytes each. `s` is **always** in the low half of `n` (`s ≤ ⌊n/2⌋`). No DER, no length prefix, no recovery byte.

Schnorr (`SIGN_SCHNORR_K1`, Phase 5B) will share the same 64-byte fixed-width layout — BIP-340 already mandates `R.x ‖ s` of fixed length 32 + 32. Ed25519 (`SIGN_ED25519`, Phase 5C) likewise yields `R ‖ s` of fixed length 32 + 32 = 64 bytes per RFC 8032 §5.1.6.

### Nonce policy

The Phase 5 ECDSA primitive uses whatever nonce policy the underlying JC platform's `Signature.ALG_ECDSA_SHA_256` exposes — the applet does not install an external `k`. This deviates from ADR-0003's "deterministic RFC 6979 nonce" wording, which we update via this ADR to reflect the JC 3.0.5 reality:

- **Real silicon** (JCOP3 / JCOP4 / NXP P71 / Infineon SLE78): the ECDSA primitive uses the card's TRNG to draw a fresh random `k` per signature. Two signatures over the same `digest` at the same path yield different `r,s` bytes with overwhelming probability.
- **JCardSim** (host-side simulator used by the test suite): the implementation delegates to BouncyCastle's `ECDSASigner`, which defaults to **RFC 6979 deterministic** nonces. Two signatures over the same `digest` at the same path are byte-for-byte identical.

Both behaviours are accepted as valid ECDSA per FIPS 186-4 §6.4 and per every chain meowl signs for (Bitcoin, EVM, Cosmos, Tron, Filecoin, Spark, XRPL). The deterministic-vs-random property is a reproducibility distinction, not a validity distinction. Concretely:

- Deterministic reproducibility (replay the same `r,s` for the same `digest`) is a host-side concern: a host SDK that wants RFC 6979 across heterogeneous cards can pre-compute the deterministic `k` and sign in software, since it owns the seed exposed by `GENERATE_SEED` (or the seed it imported via `IMPORT_SEED`). The card's role is to be the authoritative signer for the seed it custodies; reproducibility off-card does not require it.
- A future ADR may re-introduce on-card RFC 6979 once a JC 3.x kit ships a `signWithProvidedNonce`-equivalent primitive, or as a software fallback if the threat model demands it. For v1.0 the simplicity wins.

The test suite asserts only the validity invariant (every signature verifies under the derived pubkey, and `s ≤ ⌊n/2⌋`), never the equality or inequality of two signatures over the same input.

### Low-s normalisation

The card performs low-`s` normalisation **on-card**: after the JC ECDSA call returns, the applet compares the parsed `s` against the pre-computed `⌊n/2⌋` constant; if `s > ⌊n/2⌋` it replaces `s` with `n − s`. This keeps the host SDK trivial and prevents accidental high-`s` malleability bugs at the boundary.

### Recovery byte `v`

The card **does not** emit a recovery byte. Hosts that need `v` (Ethereum, Filecoin, EIP-712 wallets) recover it post-facto by trying both `v ∈ {0, 1}`, recovering a candidate pubkey from `(r, s, digest, v)`, and matching against the expected pubkey returned by a prior `EXPORT_XPUB`. Standard reference libraries (`bitcoinjs-lib`, `noble-curves`, `kobe`) do this in O(1) elliptic-curve operations.

The rationale for keeping `v` off-card:

- Computing `v` on-card requires recovering the `R` point from `r`, which entails a modular square root over `F_p`. JC 3.0.5 provides no primitive for this; we would have to implement Tonelli-Shanks (or exploit `p ≡ 3 mod 4` and compute `r^((p+1)/4) mod p`) in user code, plus point arithmetic to compare candidates. The added code surface for one bit of information is not justified.
- The host pubkey is already cached after `EXPORT_XPUB`; recovery is ~50 µs in software on a phone.

### DER parsing

The applet parses the JC-native DER output strictly:

```text
0x30 [seqLen]
  0x02 [rLen] [r bytes, optionally with one leading 0x00]
  0x02 [sLen] [s bytes, optionally with one leading 0x00]
```

A leading `0x00` byte (the DER sign byte for an integer whose top bit would otherwise look negative) is stripped during the left-pad to 32 bytes. Anything outside this exact shape — wrong tags, mismatched length, value width > 33 bytes — raises `SW_UNSUPPORTED_FEATURE`, on the basis that such an output indicates a buggy silicon implementation rather than caller-induced bad input. The host cannot trigger this by varying its inputs; only a non-conformant card can.

## Consequences

### Positive

- The 64-byte fixed-length output is uniform across ECDSA / Schnorr / Ed25519 and trivial for the host SDK to consume.
- Low-`s` canonicalisation is enforced exactly once, on-card, so every Bitcoin/Ethereum host sees a mainnet-policy-compliant signature with no extra work.
- The Phase 5A applet code remains under ~150 lines (`EcdsaK1.java`) by delegating both the cryptographic mechanism and the DER framing to JC native primitives; we only add the parser and the low-`s` reduction.

### Negative

- ADR-0003's "deterministic RFC 6979 nonce" wording is superseded for v1.0 (this ADR notes the deviation). Hosts relying on bit-for-bit reproducibility across signing calls must implement RFC 6979 themselves; the card cannot guarantee the same `r,s` for the same `digest`.
- Hosts must implement recovery-byte derivation themselves. Every mainstream wallet SDK already does this, so the cost is negligible.

### Neutral

- A future ADR may revisit either decision once JC 3.x ships a deterministic-nonce primitive or once we add a software ECDSA path. Neither is on the v1.0 roadmap.
