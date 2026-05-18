# ADR-0010: Signing API contract — output format, nonce policy, low-s normalisation

Date: 2026-05-18

## Status

Accepted

## Context

[ADR-0003](./0003-curves-and-signing-primitives.md) decided which curves and signature schemes the card implements (secp256k1 ECDSA, secp256k1 BIP-340 Schnorr, Ed25519 EdDSA). [ADR-0007](./0007-card-only-signs-hashes.md) decided that the card signs hashes only and never parses transactions — with one principled exception, called out below, where the algorithm itself hashes the message internally. What ADR-0003 deliberately left open is the **wire-level contract** of every Phase 5 signing APDU: input layout, output layout, nonce derivation, canonicalisation. Phase 5A (ECDSA secp256k1), Phase 5B (BIP-340 Schnorr), and Phase 5C (Ed25519 EdDSA) all ship in v1.0, so the contract has to be pinned down before the host SDK is wired to them.

The relevant constraints:

- JavaCard 3.0.5 exposes `Signature.ALG_ECDSA_SHA_256` and `Signature.signPreComputedHash(...)`; the output is **DER-encoded** `ECDSA-Sig-Value` (RFC 3279 §2.2.3). The applet must parse this and decide how to surface it to the host.
- JavaCard 3.0.5 does **not** expose an RFC 6979 deterministic-nonce interface. The native ECDSA implementation draws a fresh random `k` per signature (typically via the card's TRNG, which is the same source we trust for the authentikey and the master seed). There is no portable way to install an external `k` short of reimplementing ECDSA in software.
- JavaCard 3.0.5 ships **no native BIP-340 / Schnorr primitive**. The only EC operation usable for Schnorr signing is the ECDH-based scalar multiplication (`KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`), which yields the affine `(x, y)` of `k · G` for any scalar `k`. Everything else — tagged hashing, parity testing, modular addition / multiplication / reduction over the secp256k1 group order — has to be implemented in software.
- JavaCard 3.0.5 ships **no native Ed25519 / edwards25519** primitive at all — not even a scalar-multiplication building block. The card exposes `MessageDigest.ALG_SHA_512` (sufficient for the SLIP-10 walk and the RFC 8032 inner hashes) and nothing else; every field operation modulo `p = 2²⁵⁵ − 19`, every twisted-Edwards point operation, and the scalar-mult routine itself has to be written in user code on top of `Bignat`.
- BIP-62 (Bitcoin Core policy, since v0.11.0) and EIP-2 (Ethereum Homestead) require **low-`s` canonical signatures**: any signature with `s > ⌊n/2⌋` is non-canonical and rejected by mainnet validators. Whether the host or the card performs the flip is an applet-side decision.
- The public-key recovery byte `v` (also called `recid`) is required by Ethereum-style transactions but is **not** part of the ECDSA-Sig-Value structure. Computing `v` on-card requires either a modular square root (to recover the `R` point from `r`) or two trial pubkey recoveries plus a comparison — both of which exceed the JC 3.0.5 primitive surface.
- BIP-340 mandates an **even-`y`** `R` point (so the signature emits only `R.x` and the verifier reconstructs `R` by lifting the x-coordinate to its even-`y` representative). Whether the parity flip happens on-card or off-card is again an applet-side decision.
- **RFC 8032 §5.1.6 hashes the message internally** as part of both the deterministic-nonce derivation (`r = SHA-512(prefix ‖ M) mod ℓ`) and the challenge derivation (`k = SHA-512(R_enc ‖ A_enc ‖ M) mod ℓ`). A pre-hashed input (Ed25519ph) is a *different* signature scheme that no mainnet chain meowl signs for uses. The card therefore has to accept the **raw message** for `SIGN_ED25519`, contrary to ADR-0007's blanket "hashes only" rule — the exception is intentional and is the reason ADR-0007 says "unless the signature scheme itself hashes the message".

## Decision

### Wire layout

The Phase 5A/5B signing APDUs (`SIGN_ECDSA_K1`, `SIGN_SCHNORR_K1`) share a digest-input layout:

```text
[depth(1) | path(4*depth, BE) | digest(32)]
```

`depth ≤ HD_MAX_DEPTH = 8`. `digest` is exactly 32 bytes; the host is responsible for computing the chain-specific preimage hash (per ADR-0007).

The Phase 5C `SIGN_ED25519` APDU instead uses a **raw-message** layout, because RFC 8032 hashes the message itself:

```text
[depth(1) | path(4*depth, BE) | message(0..*)]
```

The message may be of any length, including zero. The card streams it through `MessageDigest.ALG_SHA_512` twice (the nonce hash and the challenge hash) directly from the APDU buffer, so no intermediate copy is needed beyond the buffer the secure-channel layer already provides. The depth/path semantics are identical to the digest-input layout above; only the trailing payload differs.

The response of `SIGN_ECDSA_K1` is:

```text
[r(32) | s(32)]
```

`r` and `s` are big-endian, zero-padded to 32 bytes each. `s` is **always** in the low half of `n` (`s ≤ ⌊n/2⌋`). No DER, no length prefix, no recovery byte.

The response of `SIGN_SCHNORR_K1` is:

```text
[bytes(R)(32) | s(32)]
```

where `bytes(R)` is the 32-byte big-endian x-coordinate of `R` with implicit even-`y` (SEC 1 §2.3.5 x-only form, as BIP-340 §2 specifies). The parity flip — picking `k ← n − k'` whenever the random `k' · G` lands on an odd-`y` point — is performed on-card, so the host verifier always sees an even-`y` `R` and never needs to encode a parity hint. `s` is in `[0, n)` per the BIP-340 sign algorithm; the low-`s` restriction is **not** part of BIP-340 (Schnorr is non-malleable by construction), so no Bitcoin-style low-`s` flip is applied here.

The response of `SIGN_ED25519` is:

```text
[R_enc(32) | S_enc(32)]
```

following RFC 8032 §5.1.6 verbatim. `R_enc` is the compressed Edwards encoding of `R = r · B` per RFC 8032 §5.1.2 (32-byte little-endian `y` with the high bit of byte 31 carrying bit 0 of `x`). `S_enc` is the 32-byte little-endian encoding of `S = (r + k · s) mod ℓ`, where `ℓ = 2²⁵² + 27742317777372353535851937790883648493` is the ed25519 group order. The host may feed this 64-byte blob into any standards-compliant Ed25519 verifier without further framing (the test suite uses the JDK's `Signature.getInstance("Ed25519")` directly).

### EXPORT_XPUB extension for Ed25519

Phase 5C also closes the loop on `EXPORT_XPUB` for the ed25519 branch: now that the applet can do a base-point scalar multiplication, the response on `CURVE_ED25519` becomes

```text
[pubkey(32) | chain_code(32)]
```

with `pubkey` in RFC 8032 §5.1.2 LE-compressed form derived on-card via the same scalar-mult routine that powers `SIGN_ED25519`. Phase 4's stop-gap shape (chain code only) is superseded; no host SDK still consumes the old 32-byte response.

### Nonce policy

The Phase 5 ECDSA primitive uses whatever nonce policy the underlying JC platform's `Signature.ALG_ECDSA_SHA_256` exposes — the applet does not install an external `k`. This deviates from ADR-0003's "deterministic RFC 6979 nonce" wording, which we update via this ADR to reflect the JC 3.0.5 reality:

- **Real silicon** (JCOP3 / JCOP4 / NXP P71 / Infineon SLE78): the ECDSA primitive uses the card's TRNG to draw a fresh random `k` per signature. Two signatures over the same `digest` at the same path yield different `r,s` bytes with overwhelming probability.
- **JCardSim** (host-side simulator used by the test suite): the implementation delegates to BouncyCastle's `ECDSASigner`, which defaults to **RFC 6979 deterministic** nonces. Two signatures over the same `digest` at the same path are byte-for-byte identical.

Both behaviours are accepted as valid ECDSA per FIPS 186-4 §6.4 and per every chain meowl signs for (Bitcoin, EVM, Cosmos, Tron, Filecoin, Spark, XRPL). The deterministic-vs-random property is a reproducibility distinction, not a validity distinction. Concretely:

- Deterministic reproducibility (replay the same `r,s` for the same `digest`) is a host-side concern: a host SDK that wants RFC 6979 across heterogeneous cards can pre-compute the deterministic `k` and sign in software, since it owns the seed exposed by `GENERATE_SEED` (or the seed it imported via `IMPORT_SEED`). The card's role is to be the authoritative signer for the seed it custodies; reproducibility off-card does not require it.
- A future ADR may re-introduce on-card RFC 6979 once a JC 3.x kit ships a `signWithProvidedNonce`-equivalent primitive, or as a software fallback if the threat model demands it. For v1.0 the simplicity wins.

The Phase 5B Schnorr primitive follows the **synthetic-nonce** branch of BIP-340 §3.2: `k' = int(tagged_hash("BIP0340/nonce", t ‖ bytes(P) ‖ m)) mod n` with `t = bytes(d) ⊕ tagged_hash("BIP0340/aux", aux)` and `aux ← TRNG(32)`. The aux randomness is drawn from the same JC `RandomData.ALG_KEYGENERATION` (fallback `ALG_TRNG`) source as the master seed; signatures are therefore **non-deterministic on every platform, including JCardSim**, and two signatures over the same `(path, digest)` differ in both `R` and `s` with overwhelming probability. BIP-340 §3.2 explicitly endorses this synthetic-nonce variant as the recommended default precisely because it adds fault-resistance over the pure-deterministic variant.

The Phase 5C Ed25519 primitive is the only one that is **fully deterministic** in the RFC 6979/8032 sense, and it is so on every platform — silicon and JCardSim alike. RFC 8032 §5.1.6 derives the ephemeral scalar as `r = SHA-512(prefix ‖ M) mod ℓ` where `prefix = SHA-512(sk)[32..64]` is itself a deterministic function of the SLIP-10 leaf private key. No RNG is consulted; two signatures over the same `(path, message)` are byte-for-byte identical, and `PhaseFiveCTest.Determinism.deterministicSignatures` pins this invariant. This is the property mainnet Solana / Sui / TON / Aptos validators expect and is the reason the chain ecosystem standardised on Ed25519 over Schnorr for these networks.

The test suite asserts only the validity invariant (every signature verifies under the derived pubkey, ECDSA satisfies `s ≤ ⌊n/2⌋`, Schnorr satisfies `y(R) is even` and `0 ≤ s < n`, Ed25519 verifies under the JDK's `Signature.getInstance("Ed25519")` for the corresponding pubkey returned by `EXPORT_XPUB`), plus the determinism invariant for Ed25519 specifically.

### Low-s normalisation (ECDSA only)

The card performs low-`s` normalisation **on-card**: after the JC ECDSA call returns, the applet compares the parsed `s` against the pre-computed `⌊n/2⌋` constant; if `s > ⌊n/2⌋` it replaces `s` with `n − s`. This keeps the host SDK trivial and prevents accidental high-`s` malleability bugs at the boundary.

BIP-340 Schnorr signatures are **not** low-`s` normalised: the scheme is malleability-free by construction (the verification equation `s · G = R + e · P` admits a unique `s` for any fixed `(R, P, m)` once parity of `R` is fixed), and BIP-341 / Taproot validators reject any flip of `s` to `n − s` because that produces a different — and equally non-malleable — signature for the same message. `s` is emitted verbatim in `[0, n)`.

### Even-y R enforcement (Schnorr only)

The parity flip of step 6 of BIP-340 §3.2 (`k ← n − k'` whenever `y(k' · G)` is odd) is performed on-card. The host verifier therefore reconstructs `R` by lifting `bytes(R)` to its **even-`y`** representative — the operation BIP-340 §3.3 step 6 specifies as `R = lift_x(int(r))`. No parity hint travels on the wire.

### Recovery byte `v`

The card **does not** emit a recovery byte. Hosts that need `v` (Ethereum, Filecoin, EIP-712 wallets) recover it post-facto by trying both `v ∈ {0, 1}`, recovering a candidate pubkey from `(r, s, digest, v)`, and matching against the expected pubkey returned by a prior `EXPORT_XPUB`. Standard reference libraries (`bitcoinjs-lib`, `noble-curves`, `kobe`) do this in O(1) elliptic-curve operations.

The rationale for keeping `v` off-card:

- Computing `v` on-card requires recovering the `R` point from `r`, which entails a modular square root over `F_p`. JC 3.0.5 provides no primitive for this; we would have to implement Tonelli-Shanks (or exploit `p ≡ 3 mod 4` and compute `r^((p+1)/4) mod p`) in user code, plus point arithmetic to compare candidates. The added code surface for one bit of information is not justified.
- The host pubkey is already cached after `EXPORT_XPUB`; recovery is ~50 µs in software on a phone.

### Software big-integer arithmetic (Schnorr only)

Schnorr's `s = (k + e · d) mod n` requires a full multi-precision multiply-then-reduce, which JC 3.0.5 does not expose. `Bignat.java` (Phase 5B) supplies the four primitives needed — big-endian byte-string add / subtract / less-than / multiply-then-mod-`n` — using classical school-book algorithms over `byte`-arrays. The multiply produces a 64-byte product; `Bignat.mod(...)` reduces it to 32 bytes by long division against the 32-byte modulus. Every Bignat operation is exercised by `BignatTest` against `java.math.BigInteger` as an oracle (800+ randomised tests).

All Bignat scratch lives in `JCSystem.makeTransientByteArray(CLEAR_ON_DESELECT)` and is explicitly wiped in a `finally` clause on every code path in `Schnorr.signDigest(...)` — the transient lifecycle alone is not sufficient because a subsequent call within the same session would otherwise see stale secrets.

### Scalar multiplication for Schnorr

`Schnorr.signDigest` calls `Bip32.scalarMultG(scalar, out)` twice — once to compute the public key `P = d' · G` (needed for parity testing and the challenge tag), and once for the nonce point `R = k' · G`. Internally this delegates to the same JC `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` primitive that powers `EXPORT_XPUB`, providing the uncompressed `0x04 ‖ x ‖ y` encoding the parity check needs. No software EC arithmetic is involved in this step.

### Software field, curve, and scalar arithmetic (Ed25519)

Ed25519 has no JC-native fallback at all, so Phase 5C reimplements the full algebraic stack on top of `Bignat`:

- **`Field25519.java`** — modular `add / sub / neg / mul / sqr / inv` over `F_p` with `p = 2²⁵⁵ − 19`. Multiplication and squaring delegate to `Bignat.mult` and `Bignat.mod`; inversion uses Fermat's little theorem (`a⁻¹ = a^(p−2) mod p`) with the binary square-and-multiply ladder. Inputs may freely alias the output thanks to a read-then-write byte-order discipline. All operations are oracle-checked against `java.math.BigInteger` by `Field25519Test`.
- **`Edwards25519.java`** — twisted-Edwards group operations in extended projective coordinates `(X, Y, Z, T)` per the EFD `add-2008-hwcd-3` (9 multiplications) and `dbl-2008-hwcd` (3 squarings + 4 multiplications) formulas, specialised for `a = −1`. Scalar multiplication is a **constant-time double-and-always-add** over the full 256 scalar bits: each iteration performs exactly one doubling and one addition, with the addend selected via byte-wise masking between the input point and the identity element so the secret bit never branches the control flow. Encoding is the RFC 8032 §5.1.2 LE-compressed `y ‖ sign_bit(x)` form.
- **`Ed25519.java`** — the RFC 8032 §5.1.6 sign pipeline itself: SHA-512 expansion of the SLIP-10 leaf seed, RFC 8032 clamping (`s[0] &= 248; s[31] &= 127; s[31] |= 64`), `A = s · B`, the two SHA-512-with-message hashes for `r` and `k`, the `mod ℓ` reductions (via `Bignat.mod` against the 32-byte group order), the `S = (r + k · s) mod ℓ` accumulation, and the final 64-byte LE encoding.

The whole stack uses one 1024-byte `CLEAR_ON_DESELECT` transient scratch buffer that hosts SHA-512 outputs, both scalar slots (clamped `s`, ephemeral `r`, challenge `k`, accumulated `S`), both intermediate point buffers (`A` then `R`), the base point, and the 512-byte scalar-mult workspace. `Ed25519.sign(...)` wipes the entire buffer in a `finally` clause regardless of which code path threw — the same pattern Schnorr uses. The end-to-end flow is exercised against the JDK's Ed25519 verifier by `PhaseFiveCTest` (every card-produced signature must verify) plus the official SLIP-10 reference vectors for the pubkey half.

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
- The Phase 5B applet code (`Schnorr.java` + `Bignat.java`) totals under ~500 lines by building Schnorr on top of two reusable primitives (`Bignat` for multi-precision arithmetic, `Bip32.scalarMultG` for the curve-point computation). The big-integer code is exercised against `java.math.BigInteger` by 800+ randomised tests in `BignatTest`, and the full Schnorr flow is exercised against a host-side BIP-340 verifier in `PhaseFiveBTest`.
- BIP-340 even-`y` enforcement is performed on-card, so the host verifier is a direct port of the BIP-340 reference algorithm with no parity-hint plumbing.
- The Phase 5C applet code (`Field25519.java` + `Edwards25519.java` + `Ed25519.java`) totals ~900 lines and is layered on top of the same `Bignat` library Schnorr uses, sharing the `mult` / `mod` primitives. The field layer is oracle-checked against `java.math.BigInteger` (~300 randomised tests in `Field25519Test`), the curve layer is oracle-checked against a `BigInteger`-backed affine reference implementation plus the RFC 8032 sk→pk derivation vectors (`Edwards25519Test`), and the full sign pipeline is end-to-end verified against the JDK's `Signature.getInstance("Ed25519")` for every card-produced signature (`PhaseFiveCTest`).
- Ed25519 is the only signing primitive that is fully deterministic on every supported platform: hosts that need bit-for-bit replay across multiple cards (e.g. Solana proof-of-history sequencers) get it for free, with no extra software path.

### Negative

- ADR-0003's "deterministic RFC 6979 nonce" wording is superseded for v1.0 (this ADR notes the deviation). Hosts relying on bit-for-bit reproducibility across signing calls must implement RFC 6979 themselves; the card cannot guarantee the same `r,s` for the same `digest`.
- The Phase 5B Schnorr primitive is **always** non-deterministic on-card (it follows the BIP-340 synthetic-nonce branch with RNG-sourced aux randomness). Hosts that want pure-deterministic BIP-340 (`aux = 0x00..00`, no XOR with `t`) for cross-card replay reasons must again sign in software, since the card owns the seed.
- Hosts must implement recovery-byte derivation themselves. Every mainstream wallet SDK already does this, so the cost is negligible.
- Schnorr signing is **software-implemented** on top of `Bignat`, so it is slower than the JC-native ECDSA path. Order-of-magnitude budget on JCOP3 / JCOP4 silicon: ~100 ms per Schnorr sign (dominated by two `scalarMultG` calls of ~30 ms each and one 32×32 software multiply of ~10 ms), versus ~20 ms for a JC-native ECDSA sign. This is well below the human-perceptible threshold for a single APDU; bulk-signing workloads (rare in a hardware-wallet context) should pipeline.
- Ed25519 signing is **fully software** down to the field level — two 256-bit scalar multiplications (one for `A = s · B` during pubkey derivation, one for `R = r · B` during sign), each iterating 256 doublings and 256 additions, plus three SHA-512 calls and one 32×32 multiply-then-reduce for `S`. Order-of-magnitude budget on JCOP3 / JCOP4 silicon: ~400–600 ms per `SIGN_ED25519`, versus ~20 ms for native ECDSA and ~100 ms for software Schnorr. This is at the edge of the human-perceptible threshold for a single tap. The constant-time double-and-always-add does ~2× the work a leaky double-and-add would (and is the right tradeoff against an SE that may be probed); a future ADR may revisit this with a precomputed-base-point table once the v1.0 chain coverage is in production and we have measurements from real silicon.
- The applet's transient-memory budget grows by ~1024 bytes for the Ed25519 scratch slot. Real JCOP3 / JCOP4 / P71 silicon comfortably handles this (4–8 KB of transient RAM per applet); pre-3.0.4 cards would not, but ADR-0001 already excludes them.
- The Ed25519 sign APDU's `message` field is variable-length (up to ~225 bytes after the depth + path + secure-channel overhead fits inside one Lc-extended APDU). Hosts that need to sign messages larger than that must use the chain's existing pre-hashing convention (Solana already wraps in a 32-byte transaction-hash for cross-program invocation; Sui / TON / Aptos likewise). This is a wire-budget concern, not a protocol-correctness concern — the algorithm itself accepts arbitrary-length messages.

### Neutral

- A future ADR may revisit either decision once JC 3.x ships a deterministic-nonce primitive or once we add a software ECDSA path. Neither is on the v1.0 roadmap.
