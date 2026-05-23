---
meap: 2
title: Secure Channel — ECDH + AES-256-CBC + HMAC-SHA-256
description: Ephemeral-ECDH handshake on secp256k1, HKDF-SHA-256 key schedule and an authenticated record layer that wraps every inner-band command.
status: Draft
type: Standards Track
category: Wire
created: 2026-05-19
requires: [1]
author: meowl.social contributors
---

# MEAP-2: Secure Channel — ECDH + AES-256-CBC + HMAC-SHA-256

## Abstract

This MEAP specifies the Secure Channel that wraps every command in the inner-band INS surface defined by [MEAP-1](./meap-1.md). The channel comprises a one-roundtrip ephemeral-ECDH handshake on secp256k1, a HKDF-SHA-256 key schedule deriving a 256-bit AES-CBC encryption key, a 256-bit HMAC-SHA-256 MAC key and a 16-byte IV base, and a record format that authenticates the outer APDU header alongside the encrypted inner payload. Replay is defeated by a strictly increasing inbound IV and a monotonic outbound counter. The handshake additionally lets the host authenticate the card via the long-lived `authentikey` ([MEAP-4](./meap-4.md)).

## Motivation

The card hosts the master seed and every derived private scalar. Every command that touches those secrets — PIN management, seed import, signing — flows through a contact or contactless interface that an attacker can in principle eavesdrop on, modify, or replay against another card. The Secure Channel exists to neutralise that wire-level attacker on three fronts:

1. **Confidentiality** — PIN bytes, seed bytes, and signing inputs MUST NOT be readable by anyone holding the wire.
2. **Integrity** — neither the host's command nor the card's response may be modified in transit; the card MUST NOT execute a tampered command and the host MUST NOT trust a tampered response.
3. **Card authentication** — the host MUST be able to distinguish a genuine meowl card from a counterfeit before sending the PIN.

Forward secrecy is a desirable fourth property: a future leak of the long-lived `authentikey` MUST NOT compromise traffic captured before the leak. The construction in this MEAP achieves all four with primitives universally supported on JC 3.0.4-and-later silicon (per JCAlgTest population data).

## Specification

### Notation

Throughout this MEAP, `‖` denotes byte-string concatenation, `[a..b)` denotes the half-open byte range, and "wide" arithmetic on integers (e.g. "monotonically increasing") refers to interpreting the bytes as a 128-bit big-endian unsigned integer.

The 16-byte AES-CBC IV is referred to as `IV` throughout; the parameter name is overloaded with the AES init-vector slot, but no distinct IV is required by this MEAP.

### Cipher suite

A conforming applet MUST implement, and a conforming host MUST drive, exactly the following primitive set:

- **Curve and signature**: secp256k1 with `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` for ephemeral ECDH and `Signature.ALG_ECDSA_SHA_256` for handshake authentication.
- **Key derivation**: HKDF-SHA-256 (RFC 5869), Extract-then-Expand.
- **Confidentiality**: AES-256-CBC with PKCS#5 padding (`Cipher.ALG_AES_BLOCK_128_CBC_NOPAD` plus an explicit padding step in software).
- **Authentication**: HMAC-SHA-256 (`Signature.ALG_HMAC_SHA_256`), output truncated to the leftmost 16 bytes.

This suite is advertised by the `CAP_SC_CBC_HMAC` capability bit (mask `0x0010` per [MEAP-1](./meap-1.md)). A future MEAP MAY introduce additional Secure Channel suites and allocate further capability bits at that time.

### Handshake — `INIT_SECURE_CHANNEL` (INS `0x10`)

The handshake is one APDU round-trip. It consumes the host's ephemeral keypair on the inbound side and emits the card's ephemeral keypair plus a card-authentication signature on the outbound side. The handshake itself is **not** encrypted because the keys it needs are precisely the keys it derives.

Inbound APDU body:

```text
client_eph_pub  : 65 bytes  ; SEC1-uncompressed secp256k1 point: 0x04 ‖ x ‖ y
```

A conforming applet MUST reject any other body length with `6700`. It MUST reject a body whose first byte is not `0x04` with `6FB2` (Secure Channel cryptographic check failed) — only the uncompressed encoding is accepted; the host SHOULD NOT send a compressed point even if the curve admits one.

A conforming applet MUST additionally ensure that `client_eph_pub` is a valid secp256k1 point — i.e. that `y² ≡ x³ + 7 (mod p)`. The reference implementation delegates this check to the underlying `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` implementation, which the JC 3.0.5 specification requires to raise `CryptoException.ILLEGAL_VALUE` on a non-curve point. The applet MUST capture any exception raised by `generateSecret` (whether `CryptoException`, `ArrayIndexOutOfBoundsException` or another) and convert it to `6FB2`, never propagating the silicon-specific exception type to the host. Deployments MUST verify, as part of the silicon admission checklist, that the target card actually performs point validation in its native ECDH (cards that silently accept off-curve points MUST NOT be qualified for production); see *Invalid-point rejection* in §Security Considerations for the rationale and threat model.

The card MUST then:

1. Generate a fresh ephemeral secp256k1 keypair `(eph_card_priv, eph_card_pub)` using `RandomData.ALG_KEYGENERATION` (or `ALG_TRNG` fallback).
2. Compute `shared_xy ← ECDH(eph_card_priv, client_eph_pub)` using `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`. The output is the uncompressed point `0x04 ‖ shared_x ‖ shared_y`; only `shared_x` (the 32 bytes following the `0x04` prefix) feeds the KDF.
3. Run the HKDF schedule defined in *Key derivation* below.
4. Sign the concatenation `eph_card_pub ‖ client_eph_pub` (i.e. the two SEC1-uncompressed encodings, totalling 130 bytes) with the long-lived `authentikey` using `Signature.ALG_ECDSA_SHA_256`. The signature is DER-encoded per the JC platform default; its length is variable.
5. Emit the response described below.

Outbound APDU body:

```text
card_eph_pub    : 65 bytes              ; SEC1-uncompressed
sig_len         : 2 bytes               ; unsigned 16-bit big-endian length of the signature
sig             : sig_len bytes, ≤72    ; DER-encoded ECDSA signature over the two pubkeys
```

The DER signature is variable-length (typically 70–72 bytes; structurally bounded by 72 because each of `r` and `s` is at most 33 bytes including the optional leading `0x00` sign byte). The 2-byte big-endian `sig_len` prefix makes the boundary explicit so the host can locate the signature without first parsing the DER structure — a deliberate engineering trade-off to keep the wire parseable by hosts that do not link a full ASN.1 toolchain.

A conforming host MUST verify the DER-encoded signature against the `authentikey` public key obtained from `GET_INFO` ([MEAP-1](./meap-1.md) §`GET_INFO` payload) before deriving the session keys. The host MUST treat any DER-decoding failure or signature-verification failure as a fatal error and MUST NOT proceed to the encrypted record layer. Hosts that previously cached the `authentikey` SHOULD compare against the cached fingerprint to defeat counterfeit cards that present a manufacturer-issued (i.e. legitimately signed) but different `authentikey`.

A conforming applet MUST emit `sig_len` matching the exact length of the DER signature it produces, and MUST NOT emit any trailing bytes past `sig`. A conforming host MUST treat a body length other than `65 + 2 + sig_len` as a fatal protocol error.

A conforming applet MUST tear down any previously open Secure Channel and any prior `VERIFY_PIN` authorisation flag at the **start** of `INIT_SECURE_CHANNEL`, before generating the new ephemeral keypair. This makes the PIN session strictly bound to a single Secure Channel session; an attacker who steals an authenticated card cannot inherit the PIN flag by re-handshaking.

### Key derivation

Both endpoints derive the session keys identically:

```text
salt = client_eph_pub_x ‖ card_eph_pub_x      ; 64 bytes (the two x-coordinates)
ikm  = shared_x                                ; 32 bytes (ECDH x-coordinate)
PRK  = HKDF-Extract(salt, ikm)                 ; 32 bytes (HMAC-SHA-256 output length)
okm  = HKDF-Expand(PRK, "meowl-sc-v1", L=80)  ; 80 bytes
       └─ K_enc      = okm[ 0..32)            ; AES-256 key
       └─ K_mac      = okm[32..64)            ; HMAC-SHA-256 key
       └─ IV_base    = okm[64..80)            ; 16 bytes, used as a per-session XOR mask
```

The `info` parameter MUST be the ASCII byte string `meowl-sc-v1`, exactly 11 bytes, with no terminating NUL. A future Secure Channel revision MUST allocate a fresh label (e.g. `"meowl-sc-v2"`) so that the same shared secret cannot be re-used across protocol revisions.

A conforming applet MUST place `K_enc`, `K_mac` and `IV_base` in transient memory (`CLEAR_ON_DESELECT` lifecycle). Both endpoints MUST destroy the ephemeral private key as soon as the shared secret is computed; the ephemeral public keys MAY linger for the duration of the handshake response.

### Record layer — `OPEN_SECURE_CHANNEL` (INS `0x11`)

Every inner-band APDU travels inside `OPEN_SECURE_CHANNEL` envelopes. The envelope authenticates the outer APDU header along with the encrypted inner payload, defeating both eavesdropping and selective-modification attacks.

#### Inbound (host → card)

The outer-frame APDU is built as:

```text
[CLA INS P1 P2 LC]   IV(16)   ciphertext(N×16)   MAC(16)
```

where:

- `CLA = 0x80`, `INS = 0x11`, `P1 = P2 = 0x00`.
- `LC` is the total inner data length: `16 + N×16 + 16` for an `N`-block ciphertext.
- `IV` is a 16-byte big-endian counter strictly greater than the previously accepted inbound `IV`. The first APDU after a successful handshake therefore uses any nonzero `IV`; subsequent APDUs MUST monotonically advance.
- `ciphertext = AES-256-CBC-encrypt(K_enc, IV, plaintext ‖ pad)` where `pad` is PKCS#5 padding making the total length a multiple of 16.
- `MAC = HMAC-SHA-256(K_mac, [CLA INS P1 P2 LC] ‖ IV ‖ ciphertext)[0..16]`.

The plaintext is the inner APDU as if it had been sent at the outer frame: `[inner_CLA inner_INS inner_P1 inner_P2 inner_LC inner_DATA]` with `inner_CLA = 0x80`. The inner header may carry any inner-band INS specified by [MEAP-3](./meap-3.md), [MEAP-4](./meap-4.md), [MEAP-5](./meap-5.md) or [MEAP-6](./meap-6.md).

A conforming applet MUST process inbound `OPEN_SECURE_CHANNEL` APDUs as follows:

1. **Verify lengths**: the data field MUST be at least 32 bytes (`IV + minimum ciphertext + MAC` is `16 + 0 + 16` but the minimum non-empty ciphertext is one 16-byte block, so the minimum useful length is 48). Reject with `6700` otherwise.
2. **Verify replay**: compare `IV` byte-for-byte against `last_inbound_IV`. If `IV ≤ last_inbound_IV`, reject with `6FB2` (Secure Channel cryptographic check failed). The replay check MUST happen before MAC verification so a wire attacker with no MAC key still gets a hard reject; this is a defense-in-depth measure.
3. **Verify MAC**: compute `expected_MAC = HMAC-SHA-256(K_mac, [CLA INS P1 P2 LC] ‖ IV ‖ ciphertext)[0..16]`. Compare against the received `MAC` using a constant-time equality function (the reference implementation uses `BigNat.ctEquals`; `Util.arrayCompare` is **not** constant-time per the JC 3.x specification and MUST NOT be used here). If the comparison fails, reject with `6FB2`.
4. **Decrypt**: `padded_plaintext = AES-256-CBC-decrypt(K_enc, IV, ciphertext)`. Strip the trailing PKCS#5 padding to recover the inner APDU. A pad length outside `[1, 16]` or any `pad[i] ≠ pad_length` MUST cause a `6FB2` rejection — this case can only arise from a key mismatch (the MAC having already verified) or from a buggy host, neither of which the card should accommodate.
5. **Update replay state**: as soon as the MAC verification and the strict-greater-than `IV` check have both passed, store `IV` as the new `last_inbound_IV`. The applet MUST commit the replay counter at this point — before AES decryption proceeds — because any subsequent failure (PKCS#5 padding mismatch, decrypt error, inner-INS dispatch error) tears down the session entirely and requires a fresh `INIT_SECURE_CHANNEL` handshake before the host can resume; the legitimate host therefore never re-uses an `IV` and an attacker cannot exploit a stale `IV` either. Anchoring the counter advance to the MAC + IV-monotonicity check (both of which the attacker cannot pass without `K_mac`) is what makes the replay defense tight: a wire attacker fabricating an envelope under a fresh `IV` either gets a `6FB2` (MAC mismatch) without advancing the counter, or — if they somehow break the MAC — has already won and the counter advance is irrelevant.
6. **Dispatch**: parse the inner APDU header from the decrypted plaintext and dispatch to the appropriate inner-INS handler.

A conforming host MUST:

- Use a fresh `IV` for every `OPEN_SECURE_CHANNEL` APDU. The reference host generates `IV` from a 64-bit counter packed into the low 8 bytes of a 16-byte buffer; this trivially satisfies "strictly increasing" while being trivial to inspect in logs.
- Never send the same `IV` twice in a session, including across retries. A retry after a transport-level failure MUST use a fresh `IV`.

#### Outbound (card → host)

Every successful inner-INS response is wrapped as:

```text
IV(16)   ciphertext(N×16)   MAC(16)        ; followed by SW1 SW2 = 9000
```

where:

- `IV` is `IV_base XOR outbound_counter` where `outbound_counter` is incremented on every successful outbound wrap.
- `ciphertext = AES-256-CBC-encrypt(K_enc, IV, response_plaintext ‖ pad)`.
- `MAC = HMAC-SHA-256(K_mac, 0xFF ‖ IV ‖ ciphertext)[0..16]`. The `0xFF` direction-tag is fixed and distinguishes outbound MACs from inbound MACs (which are tagged by the outer-frame APDU header `0x80 0x11 0x00 0x00 LC`); this dispels any cross-direction confusion attack.

A conforming applet MUST emit the outbound envelope verbatim regardless of whether the inner handler succeeded. If the inner handler throws an `ISOException` with status word `SW_INNER`, the applet MUST emit an outbound envelope whose plaintext is empty and whose outer status word is `SW_INNER` (i.e. the inner status word is surfaced to the host directly, not stuffed into the encrypted body). This makes the wire status indistinguishable from a raw error response and avoids leaking the existence of the encrypted layer to a passive observer.

If MAC verification fails on the inbound side, the applet MUST respond with status word `6FB2` and an empty data field; no outbound envelope is emitted in that case.

### Session lifecycle

A conforming applet MUST tear down the Secure Channel session — clear `K_enc`, `K_mac`, `IV_base`, `last_inbound_IV`, `outbound_counter` and the `pinManager.pin_verified` flag — on every one of the following events:

- Card deselect (`select()` of any other applet, or end of contactless session).
- Receipt of a fresh `INIT_SECURE_CHANNEL` (a new handshake replaces the prior session unconditionally).
- Receipt of a `RESET_TO_FACTORY` invocation that completes the wipe (the fourth in the [MEAP-3](./meap-3.md) countdown).
- An unrecoverable cryptographic failure in the record layer (replay, MAC mismatch, padding mismatch).

The `pin_verified` flag is **session-scoped**: a host that has called `VERIFY_PIN` inside one Secure Channel session MUST re-call `VERIFY_PIN` after any of the events above, and a fresh handshake therefore opens an unauthenticated session even if the handshake itself succeeds. This prevents an attacker with brief physical access to an authenticated card from inheriting the PIN authorisation by opening their own Secure Channel session.

## Rationale

### Why CBC + HMAC, not GCM

JCAlgTest's [survey of 112 production cards](https://jcalgtest.org/) finds `AEADCipher.ALG_AES_GCM` available on only 7 cards (≈6%). Even within the JCOP 3 / JCOP 4 family — the primary deployment target of this MEAP — the SECID-grade J3R180 does not advertise GCM. By contrast `Cipher.ALG_AES_BLOCK_128_CBC_NOPAD` is on ≈45% of cards and `Signature.ALG_HMAC_SHA_256` on ≈54%, with the modern silicon sample skewing heavily toward "supported". Choosing CBC + HMAC therefore maximises silicon portability without sacrificing security level: AES-256-CBC with a 256-bit HMAC-SHA-256 MAC matches the 256-bit symmetric strength of AES-256-GCM exactly, given two side conditions both met by this MEAP:

1. The MAC verification is constant-time (`BigNat.ctEquals`).
2. The plaintext is **never** parsed before the MAC has been verified (the MAC-then-decrypt order).

A future MEAP MAY introduce an AES-GCM cipher suite once silicon support is broader. Such a MEAP would assign a different HKDF `info` label so that the two suites cannot be confused for one another by a host.

### Why ephemeral ECDH on both sides

A purely card-side ephemeral key would protect the card's traffic but not the host's. Mutual ephemeral ECDH gives **forward secrecy in both directions**: an attacker who later compromises the long-lived `authentikey` cannot decrypt past traffic, because past traffic was protected by ephemeral keys that the card destroyed at handshake's end. The host SDK is responsible for treating its ephemeral private key with the same hygiene.

### Why HKDF rather than KDF1/KDF2/KDF3

HKDF-SHA-256 is the modern default specified in RFC 5869. KDF1 (X9.63) and KDF2 (NIST SP 800-56A pre-2018 revision) lack the explicit Extract step that gives HKDF its uniform-output-distribution property when the input keying material is biased (which an ECDH x-coordinate is, slightly: `shared_x` is uniform over `[1, p−1]` modulo the curve order, not over `[0, 2²⁵⁶)`). Using HKDF erases that small bias from the derived keys.

### Why MAC over the outer header

Including `[CLA INS P1 P2 LC]` in the inbound MAC computation binds the encryption to the outer APDU framing. An attacker cannot strip the encrypted payload off one envelope and replay it under a different `LC` (e.g. truncating the ciphertext); the MAC catches the substitution. The reference implementation deliberately uses the full outer header rather than just `LC` to make the binding explicit.

### Why a fixed `0xFF` direction tag

The inbound MAC's first byte is the outer `CLA = 0x80`; the outbound MAC's first byte is `0xFF`. The two directions therefore cannot collide under any forging strategy: an attacker who replays a card response to the card itself, or vice versa, gets a MAC mismatch on the first byte alone. `0xFF` is chosen because it is outside the ISO 7816-4 CLA range and unambiguously identifies the outbound direction.

### Why PKCS#5 padding

PKCS#5 (= PKCS#7 for AES's 16-byte block) is the only padding scheme universally supported across JC 3.0.4+ silicon. ISO/IEC 7816-4 padding (one `0x80` byte plus zero-padding) is tempting because it leaks less information on a malformed message, but it is not widely available natively and a software implementation would expand the applet's audit surface for negligible benefit given that the MAC-then-decrypt order eliminates the only attack PKCS#5 padding is theoretically exposed to (the padding-oracle attack).

## Backwards Compatibility

N/A — no prior revision. A successor MEAP MAY introduce an alternative cipher suite, identified by a different `info` label and a different `CAP_SC_*` capability bit; until then, every implementation MUST speak `meowl-sc-v1`.

## Test Vectors

The end-to-end handshake is non-deterministic (each side draws a fresh ephemeral keypair), but the KDF schedule from §*Key derivation* is purely deterministic given its three inputs. The reference test suite pins both surfaces.

### KDF vector (deterministic)

Given the following synthetic ECDH outputs — the byte values are not on-curve points; they are chosen for ease of reproduction by any host SDK with an HMAC-SHA-256 implementation:

```text
client_eph_pub_x = 32 × 0x11
card_eph_pub_x   = 32 × 0x22
shared_x         = 32 × 0x33
salt             = client_eph_pub_x ‖ card_eph_pub_x  ; 64 bytes total (32 × 0x11 then 32 × 0x22)
ikm              = shared_x                            ; 32 bytes
info             = "meowl-sc-v1"                       ; 11 ASCII bytes, no terminating NUL
L                = 80
```

A conforming HKDF-SHA-256 implementation MUST produce, byte-for-byte:

```text
PRK     = 27d5c053aba7808dccba40fc66bfa0094129483e592db687e7345ec0550da58e
K_enc   = 6189c1be9f1bb2feb34f38887be5e37f8360d16ba16f845cba9827dc6e8d1d3c
K_mac   = e22e70e0bc34d1e073d444dacc8f3065195571aef13ff7232387c8cf70432317
IV_base = 215d786fc0934b749621541e7203add4
```

This vector is pinned in [`SecureChannelTest.kdfVectorMatchesPinnedExpectation`](../../tests/src/test/java/social/meowl/applet/SecureChannelTest.java) and is the single check a host SDK author can run to confirm their HKDF + label routing matches the reference applet without standing up a JCardSim end-to-end.

### Envelope invariants (non-deterministic)

The end-to-end handshake produces fresh ephemeral keypairs on every run, so byte-level signature / `IV` pinning is not possible. The reference test suite pins the **invariants**:

- After a successful handshake, the next `OPEN_SECURE_CHANNEL` envelope decrypts to the inner APDU verbatim, regardless of length and content.
- A modified MAC byte → `6FB2`.
- A modified ciphertext byte → `6FB2` on MAC verification (not on padding).
- A replayed `IV` → `6FB2` (regardless of MAC validity).
- A `select()` between two `OPEN_SECURE_CHANNEL` calls → the second call MUST fail with `6FB1` (Secure Channel required) because the session is gone.

The reference test scaffolding builds and consumes the envelope in pure JCE / BouncyCastle code as a host would, then drives the simulator. See the helper `Session` class shared across the inner-INS test files for the exact algorithm.

## Reference Implementation

- Handshake and record layer: [`SecureChannel`](../../applet/src/main/java/social/meowl/applet/SecureChannel.java).
- HKDF-SHA-256 implementation: [`Hkdf`](../../applet/src/main/java/social/meowl/applet/Hkdf.java).
- Constant-time MAC comparison: `BigNat.ctEquals` in [`BigNat`](../../applet/src/main/java/social/meowl/applet/BigNat.java).
- Reference test class: [`SecureChannelTest`](../../tests/src/test/java/social/meowl/applet/SecureChannelTest.java); the inner-INS test files (`PersonalisationTest`, `HdDerivationTest`, `EcdsaK1Test`, `SchnorrK1Test`, `Ed25519SigningTest`) each carry an inline host-side `Session` helper that exercises the wire end-to-end.

## Security Considerations

### Padding-oracle resistance

PKCS#5 padding alone would be vulnerable to padding-oracle attacks. MEAP-2 closes the surface through two Specification-level rules: MAC-then-decrypt ordering (a tampered ciphertext fails MAC verification before the padding check is ever reached) and constant-time MAC comparison via `BigNat.ctEquals`. The audit-critical invariant is that a non-constant-time substitute such as `Util.arrayCompare` MUST NOT replace `BigNat.ctEquals` in the MAC-verify path; the tamper-MAC and replay-IV cases in `SecureChannelTest` exercise the equivalence end-to-end.

### Post-handshake authentication

The handshake authenticates the **card** to the host (via the `authentikey` ECDSA signature over the two ephemeral pubkeys). It does **not** authenticate the host to the card; that is the role of `VERIFY_PIN` ([MEAP-3](./meap-3.md)). A conforming host MUST therefore complete `VERIFY_PIN` inside the freshly opened Secure Channel session before invoking any sensitive inner-INS opcode; the card enforces this by gating those opcodes behind the `pin_verified` flag.

### Host-side ephemeral entropy

The host's ephemeral keypair MUST be drawn from a CSPRNG, not from a deterministic source. A predictable ephemeral private key would let a network adversary recover `shared_x` after observing one handshake from each side, defeating the forward-secrecy property. Reference host SDKs SHOULD use the platform CSPRNG (`/dev/urandom`, `getrandom(2)`, `BCryptGenRandom` etc.) for this purpose.

### Counterfeit cards

A counterfeit card with its own legitimately-issued `authentikey` (e.g. a card from the same manufacturer programmed with a different applet) would pass the handshake's signature check. Hosts that need to bind to a *specific* card SHOULD pin the `authentikey` fingerprint on first use (TOFU) and reject any subsequent handshake that presents a different fingerprint. The optional manufacturer PKI specified in [MEAP-4](./meap-4.md) provides a stronger anchor by tying each `authentikey` to a chain of trust the host can verify.

### Invalid-point rejection

The handshake's secp256k1 ECDH is the only place where an attacker-controlled EC point reaches a private-scalar multiplication. If the silicon's `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` were to silently accept a point that does not lie on the curve, the "shared secret" could land on a twist or substitution subgroup with much smaller order; multiple handshakes would then suffice to recover the ephemeral private scalar (invalid-curve attack).

The Specification's exception-to-`6FB2` rule and the deployment-side admission check it cites both depend on the silicon actually validating points natively. Every JCOP 3, JCOP 4 and SECID platform in JCAlgTest's current corpus complies; deployments MUST re-verify on every new silicon revision before qualification. The applet does NOT carry an in-software `y² ≡ x³ + 7 (mod p)` validator — the cost (≈5 KB CAP space plus a modular-square-root audit surface) is not warranted while every modern target silicon validates correctly.

Damage from a missed validation is bounded by the ephemeral-ephemeral construction: the long-lived `authentikey` never participates in EC arithmetic with attacker-controlled input. The worst case is the recovery of the ephemeral scalar of a single handshake — protecting one Secure Channel session whose plaintext the attacker, being the originating host, already has.

## Copyright

This document is licensed under the AGPL-3.0-or-later licence the rest of the project uses; see [LICENSE](../../LICENSE).
