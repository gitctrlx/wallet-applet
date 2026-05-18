# ADR-0004: Secure Channel cipher suite

Date: 2026-05-18

## Status

Accepted

## Context

Every non-public APDU sent to the card must be encrypted and authenticated end-to-end between the host and the secure element. Satochip's Secure Channel (introduced in v0.11-0.1) is built around:

- ECDH on secp256k1 to derive a shared secret.
- HMAC-SHA160 (i.e., HMAC-SHA-1, 160-bit output) as the key-derivation primitive.
- AES-128 in CBC mode for confidentiality.
- HMAC-SHA160 again as the message MAC.

HMAC-SHA1 and AES-128 are not broken, but they are below the contemporary 128-bit security floor and are categorically inferior to modern AEAD constructions. We are not bound by Satochip's wire format (see [ADR-0002](./0002-cla-and-greenfield-protocol.md)), so we can specify a better cipher suite.

## Decision

**Single suite (`SC-V1`)** — AES-256-CBC + HMAC-SHA-256:

- **Handshake:** ECDH over secp256k1 with ephemeral keys on both sides (host uses 65-byte uncompressed SEC1 form). The card additionally signs the concatenation of both ephemeral public keys with the long-lived `authentikey` ([ADR-0005](./0005-authentikey-lifecycle.md)) so the host can authenticate the card.
- **Key derivation:** HKDF-SHA-256 (RFC 5869) extract+expand.
  - `salt = client_eph_x ‖ card_eph_x` (64 bytes)
  - `ikm  = shared_x` (32 bytes, the x-coordinate of the ECDH point)
  - `info = "meowl-sc-v1"` (11 bytes)
  - `okm  = HKDF-Expand(PRK, info, 80)` split as:
    - 32 bytes → `K_enc` (AES-256 key)
    - 32 bytes → `K_mac` (HMAC-SHA-256 key)
    - 16 bytes → `IV_base` (XOR-mixed with a monotonic counter to produce each outbound IV)
- **Confidentiality:** AES-256-CBC with PKCS#5 padding. Every direction carries a fresh 16-byte IV.
- **Authentication:** HMAC-SHA-256 keyed with `K_mac`, truncated to 16 bytes (`SC_MAC_LEN`).
  - **Inbound MAC** = `HMAC(K_mac, outer_header[CLA,INS,P1,P2,LC] ‖ IV ‖ ciphertext)[0..16]`
  - **Outbound MAC** = `HMAC(K_mac, 0xFF ‖ IV ‖ ciphertext)[0..16]` (`0xFF` is a fixed direction-tag).
- **Replay defense:** the card stores the last accepted inbound IV; each new inbound IV must strictly exceed it.

We deliberately ship a single cipher suite, not the dual GCM/CBC scheme the original plan suggested. Rationale, with hard data:

- **Hardware coverage.** [JCAlgTest](https://jcalgtest.org/) measured algorithm support across 112 real cards: `AEADCipher.ALG_AES_GCM` is implemented on only **7 / 112 = 6.3 %**. Even within the modern JCOP family, the JCOP4 SECID-grade card (J3R180) — a likely production target for meowl — does **not** expose AES-GCM. By contrast `Cipher.ALG_AES_BLOCK_128_CBC_NOPAD` is on 51 / 112 (45.5 %) and `Signature.ALG_HMAC_SHA_256` on 61 / 112 (54.5 %), with the modern silicon sample skewing heavily toward "supported". CBC + HMAC-SHA-256 is the choice that maximises silicon portability without sacrificing security level.
- **Cryptographic equivalence.** AES-256-CBC with a 256-bit HMAC-SHA-256 MAC reaches the same 256-bit symmetric security level as AES-256-GCM, with no known weakness in the construction when MAC verification is constant-time and the plaintext does not have to be parsed before MAC verification (both true here).
- **Operational simplicity.** A single suite removes the capability-driven cipher-suite negotiation that the original ADR proposed. The `CAP_SC_CBC_HMAC` capability bit is unconditionally set in `GET_INFO`; the unallocated `CAP_SC_GCM` bit remains reserved for a future revision should GCM become ubiquitous on production-grade silicon.

## Consequences

### Positive

- **Security margin:** AES-256 + 256-bit MAC, AEAD with explicit AAD binding the outer header, monotonic IV with replay protection on the card side.
- **Forward secrecy:** ephemeral ECDH on both sides means a compromise of the long-lived `authentikey` does **not** compromise past session traffic.
- **Card-side authentication:** the host can verify it is talking to a genuine meowl card via the `authentikey` signature on the card's ephemeral public key; combined with the factory PKI cert, this defeats counterfeit cards.

### Negative

- **Slightly heavier handshake** than Satochip's (extra 32-byte HKDF expansion plus a card-signed ephemeral pubkey), at the cost of dozens of milliseconds per session establishment — acceptable.
- **PKCS#5 padding** is conceptually weaker than an AEAD construction (an attacker can in principle mount a padding-oracle attack if MAC verification leaks the first-difference position). We mitigate on two fronts: (a) **always MAC-then-decrypt** — the cipher is only invoked once the MAC has verified, and (b) **MAC verification uses our own `ConstantTime.equals`** rather than `Util.arrayCompare`. The JavaCard 3.x specification only guarantees that `Util.arrayCompare` performs the comparison "from left to right" and returns a ternary result; it does **not** promise constant time. A short-circuit on first mismatch would leak the position of the first differing byte. Our `ConstantTime.equals` XOR-accumulates every byte into a single difference register and decides equality at the end, removing the timing channel.

### Neutral

- A future ADR may introduce an AES-256-GCM suite as `CAP_SC_GCM` once silicon support is widespread, but this is purely an internal simplification — the security level is identical.
