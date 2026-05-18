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

We deliberately ship a single cipher suite, not the dual GCM/CBC scheme the original plan suggested. The rationale: AES-256-CBC + HMAC-SHA-256 reaches the same 256-bit security level as AES-256-GCM, is supported by every JavaCard 3.0.4+ silicon we target, and removes the complexity of capability-driven cipher-suite negotiation between host and card. The `CAP_SC_CBC_HMAC` capability bit is advertised in `GET_INFO`; `CAP_SC_GCM` is reserved for a future revision should silicon support warrant it.

## Consequences

### Positive

- **Security margin:** AES-256 + 256-bit MAC, AEAD with explicit AAD binding the outer header, monotonic IV with replay protection on the card side.
- **Forward secrecy:** ephemeral ECDH on both sides means a compromise of the long-lived `authentikey` does **not** compromise past session traffic.
- **Card-side authentication:** the host can verify it is talking to a genuine meowl card via the `authentikey` signature on the card's ephemeral public key; combined with the factory PKI cert, this defeats counterfeit cards.

### Negative

- **Slightly heavier handshake** than Satochip's (extra 32-byte HKDF expansion plus a card-signed ephemeral pubkey), at the cost of dozens of milliseconds per session establishment — acceptable.
- **PKCS#5 padding** is conceptually weaker than an AEAD construction (an attacker can in principle mount a padding-oracle attack if MAC verification is constant-time-incorrect). We mitigate by always MAC-then-decrypt: the cipher is only invoked once the MAC has verified, and `Util.arrayCompare` is constant-time per the JC spec.

### Neutral

- A future ADR may introduce an AES-256-GCM suite as `CAP_SC_GCM` once silicon support is widespread, but this is purely an internal simplification — the security level is identical.
