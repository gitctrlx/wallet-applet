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

**Preferred suite (`SC-V1`):**

- **Handshake:** ECDH over secp256k1 with ephemeral keys on both sides; the card additionally signs its ephemeral public key with the long-lived `authentikey` ([ADR-0005](./0005-authentikey-lifecycle.md)) so the host can authenticate the card.
- **Key derivation:** HKDF-SHA-256 (RFC 5869) expands the shared secret + the concatenation of both ephemeral public keys (as salt) + the literal `"meowl-sc-v1"` (as info) into 80 bytes:
  - 32 bytes → `K_enc` (AES-256 key).
  - 32 bytes → `K_mac` (HMAC-SHA-256 key, used only in the fallback suite).
  - 16 bytes → `IV_seed` (initial counter value).
- **Encryption:** AES-256-GCM, 12-byte IV (4-byte monotonically increasing counter ‖ 8-byte random per message), 16-byte authentication tag.
- **Additional Authenticated Data:** the outer APDU header (`CLA ‖ INS ‖ P1 ‖ P2 ‖ LC`) is fed to GCM as AAD, preventing a man-in-the-middle from altering the header without invalidating the tag.

**Fallback suite (`SC-V1-CBC`):**

If the host detects via `GET_INFO` capability bits that the card lacks AES-GCM (commonly true on JavaCard 3.0.5 silicon — GCM only became standard at JC 3.1):

- Same handshake and HKDF derivation.
- **Encryption:** AES-256-CBC with a 16-byte IV (4-byte counter ‖ 12-byte random).
- **Authentication:** HMAC-SHA-256 over `IV ‖ AAD ‖ ciphertext` using `K_mac`. Truncated to 16 bytes for wire economy.

The card advertises which suite is available via the `CAP_SC_GCM` and `CAP_SC_CBC_HMAC` bits in `GET_INFO`. The host picks the strongest mutually supported suite.

## Consequences

### Positive

- **Security margin:** AES-256 + 256-bit MAC, AEAD with explicit AAD binding the outer header, monotonic IV with replay protection on the card side.
- **Forward secrecy:** ephemeral ECDH on both sides means a compromise of the long-lived `authentikey` does **not** compromise past session traffic.
- **Card-side authentication:** the host can verify it is talking to a genuine meowl card via the `authentikey` signature on the card's ephemeral public key; combined with the factory PKI cert, this defeats counterfeit cards.

### Negative

- **GCM availability:** Phase 2 must probe AES-GCM at applet install time. If unavailable, fall back to CBC-HMAC. Both code paths must ship and both must be tested.
- **Slightly heavier handshake** than Satochip's (extra 32-byte HKDF expansion plus a card-signed ephemeral pubkey), at the cost of dozens of milliseconds per session establishment — acceptable.

### Neutral

- The fallback CBC-HMAC suite is identical in security level to the GCM one (both at 256-bit symmetric strength); GCM is preferred only for cleaner code and AEAD's compactness.
