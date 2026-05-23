---
meap: 4
title: Card identity — authentikey and manufacturer PKI
description: Long-lived authentikey keypair generated at applet install, preserved across reset, and the optional manufacturer PKI signing ceremony.
status: Draft
type: Standards Track
category: Wire
created: 2026-05-19
requires: [1, 2, 3]
author: meowl.social contributors
---

# MEAP-4: Card identity — authentikey and manufacturer PKI

## Abstract

This MEAP specifies the card's stable cryptographic identity — the `authentikey`, a long-lived secp256k1 keypair generated once at applet install — and the optional manufacturer PKI flow that anchors that identity to a manufacturer-issued certificate. The `authentikey` is the trust root the [Secure Channel](./meap-2.md) handshake relies on for card authentication, the cryptographic primitive a host SDK uses to fingerprint a specific card (TOFU) and the subject public key the manufacturer's certificate signs over.

## Motivation

The card needs a stable identity that survives the [reset-to-factory](./meap-3.md) wipe so that:

- The host SDK can recognise "the same card" across PIN resets, seed re-imports and even certificate re-issuances. Re-pairing every time a user resets their card would be hostile UX.
- The Secure Channel handshake has a key the host can validate against — without a stable card key, the host cannot distinguish a genuine card from any other ECDH endpoint.
- Manufacturers can issue certificates that bind the card identity to a chain of trust the host can verify, without re-issuing on every wipe.

Three distinct provisioning models exist for this identity in the wider hardware-wallet space:

1. **Generated at applet install** by the JavaCard runtime's CSPRNG. The keypair exists before the manufacturer ever touches the card; manufacturer personalisation is purely a signing ceremony.
2. **Generated during personalisation** as part of a manufacturer-controlled flow. The manufacturer can keep an off-card record of every key.
3. **Imported from the manufacturer** — the card receives the keypair pre-baked. The manufacturer holds every private key.

Models 2 and 3 give the manufacturer too much authority — a malicious or compromised manufacturer could keep a copy of the `authentikey` private half and impersonate any card it ever shipped. Model 1 makes the manufacturer's role purely advisory: the manufacturer signs whatever public key the card produced, but never sees the corresponding private key.

## Specification

### `authentikey` keypair

A conforming applet MUST generate the `authentikey` keypair exactly **once**, at applet `install` time, by calling `KeyPair.genKeyPair()` on a freshly built secp256k1 keypair object. The keygen primitive draws from the platform's CSPRNG (typically `RandomData.ALG_KEYGENERATION` on JC 3.0.4+ silicon) without the applet selecting an explicit `RandomData` algorithm. The keypair is over secp256k1 with the standard SEC1 parameters.

A conforming applet MUST NOT expose any APDU that re-generates, replaces, imports or exports the `authentikey` private half. The private half is reachable only by:

- The Secure Channel handshake signer ([MEAP-2 §Handshake](./meap-2.md)), which signs `eph_card_pub ‖ client_eph_pub` to authenticate the card.
- The PKI CSR signer (this MEAP, `SIGN_PKI_CSR` below), which signs the host-supplied 32-byte CSR digest during manufacturer personalisation.

The public half is reachable through three commands:

| INS | Mnemonic | Form |
| --- | --- | --- |
| `0x01` | `GET_INFO` | TLV tag `0x05` (`TAG_AUTHENTIKEY_PUBKEY`), 33-byte SEC1-compressed point |
| `0x02` | `GET_AUTHENTIKEY` | 33-byte SEC1-compressed point as the entire response body |
| `0x30` | `EXPORT_PKI_PUBKEY` | 33-byte SEC1-compressed point as the entire response body, used by the manufacturer to construct the CSR subject |

The three commands return identical byte content for the same card; `GET_AUTHENTIKEY` and `EXPORT_PKI_PUBKEY` differ only in the lifecycle states they accept (see below).

### Reset-to-factory survives the `authentikey`

A conforming applet MUST preserve the `authentikey` keypair across [`RESET_TO_FACTORY`](./meap-3.md). The wipe clears the seed, PIN/PUK, manufacturer certificate, Secure Channel state and the lifecycle FSM, but the `authentikey` keypair endures. After reset, the card returns to `UNINITIALIZED` with the same `TAG_AUTHENTIKEY_PUBKEY` value it had before — a host that pinned the public key on first use can still recognise the card.

### Manufacturer PKI flow

A conforming applet MAY implement an optional manufacturer PKI flow that lets a manufacturer issue and store an X.509 (or any other format the manufacturer chooses) certificate over the `authentikey` public half. The flow is a **signing ceremony** between the manufacturer's host and the card, all of it inside the Secure Channel envelope per [MEAP-2](./meap-2.md). Capability bit `CAP_PKI` (mask `0x0020` per [MEAP-1](./meap-1.md)) advertises the flow.

The flow comprises five INSes, all in the `0x30`–`0x3F` band, all reachable only in `UNINITIALIZED`:

#### `EXPORT_PKI_PUBKEY` (INS `0x30`)

Returns the 33-byte SEC1-compressed `authentikey` public key. The manufacturer uses this to construct the X.509 / RFC 2986 CSR's `SubjectPublicKeyInfo`.

Inner data: empty.
Inner response: `[pubkey(33)]`.
Status: `9000` on success, `6985` if the lifecycle is anything other than `UNINITIALIZED`.

#### `SIGN_PKI_CSR` (INS `0x31`)

Signs a host-supplied 32-byte CSR digest with the `authentikey` private half. The manufacturer constructs `CertificationRequestInfo` (RFC 2986 §4.1) off-card, hashes it to a 32-byte digest with SHA-256, sends the digest, and the card returns the ECDSA-SHA-256 signature.

Inner data: `[digest(32)]`.
Inner response: DER-encoded `ECDSA-Sig-Value` (variable length, ≤72 bytes).

A conforming applet MUST sign the digest using `Signature.signPreComputedHash` so the bytes are signed verbatim and not re-hashed (the manufacturer has already hashed the CSR's `CertificationRequestInfo`). A conforming applet MUST NOT enforce any low-`s` normalisation on the result; the certificate-issuance pipeline expects the canonical DER output.

A conforming applet MUST reject this command in any state other than `UNINITIALIZED` with `6985`.

#### `IMPORT_PKI_CERT` (INS `0x32`, three-step)

Uploads the manufacturer-issued certificate in chunks. P1 selects the step:

| P1 | Step | Inner data |
| -- | ---- | ---------- |
| `0x00` | `INIT` | `[total_size(2 BE)]` — declares the total certificate size and resets the staging area |
| `0x01` | `WRITE` | `[offset(2 BE), chunk(...)]` — writes `chunk` at `offset` into the staged certificate |
| `0x02` | `FINALIZE` | empty — commits the staged certificate |

A conforming applet MUST cap `total_size` at the implementation-defined `PKI_CERT_MAX_LEN` (the reference implementation uses 1024 bytes — the typical ceiling for an X.509v3 EE cert with no embedded chain). A conforming applet MUST cap `chunk` length at `PKI_CERT_CHUNK_MAX_LEN` (200 bytes in the reference implementation; sized so that the encrypted envelope fits inside a 261-byte short APDU after Secure Channel framing).

Each `WRITE` MUST reject any `offset` or `offset + chunk_len` outside `[0, total_size]` with `6700`. The applet MUST reject `WRITE` and `FINALIZE` calls before a successful `INIT` with `6985`.

The reference implementation uses `JCSystem.beginTransaction` around the EEPROM write so a torn power-off mid-`WRITE` cannot leave the certificate partially overwritten with an old value (this matters when a fresh certificate is being staged on top of an already-`FINALIZE`d one).

A conforming applet MUST reject this command in any state other than `UNINITIALIZED`.

#### `EXPORT_PKI_CERT` (INS `0x33`)

Pages through the committed certificate. Reachable in any state ≥ `PERSONALIZED` so a host can fetch the cert before the user PIN exists.

Inner data: `[offset(2 BE), requested_len(2 BE)]`.
Inner response: `[cert_total_len(2 BE), cert_window(window_len)]`.

The applet MUST emit `cert_total_len` first so the host knows how many bytes to page through; on a card that has no certificate at all, `cert_total_len` is `0x0000` and `window_len` is zero. The host MAY perform a single `[0, 0xFFFF]` query to get the total length without paging through any bytes.

#### `LOCK_PKI` (INS `0x34`)

Finalises personalisation. Transitions the lifecycle from `UNINITIALIZED` to `PERSONALIZED`, after which `IMPORT_PKI_CERT` and `SIGN_PKI_CSR` are irreversibly rejected with `6985`.

Inner data: empty.
Inner response: empty, status `9000`.

A conforming applet MUST reject `LOCK_PKI` if no certificate has been committed (`hasCert()` returns false) with `6985`. The state advance and any companion writes MUST commit atomically.

### Cardholder-side certificate verification

A conforming host SHOULD verify the manufacturer-issued certificate before sending the user PIN, using the manufacturer's pinned root certificate. The reference verification flow is:

1. Open a Secure Channel via `INIT_SECURE_CHANNEL` (per [MEAP-2](./meap-2.md)). The card-authentication signature on `eph_card_pub ‖ client_eph_pub` proves the card holds the `authentikey` private half.
2. Inside the channel, fetch `GET_INFO` and read `TAG_AUTHENTIKEY_PUBKEY` to confirm the same `authentikey` value the handshake signed.
3. Page the certificate via `EXPORT_PKI_CERT` and verify:
   - The certificate's chain terminates at the manufacturer's pinned root.
   - The certificate's `SubjectPublicKeyInfo` matches the `authentikey` returned in step 2.
   - Optional: the certificate's `Subject` distinguished name matches what the host expects (e.g. a manufacturer batch identifier).

A host that fails verification MUST NOT send `VERIFY_PIN` and SHOULD inform the user that the card is not recognised. Hosts MAY skip the chain-of-trust verification for development cards (where no manufacturer signed the cert) but MUST then surface that fact to the user; no host SHOULD silently accept an unsigned certificate.

## Rationale

### Why generate `authentikey` at install

The alternative — generating during the PKI flow — would mean the keypair only exists *after* the manufacturer has touched the card. That ordering breaks the threat model: until the keypair exists, there is no Secure Channel possible, and so the manufacturer's personalisation traffic is unauthenticated. Generating at install closes this gap: the keypair exists before any external party sees the card, and the manufacturer's personalisation flow is itself protected by the Secure Channel that the keypair enables.

It also simplifies the card-vs-manufacturer trust boundary: the manufacturer **never sees** the `authentikey` private half. Even a compromised manufacturer cannot impersonate cards it has shipped.

### Why preserve `authentikey` across reset

A reset that mints a new `authentikey` would break every host-side TOFU pin and break every manufacturer certificate (which signs over the now-stale public key). Real users reset their cards for many benign reasons (retiring a stale seed, repurposing the card, troubleshooting); making them re-personalise the card every time would be hostile.

The cost of preservation is that an attacker who learns the `authentikey` public key can recognise the card after a reset. This is by design — the public key is, well, public. The attacker gains nothing exploitable: they cannot sign as the card without the private half, which never leaves the secure element.

### Why an optional flow

Some deployments will never need a manufacturer-issued certificate (development cards, self-distributed cards, cards used purely with a single host that owns its own pinning). Forcing the PKI flow would needlessly burden those deployments. The capability bit `CAP_PKI` lets hosts discover whether the flow is implemented; the lifecycle FSM lets a card skip personalisation by going directly from `UNINITIALIZED` (where `SETUP` is illegal) to `PERSONALIZED` only via `LOCK_PKI`, which itself requires a committed certificate.

A future MEAP MAY add a "no-cert personalisation" path that skips the certificate step but still advances the FSM; this MEAP deliberately does not, to keep the v1.0 specification minimal.

### Three-step `IMPORT_PKI_CERT`

A 1024-byte certificate cannot fit in a single short APDU after Secure Channel framing (the envelope adds 16 IV + 16 MAC + PKCS#5 padding, and the inner APDU header takes another 5). Three-step chunked import is the simplest way to handle this without committing to extended-length APDUs (which not every JC silicon supports). Each chunk is itself wrapped in the Secure Channel envelope so an attacker on the wire cannot stage a different certificate.

`INIT` declares the total size up front so the card can pre-allocate the EEPROM region and reject over-large transfers immediately, before the host wastes bandwidth.

## Backwards Compatibility

N/A — v1.0 greenfield.

## Test Vectors

`PersonalisationTest` exercises the full flow in the reference test environment:

- `EXPORT_PKI_PUBKEY` returns the same 33-byte `authentikey` value as `GET_AUTHENTIKEY` and as the `TAG_AUTHENTIKEY_PUBKEY` TLV in `GET_INFO`. All three responses are byte-identical.
- `SIGN_PKI_CSR` over a known 32-byte digest produces a DER-encoded ECDSA signature that verifies under the `authentikey` public key in any standard verifier (the test uses BouncyCastle).
- A round-trip `IMPORT_PKI_CERT(INIT) → IMPORT_PKI_CERT(WRITE)*N → IMPORT_PKI_CERT(FINALIZE) → LOCK_PKI → EXPORT_PKI_CERT` returns the certificate bytes verbatim across the round-trip.
- Calling `LOCK_PKI` without a committed certificate returns `6985`.
- Any of `EXPORT_PKI_PUBKEY`, `SIGN_PKI_CSR`, `IMPORT_PKI_CERT` after `LOCK_PKI` returns `6985`.
- After `RESET_TO_FACTORY` (four invocations), `GET_INFO`'s `TAG_AUTHENTIKEY_PUBKEY` is unchanged; `EXPORT_PKI_CERT` returns `cert_total_len = 0x0000`.

## Reference Implementation

- Authentikey keypair management: [`Authentikey`](../../applet/src/main/java/social/meowl/applet/Authentikey.java).
- PKI flow: [`PkiManager`](../../applet/src/main/java/social/meowl/applet/PkiManager.java).
- Reference test class: [`PersonalisationTest`](../../tests/src/test/java/social/meowl/applet/PersonalisationTest.java).

## Security Considerations

### TOFU vs cert-anchored

A host that does not verify the manufacturer certificate falls back to TOFU on the `authentikey` fingerprint. TOFU is sufficient to detect a *substitution* attack (the host notices when a different card is presented after first use) but cannot detect a *first-use* counterfeit. For deployments where first-use counterfeit is a real threat (e.g. retail-channel hardware wallets), the host MUST verify the manufacturer cert against a pinned root and MUST reject unsigned development cards.

### Cert-as-secret confusion

The manufacturer-issued certificate is **public** by design — it is meant to be inspected by anyone holding the card. A host MUST NOT treat the certificate as a secret credential and MUST NOT include it in any pinning material that needs forward secrecy. Hosts that need a secret-handshake-style anchor SHOULD use the user PIN ([MEAP-3](./meap-3.md)) instead.

### Replay of `SIGN_PKI_CSR` across cards

`SIGN_PKI_CSR` produces a signature that binds to a specific 32-byte digest. The manufacturer MUST construct the digest over a `CertificationRequestInfo` whose `SubjectPublicKeyInfo` is the `authentikey` of *this specific card*; otherwise an attacker who intercepts a digest from card A could route it to card B and obtain a signature from B's `authentikey` over A's CSR. The reference manufacturer flow folds the card's `authentikey` into the digest preimage by construction, so this attack is prevented at the host (manufacturer) side; the card itself does not validate the digest's preimage.

### Certificate-write torn power-off

`IMPORT_PKI_CERT(WRITE)` uses a JavaCard transaction so a torn power-off cannot leave the staged certificate partially overwritten. `IMPORT_PKI_CERT(FINALIZE)` likewise commits atomically. A power loss between two `WRITE` chunks leaves the staging area in whatever state the prior `WRITE` committed; the host MUST track its progress and re-issue the missed chunks rather than re-uploading from offset zero, to avoid wasting EEPROM write cycles.

## Copyright

This document is licensed under the AGPL-3.0-or-later licence the rest of the project uses; see [LICENSE](../../LICENSE).
