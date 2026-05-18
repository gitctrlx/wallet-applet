# ADR-0005: Authentikey lifecycle

Date: 2026-05-18

## Status

Accepted

## Context

The `authentikey` is a long-lived secp256k1 keypair whose public half identifies the physical card. It serves three purposes:

1. **Card authentication during Secure Channel handshake** — the card signs its ephemeral public key with the `authentikey`, letting the host verify it is talking to a genuine meowl card.
2. **PKI personalisation anchor** — the manufacturer signs a certificate over the `authentikey` public key and stores the certificate on-card. Any party can later request the certificate and verify the chain.
3. **Per-card identity for end users** — applications can display a stable fingerprint of the `authentikey` so the user recognises "their" card.

Satochip generates the `authentikey` during the PKI personalisation flow. Other wallets generate it during applet install. The two choices interact with what `reset-to-factory` should erase.

## Decision

- The `authentikey` keypair is generated **once, deterministically random, at applet `install` time** using the JavaCard `RandomData.ALG_SECURE_RANDOM` source.
- The keypair is **immutable** for the lifetime of the applet instance. No APDU can replace it, including the PKI personalisation flow.
- `reset-to-factory` **does not erase** the `authentikey`. It wipes the seed, PINs, PKI certificate, and Secure Channel state, but the card identity survives.
- The PKI personalisation flow consumes the existing `authentikey` public key to sign a Certificate Signing Request and stores the manufacturer-issued certificate next to it.

## Consequences

### Positive

- **Stable card identity:** users and integrators can refer to a card by its `authentikey` fingerprint across reset cycles, just like a hardware serial number.
- **No race during personalisation:** the `authentikey` exists before any external party touches the card. The PKI flow is purely a signing ceremony, not a key-generation ceremony.
- **Reset is recoverable:** a user who triggers `reset-to-factory` does not lose their PKI-anchored identity; the manufacturer can re-sign a fresh certificate without minting a new card identity.

### Negative

- **No "fresh" reset:** a sufficiently determined attacker who learns the `authentikey` public key could still recognise a card after a reset. This is by design — the public key is, well, public. The attacker gains nothing exploitable.
- **Tied to install:** if a card is re-personalised (uninstalled and re-installed), it gets a new `authentikey`. This matches industry practice (re-personalisation = new card).

### Neutral

- The on-card representation is two `ECPrivateKey` / `ECPublicKey` objects backed by EEPROM. Access to the private key is restricted to two internal call sites: the Secure Channel handshake signer and the PKI CSR signer. No INS exposes the private key.
