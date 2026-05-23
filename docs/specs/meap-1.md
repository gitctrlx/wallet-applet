---
meap: 1
title: Protocol framing — CLA, INS layout, ISO 7816-4 conformance
description: CLA byte, INS bands, outer-vs-inner frame partition, TLV layout and the GET_INFO record that frames every other MEAP's payload.
status: Draft
type: Standards Track
category: Wire
created: 2026-05-19
author: meowl.social contributors
---

# MEAP-1: Protocol framing — CLA, INS layout, ISO 7816-4 conformance

## Abstract

This MEAP specifies the wire framing of every command exchanged with the meowl applet: the class byte, the layout of the instruction byte across semantic bands, the rules for ISO 7816-4 status-word emission, the TLV encoding used inside command and response data fields, and the partition of the instruction surface into commands reachable on a freshly installed card and commands reachable only inside a Secure Channel envelope. It pins the bytes that frame every other MEAP's payload.

## Motivation

A multi-chain hardware wallet exposes its functionality to host SDKs through a strict APDU contract. The contract has three concerns:

1. **Surface identification** — the card must tell host SDKs which protocol they are speaking. If two different applets answer to the same `CLA`, the host cannot tell them apart from the wire alone.
2. **Trust boundary** — some commands are safe to expose on the contact / contactless interface unauthenticated (identity, capability discovery, factory reset). Most are not. The framing must make this partition unambiguous so a host that forgets to open a Secure Channel cannot accidentally hit a sensitive command.
3. **Forward compatibility** — additions to the protocol (new signing primitives, new derivation schemes) must not require reshuffling existing INS opcodes. The instruction surface must therefore be banded by semantic group so that adding a new opcode within a band is monotonic.

Inheriting the legacy MUSCLE / Cryptoflex / Satochip framing (CLA `0xB0`, ad-hoc INS allocation) would couple the wire to design decisions made in the early 2000s for completely different use cases (multi-PIN slots, ACL bitmasks, on-card transaction parsing). MEAP-1 therefore specifies a **greenfield** wire that owes nothing to those lineages beyond inspiration.

The card is also positioned as a **standalone hardware-wallet authority** — it owns the master seed and every derived private scalar; the host never sees a non-public key. This positioning constrains the wire: no INS may export a private key, every signing INS must produce a signature rather than reveal the scalar that produced it. Subsequent MEAPs depend on this property, and MEAP-1 codifies it.

## Specification

### Class byte

A conforming applet MUST accept commands with the class byte (`CLA`):

```text
CLA = 0x80
```

The applet MUST reject commands whose class byte is any other value with the status word [`6E00` (CLA not supported)](./meap-7.md). The choice of `0x80` places the protocol in the ISO 7816-4 *proprietary* class range and avoids collision with the `0xBn` range historically used by the MUSCLE / Cryptoflex / Satochip lineage; a host SDK can dispatch on `CLA` alone.

A conforming host implementation MUST send `CLA = 0x80` and MUST NOT use the lower nibble of the class byte for ISO 7816-4 logical channels in this revision. Logical-channel addressing is reserved for a future MEAP.

### Instruction layout

The instruction byte (`INS`) is partitioned into semantic bands. A conforming applet MUST allocate new opcodes within these bands; a conforming host MUST treat unallocated INS values as `6D00` (INS not supported) returns rather than parsing into the band of the nearest neighbour.

| Band | INS range | Subsystem | Reachability |
| --- | --- | --- | --- |
| Lifecycle / identity | `0x00`–`0x0F` | identity, capability discovery, factory reset | outer |
| Secure Channel | `0x10`–`0x1F` | session establishment, encrypted envelope | outer |
| PIN / PUK | `0x20`–`0x2F` | provisioning, verification, rotation, unblock | inner |
| PKI personalisation | `0x30`–`0x3F` | manufacturer cert flow, lock | inner |
| Seed management | `0x40`–`0x4F` | import, generation, public-key export | inner |
| Signing primitives | `0x50`–`0x5F` | ECDSA, Schnorr, EdDSA | inner |
| Derivation utilities | `0x60`–`0x6F` | reserved | inner |
| Reset trigger | `0xFF` | last invocation tally | outer |

The bands `0x00`–`0x0F` and `0x10`–`0x1F` and the single opcode `0xFF` constitute the **outer-frame INS surface**. Every opcode in those bands MUST be reachable on a freshly installed card without any prior session or secret. Every other INS constitutes the **inner-frame INS surface** and MUST be reachable only inside an `OPEN_SECURE_CHANNEL` envelope as specified in [MEAP-2](./meap-2.md).

### Outer-frame INS surface

A conforming applet MUST implement, and a conforming host SHOULD discover via `GET_INFO`, exactly these outer-frame instructions:

| INS | Mnemonic | Purpose |
| --- | --- | --- |
| `0x01` | `GET_INFO` | Returns the card's protocol/applet version, lifecycle state, capability bitmap and the public half of the [`authentikey`](./meap-4.md). |
| `0x02` | `GET_AUTHENTIKEY` | Returns just the compressed `authentikey` public key. Convenience opcode for hosts that only want to fingerprint the card. |
| `0x03` | `RESET_TO_FACTORY` | Decrements an internal countdown; on the fourth consecutive invocation triggers the factory wipe specified in [MEAP-3 §Reset-to-Factory](./meap-3.md). |
| `0x10` | `INIT_SECURE_CHANNEL` | Begins an ECDH handshake. Specified in [MEAP-2 §Handshake](./meap-2.md). |
| `0x11` | `OPEN_SECURE_CHANNEL` | Carries an inner APDU inside an encrypted-and-MACed envelope. Specified in [MEAP-2 §Record layer](./meap-2.md). |

A conforming host MUST send any other INS only inside an `OPEN_SECURE_CHANNEL` envelope. A conforming applet MUST reject any non-outer INS sent at the outer frame with `6D00` (INS not supported); it MUST NOT silently process such a command nor reveal whether a corresponding inner handler exists.

### TLV encoding inside command and response data fields

`GET_INFO` and any future opcode that returns a heterogeneous record MUST encode the record as a sequence of single-byte-tag TLV items:

```text
TLV item :=  TAG (1 byte)  ‖  LEN (1 byte)  ‖  VALUE (LEN bytes)
```

`TAG` is allocated from the application-private range so it cannot collide with any ISO 7816-4 reserved primitive tag. `LEN` is unsigned, in the inclusive range `[0, 255]`. Values larger than 255 bytes MUST NOT be placed under a single tag; they MUST be paged via a chunked protocol owned by the relevant MEAP (see [MEAP-4 §EXPORT_PKI_CERT](./meap-4.md) for an example).

The applet MUST emit the TLV items in the order specified by the relevant MEAP. The host MAY parse TLVs in any order; a host that ignores an unrecognised tag MUST do so silently — emitting a forward-compatible response is the applet's prerogative.

### `GET_INFO` payload

The `GET_INFO` response (status `9000`) is the canonical TLV record. A conforming applet MUST emit the items below, in the listed order:

| Tag | Mnemonic | Value |
| --- | --- | --- |
| `0x01` | `TAG_PROTOCOL_VERSION` | 2 bytes, big-endian, packed as `major(1)` ‖ `minor(1)`. The MEAP wire revision the applet implements; `0x0100` ("1.0") for this revision. |
| `0x02` | `TAG_APPLET_VERSION` | 2 bytes, big-endian. The applet implementation's own version; freely allocated by the applet author. |
| `0x03` | `TAG_LIFECYCLE_STATE` | 1 byte. The current lifecycle FSM state; see [MEAP-3 §Lifecycle](./meap-3.md) for the encoding. |
| `0x04` | `TAG_CAPABILITIES` | 2 bytes, big-endian. The capability bitmap defined below. |
| `0x05` | `TAG_AUTHENTIKEY_PUBKEY` | 33 bytes. SEC1-compressed `authentikey` public key. |

Future MEAPs MAY add tags `0x06` and above; conforming hosts MUST tolerate unknown trailing tags.

### Capability bitmap

`TAG_CAPABILITIES` is a 16-bit big-endian bitmap. Each bit advertises the presence of an optional feature. A conforming applet MUST set a bit if and only if every wire requirement of the corresponding MEAP is fulfilled.

| Bit | Mask | Capability |
| --- | --- | --- |
| 0 | `0x0001` | `CAP_K1_ECDSA` — secp256k1 ECDSA signing per [MEAP-6 §SIGN_ECDSA_K1](./meap-6.md). |
| 1 | `0x0002` | `CAP_K1_SCHNORR` — BIP-340 Schnorr signing per [MEAP-6 §SIGN_SCHNORR_K1](./meap-6.md). |
| 2 | `0x0004` | `CAP_ED25519` — RFC 8032 Ed25519 signing per [MEAP-6 §SIGN_ED25519](./meap-6.md). |
| 4 | `0x0010` | `CAP_SC_CBC_HMAC` — AES-256-CBC + HMAC-SHA-256 Secure Channel per [MEAP-2](./meap-2.md). |
| 5 | `0x0020` | `CAP_PKI` — Manufacturer PKI personalisation flow per [MEAP-4 §PKI](./meap-4.md). |
| 6 | `0x0040` | `CAP_RESET_TO_FACTORY` — Multi-step factory reset per [MEAP-3 §Reset-to-Factory](./meap-3.md). |
| 7 | `0x0080` | `CAP_BIP32` — secp256k1 BIP-32 derivation per [MEAP-5 §BIP-32](./meap-5.md). |
| 8 | `0x0100` | `CAP_SLIP10` — Ed25519 SLIP-10 derivation per [MEAP-5 §SLIP-10](./meap-5.md). |
| 3, 9–15 | — | Reserved. MUST be `0`. A successor MEAP that allocates one of these bits supersedes this MEAP’s bit-allocation table. |

A conforming applet on this revision MUST set at minimum `CAP_SC_CBC_HMAC | CAP_RESET_TO_FACTORY` because those two capabilities are unconditional under MEAP-2 and MEAP-3. A conforming host MAY discover further features by inspecting the rest of the bitmap; absent a bit, the host MUST behave as if the corresponding INS would return `6D00` (INS not supported) regardless of whether the underlying applet would actually accept it.

### Status words

Every response — encrypted or plaintext — terminates in a 2-byte ISO 7816-4 status word `SW1 SW2`, big-endian. Two ranges are in use:

- **ISO 7816-4 standard codes** for generic outcomes (success, length, security state, lifecycle, P1/P2, INS / CLA).
- **Applet-private `6Fxx` codes** for meowl-specific signals — reset countdown (`6FAn`), Secure Channel state (`6FBn`), implementation / silicon sentinels (`6FEn`).

The complete dictionary — every code, every triggering condition, every owning MEAP — is normative in [MEAP-7](./meap-7.md). A conforming host MUST handle every code listed there; unknown `6Fxx` values from a future MEAP MAY be treated as fatal protocol errors.

### Standalone-authority invariant

A conforming applet MUST NOT expose any INS that returns secret key material in plaintext, with one explicitly enumerated exception: `GENERATE_SEED` (specified in [MEAP-5](./meap-5.md)) returns the freshly generated 64-byte seed once, on the call that creates it, so the host can render a backup mnemonic. After that single response the seed bytes never leave the card. Specifically:

- A conforming applet MUST NOT export the master seed after `IMPORT_SEED` or after the single `GENERATE_SEED` response.
- A conforming applet MUST NOT export any private scalar derived from the master seed under any circumstances.
- A conforming applet MUST NOT export the `authentikey` private key under any circumstances.

The host SDK is responsible for transaction construction, public-key-to-address encoding and chain-specific preimage hashing; the card's only signing-time input is a 32-byte digest (or, for Ed25519, the raw message — see [MEAP-6 §SIGN_ED25519](./meap-6.md) for the explicit reason).

## Rationale

### CLA = `0x80`

`0x80` is the lowest ISO 7816-4 private-class CLA byte. Lower values are reserved for ISO commands. Higher private-class values (`0x90`, `0xA0`, etc.) are also legal but bring no benefit and overlap with various GlobalPlatform extensions; `0x80` is the conventional default for new applet-private command sets.

The Satochip wallet uses `CLA = 0xB0`, inherited from MUSCLE which chose `0xB0` to dodge ISO commands in an era when applet isolation was less robust. Today the JavaCard runtime fully isolates applets and the historical reason no longer applies; `0x80` is therefore chosen over Satochip's value, on the principle that nothing about the meowl wire is downstream of the MUSCLE lineage.

### Greenfield wire vs Satochip-compatible wire

Inheriting Satochip's wire would buy compatibility with `pysatochip`, Electrum-Satochip and similar host clients. It would also lock the design into Satochip's HMAC-SHA-1 Secure Channel MAC, AES-128 session keys, multi-PIN slot semantics, ACL bitmasks and on-card transaction parsing. Each of those is cryptographically sub-modern (HMAC-SHA-1, AES-128) or operationally sub-modern (multi-PIN, transaction parser without a screen). The protocol is therefore greenfield rather than backwards-compatible with Satochip.

### TLV with single-byte tags

Multi-byte BER-TLV tags would future-proof the protocol but cost two extra bytes on every short tag. The card's typical response is dominated by 32-byte and 33-byte cryptographic values (chain codes, public keys, signatures); a single-byte tag header is the right trade-off. A future MEAP that exhausts the `0x01..0xFE` tag space (`0x00` and `0xFF` are reserved as TLV escape values) MAY introduce multi-byte tags via a versioned extension; the current allocation density makes that contingency remote.

### INS bands

Allocating opcodes by semantic band rather than densely lets a reader of the disassembled CAP file or of an APDU trace identify the subsystem at a glance: `0x42` is "in the seed band, so probably an `EXPORT` or `IMPORT`". Dense allocation would be more memory-efficient but every modern smart-card has hundreds of bytes of code-storage slack; the readability win is worth more than 16 spare opcodes per band.

## Backwards Compatibility

N/A — no prior revision. A successor MEAP MAY supersede this one if the wire requires a non-monotonic change.

## Test Vectors

A freshly installed applet, immediately after a successful applet `install`, MUST respond to the outer-frame APDU `0x80 0x01 0x00 0x00 0x00` (`GET_INFO`, no data, no expected length) with status `9000` and a TLV body of the form:

```text
01 02 01 00     ; TAG_PROTOCOL_VERSION  = 0x0100 in this revision
02 02 ?? ??     ; TAG_APPLET_VERSION    = applet-defined
03 01 00        ; TAG_LIFECYCLE_STATE   = 0x00 (UNINITIALIZED)
04 02 00 50     ; TAG_CAPABILITIES      = CAP_RESET_TO_FACTORY | CAP_SC_CBC_HMAC
05 21 02|03 .. ; TAG_AUTHENTIKEY_PUBKEY = 33-byte SEC1-compressed point (prefix 0x02 or 0x03)
```

The `TAG_CAPABILITIES` value `0x0050` in the listing above is the minimum mandatory set. A specific applet build will set additional bits per its supported MEAPs; for example, the reference applet in this repository emits `0x01F7` (every currently allocated bit).

A non-installed applet MUST respond with the underlying GlobalPlatform / ISO 7816-4 default and not be reachable as a meowl applet at all; reaching `GET_INFO` is itself a sign of correct installation.

## Reference Implementation

- Outer dispatch and band partition: `MeowlApplet.process(APDU)` and `MeowlApplet.dispatchInner(...)` in [`applet/src/main/java/social/meowl/applet/MeowlApplet.java`](../../applet/src/main/java/social/meowl/applet/MeowlApplet.java).
- TLV emission: `ApduTlv` in [`applet/src/main/java/social/meowl/applet/ApduTlv.java`](../../applet/src/main/java/social/meowl/applet/ApduTlv.java).
- Constant table for INS / status words / capability bits: [`Constants.java`](../../applet/src/main/java/social/meowl/applet/Constants.java).
- Reference test vectors: [`MeowlAppletTest`](../../tests/src/test/java/social/meowl/applet/MeowlAppletTest.java) for `GET_INFO` / `GET_AUTHENTIKEY` / `RESET_TO_FACTORY`; the inner-band INSes are exercised by the per-subsystem test classes (`PersonalisationTest`, `HdDerivationTest`, `EcdsaK1Test`, `SchnorrK1Test`, `Ed25519SigningTest`).

## Security Considerations

The outer-frame INS surface is unauthenticated by definition. Every opcode in that surface MUST therefore be either purely informational (`GET_INFO`, `GET_AUTHENTIKEY`) or rate-limited and irreversible (`RESET_TO_FACTORY` requires four consecutive invocations and is recoverable only by re-personalising the card). The handshake opcode `INIT_SECURE_CHANNEL` is allowed to consume entropy and produce a signature with the long-lived `authentikey` precisely because that signature is the host's only means of authenticating the card — the card cannot prove its identity until the host has interacted with the outer frame at least once.

A conforming applet MUST NOT extend the outer-frame INS surface beyond the five opcodes listed above without a successor MEAP that explicitly enumerates the new opcodes' threat models. Adding a sensitive opcode at the outer frame would silently break every host that relies on the partition implied by MEAP-1.

The capability bitmap is **advertised** but not authenticated by the outer frame; an attacker on the wire (which is not the threat model the Secure Channel defends — that channel exists *because* the wire is untrusted) could in principle return forged capabilities. Hosts that pin a particular set of expected capabilities MUST verify them inside the Secure Channel by inspecting `GET_INFO`'s response after `OPEN_SECURE_CHANNEL` is established; the encrypted-and-MACed envelope guarantees integrity at that point.

## Copyright

This document is licensed under the AGPL-3.0-or-later licence the rest of the project uses; see [LICENSE](../../LICENSE).
