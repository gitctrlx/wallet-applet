# MEAP — Meowl Applet Proposals

A **MEAP** (pronounced "meep", *Meowl Applet Proposal*) is the unit of normative specification for the meowl hardware-wallet applet. Each MEAP fixes one well-bounded slice of the on-card protocol — wire framing, the Secure Channel, the lifecycle FSM, an HD-derivation scheme, a signing primitive — and is binding on every conforming implementation.

MEAP-0 is itself a MEAP; it specifies the format, numbering, status lifecycle and contribution process of the MEAP set. Read it first if you intend to propose a change.

## Index

| Number | Title | Description | Status | Type | Category |
| ------ | ----- | ----------- | ------ | ---- | -------- |
| [MEAP-0](./meap-0.md) | MEAP process and template | Format, numbering, lifecycle and contribution workflow of the MEAP set itself. | Draft | Process | — |
| [MEAP-1](./meap-1.md) | Protocol framing | CLA byte, INS bands, outer-vs-inner frame partition, TLV layout and the `GET_INFO` record. | Draft | Standards Track | Wire |
| [MEAP-2](./meap-2.md) | Secure Channel | Ephemeral-ECDH handshake, HKDF-SHA-256 schedule and the authenticated record layer. | Draft | Standards Track | Wire |
| [MEAP-3](./meap-3.md) | Lifecycle and PIN/PUK | Four-state FSM, single PIN/PUK policy, three authorisation rules, multi-step reset. | Draft | Standards Track | Wire |
| [MEAP-4](./meap-4.md) | Card identity | `authentikey` keypair generated at install, preserved across reset, plus manufacturer PKI. | Draft | Standards Track | Wire |
| [MEAP-5](./meap-5.md) | HD key derivation | BIP-32 over secp256k1 and SLIP-10 hardened-only over Ed25519, sharing one master seed. | Draft | Standards Track | Crypto |
| [MEAP-6](./meap-6.md) | Signing primitives | ECDSA, BIP-340 Schnorr and RFC 8032 Ed25519 with a hash-only invariant. | Draft | Standards Track | Crypto |
| [MEAP-7](./meap-7.md) | Status-word reference | Single-source enumeration of every two-byte status word a conforming applet may emit. | Draft | Standards Track | Wire |

## Conformance

A conforming applet implementation MUST satisfy every MUST/SHALL clause across every MEAP it claims to implement, and SHOULD satisfy every SHOULD clause unless the MEAP permits a documented deviation. A conforming host implementation MUST satisfy every MUST/SHALL clause that addresses the host (tagged inside each Specification section) and MUST treat any unspecified card behaviour as undefined.

The reference implementation lives in [`applet/src/main/java/social/meowl/applet/`](../../applet/src/main/java/social/meowl/applet/); the reference test suite lives in [`tests/src/test/java/social/meowl/applet/`](../../tests/src/test/java/social/meowl/applet/). Every test vector listed in a MEAP MUST round-trip against the suite as a CI gate.

## Process

The status lifecycle, numbering rules, editorial template and contribution workflow are normative in [MEAP-0](./meap-0.md). Read it before proposing or amending a MEAP.

## License

Every MEAP is licensed under the project licence ([AGPL-3.0-or-later](../../LICENSE)) unless its Copyright section says otherwise.
