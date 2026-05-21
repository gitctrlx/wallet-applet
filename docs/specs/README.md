# MEAP — Meowl Applet Proposals

A **MEAP** (pronounced "meep", *Meowl Applet Proposal*) is the unit of normative specification for the meowl hardware-wallet applet. Each MEAP fixes one well-bounded slice of the on-card protocol — wire framing, the Secure Channel, the lifecycle FSM, an HD-derivation scheme, a signing primitive — and is binding on every conforming implementation.

MEAP-0 is itself a MEAP; it specifies the format, numbering, status lifecycle and contribution process of the MEAP set. Read it first if you intend to propose a change.

## Index

| Number | Title | Description | Status | Type | Category |
| ------ | ----- | ----------- | ------ | ---- | -------- |
| [MEAP-0](./meap-0.md) | MEAP process and template | Format, numbering, lifecycle and contribution workflow of the MEAP set itself. | Final | Process | — |
| [MEAP-1](./meap-1.md) | Protocol framing | CLA byte, INS bands, outer-vs-inner frame partition, TLV layout and the `GET_INFO` record. | Final | Standards Track | Wire |
| [MEAP-2](./meap-2.md) | Secure Channel | Ephemeral-ECDH handshake, HKDF-SHA-256 schedule and the authenticated record layer. | Final | Standards Track | Wire |
| [MEAP-3](./meap-3.md) | Lifecycle and PIN/PUK | Four-state FSM, single PIN/PUK policy, three authorisation rules, multi-step reset. | Final | Standards Track | Wire |
| [MEAP-4](./meap-4.md) | Card identity | `authentikey` keypair generated at install, preserved across reset, plus manufacturer PKI. | Final | Standards Track | Wire |
| [MEAP-5](./meap-5.md) | HD key derivation | BIP-32 over secp256k1 and SLIP-10 hardened-only over Ed25519, sharing one master seed. | Final | Standards Track | Crypto |
| [MEAP-6](./meap-6.md) | Signing primitives | ECDSA, BIP-340 Schnorr and RFC 8032 Ed25519 with a hash-only invariant. | Final | Standards Track | Crypto |
| [MEAP-7](./meap-7.md) | Status-word reference | Single-source enumeration of every two-byte status word a conforming applet may emit. | Final | Standards Track | Wire |

## Status definitions

| Status | Meaning |
| ------ | ------- |
| **Idea** | A short-form sketch under discussion in an issue, not yet allocated a number. |
| **Draft** | Numbered, openly discussed, and free to change in any direction. |
| **Last Call** | Frozen for community review. No substantive changes; only typographical or normative-language clarifications. |
| **Final** | Ratified. Implementations on the wire are bound by the text. Errata are recorded; substantive changes require a new MEAP that explicitly supersedes this one. |
| **Stagnant** | Authored, never advanced past Draft, no longer maintained. Future work may reference but not depend on it. |
| **Withdrawn** | Authored and withdrawn by the author before ratification. Number is permanently retired. |
| **Superseded** | Was Final, replaced by a later MEAP that lists this one in its `replaces:` header. |

## Conformance

A conforming **applet implementation** MUST satisfy every MUST/SHALL clause across every Final MEAP listed above and SHOULD satisfy every SHOULD clause unless the document permits a documented deviation. A conforming **host implementation** MUST satisfy every MUST/SHALL clause that addresses the host (these are explicitly tagged in the Specification section of each MEAP) and MUST treat any unspecified card behaviour as undefined.

The reference implementation lives in [`applet/src/main/java/social/meowl/applet/`](../../applet/src/main/java/social/meowl/applet/). The reference test suite lives in [`tests/src/test/java/social/meowl/applet/`](../../tests/src/test/java/social/meowl/applet/) and is binding on every applet implementation that wants to claim MEAP conformance — the test vectors in each MEAP MUST pass against the implementation.

## Security audit

Every reference-implementation release ships with a line-by-line audit report in [`docs/AUDIT-REPORT.md`](../AUDIT-REPORT.md). The report enumerates every finding (S1 — Critical to S5 — Info), records its fix status (✅ Fixed / 🟡 Mitigated / ⏸ Deferred), and compares each design decision against the major reference implementations (Status Keycard, Satochip, Trezor firmware, Coldcard, libsodium, BoringSSL, Bitcoin Core). New conforming implementations SHOULD reproduce the table in §1.3 of the audit report against their own codebase before claiming MEAP conformance.

The threat model that scopes those findings is normative in [MEAP-6 §Threat model](./meap-6.md); user-facing performance budgets for every signing INS live in the same MEAP under §Performance budget and are mirrored in the project [`README.md`](../../README.md).

## Numbering rules

- Numbers are integers, allocated densely in submission order, never re-used. A withdrawn MEAP keeps its number permanently.
- File names follow `meap-<n>.md` (no leading zeros). The body's title line follows `# MEAP-<n>: <title>`.
- A MEAP may declare itself `replaces:` an earlier MEAP only when accepted as Final; the replaced MEAP simultaneously moves to **Superseded** with a back-reference in its Status block.

See [MEAP-0](./meap-0.md) for the full editorial template, header schema and process timing rules.

## Contributing

To propose a new MEAP, open an issue describing the problem first, then submit a pull request adding `meap-<n>.md` against the editorial template in [MEAP-0 §Specification](./meap-0.md). Editors will assign the number on PR open. Substantive amendments to a Final MEAP MUST be made via a new MEAP that lists the affected one in its `replaces:` header — the in-place text of a Final MEAP changes only for editorial errata.

## License

Every MEAP is licensed under the project licence ([AGPL-3.0-or-later](../../LICENSE)) unless its Copyright section says otherwise.
