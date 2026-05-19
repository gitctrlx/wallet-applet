# meowl-applet documentation

Two top-level documents back the project, separated by audience and intent:

| Document set | Path | Audience | Question it answers |
| --- | --- | --- | --- |
| **MEAP — Meowl Applet Proposals** | [`./specs/`](./specs/) | Host SDK authors, integrators, security auditors | *"What does the card promise to do, and how do I drive it?"* |
| **README, CONTRIBUTING, SECURITY** | repository root | Contributors, operators, vulnerability reporters | *"How do I build, run, install, and report on this code?"* |

The MEAP set is the **normative** specification of the on-card protocol. Every byte that crosses the contact-or-NFC boundary, every status word the card can emit, and every cryptographic construction the card commits to, is fixed by a MEAP. Implementations on either side of the wire (the applet itself and any host SDK) MUST conform to the MEAP they target.

## Quick start

If you are writing a host SDK or auditing the protocol, start at the [MEAP index](./specs/README.md). The recommended reading order is:

1. **[MEAP-0](./specs/meap-0.md)** — process, numbering and the lifecycle of a MEAP. Read this first if you intend to propose changes.
2. **[MEAP-1](./specs/meap-1.md)** — protocol framing: CLA, INS layout, TLV encoding, ISO 7816-4 conformance.
3. **[MEAP-2](./specs/meap-2.md)** — Secure Channel handshake and record layer.
4. **[MEAP-3](./specs/meap-3.md)** — applet lifecycle, PIN/PUK policy, multi-step reset.
5. **[MEAP-4](./specs/meap-4.md)** — card identity (`authentikey`) and manufacturer PKI.
6. **[MEAP-5](./specs/meap-5.md)** — hierarchical-deterministic key derivation.
7. **[MEAP-6](./specs/meap-6.md)** — signing primitives (ECDSA, Schnorr, EdDSA).
8. **[MEAP-7](./specs/meap-7.md)** — status-word reference.

If you are integrating against a single primitive, jump directly to the MEAP that owns it; every spec is self-contained except where it explicitly `requires:` another in its header.

## Conventions

- **Normative language** — MEAPs use the [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) keywords (MUST, SHOULD, MAY, etc.) interpreted as in [BCP 14](https://datatracker.ietf.org/doc/html/bcp14). Outside Specification sections those keywords are descriptive only.
- **Byte order** — every multi-byte field on the wire is **big-endian** unless a referenced upstream standard mandates otherwise (notably RFC 8032 Ed25519, which serialises in little-endian; this is called out at every occurrence).
- **Hex notation** — `0x...` for inline byte literals, ` ` (single ASCII space) as the only permitted separator inside long hex strings, and lowercase digits.
- **Test vectors** — bit-for-bit reproducible. Where a spec lists a vector it is recoverable from the listed inputs alone, with no ambient state.

## Project README

The repository [README](../README.md) covers what `meowl-applet` is at a product level (multi-chain hardware-wallet applet, JavaCard 3.0.5, AGPL-3.0). It is not part of the protocol specification and may evolve independently of the MEAP set.
