# Meowl Hardware Wallet Applet

> The open-source crypto hardware-wallet applet for [meowl.social](https://meowl.social).

[![CI](https://github.com/qntx/meowl-applet/actions/workflows/ci.yml/badge.svg)](https://github.com/qntx/meowl-applet/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](./LICENSE)
[![JavaCard](https://img.shields.io/badge/JavaCard-3.0.5%20%E2%86%92%203.2.0-orange)](https://www.oracle.com/java/technologies/javacard-sdk-downloads.html)
[![SLSA Level 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)

`meowl-applet` is the JavaCard applet that runs on the secure element of every meowl.social hardware wallet. It is compiled with the Oracle JavaCard `3.2.0 v26.0` SDK and targets the `3.0.5` runtime so the same CAP file deploys cleanly on every certified card we ship.

## Toolchain

| Layer | Choice |
| --- | --- |
| Build system | Gradle 9 + Kotlin DSL |
| CAP builder | [`ant-javacard`](https://github.com/martinpaljak/ant-javacard) (invoked natively from Gradle) |
| SDK | Oracle JavaCard `3.2.0 v26.0`, target `3.0.5` |
| Simulator | [`jcardsim`](https://github.com/licel/jcardsim) (`com.klinec` fork) |
| Card loader | [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) |
| Host I/O | [`apdu4j`](https://github.com/martinpaljak/apdu4j) |
| Tests | JUnit 6 + BouncyCastle |
| CI | GitHub Actions with SLSA L3 provenance and CycloneDX SBOM |

## Installing on a card

Every tagged release publishes a verified `meowl-applet.cap`. Download the CAP, the SBOM, and `sha256sums.txt` from the [latest release](https://github.com/qntx/meowl-applet/releases/latest), then verify and install:

```bash
# Verify checksums
sha256sum -c sha256sums.txt

# Verify the SLSA build provenance (requires gh ≥ 2.49)
gh attestation verify meowl-applet.cap --repo qntx/meowl-applet

# Install onto a card you own using the bundled `meowl` CLI
./gradlew :tools:run --args="gp install meowl-applet.cap"
```

> The default AID prefix `F0` lives in the ISO/IEC 7816-5 *proprietary* range — fine for development. For production deployments register your own RID per ISO/IEC 7816-5.

## Host-side CLI (`meowl`)

The `:tools` subproject ships a picocli-based CLI that wraps every host-side workflow you need while building, debugging or operating the meowl-applet — APDU pass-through, GlobalPlatform install / uninstall / list, MEAP-2 Secure Channel client and an interactive JLine shell.

```bash
./gradlew :tools:run -q --args="--help"           # full command listing
./gradlew :tools:run -q --args="info"             # GET_INFO TLV pretty-print
./gradlew :tools:run -q --args="info --json"      # machine-readable for scripts
./gradlew :tools:run -q --args="sc handshake"     # MEAP-2 Secure Channel diagnostics
./gradlew :tools:run -q --args="shell"            # interactive REPL with persistent SC session
```

See [`tools/README.md`](./tools/README.md) for the complete command surface, exit-code policy and JSON-output schema.

## Performance budgets

Every signing primitive runs in **software** on the J3R180 SECID stack — there is no native-curve acceleration on the underlying NXP firmware for Curve25519 / secp256k1 BIP-340. The numbers below are the wall-clock budgets the host-side SDK should plan for; deeper context (algorithm choice, threat model, side-channel posture) lives in [MEAP-6 §Performance](./docs/specs/meap-6.md).

| INS | Operation | Typical (J3R180@~32 MHz) | Notes |
| --- | --------- | ------------------------ | ----- |
| `SIGN_ECDSA_K1` (0x50) | secp256k1 ECDSA over a 32-byte digest | **150 – 300 ms** | Native `Signature.ALG_ECDSA_SHA_256` + DER parse + low-s normalisation |
| `SIGN_SCHNORR_K1` (0x51) | BIP-340 Schnorr over a 32-byte digest | **400 – 900 ms** | Two software scalar mults on secp256k1; constant-time challenge / nonce hashes use precomputed `SHA256(tag)` |
| `SIGN_ED25519` (0x52) | RFC 8032 Ed25519 over an arbitrary-length message | **3 – 6 s** | Two software scalar mults on Edwards25519 + projective blinding (audit F-01 mitigation); message capped at 222 bytes by the inner short-form LC |
| `EXPORT_XPUB` (0x42) | One BIP-32 / SLIP-10 step plus serialisation | **80 – 200 ms** | One HMAC-SHA-512 + one EC point add (non-hardened) or one HMAC-SHA-512 (hardened) |

The Schnorr / Ed25519 budgets dominate the wallet UX. Wallets that need sub-second Ed25519 signatures should either use the secp256k1 curve (`SIGN_ECDSA_K1` / `SIGN_SCHNORR_K1`) or wait for the v2.0 `Field25519` limb-radix rewrite tracked in [`docs/AUDIT-REPORT.md` §6.3](./docs/AUDIT-REPORT.md).

## Audit and threat model

`meowl-applet` undergoes per-release line-by-line audits. The latest report — including findings, fix status (✅ Fixed, 🟡 Mitigated, ⏸ Deferred), reference-implementation comparisons (Status Keycard, Satochip, Trezor, Coldcard) and the v1.1 sweep summary — lives in [`docs/AUDIT-REPORT.md`](./docs/AUDIT-REPORT.md).

The v1.0 / v1.1 release threat model targets a **software-only adversary on the host** (malware, networked APIs, host-side memory disclosure). Strong physical adversaries with sub-millisecond timing oracles on the PCSC link are explicitly **out of scope** for v1.x; users in that threat model should wait for v2.0's constant-time `Field25519` rewrite or pick a vendor with hardware-resistance certification at the EAL 6+ level. See [MEAP-6 §Threat model](./docs/specs/meap-6.md) for the full statement.

## License

Licensed under the GNU Affero General Public License Version 3.0 ([LICENSE](LICENSE) or <https://www.gnu.org/licenses/agpl-3.0.html>).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be licensed under the same terms, without any additional conditions.

---

<div align="center">

A **[QNTX](https://qntx.fun)** open-source project.

<a href="https://qntx.fun"><img alt="QNTX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx-banner.svg" /></a>

<!--prettier-ignore-->
Code is law. We write both.

</div>
