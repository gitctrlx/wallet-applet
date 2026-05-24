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
| Simulator | [`jcardsim`](https://github.com/licel/jcardsim) (`com.klinec` fork) — unit-test backend only; integration tests target real silicon |
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

## Testing

`meowl-applet` is single-target hardened for **NXP JCOP4 J3R180 (P71)**. Algorithm choices, key types, and memory layouts are picked from the JCAlgTest profile pinned in [`3rdparty/NXPJ3R180_NFC_1_ALGSUPPORT_*.csv`](3rdparty/) — no jcardsim-shaped fallbacks.

Tests are split into two tracks via JUnit tags:

| Task | Scope | Status |
| --- | --- | --- |
| `./gradlew :tests:test` | Pure unit tests + simulator-safe assertions (`HmacSha512Test`, `BarrettTest`, `BigNatTest`, `Fp25519Test` arithmetic, `BoundsTest`, `ApduTlvTest`, `SchnorrTagHashTest`, `SecureChannelStripPkcs5Test`, `LifecycleStateTest.IsLegalForward`, …) | ✅ Default; runs in CI |
| `./gradlew :tests:realCardTest -Preader=NAME` | `@Tag("real-card")` suites driven over PCSC by `RealCardClient`: `MeowlAppletTest`, `SecureChannelTest`, `SchnorrK1Test`, `EcdsaK1Test`, `Ed25519SigningTest`, `HdDerivationTest`, `PersonalisationTest`, `ResetToFactoryTest`, `Wei25519Test`, `BenchmarkSuite`, `LifecycleStateTest.Stateful`, `Fp25519Test.Multiplicative.inv` | ✅ Opt-in; requires a J3R180 with the applet pre-installed on the named PCSC reader |
| `./gradlew :tools:realCardTest -Preader=NAME` | `SecureChannelClientIT` against the same physical card — verifies the host-side `SecureChannelClient` MEAP-2 implementation byte-for-byte against the applet | ✅ Opt-in; same prerequisites as `:tests:realCardTest` |

Until the real-card backend lands, **every release tag is gated on a manual `./gradlew :tools:run --args="bench"` run against a real J3R180** plus a structural smoke test through the `meowl` CLI. The simulator alone is not a sufficient correctness target — the [`:applet:Fp25519Inv`](applet/src/main/java/social/meowl/applet/Fp25519Inv.java) RSA path and [`:applet:EcPoint`](applet/src/main/java/social/meowl/applet/EcPoint.java) transient EC key allocation only function on the real chip.

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
