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

# Install onto a card you own using GlobalPlatformPro
gp --install meowl-applet.cap
```

> The default AID prefix `F0` lives in the ISO/IEC 7816-5 *proprietary* range — fine for development. For production deployments register your own RID per ISO/IEC 7816-5.

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
