# Meowl Hardware Wallet Applet

> The open-source crypto hardware-wallet applet for [meowl.social](https://meowl.social).

[![CI](https://github.com/qntx/meowl-applet/actions/workflows/ci.yml/badge.svg)](https://github.com/qntx/meowl-applet/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](./LICENSE)
[![JavaCard](https://img.shields.io/badge/JavaCard-3.0.5%20%E2%86%92%203.2.0-orange)](https://www.oracle.com/java/technologies/javacard-sdk-downloads.html)

`meowl-applet` is a JavaCard applet built with the **2026-grade** toolchain:

| Layer        | Choice                                                                                                                |
| ------------ | -------------------------------------------------                                                                     |
| Build system | Gradle 9 + Kotlin DSL                                                                                                 |
| CAP builder  | [`ant-javacard`](https://github.com/martinpaljak/ant-javacard) (called natively from Gradle — no dead wrapper plugin) |
| SDK          | Oracle JavaCard `3.2.0 v26.0`, target `3.0.5`                                                                         |
| Simulator    | [`jcardsim`](https://github.com/licel/jcardsim) (`com.klinec` fork)                                                   |
| Card loader  | [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro)                                                |
| Host I/O     | [`apdu4j`](https://github.com/martinpaljak/apdu4j)                                                                    |
| Test         | JUnit 5 + BouncyCastle                                                                                                |
| CI           | GitHub Actions                                                                                                        |
| License      | AGPL-3.0-or-later (REUSE 3.3 compliant)                                                                               |

## Prerequisites

- **JDK 21** on `PATH` (Temurin recommended).
- **Git** with submodule support — the JavaCard SDK is a git submodule.
- A **PC/SC** reader if you want to load on a physical card.

## First-time setup

```bash
git clone --recurse-submodules https://github.com/qntx/meowl-applet.git
cd meowl-applet
./gradlew :applet:buildCap
```

The CAP file lands in `applet/build/cap/meowl-applet.cap`.

## Common tasks

```bash
# Format & lint
./gradlew spotlessApply

# Build the CAP
./gradlew :applet:buildCap

# Run the JCardSim test suite (no card required)
./gradlew :tests:test

# Install onto a connected card (uses GlobalPlatformPro with default keys)
./gradlew :tools:installCap

# Talk to the card directly
./gradlew :tools:run --args="80010000"

# Run GlobalPlatformPro with arbitrary args
./gradlew :tools:gp -Pargs="--list"
```

## Project layout

```text
.
├── applet/        # JavaCard source — compiled into the CAP
├── tests/         # JCardSim integration tests
├── tools/         # Host-side CLI + GP wrapper
├── sdks/          # ← submodule: Oracle JavaCard SDKs
├── gradle/        # Wrapper + libs.versions.toml (version catalog)
├── config/        # Spotless license header template
└── .github/       # GitHub Actions CI
```

## Configuration knobs

All overridable via Gradle properties (e.g. `-Papplet.appletAid=...`):

| Property              | Default                              | Purpose                |
| --------------------- | ------------------------------------ | ---------------------- |
| `applet.packageAid`   | `F06D656F776C`                       | CAP package AID (hex)  |
| `applet.appletAid`    | `F06D656F776C01`                     | Applet instance AID    |
| `applet.class`        | `social.meowl.applet.MeowlApplet`    | Applet class           |
| `applet.packageName`  | `social.meowl.applet`                | Java package           |
| `appletVersion`       | `0.1.0-SNAPSHOT`                     | Package version        |

> **Note**: the default AID prefix `F0` lives in the ISO/IEC 7816-5 *proprietary*
> range, fine for development. For production register your own RID with
> ISO/IEC 7816-5 or use a 5-byte GP development AID.

## License

[AGPL-3.0-or-later](./LICENSE). See [`SECURITY.md`](./SECURITY.md) for the
threat model and disclosure policy, [`CONTRIBUTING.md`](./CONTRIBUTING.md) for
development workflow.
