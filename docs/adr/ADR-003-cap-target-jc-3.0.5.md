<!--
SPDX-FileCopyrightText: 2026 meowl.social contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# ADR-003 — CAP file targets JavaCard 3.0.5, built with JCDK v26.0

- **Status**: Accepted
- **Date**: 2026-05-25
- **Author(s)**: meowl.social contributors
- **Touches**: `applet/build.gradle.kts`, `gradle/libs.versions.toml`, `gradle/wrapper/gradle-wrapper.properties`

## Context

The CAP file converter version (build-time SDK) and the CAP target (runtime classes file `targetsdk` field) are independent dimensions. We use the latest published JCDK at build time but cap the runtime target at the oldest JC version that still ships on cards we want to support.

J3R180 (P71) advertises JC 3.0.5 capability. So do most production-grade cards in the Keycard ecosystem and broader open-hardware-wallet space. JC 3.1 cards exist (G+D StarSign, newer NXP JCOP4) but are uncommon in the user-installable hardware-wallet category.

Building with the latest JCDK (currently `jc320v26.0_kit` at `gradle/libs.versions.toml:7`) catches converter bugs earlier and improves diagnostics, but emitting a 3.1-targeted CAP would lock us out of every 3.0.5-only card.

## Options considered

### Option A — Build with v26.0, target 3.0.5

Use `jc320v26.0_kit` for the converter and tools, set `targetsdk="3.0.5"` in the ant-javacard task.

- **Pros**: Modern toolchain, broadest card compatibility, identical CAP runs on J3R180 and any newer JC 3.x card.
- **Cons**: Cannot use JC 3.1 features (e.g. `Signature.SIG_CIPHER_AES_CMAC_128` constants directly on JC 3.0.5; we work around this where needed).

### Option B — Build with v26.0, target 3.1

Lift the target to JC 3.1 and use newer API surface.

- **Pros**: Access to JC 3.1 features (e.g. `Signature.ALG_AES_CMAC_128` rather than `ALG_AES_MAC_128_NOPAD` workarounds).
- **Cons**: Locks out J3R180 and every JC 3.0.5-only card. Eliminates the entire deployment fleet we ship today.

### Option C — Build with an older JCDK (e.g. v3.0.5 SDK)

Use the JC 3.0.5 SDK directly so build-time and runtime versions match.

- **Pros**: No version skew between build and runtime.
- **Cons**: Older converter is buggier and slower; loses diagnostics of v26.0; no benefit since v26.0 already supports `targetsdk=3.0.5`.

## Decision

**Option A**. CAP target stays at `3.0.5`; build SDK is `jc320v26.0_kit`. Captured by `gradle/libs.versions.toml:7-9`:

```toml
javacard-sdk = "jc320v26.0_kit"
javacard-target = "3.0.5"
```

## Consequences

### Positive

- Single CAP artefact runs on every certified J3R180 and on JC 3.1 cards (forward compatible).
- Modern converter improves diagnostics during development.
- README badge `JavaCard 3.0.5 → 3.2.0` accurately advertises the supported runtime range.

### Negative / accepted residual risk

- We cannot rely on JC 3.1 / 3.2 surface in applet code paths, even though our build SDK exposes them. Cocnsequences mostly bite when adopting new crypto primitives — for instance Ed25519 had to be reconstructed via Wei25519 mapping (see ADR-007 once written) instead of using a JC 3.1 native EdDSA primitive, because such a primitive is not in 3.0.5.

### Mitigations and follow-ups

- Revisit this ADR when (a) J3R180 deprecation is in sight, (b) a critical primitive needs JC 3.1+, or (c) a new feature class would otherwise require a 3.1 fork.
- The applet code should never `import` JC 3.1+ types. Spotless / static analysis catches this implicitly because the JC 3.0.5 stub jar (`sdks/jc320v26.0_kit/lib/api_classic-3.0.5.jar` per `applet/build.gradle.kts:43`) is the only `compileOnly` API source, so JC 3.1+ symbols simply will not resolve.

## References

- `gradle/libs.versions.toml:7-9` — version pins
- `applet/build.gradle.kts:36-43` — converter / target wiring
- Oracle JavaCard SDK release notes (v26.0)
- NXP J3R180 product brief (capability advertised: JC 3.0.5)
