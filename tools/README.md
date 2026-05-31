<!--
SPDX-FileCopyrightText: 2026 meowl.social contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# `meowl` — host-side CLI for the meowl-applet

A modern picocli command tree that wraps every host-side workflow you need while building, debugging or operating the meowl-applet:

| Surface | Verb | Purpose |
| --- | --- | --- |
| Identity / lifecycle | `info` | Pretty-prints `GET_INFO`'s TLV blob (protocol/applet versions, lifecycle state, capabilities, authentikey). |
| | `authentikey` | Returns the 33-byte compressed authentikey public key. |
| | `select` | Issues a SELECT BY DF NAME and prints the FCI bytes. |
| | `reset --confirm` | Drives `RESET_TO_FACTORY` to completion. |
| Provisioning | `bootstrap` | One-shot personalise → SETUP → import seed (deterministic by default) to bring a fresh card to `SEEDED`. |
| Raw APDU | `apdu <hex>` | Transmits an arbitrary hex APDU (optionally with `--no-select`). |
| | `replay <dump> <hex>` | Replays a previously captured `--dump` session against `MockBIBO` — no card required. |
| GlobalPlatform | `gp list` | Enumerate installed packages, applets and security domains. |
| | `gp install <cap>` | Install (or replace) a CAP file. |
| | `gp uninstall [--aid HEX]` | Delete an applet (and, by default, its package). |
| | _ISD keys_ | Every `gp` subcommand accepts `--key-master HEX` _or_ `--key-enc HEX --key-mac HEX --key-kek HEX`; without flags the well-known GP development default `40 41 ... 4F` is used. |
| Secure Channel | `sc handshake` | One-shot Secure Channel handshake with authentikey-signature verification. |
| | `sc send <inner-hex>` | Open an SC and send one inner APDU through the encrypted envelope. |
| Benchmarking | `bench` | Measures p50/p95/p99 signing / HD-walk latency on a `SEEDED` card (`--samples`, `--warmup`, `--json`). |
| Interactive | `shell` | Persistent REPL with one PC/SC connection and an optional SC session. |

## Build / run

The CLI lives in the `:tools` Gradle subproject of the meowl-applet repository.

```bash
# Run with arguments straight from Gradle:
./gradlew :tools:run -q --args="info"
./gradlew :tools:run -q --args="apdu 80010000"
./gradlew :tools:run -q --args="sc handshake"
./gradlew :tools:run -q --args="shell"

# Or build a launcher script (works after `installDist`):
./gradlew :tools:installDist
./tools/build/install/meowl/bin/meowl --help
```

The launcher uses the JDK 25 toolchain Gradle resolves automatically (foojay).

## Global options

Every subcommand inherits the same mixin via picocli:

| Flag | Description |
| --- | --- |
| `-r, --reader=NAME` | Match the PC/SC reader by substring; falls back to `$MEOWL_READER`. |
| `--reader-ignore=NAME` | Skip readers whose name contains this substring; falls back to `$MEOWL_READER_IGNORE`. |
| `--protocol=PROTO` | PC/SC protocol; default `T=1`. |
| `--exclusive` | Acquire the reader exclusively. |
| `--trace` | Log every APDU at SLF4J `TRACE` level. |
| `-v, --verbose` | Print full stack traces on error instead of a single-line message. |
| `--dump=FILE` | Append every APDU exchange to `FILE` in the apdu4j `MockBIBO` replay format. |
| `--json` | Emit machine-readable JSON output (where the subcommand supports it). |
| `-h, --help` / `-V, --version` | Standard. |

## Typical workflows

### Provision a new card

```bash
# 1. Build the CAP and install it onto the card with the default GP keys.
./gradlew :applet:buildCap
./gradlew :tools:run -q --args="gp install applet/build/cap/meowl-applet.cap"

# 2. Sanity-check the install.
./gradlew :tools:run -q --args="info"

# 3. Hand the card to the user, who will SETUP from their wallet app.
```

### Provision a card with vendor-supplied ISD keys

Most JCOP 4 cards (incl. NXP J3R180) ship with a vendor-specific "default" ISD key set rather than the GP development static set. Supply it as a master key (when a single 16-byte master is documented) or as a pre-diversified ENC/MAC/KEK triple:

```bash
# Master-key form: per-card diversification is applied by GlobalPlatformPro.
./gradlew :tools:run -q --args="gp list --key-master 404142434445464748494A4B4C4D4E4F"

# Triple form: the three components are used as static SCP02/SCP03 keys.
./gradlew :tools:run -q --args="gp install applet/build/cap/meowl-applet.cap \
  --key-enc 5A9E63D03BADBC2A240FE8F534709EDF \
  --key-mac 7CCC1E79D64FC5FA263B8F2955282998 \
  --key-kek B040703EC3DE23EE8AE4CFB6D632AA80"
```

The two modes are mutually exclusive; supplying both raises a usage error. Each component must be exactly 16 bytes (32 hex chars) — current J3R180 silicon authenticates over SCP03 with AES-128.

### Debug a single APDU

```bash
# Plain APDU (no Secure Channel). The CLI auto-selects the meowl applet first.
./gradlew :tools:run -q --args="apdu 80010000"

# Bypass the auto-select if you are talking to the GP card manager:
./gradlew :tools:run -q --args="apdu 00A4040000 --no-select"
```

### Capture a session for offline replay

```bash
./gradlew :tools:run -q --args="--dump session.dump info"
./gradlew :tools:run -q --args="--dump session.dump authentikey"

# Later, replay the same exchanges with no card present:
./gradlew :tools:run -q --args="replay session.dump 80010000"
```

### Reach an inner-band INS through the Secure Channel

```bash
# One-shot: open SC and send EXPORT_PKI_PUBKEY (inner INS 0x30).
./gradlew :tools:run -q --args="sc send 80300000"

# Many-shot: enter the shell, handshake once, then iterate.
./gradlew :tools:run -q --args="shell"
meowl> sc handshake
meowl[sc]> sc send 80300000
meowl[sc]> sc send 8021000404123456   # VERIFY_PIN
meowl[sc]> exit
```

### JSON output for scripting

```bash
./gradlew :tools:run -q --args="info --json"
# {
#   "protocol_version": "1.0",
#   "applet_version": "0.1",
#   "lifecycle": { "code": 0, "name": "UNINITIALIZED" },
#   "capabilities": { "bits": "0x00FF", "flags": [...] },
#   "authentikey": "0x02..."
# }
```

Host SDKs and integration tests can shell out to `meowl info --json` and parse the result without re-implementing any APDU framing.

## Production hardening

> ⚠ **The vendor-supplied "default" CDK is not a secret.** It is publicly known and reused across every unprovisioned card from the same vendor (we observed identical CDKs across two independent retailers for J3R180). Anyone who knows the CDK can `GP DELETE` your applet and replace it with a malicious build that mimics the meowl wire — at which point a future `SETUP` or seed-recovery flow leaks the user's master seed.

A production deployment **MUST** rotate the ISD keys before loading any sensitive applet:

1. **Rotate** ISD keys to a per-card random value via `PUT KEY` (under the vendor CDK), using `gp` from GlobalPlatformPro.
2. **Install** the meowl applet with the new keys.
3. **Personalise** at the applet layer (`SETUP`, master seed, PIN).
4. **Lock** the ISD: switch the card to `CARD_LOCKED` lifecycle and securely destroy the rotated keys (one-way burn). After this step, no one — including you — can replace or remove the applet, which is the very definition of an immutable hardware wallet.

Until the rotation+lock flow is automated end-to-end, the safe operating mode is: **use the development-default or vendor CDK only on cards that hold no real key material**.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Generic / unexpected error (also: refused destructive operations such as `reset` without `--confirm`). |
| `2` | Picocli usage error (unknown option, missing argument, malformed input). |
| `3` | Card-layer I/O failure (no reader, card removed, PC/SC error). |
| `4` | Protocol failure (the card returned a non-9000 status word in a context where success was asserted). |
| `5` | Secure Channel failure (host/card crypto mismatch, MAC failure, malformed envelope). |
| `6` | GlobalPlatform card-management failure (`gp` subcommands: wrong ISD keys, install/delete error). |

Run with `-v` / `--verbose` to see the underlying stack trace. APDU-level tracing is the separate `--trace` flag.

## Architecture at a glance

```text
tools/src/main/java/social/meowl/tools/
├── Main.java                     ── one-line entry: System.exit(MeowlCli.commandLine().execute(args))
├── core/                         ── pure helpers + wire mirrors (Hex, Tlv, MeowlAid, MeowlInsn, MeowlSw,
│                                     MeowlCapability, MeowlLifecycle, MeowlInfo, ProtocolException)
├── transport/                    ── apdu4j BIBO stack + ReaderPreferences + visitor run() / connect()
├── proto/                        ── Secure Channel host client (KdfCmac, HostCrypto, SecureChannelClient)
├── card/                         ── MeowlCard operations facade, shared by cli + shell
├── gp/                           ── in-process GlobalPlatformPro (GpFacade)
├── shell/                        ── stateful REPL engine (ShellSession, delegates to MeowlCard)
└── cli/                          ── picocli command tree (MeowlCli + subcommands)
```

Test pyramid:

| Layer | Tests | Speed |
| --- | --- | --- |
| `core/` & helpers | strict hex / TLV / INS / SW / AID round-trips | <100 ms |
| `proto/` | RFC 5869 vectors, AES / ECDH round-trips, BouncyCastle oracles | ~1 s |
| `card/` | MockBIBO-driven `MeowlCard` operations (select / info / reset) | <100 ms |
| `cli/` | picocli registration, JSON output, exit-code mapping | <100 ms |
| `shell/` | MockBIBO-driven dispatcher tests | <100 ms |
| `transport/` | MockBIBO decorator / dump-replay / PrintStream layering | <100 ms |

The full unit suite runs in well under a second on a warm JVM.

## License

AGPL-3.0-or-later. See [LICENSE](../LICENSE).
