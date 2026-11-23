<!-- markdownlint-disable MD033 MD041 -->

# wallet-applet

The qntx card: an NFC Java Card applet that holds an HD wallet seed and signs for
[qntx/wallet](https://github.com/qntx/wallet). The card has no screen and no button; private keys
are generated on the card (or transferred once from another card of the same set) and no command
reveals a key, the seed or the access code.

[`spec/protocol.md`](spec/protocol.md) is the single normative specification (protocol 1, not yet
frozen); [`spec/vectors/`](spec/vectors/) holds its test vectors. [`AGENTS.md`](AGENTS.md) lists
the invariants every change keeps.

## Status

The repository is being rewritten from zero against `spec/protocol.md`. This revision implements
identity, personalisation, the secure session, the wallet commands, derivation, the three
signing commands, multi-card transfer and the read-only NDEF applet (§5–§15); the tools follow.

## Layout

| Path | Content | License |
| --- | --- | --- |
| `applet/` | The one CAP: package `org.qntx.card` (Java Card 3.0.5 Classic), wallet + NDEF applets | AGPL-3.0-or-later |
| `sim/` | jcardsim fork (`sim/jcardsim`, pinned upstream commit plus patches) with transactions, power-loss injection and memory accounting | Apache-2.0 (fork), AGPL-3.0-or-later |
| `host/` | Reference host library written from the specification | AGPL-3.0-or-later |
| `tests/` | Simulator, vector and mutation tests | AGPL-3.0-or-later |
| `tools/` | `qntx-card` installation and personalisation tool | AGPL-3.0-or-later |
| `spec/` | Protocol specification and vectors | MIT OR Apache-2.0 |
| `sdks/` | Oracle Java Card SDKs (submodule; the JCDK converter) | Oracle |

Identifiers: load file `F0716E747800`, wallet applet `F0716E74780101` (`spec/protocol.md` §2).

## Build

Requirements: JDK 25 (Gradle provisions it through the toolchain if missing), the submodule, and
Bun for the TypeScript vector generator.

```bash
git clone --recurse-submodules https://github.com/qntx/wallet-applet.git
cd wallet-applet
./gradlew build            # CAP, simulator and tests, memory report
./gradlew :tests:pitest    # mutation tests on the gate classes
spec/vectors/gen/check.sh  # both vector generators agree
```

The CAP is `applet/build/cap/qntx-card.cap`; two builds of the same sources have the same SHA-256.
Tests run the applet's JVM classes in the simulator with the `sim` agent (`-javaagent`), which
journals persistent writes, injects power loss and accounts transient memory with sizes measured on
the baseline chip (NXP JCOP 4 P71).

## Simulator (`card-sim.jar`)

`./gradlew :sim:shadowJar` builds `sim/build/libs/card-sim.jar`, a fat jar of the simulator,
applet and host classes. The manifest's `Launcher-Agent-Class` starts the bytecode agent that
makes persistent writes tearable; run it directly:

```bash
java -jar card-sim.jar [--cards N] [--port P] [--state empty|factory|blank]
```

- `--cards N`: simulated cards, 1–16 (default 3). Card `i` listens on `127.0.0.1:P+i`;
  `--port 0` gives every card an ephemeral port.
- `--port P`: first TCP port (default 35963, vpcd's port).
- `--state empty`: no package and no applets — only the issuer security domain (below).
- `--state factory`: install the wallet and NDEF applets and stop (life `FACTORY`).
- `--state blank` (default): also personalise each card under the `ca1` test CA of
  `spec/vectors/cert.json` (life `BLANK`).

In `factory` and `blank` states every card carries the wallet applet (`F0716E74780101`) and the
NDEF applet (`D2760000850101`, message "qntx card"). Startup prints one `card` line per card —
`empty` cards have no identity, so their lines end after the port — then, in `blank` state only,
a single `anchor` line, then `ready`:

```text
card <i> port <port> id <ID(A), 32 hex> short <XXXX-XXXX>
anchor <ca1 public key, 130 hex>
ready
```

Bad arguments print usage on stderr and exit 2; `--help` prints it on stdout and exits 0.

### Framing

Each card's TCP connection carries vpcd-style frames `u16(len) ‖ payload` (vsmartcard vpcd):

| `len` | Payload | Meaning | Reply |
| --- | --- | --- | --- |
| ≥ 4 | command APDU | transmit to the card | `u16(len) ‖ R-APDU` |
| 1 | `00` | power off | none |
| 1 | `01` | power on (a power cycle when unpowered; no-op when powered) | none |
| 1 | `02` | reset (power cycle) | none |
| 1 | `04` | get ATR | `u16(len) ‖ ATR` |
| 3 | `10 ‖ u16(N)` | arm power loss at the N-th persistent write of the next command that makes at least N writes | none |

A new connection powers the card on with a power cycle; closing it powers the card off. Card
state (persistent memory) lives as long as the server process; one connection per card at a time,
a second connection waits until the first closes. Anything else — `len` 0 or 2, a 3-byte payload
not starting with `10`, an unknown control byte, `N = 0` — closes the connection.

An APDU on an unpowered card, or an APDU during which the armed tear fired, is answered with the
empty frame `00 00` — no response, the field was lost. After a tear the card is unpowered until a
power-on or reset control. The armed tear is a per-command write count: it stays armed until it
fires or the card is power-cycled/powered off.

### Issuer security domain

Every card answers as a simulated GlobalPlatform issuer security domain, AID
`A000000151000000`, selected by default at power-up and answering SELECT-by-empty-AID with the
FCI `6F108408A000000151000000A5049F6501FF`. One AES-128 key set at KVN `0x30`, ENC = MAC = DEK =
`404142434445464748494A4B4C4D4E4F` (the GP test key). Emulated:

- SCP03 with `i = 0x00` (random card challenge, no sequence counter, no R-MAC/R-ENC, S8 MACs):
  INITIALIZE UPDATE (KVN `00` or `30`, else `6A88`), EXTERNAL AUTHENTICATE with security level
  `01` or `03`, and from then on only `84`-wrapped commands — a bad C-MAC closes the channel.
- GET DATA `9F 7F` returns the CPLC (fixed bytes except a per-card IC serial); unknown tags and
  other GET DATA → `6A88`.
- GET STATUS (`80 F2`) for the ISD, applications, load files and modules, in the card A formats.
- INSTALL [for load] + LOAD: the `C4` block must be a concatenation of components each
  byte-identical to the same-tagged component of the CAP embedded in the jar and covering all of
  them except Descriptor and Debug; an LFDBH, when present, must equal the block's SHA-256.
- INSTALL [for install and make selectable]: loaded package, class AID `F0716E74780101` or
  `F0716E74780201`, free instance AID, empty privileges, applet data from the `C9` TLV.
- PUT KEY `80 D8 kvn 81` replacing all three keys as `GPPro putKeys(keys, true)` encodes them —
  AES or DES entries encrypted under the static DEK, each KCV verified — after which the old keys
  no longer open a channel.

Not emulated: SCP02/SCP01 (INITIALIZE UPDATE with `i ≠ 00` gets `6A86`), key diversification,
sequence counters, R-MAC, DAP blocks, receipts, install tokens, delegated management, extradition
and DELETE — anything not listed answers `6D00`, and management commands outside a secure channel
answer `6982`.

## License

The applet, simulator patches, host, tests and tools are licensed under the GNU Affero General
Public License v3.0 or later ([LICENSE](LICENSE)). The specification and vectors under `spec/` are
licensed under MIT OR Apache-2.0. The vendored jcardsim under `sim/jcardsim` remains Apache-2.0.
Every file carries REUSE metadata ([`REUSE.toml`](REUSE.toml), [`LICENSES/`](LICENSES/)).

---

<div align="center">

A **[QuantX](https://qntx.org)** project.

<a href="https://qntx.org"><img alt="QuantX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx.svg" /></a>

Code is law. We write both.

</div>
