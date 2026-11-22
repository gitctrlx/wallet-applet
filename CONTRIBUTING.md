# Contributing

Read [`AGENTS.md`](AGENTS.md) first: it lists the invariants and conventions every change keeps.

## Setup

```bash
git clone --recurse-submodules https://github.com/qntx/wallet-applet.git
```

JDK 25 (or let Gradle's toolchain provision it) and Bun (vector generator) are the only tools.

## Before a pull request

```bash
./gradlew spotlessApply
./gradlew build :tests:pitest
spec/vectors/gen/check.sh
uvx --from 'reuse[charset-normalizer]==6.3.0' reuse lint
```

- `spec/protocol.md` is normative. A change of behaviour changes the specification in the same pull
  request; a disagreement between code and specification is a bug in both.
- Tests derive from the specification and independent oracles (official vectors, BouncyCastle,
  noble), never from the applet's own output.
- Applet code: Java Card 3.0.5 Classic subset (no `int`, `String`, floating point, recursion or
  allocation after install); every persistent write inside the transaction the specification names.
- Commits follow Conventional Commits in English (imperative subject of at most 50 characters,
  body wrapped at 72).
