# Security policy

## Reporting a vulnerability

Do not open a public issue. Report privately through GitHub's
[private vulnerability reporting](https://github.com/qntx/wallet-applet/security/advisories/new)
with the command sequence (or a simulator test under `tests/`), the expected and the observed
behaviour, and whether it reproduces in the simulator, on a card, or both.

## Scope

The applet implements `spec/protocol.md`; a deviation from the specification is a vulnerability
when it weakens a property the specification states. The protocol is not yet frozen: until the
external audit (`spec/protocol.md` §17) no card built from this repository is a production card.
Shipped cards cannot be updated, so a defect found after the freeze is handled by the host
(`spec/protocol.md` §17).

What the card cannot protect against is part of the design and not a vulnerability: a compromised
wallet kernel that asks the card to sign a different digest after the user unlocked it; a thief who
holds the card and knows the access code; a malicious personaliser; attacks on the chip beyond its
certification.

## Supply chain

The CAP build is reproducible (fixed timestamps, sorted inputs; CI builds it twice and compares the
SHA-256). Dependencies are pinned in `gradle/libs.versions.toml` and `spec/vectors/gen/ts/bun.lock`;
GitHub Actions are pinned by commit.
