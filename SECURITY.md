# Security Policy

## Supported versions

Only the latest tagged release of `meowl-applet` receives security fixes. As
this applet is the trust anchor of the meowl.social hardware wallet, we
strongly recommend keeping cards up to date with the latest CAP build.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Email `security@meowl.social` with:

- A clear description of the issue (APDU sequence, expected vs actual behavior).
- A minimal reproducer if possible (test case under `tests/`, or a script).
- Whether the issue is exploitable on a physical card or only in the simulator.
- Your preferred credit (GitHub handle, real name, or anonymous).

We acknowledge reports within **72 hours** and aim to ship a fix within
**30 days** for severity High and above. Coordinated disclosure is appreciated.

## Threat model

The applet is the only trusted component on the card and **must** assume:

1. The host (USB / NFC initiator) is hostile.
2. Power analysis and fault-injection attacks are possible on cheap cards.
3. APDU transcripts may be replayed.

Mitigations covered by the codebase / process:

- `OwnerPIN` with bounded retries (no plaintext PIN comparison).
- Constant-time comparisons for sensitive material.
- All write paths wrapped in `JCSystem.beginTransaction()` / `commitTransaction()`.
- Secure channel (SCP-class) for any command that exposes secrets.
- Reproducible CAP builds (signed in CI, hash published with each release).
