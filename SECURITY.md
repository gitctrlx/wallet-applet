# Security Policy

## Supported versions

Only the latest tagged release of `meowl-applet` receives security fixes. Because this applet is the trust anchor of the meowl.social hardware wallet, we strongly recommend keeping cards up to date with the most recent CAP build.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Email `security@meowl.social` with:

- A clear description of the issue — the APDU sequence, expected vs. actual behaviour.
- A minimal reproducer if possible: a JCardSim test under `tests/`, or a host-side script.
- Whether the issue is exploitable on a physical card or only in the simulator.
- Your preferred credit (GitHub handle, real name, or anonymous).

We acknowledge reports within **72 hours** and aim to ship a fix within **30 days** for severity High and above. Coordinated disclosure is appreciated; we will publish an advisory and credit you once a patched release is available.

## Threat model

The applet is the only trusted component on the card and **must** assume that:

1. The host (USB / NFC initiator) is hostile.
2. Power-analysis and fault-injection attacks are realistic on commodity cards.
3. APDU transcripts may be replayed, truncated, or selectively dropped.

## Mitigations

The codebase and release process enforce:

- `OwnerPIN` with bounded retries — no plaintext PIN comparison anywhere in the applet.
- Constant-time comparisons for every sensitive byte sequence.
- All write paths to persistent state wrapped in `JCSystem.beginTransaction()` / `commitTransaction()`.
- Secure-channel (SCP-class) handshake required for any command that exposes secrets.
- Verifiable supply chain — every release publishes a SLSA Level 3 build provenance attestation (Sigstore keyless OIDC), a CycloneDX 1.6 SBOM, and `sha256sums.txt`. Verify with:

  ```bash
  sha256sum -c sha256sums.txt
  gh attestation verify meowl-applet.cap --repo qntx/meowl-applet
  ```
