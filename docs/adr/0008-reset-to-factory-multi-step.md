# ADR-0008: Reset-to-factory requires N consecutive un-interleaved INS

Date: 2026-05-18

## Status

Accepted

## Context

`RESET_TO_FACTORY` permanently wipes the seed, PIN/PUK, PKI certificate, and Secure Channel state. A single APDU that performs this would be a denial-of-service primitive: any attacker with brief contact-interface access — for instance, a malicious NFC terminal grazing a card-in-pocket — could brick the wallet.

Satochip mitigates this by requiring the `RESET_TO_FACTORY` INS to be sent four times consecutively, with no other INS interleaved. The card decrements an internal counter on each `RESET_TO_FACTORY` and resets the counter to `MAX_RESET_COUNTER` whenever a different INS arrives. Only when the counter reaches zero does the wipe execute.

This is a simple, effective deterrent: it requires the attacker to hold contact long enough to send N un-interleaved APDUs, which is operationally meaningful.

## Decision

- `RESET_TO_FACTORY` (INS `0x03`) requires **four consecutive un-interleaved invocations** to trigger the wipe.
- The countdown counter starts at `4` on every applet `select()` and on every non-`RESET_TO_FACTORY` INS.
- Each `RESET_TO_FACTORY` invocation decrements the counter. The status word returned is `0x6FA0 + counter`, communicating the remaining count to the host. On the fourth invocation, the wipe executes and the card returns `0x6FA0` (`SW_RESET_DONE`).
- The wipe consists of, in atomic order: zeroising the master seed → clearing all derived key material → clearing PIN/PUK → clearing the PKI certificate → resetting the lifecycle state to `STATE_UNINITIALIZED`. The `authentikey` is preserved per [ADR-0005](./0005-authentikey-lifecycle.md).

## Consequences

### Positive

- **Robust against brief contact attacks** like skim-by-NFC. The attacker has to hold the card for the duration of four full APDU round-trips.
- **Recoverable from accidents:** an honest user who sends one or two `RESET_TO_FACTORY` APDUs by mistake just needs to send any other APDU to reset the counter.
- **Counter visibility:** the status word communicates the countdown so a host wallet can render a confirmation UI ("3 more confirmations needed").

### Negative

- **Determined attackers** with sustained contact-interface access can still trigger a reset. This is unavoidable without a physical confirmation button; the design only deters drive-by attacks.
- **Not a recovery mechanism.** Reset destroys the seed. Users must back up their seed elsewhere (or via Seedkeeper-style sharding in a future release).

### Neutral

- `4` is a sensible default; we may parameterise it via the PKI personalisation phase if real-world deployments show one value works better than another.
