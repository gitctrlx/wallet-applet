# ADR-0006: Single PIN + single PUK with bounded retries

Date: 2026-05-18

## Status

Accepted

## Context

The MUSCLE framework that Satochip inherits supports up to eight PIN slots and eight PUK slots, with per-slot retry counters and ACL bitmasks gating which PIN guards which command. In practice Satochip uses only slot 0. The complexity buys nothing for a personal hardware wallet and exposes more state than it secures.

Modern hardware wallets converge on a single PIN that gates every sensitive operation, optionally paired with a single PUK that can unblock the PIN after exhausting its retry counter.

## Decision

- **Exactly one PIN** guards every sensitive command (everything except `GET_INFO`, `INIT_SECURE_CHANNEL`, `OPEN_SECURE_CHANNEL`, and `RESET_TO_FACTORY`).
- **Exactly one PUK** can unblock the PIN after the PIN's retry counter hits zero. Exhausting the PUK's own retry counter **permanently bricks** the card.
- PIN: 4–16 ASCII bytes, default retry counter `3`.
- PUK: 8–32 ASCII bytes, default retry counter `5`.
- Both counters and material are backed by JavaCard's `OwnerPIN`, which provides constant-time comparison and an atomic decrement-on-mismatch.
- The PIN and PUK are set during the `SETUP` APDU. Both can be rotated afterwards by the `CHANGE_PIN` and `CHANGE_PUK` APDUs respectively, each of which requires the current corresponding value.
- `UNBLOCK_PIN` consumes a PUK attempt regardless of whether the new-PIN candidate is valid; the new PIN must satisfy length/charset policy or the attempt is wasted.

## Consequences

### Positive

- **Cognitively simple:** users learn one PIN. No risk of "which slot was that?" confusion.
- **Auditable:** every gated command's authorisation rule reads "PIN was verified in this Secure Channel session", full stop.
- **No ACL bitmask overhead** in EEPROM or in command processing.

### Negative

- **No per-operation PIN.** Some wallets give a separate "transaction PIN" so the unlock PIN can be cached for the session. We may revisit this in a later ADR if user feedback demands.
- **PUK loss = card loss.** Users must back up their PUK alongside their seed. This is a UX concern handled by the host wallet.

### Neutral

- The PIN/PUK pair lives in EEPROM. Reset-to-factory wipes both alongside the seed.
