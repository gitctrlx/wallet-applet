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
- PIN: 4–16 bytes (no charset enforced on-card; the host wallet may impose ASCII), default retry counter `3`.
- PUK: 8–32 bytes (no charset enforced on-card), default retry counter `5`.
- Both counters and material are backed by JavaCard's `OwnerPIN`. The JC 3.x specification does not document `OwnerPIN.check` as constant-time, but the bounded retry counter (3 attempts then permanent block) makes the residual brute-force window negligible.
- The PIN and PUK are set during the `SETUP` APDU. Both can be rotated afterwards by the `CHANGE_PIN` and `CHANGE_PUK` APDUs respectively, each of which requires the current corresponding value.
- `UNBLOCK_PIN` consumes a PUK attempt regardless of whether the new-PIN candidate is valid; the new PIN must satisfy length policy or the attempt is wasted.

### Status-word table (ISO 7816-4 conformant)

| Condition                                                        | Status word         |
| ---------------------------------------------------              | -----------------   |
| Successful verification                                          | `9000`              |
| Wrong PIN, `n` retries remaining (`n` ∈ {1, 2})                  | `63C` ‖ `n`         |
| PIN length outside `[PIN_MIN_LEN, PIN_MAX_LEN]`                  | `6700`              |
| PIN blocked (or PUK blocked)                                     | `6983`              |
| Lifecycle gate violation (e.g. `VERIFY_PIN` before `SETUP_DONE`) | `6FB0`              |

### Atomicity invariant

`SETUP` performs four mutations: install PIN, install PUK, set `provisioned` flag, advance lifecycle from `PERSONALIZED` to `SETUP_DONE`. All four commit inside a single `JCSystem.beginTransaction()` / `commitTransaction()` block so a torn power-off cannot leave the card in an intermediate state. This was identified during the Phase 3 audit: a previous draft used two separate transactions and could brick the card if power was lost between them (`VERIFY_PIN` would be gated out by the FSM while `SETUP` would be rejected by the `provisioned` flag, forcing the user through `RESET_TO_FACTORY`).

### Length-policy violation does not consume a retry

A `VERIFY_PIN` whose payload length is outside `[PIN_MIN_LEN, PIN_MAX_LEN]` returns `SW_WRONG_LENGTH` (`6700`) and does **not** decrement the retry counter. Such a payload is a host-side protocol error, not a guess at the secret; a constant `6700` response carries no information about the PIN. This rule is verified by the `underLengthPinDoesNotConsumeRetry` regression test.

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
