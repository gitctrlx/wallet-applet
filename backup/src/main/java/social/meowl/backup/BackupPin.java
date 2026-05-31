/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.backup;

import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;

/**
 * Backup-card user PIN: a single {@link OwnerPIN} with no PUK, aligned with the Ledger Recovery Key
 * threat model. There is intentionally no unblock path — exhausting the {@value
 * Constants#BACKUP_PIN_RETRY_LIMIT}-try counter is a brute-force signal, and the applet responds by
 * wiping the seed (see {@code BackupApplet}). The scorched-earth policy suits a cold backup card
 * better than the wallet's PIN+PUK recovery flow.
 *
 * <p>The provisioning flag uses two Hamming-distant magic constants instead of {@code 0}/{@code 1}
 * so a single-bit fault cannot forge a provisioned state.
 *
 * <p>This class only owns PIN state; the applet decides what exhaustion means (it calls {@link
 * #check} and, on a {@code false} return with {@link #triesRemaining} {@code == 0}, triggers the
 * wipe). Length-policy violations raise {@link Constants#SW_WRONG_LENGTH} and never consume a try,
 * so a malformed candidate cannot be used to probe the counter.
 */
public final class BackupPin {

    /** Magic value for "PIN provisioned" — Hamming-distant from {@link #UNPROVISIONED}. */
    private static final short PROVISIONED = (short) 0x6CA9;

    /** Magic value for "PIN not provisioned". */
    private static final short UNPROVISIONED = (short) 0x9356;

    private final OwnerPIN pin;
    private final short[] provisioned;

    public BackupPin() {
        this.pin = new OwnerPIN(Constants.BACKUP_PIN_RETRY_LIMIT, Constants.BACKUP_PIN_MAX_LEN);
        this.provisioned = new short[1];
        this.provisioned[0] = UNPROVISIONED;
    }

    /** Whether the PIN has been provisioned by {@link #setupInTx}. */
    public boolean isProvisioned() {
        return provisioned[0] == PROVISIONED;
    }

    /** Whether the PIN has been verified in the current session. */
    public boolean isVerified() {
        return pin.isValidated();
    }

    /** Clears the in-session PIN-verified flag; called on (de)select. */
    public void clearSession() {
        pin.reset();
    }

    /** Remaining PIN tries before the seed is wiped. */
    public byte triesRemaining() {
        return pin.getTriesRemaining();
    }

    /**
     * Initial provisioning. Caller MUST hold a {@link
     * javacard.framework.JCSystem#beginTransaction()} so the PIN install and the companion
     * lifecycle advance commit atomically.
     */
    public void setupInTx(byte[] buf, short off, short len) {
        if (provisioned[0] == PROVISIONED) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        requireLengthPolicy(len);
        pin.update(buf, off, (byte) len);
        provisioned[0] = PROVISIONED;
    }

    /**
     * Checks a candidate PIN, consuming a try on mismatch. Returns {@code true} on a match (and
     * marks the session verified), {@code false} otherwise. The caller inspects {@link
     * #triesRemaining} to decide between the retry status word and the wipe-on-exhaustion path.
     *
     * @throws ISOException {@link Constants#SW_AUTH_BLOCKED} if the counter was already exhausted,
     *     or {@link Constants#SW_WRONG_LENGTH} for an out-of-policy length (no try consumed)
     */
    public boolean check(byte[] buf, short off, short len) {
        requireProvisioned();
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(Constants.SW_AUTH_BLOCKED);
        }
        requireLengthPolicy(len);
        return pin.check(buf, off, (byte) len);
    }

    /**
     * Rotates the PIN to a new value. The caller MUST have verified the old PIN in this session
     * first. Caller MUST hold a {@link javacard.framework.JCSystem#beginTransaction()}.
     */
    public void changeInTx(byte[] buf, short off, short len) {
        requireProvisioned();
        requireLengthPolicy(len);
        pin.update(buf, off, (byte) len);
    }

    /** Logically de-provisions the PIN as part of the atomic factory-reset wipe. */
    public void wipeInTx() {
        provisioned[0] = UNPROVISIONED;
    }

    private void requireLengthPolicy(short len) {
        if (len < Constants.PIN_MIN_LEN || len > Constants.BACKUP_PIN_MAX_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
    }

    private void requireProvisioned() {
        if (provisioned[0] != PROVISIONED) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
}
