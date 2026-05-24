/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;

/**
 * User PIN + PUK manager per {@code docs/specs/meap-3.md}.
 *
 * <p>Holds one user PIN and one unblock PUK, each backed by {@link OwnerPIN} for JC-native
 * bounded-retry counters and storage protection. Status-word semantics:
 *
 * <ul>
 *   <li>Correct PIN/PUK → {@code 9000}; wrong value → {@code 0x63Cn} with the 4-bit retry count in
 *       the low nibble (ISO 7816-4); exhausted counter → {@link Constants#SW_AUTH_BLOCKED}.
 *   <li>Length-policy violations return {@link Constants#SW_WRONG_LENGTH} and do <em>not</em>
 *       consume a retry — they are host-side protocol errors, not guesses.
 *   <li>{@link #unblockPin} consumes a PUK attempt even when the new PIN fails policy.
 * </ul>
 *
 * <p>Every entry point validates length bounds before invoking {@link OwnerPIN#check}, which would
 * otherwise raise {@link ArrayIndexOutOfBoundsException} on an over-long input.
 */
public final class PinManager {

    private OwnerPIN pin;
    private OwnerPIN puk;
    private final byte[] provisioned; // [0] != 0 → setup() has been called

    /**
     * Scratch used by {@link #wipeInTx()} to drive a known-pattern write through both {@link
     * OwnerPIN} cells before discarding their references. Sized at {@link Constants#PUK_MAX_LEN} so
     * the same buffer covers PIN and PUK updates.
     */
    private final byte[] scrub;

    /** Constructs an unprovisioned manager. */
    public PinManager() {
        this.pin = new OwnerPIN(Constants.PIN_RETRY_LIMIT, Constants.PIN_MAX_LEN);
        this.puk = new OwnerPIN(Constants.PUK_RETRY_LIMIT, Constants.PUK_MAX_LEN);
        this.provisioned = new byte[1];
        this.scrub =
                JCSystem.makeTransientByteArray(Constants.PUK_MAX_LEN, JCSystem.CLEAR_ON_DESELECT);
    }

    /** Returns {@code true} once {@link #setupInTx} has been called successfully. */
    private boolean isProvisioned() {
        return provisioned[0] != 0;
    }

    /** Returns {@code true} once {@link #verifyPin} has succeeded in this session. */
    public boolean isPinVerified() {
        return pin.isValidated();
    }

    /** Clears the in-session PIN-verified flag. Called from {@code select} and on session end. */
    public void clearSession() {
        // OwnerPIN.reset() is a no-op when not validated; that's the behaviour we want here.
        pin.reset();
    }

    /**
     * Initial provisioning: installs the user PIN and unblock PUK. <strong>Caller MUST hold a
     * {@link JCSystem#beginTransaction()} block</strong> so the two installs and the companion
     * lifecycle transition commit atomically. May only run when {@link #isProvisioned()} is {@code
     * false}.
     */
    public void setupInTx(
            byte[] pinBuf,
            short pinOffset,
            short pinLen,
            byte[] pukBuf,
            short pukOffset,
            short pukLen) {
        if (provisioned[0] != 0) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        requireLengthPolicy(pinLen, Constants.PIN_MIN_LEN, Constants.PIN_MAX_LEN);
        requireLengthPolicy(pukLen, Constants.PUK_MIN_LEN, Constants.PUK_MAX_LEN);
        pin.update(pinBuf, pinOffset, (byte) pinLen);
        puk.update(pukBuf, pukOffset, (byte) pukLen);
        provisioned[0] = 1;
    }

    /**
     * Verifies a candidate PIN. On success {@link OwnerPIN#isValidated} returns {@code true}.
     *
     * @throws ISOException with status word {@link Constants#SW_PIN_RETRIES_BASE} {@code | n} where
     *     {@code n} is the number of attempts remaining after the failed verification, or {@link
     *     Constants#SW_AUTH_BLOCKED} if the counter was already zero.
     */
    public void verifyPin(byte[] buf, short offset, short length) {
        requireProvisioned();
        verifyOwnerPin(pin, buf, offset, length, Constants.PIN_MIN_LEN, Constants.PIN_MAX_LEN);
    }

    /**
     * Atomically rotates the PIN. Requires the old PIN to verify against the stored value; consumes
     * a PIN attempt if the old PIN is wrong, exactly like {@link #verifyPin}.
     */
    public void changePin(
            byte[] oldBuf,
            short oldOffset,
            short oldLen,
            byte[] newBuf,
            short newOffset,
            short newLen) {
        requireProvisioned();
        requireLengthPolicy(newLen, Constants.PIN_MIN_LEN, Constants.PIN_MAX_LEN);
        verifyPin(oldBuf, oldOffset, oldLen);
        JCSystem.beginTransaction();
        pin.update(newBuf, newOffset, (byte) newLen);
        JCSystem.commitTransaction();
    }

    /** Atomically rotates the PUK. Requires the current PUK to verify; consumes a PUK attempt. */
    public void changePuk(
            byte[] oldBuf,
            short oldOffset,
            short oldLen,
            byte[] newBuf,
            short newOffset,
            short newLen) {
        requireProvisioned();
        requireLengthPolicy(newLen, Constants.PUK_MIN_LEN, Constants.PUK_MAX_LEN);
        verifyOwnerPin(
                puk, oldBuf, oldOffset, oldLen, Constants.PUK_MIN_LEN, Constants.PUK_MAX_LEN);
        JCSystem.beginTransaction();
        puk.update(newBuf, newOffset, (byte) newLen);
        JCSystem.commitTransaction();
    }

    /**
     * Unblocks the PIN after exhausted retries. Requires the PUK to verify and the new PIN to
     * satisfy the PIN policy. A PUK attempt is consumed regardless of whether the new PIN passes
     * the policy check.
     */
    public void unblockPin(
            byte[] pukBuf,
            short pukOffset,
            short pukLen,
            byte[] newPinBuf,
            short newPinOffset,
            short newPinLen) {
        requireProvisioned();
        if (pin.getTriesRemaining() != 0) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        verifyOwnerPin(
                puk, pukBuf, pukOffset, pukLen, Constants.PUK_MIN_LEN, Constants.PUK_MAX_LEN);
        requireLengthPolicy(newPinLen, Constants.PIN_MIN_LEN, Constants.PIN_MAX_LEN);
        JCSystem.beginTransaction();
        pin.update(newPinBuf, newPinOffset, (byte) newPinLen);
        pin.resetAndUnblock();
        JCSystem.commitTransaction();
    }

    /**
     * Destroys all PIN/PUK state. Drives a best-effort EEPROM scrub (an {@code update()} cycle with
     * an all-{@code 0xFF} buffer) through each {@link OwnerPIN} before re-instantiating fresh
     * instances, since the JC spec offers no {@code clearKey()}-equivalent on {@link OwnerPIN}.
     *
     * <p>Caller MUST hold a {@link JCSystem#beginTransaction()} block; used by {@link
     * MeowlApplet#wipe()} to bundle the PIN/PUK invalidation with the PKI, master-seed and
     * lifecycle wipes into one atomic reset-to-factory commit.
     */
    public void wipeInTx() {
        // Two-layer wipe: an EEPROM-cell scrub via OwnerPIN.update() with a garbage buffer,
        // then a fresh OwnerPIN re-instantiation as the JC-level invalidation. Failures during
        // the scrub MUST propagate so the enclosing JC transaction rolls back — silently
        // swallowing would leave the caller believing reset-to-factory committed while the
        // EEPROM cells still held the previous PIN/PUK hashes.
        Util.arrayFillNonAtomic(scrub, (short) 0, Constants.PUK_MAX_LEN, (byte) 0xFF);
        pin.update(scrub, (short) 0, Constants.PIN_MAX_LEN);
        puk.update(scrub, (short) 0, Constants.PUK_MAX_LEN);
        // Rebuild fresh OwnerPIN instances; JC spec offers no clearKey-equivalent.
        this.pin = new OwnerPIN(Constants.PIN_RETRY_LIMIT, Constants.PIN_MAX_LEN);
        this.puk = new OwnerPIN(Constants.PUK_RETRY_LIMIT, Constants.PUK_MAX_LEN);
        this.provisioned[0] = 0;
    }

    /**
     * Shared verify backbone: tries-remaining probe → length-policy gate → {@link OwnerPIN#check}.
     * On a wrong candidate, raises {@code SW_PIN_RETRIES_BASE | n} (or {@code SW_AUTH_BLOCKED} on
     * exhaustion). Length-policy violations return {@code SW_WRONG_LENGTH} <em>without</em>
     * consuming a retry — the same SW is returned for every length-violating input regardless of
     * candidate bytes, so this path leaks no information to a brute-force attacker.
     */
    private static void verifyOwnerPin(
            OwnerPIN owner, byte[] buf, short offset, short length, byte minLen, byte maxLen) {
        byte triesRemaining = owner.getTriesRemaining();
        if (triesRemaining == 0) {
            ISOException.throwIt(Constants.SW_AUTH_BLOCKED);
        }
        if (length < minLen || length > maxLen) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        if (!owner.check(buf, offset, (byte) length)) {
            byte remaining = owner.getTriesRemaining();
            if (remaining == 0) {
                ISOException.throwIt(Constants.SW_AUTH_BLOCKED);
            }
            ISOException.throwIt((short) (Constants.SW_PIN_RETRIES_BASE | (remaining & 0x0F)));
        }
    }

    private static void requireLengthPolicy(short length, byte minLen, byte maxLen) {
        if (length < minLen || length > maxLen) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
    }

    private void requireProvisioned() {
        if (!isProvisioned()) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
}
