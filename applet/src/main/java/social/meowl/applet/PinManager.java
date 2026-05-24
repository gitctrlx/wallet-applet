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
 *       the low nibble (ISO 7816-4); exhausted counter → {@link Constants.Sw#AUTH_BLOCKED}.
 *   <li>Length-policy violations return {@link Constants.Sw#WRONG_LENGTH} and do <em>not</em>
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
     * Scratch used by {@link #wipe()} to drive a known-pattern write through both {@link OwnerPIN}
     * cells before discarding their references. Sized at {@link Constants.Pin#PUK_MAX_LEN} so the
     * same buffer covers PIN and PUK updates.
     */
    private final byte[] scrub;

    /** Constructs an unprovisioned manager. */
    public PinManager() {
        this.pin = new OwnerPIN(Constants.Pin.RETRY_LIMIT, Constants.Pin.MAX_LEN);
        this.puk = new OwnerPIN(Constants.Pin.PUK_RETRY_LIMIT, Constants.Pin.PUK_MAX_LEN);
        this.provisioned = new byte[1];
        this.scrub =
                JCSystem.makeTransientByteArray(
                        Constants.Pin.PUK_MAX_LEN, JCSystem.CLEAR_ON_DESELECT);
    }

    /** Returns {@code true} once {@link #setup} has been called successfully. */
    public boolean isProvisioned() {
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
            ISOException.throwIt(Constants.Sw.CONDITIONS_NOT_SATISFIED);
        }
        requirePinPolicy(pinLen);
        requirePukPolicy(pukLen);
        pin.update(pinBuf, pinOffset, (byte) pinLen);
        puk.update(pukBuf, pukOffset, (byte) pukLen);
        provisioned[0] = 1;
    }

    /**
     * Verifies a candidate PIN. On success {@link OwnerPIN#isValidated} returns {@code true}.
     *
     * @throws ISOException with status word {@link Constants.Sw#PIN_RETRIES_BASE} {@code | n} where
     *     {@code n} is the number of attempts remaining after the failed verification, or {@link
     *     Constants.Sw#AUTH_BLOCKED} if the counter was already zero.
     */
    public void verifyPin(byte[] buf, short offset, short length) {
        requireProvisioned();
        // Probe getTriesRemaining first so a blocked PIN reports as blocked regardless of length.
        byte triesRemaining = pin.getTriesRemaining();
        if (triesRemaining == 0) {
            ISOException.throwIt(Constants.Sw.AUTH_BLOCKED);
        }
        // Bounds-check before OwnerPIN.check (which raises AIOOBE on length > maxPINSize). Policy
        // violations return SW_WRONG_LENGTH without consuming a retry — the same SW is returned
        // for every length-violating input regardless of candidate bytes, so this path leaks no
        // information to a brute-force attacker.
        if (length < Constants.Pin.MIN_LEN || length > Constants.Pin.MAX_LEN) {
            ISOException.throwIt(Constants.Sw.WRONG_LENGTH);
        }
        if (!pin.check(buf, offset, (byte) length)) {
            byte remaining = pin.getTriesRemaining();
            if (remaining == 0) {
                ISOException.throwIt(Constants.Sw.AUTH_BLOCKED);
            }
            ISOException.throwIt((short) (Constants.Sw.PIN_RETRIES_BASE | (remaining & 0x0F)));
        }
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
        requirePinPolicy(newLen);
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
        requirePukPolicy(newLen);
        verifyPukInternal(oldBuf, oldOffset, oldLen);
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
            ISOException.throwIt(Constants.Sw.CONDITIONS_NOT_SATISFIED);
        }
        verifyPukInternal(pukBuf, pukOffset, pukLen);
        requirePinPolicy(newPinLen);
        JCSystem.beginTransaction();
        pin.update(newPinBuf, newPinOffset, (byte) newPinLen);
        pin.resetAndUnblock();
        JCSystem.commitTransaction();
    }

    /**
     * Destroys all PIN/PUK state. Drives a best-effort EEPROM scrub (an {@code update()} cycle with
     * an all-{@code 0xFF} buffer) through each {@link OwnerPIN} before re-instantiating fresh
     * instances, since the JC spec offers no {@code clearKey()}-equivalent on {@link OwnerPIN}.
     */
    public void wipe() {
        JCSystem.beginTransaction();
        wipeInTx();
        JCSystem.commitTransaction();
    }

    /**
     * Transaction-less wipe variant. Caller MUST hold a {@link JCSystem#beginTransaction()} block;
     * used by {@link MeowlApplet#wipe()} to bundle the PIN/PUK invalidation with the PKI, master-
     * seed and lifecycle wipes into one atomic reset-to-factory commit.
     */
    public void wipeInTx() {
        // Two-layer wipe: an EEPROM-cell scrub via OwnerPIN.update() with a garbage buffer,
        // then a fresh OwnerPIN re-instantiation as the JC-level invalidation. Failures during
        // the scrub MUST propagate so the enclosing JC transaction rolls back — silently
        // swallowing would leave the caller believing reset-to-factory committed while the
        // EEPROM cells still held the previous PIN/PUK hashes.
        Util.arrayFillNonAtomic(scrub, (short) 0, Constants.Pin.PUK_MAX_LEN, (byte) 0xFF);
        pin.update(scrub, (short) 0, Constants.Pin.MAX_LEN);
        puk.update(scrub, (short) 0, Constants.Pin.PUK_MAX_LEN);
        // Rebuild fresh OwnerPIN instances; JC spec offers no clearKey-equivalent.
        this.pin = new OwnerPIN(Constants.Pin.RETRY_LIMIT, Constants.Pin.MAX_LEN);
        this.puk = new OwnerPIN(Constants.Pin.PUK_RETRY_LIMIT, Constants.Pin.PUK_MAX_LEN);
        this.provisioned[0] = 0;
    }

    /** Returns the current PIN try counter; useful for inclusion in {@code GET_INFO}. */
    public byte pinTriesRemaining() {
        return isProvisioned() ? pin.getTriesRemaining() : Constants.Pin.RETRY_LIMIT;
    }

    /** Returns the current PUK try counter. */
    public byte pukTriesRemaining() {
        return isProvisioned() ? puk.getTriesRemaining() : Constants.Pin.PUK_RETRY_LIMIT;
    }

    private void verifyPukInternal(byte[] buf, short offset, short length) {
        byte triesRemaining = puk.getTriesRemaining();
        if (triesRemaining == 0) {
            ISOException.throwIt(Constants.Sw.AUTH_BLOCKED);
        }
        if (length < Constants.Pin.PUK_MIN_LEN || length > Constants.Pin.PUK_MAX_LEN) {
            ISOException.throwIt(Constants.Sw.WRONG_LENGTH);
        }
        if (!puk.check(buf, offset, (byte) length)) {
            byte remaining = puk.getTriesRemaining();
            if (remaining == 0) {
                ISOException.throwIt(Constants.Sw.AUTH_BLOCKED);
            }
            ISOException.throwIt((short) (Constants.Sw.PIN_RETRIES_BASE | (remaining & 0x0F)));
        }
    }

    private static void requirePinPolicy(short length) {
        if (length < Constants.Pin.MIN_LEN || length > Constants.Pin.MAX_LEN) {
            ISOException.throwIt(Constants.Sw.WRONG_LENGTH);
        }
    }

    private static void requirePukPolicy(short length) {
        if (length < Constants.Pin.PUK_MIN_LEN || length > Constants.Pin.PUK_MAX_LEN) {
            ISOException.throwIt(Constants.Sw.WRONG_LENGTH);
        }
    }

    private void requireProvisioned() {
        if (!isProvisioned()) {
            ISOException.throwIt(Constants.Sw.CONDITIONS_NOT_SATISFIED);
        }
    }
}
