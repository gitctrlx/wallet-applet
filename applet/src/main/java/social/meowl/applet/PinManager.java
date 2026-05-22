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
 * <p>The card holds exactly one user PIN and one unblock PUK, each backed by {@link OwnerPIN} which
 * provides JC-native bounded retry counters and built-in storage protection.
 *
 * <p>API guidelines:
 *
 * <ul>
 *   <li>{@link #setupInTx(byte[], short, short, byte[], short, short)} is invoked exactly once
 *       during the SETUP APDU; subsequent invocations on a non-{@code UNINITIALIZED} instance fail.
 *       The name carries the {@code InTx} suffix because the caller is required to open a {@link
 *       JCSystem#beginTransaction()} block around it; see the method-level javadoc for the
 *       rationale.
 *   <li>{@link #verifyPin(byte[], short, short)} returns the post-attempt try counter via the
 *       status word — success raises {@code 9000}, failure raises {@code 0x63Cn} per ISO 7816-4
 *       (with the 4-bit retry count in the low nibble). A length-policy violation returns {@link
 *       Constants#SW_WRONG_LENGTH} and does <em>not</em> consume a retry; it is a protocol error on
 *       the host side, not a guess.
 *   <li>{@link #changePin(byte[], short, short, byte[], short, short)} requires the caller to first
 *       {@code verifyPin} successfully; we additionally verify the old PIN inside the call to avoid
 *       relying on a stale validated flag in case of concurrent commands.
 *   <li>{@link #unblockPin(byte[], short, short, byte[], short, short)} consumes a PUK attempt even
 *       on PIN-policy failure of the new PIN.
 * </ul>
 *
 * <p>Length validation: every entry point validates against {@link Constants#PIN_MIN_LEN}, {@link
 * Constants#PIN_MAX_LEN}, {@link Constants#PUK_MIN_LEN} and {@link Constants#PUK_MAX_LEN}
 * <em>before</em> handing the buffer to {@link OwnerPIN#check}, because {@code check} would raise
 * {@link ArrayIndexOutOfBoundsException} on an over-long input.
 *
 * <p>Wipe semantics: {@link #wipe()} re-installs both {@link OwnerPIN} instances with their default
 * try limits and an arbitrary single-zero PIN as a transient placeholder. After a wipe the manager
 * reports {@link #isProvisioned()} = {@code false} and a subsequent {@code setupInTx} is required
 * before any verification will succeed.
 */
public final class PinManager {

    private OwnerPIN pin;
    private OwnerPIN puk;
    private final byte[] provisioned; // [0] != 0 → setup() has been called

    /**
     * Pre-allocated scratch used by {@link #wipe()} to drive a known-pattern write through both
     * {@link OwnerPIN} cells before discarding their references (audit H-1.16). Sized at {@link
     * Constants#PUK_MAX_LEN} so the same buffer covers both PIN and PUK updates without an
     * out-of-bounds read on the PUK call. Lives in {@link JCSystem#CLEAR_ON_DESELECT} memory
     * because its lifetime is bounded by a single APDU.
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
        // OwnerPIN.reset() only clears the flag when previously validated, which is exactly what
        // we want — calling it on a non-validated PIN is a no-op.
        pin.reset();
    }

    /**
     * Initial provisioning: installs the user PIN and the unblock PUK.
     *
     * <p>Must be invoked inside a {@link JCSystem#beginTransaction()} / {@code commitTransaction()}
     * block opened by the caller so that the pin install, the puk install and any companion
     * mutation (e.g. lifecycle transition) commit atomically. {@link OwnerPIN#update} is
     * transaction-aware per the JC spec and will join the open transaction.
     *
     * <p>May only be called when {@link #isProvisioned()} is {@code false}; the calling handler has
     * already enforced the {@code PERSONALIZED} lifecycle gate.
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
        requirePinPolicy(pinLen);
        requirePukPolicy(pukLen);
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
        // Probe getTriesRemaining first so a blocked PIN reports as blocked regardless of the
        // candidate length.
        byte triesRemaining = pin.getTriesRemaining();
        if (triesRemaining == 0) {
            ISOException.throwIt(Constants.SW_AUTH_BLOCKED);
        }
        // OwnerPIN.check raises ArrayIndexOutOfBoundsException if length > maxPINSize; guard the
        // policy bounds before invoking it. A length-policy violation is reported as
        // SW_WRONG_LENGTH and does NOT consume a retry: it is a client-side protocol mistake,
        // not a guess at the secret. An attacker cannot use this path to brute-force the PIN
        // because every length-policy violation returns the same status word regardless of the
        // candidate bytes.
        if (length < Constants.PIN_MIN_LEN || length > Constants.PIN_MAX_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        if (!pin.check(buf, offset, (byte) length)) {
            byte remaining = pin.getTriesRemaining();
            if (remaining == 0) {
                ISOException.throwIt(Constants.SW_AUTH_BLOCKED);
            }
            ISOException.throwIt((short) (Constants.SW_PIN_RETRIES_BASE | (remaining & 0x0F)));
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
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        verifyPukInternal(pukBuf, pukOffset, pukLen);
        requirePinPolicy(newPinLen);
        JCSystem.beginTransaction();
        pin.update(newPinBuf, newPinOffset, (byte) newPinLen);
        pin.resetAndUnblock();
        JCSystem.commitTransaction();
    }

    /**
     * Destroys all PIN/PUK state. Called by the reset-to-factory flow.
     *
     * <p>The JC platform exposes no {@code clearKey()}-equivalent on {@link OwnerPIN}, so the
     * EEPROM cells that held the previous PIN/PUK might retain recoverable signal until they are
     * written over by a future {@code update()} call. Audit H-1.16 asks for a best-effort
     * overwrite: before discarding the references, we drive one {@code update()} cycle through each
     * {@code OwnerPIN} with a 16-byte all-{@code 0xFF} buffer. This forces a write through whatever
     * internal storage the JC implementation uses, defeating the simplest residue-recovery attacks
     * against a clear EEPROM cell. We then re-instantiate fresh {@code OwnerPIN} objects so the
     * provisioned flag flips back to "fresh card" semantics.
     *
     * <p>The overwrite-buffer length matches the max PIN/PUK size declared at construction ({@code
     * PIN_MAX_LEN} / {@code PUK_MAX_LEN}); writing under the platform's per-PIN length bound is
     * exactly what {@code OwnerPIN.update()} accepts.
     */
    public void wipe() {
        JCSystem.beginTransaction();
        wipeInTx();
        JCSystem.commitTransaction();
    }

    /**
     * Transaction-less wipe variant. Caller MUST hold a {@link JCSystem#beginTransaction()} block
     * around this call; used by {@link MeowlApplet#wipe()} to bundle the PIN/PUK invalidation with
     * the PKI, master-seed and lifecycle wipes into one atomic commit so a torn power-off during
     * the reset-to-factory flow cannot leave the card in a partially-wiped state (audit F-15).
     */
    public void wipeInTx() {
        // Best-effort EEPROM scrub: overwrite the existing PIN/PUK with a known-garbage value
        // before discarding the OwnerPIN references. The new bytes are not a credential the user
        // can verify against (we set provisioned[0] = 0 below, so any verify call short-circuits
        // out before reaching the PIN material), but they do drive at least one write through
        // whatever internal cells the JC implementation uses. Audit H-1.16.
        Util.arrayFillNonAtomic(scrub, (short) 0, Constants.PUK_MAX_LEN, (byte) 0xFF);
        try {
            pin.update(scrub, (short) 0, Constants.PIN_MAX_LEN);
        } catch (Exception ignored) {
            // If the platform rejects the scrub update for any reason, proceed with the
            // re-instantiation below — that still provides the JC-level invalidation.
        }
        try {
            puk.update(scrub, (short) 0, Constants.PUK_MAX_LEN);
        } catch (Exception ignored) {
            // Same fallback rationale as the PIN scrub.
        }
        // Rebuild fresh OwnerPIN instances rather than try to scrub the old ones in-place; the
        // JC spec does not document a clearKey-style method for OwnerPIN.
        this.pin = new OwnerPIN(Constants.PIN_RETRY_LIMIT, Constants.PIN_MAX_LEN);
        this.puk = new OwnerPIN(Constants.PUK_RETRY_LIMIT, Constants.PUK_MAX_LEN);
        this.provisioned[0] = 0;
    }

    /** Returns the current PIN try counter; useful for inclusion in {@code GET_INFO}. */
    public byte pinTriesRemaining() {
        return isProvisioned() ? pin.getTriesRemaining() : Constants.PIN_RETRY_LIMIT;
    }

    /** Returns the current PUK try counter. */
    public byte pukTriesRemaining() {
        return isProvisioned() ? puk.getTriesRemaining() : Constants.PUK_RETRY_LIMIT;
    }

    private void verifyPukInternal(byte[] buf, short offset, short length) {
        byte triesRemaining = puk.getTriesRemaining();
        if (triesRemaining == 0) {
            ISOException.throwIt(Constants.SW_AUTH_BLOCKED);
        }
        if (length < Constants.PUK_MIN_LEN || length > Constants.PUK_MAX_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        if (!puk.check(buf, offset, (byte) length)) {
            byte remaining = puk.getTriesRemaining();
            if (remaining == 0) {
                ISOException.throwIt(Constants.SW_AUTH_BLOCKED);
            }
            ISOException.throwIt((short) (Constants.SW_PIN_RETRIES_BASE | (remaining & 0x0F)));
        }
    }

    private static void requirePinPolicy(short length) {
        if (length < Constants.PIN_MIN_LEN || length > Constants.PIN_MAX_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
    }

    private static void requirePukPolicy(short length) {
        if (length < Constants.PUK_MIN_LEN || length > Constants.PUK_MAX_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
    }

    private void requireProvisioned() {
        if (!isProvisioned()) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
}
