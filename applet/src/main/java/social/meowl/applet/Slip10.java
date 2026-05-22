/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * SLIP-10 Ed25519 hierarchical deterministic key derivation.
 *
 * <p>Per <a href="https://github.com/satoshilabs/slips/blob/master/slip-0010.md">SLIP-10</a>,
 * Ed25519 supports only <strong>hardened</strong> derivation:
 *
 * <pre>
 *   I = HMAC-SHA-512(c_par, 0x00 ‖ k_par ‖ ser32(i))
 *   k_i = I[0..32]
 *   c_i = I[32..64]
 *   No mod-n reduction; no public-key arithmetic.
 * </pre>
 *
 * <p>If the caller passes a non-hardened index (top bit clear) the handler raises {@link
 * Constants#SW_CONDITIONS_NOT_SATISFIED}; this is the safe interpretation of the spec's
 * "non-hardened derivation is not defined" rule. Earlier revisions returned {@code
 * SW_INCORRECT_P1P2} but ISO 7816-4 reserves the {@code 6A86} class for malformed APDU headers, not
 * for inner-data policy violations — see audit F-14.
 *
 * <p>Two derivation entry points sit on top of the shared SLIP-10 walk:
 *
 * <ul>
 *   <li>{@link #deriveChainCode} returns just the leaf chain code, suitable for hosts that only
 *       need to prepare the next derivation level on their own.
 *   <li>{@link #deriveLeafKey} returns the leaf 32-byte private key (the RFC 8032 secret-key seed
 *       for the leaf node), used by {@code SIGN_ED25519} and by the Ed25519 branch of {@code
 *       EXPORT_XPUB} for on-card public-key derivation.
 * </ul>
 */
public final class Slip10 {

    /** Hardened-bit mask of the top byte of a 32-bit big-endian index. */
    private static final byte HARDENED_MASK = (byte) 0x80;

    /** Constant prefix byte {@code 0x00} in the SLIP-10 HMAC data. */
    private static final byte[] ZERO_BYTE = {(byte) 0x00};

    /**
     * Length in bytes of the SLIP-10 leaf private key (≡ the RFC 8032 secret-key seed length).
     * Pinned here so the byte literals in {@link #deriveLeafKey}, {@link #walkPath} and {@link
     * #ckdPriv} all reference the same authoritative constant.
     */
    public static final short SECRET_KEY_LEN = (short) 32;

    private static final short HASH_LEN = (short) 64;

    private final MasterSeed masterSeed;
    private final HmacSha hmac;

    /** {@code k_cur(32) || c_cur(32) || I(64)} scratch. */
    private final byte[] state;

    private static final short STATE_K_OFF = (short) 0;
    private static final short STATE_C_OFF = (short) 32;
    private static final short STATE_I_OFF = (short) 64;
    private static final short STATE_LEN = (short) 128;

    /**
     * @param sharedHmac512 same shared HMAC-SHA-512 engine used by {@link MasterSeed} and {@link
     *     Bip32}. APDU handling is single-threaded so sharing one engine across the three consumers
     *     cuts the worst-case transient RAM cost on cards (e.g. J3R180) that route every HMAC
     *     through the {@link HmacSha} software fallback.
     */
    public Slip10(MasterSeed masterSeed, HmacSha sharedHmac512) {
        this.masterSeed = masterSeed;
        this.hmac = sharedHmac512;
        this.state = JCSystem.makeTransientByteArray(STATE_LEN, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Derives the SLIP-10 Ed25519 chain code at the given hardened-only path and writes it into
     * {@code outBuf} at {@code outOff}. Returns the number of bytes written (always 32).
     */
    public short deriveChainCode(
            byte[] pathBuf, short pathOff, short depth, byte[] outBuf, short outOff) {
        walkPath(pathBuf, pathOff, depth);
        Util.arrayCopyNonAtomic(state, STATE_C_OFF, outBuf, outOff, Constants.CHAIN_CODE_LEN);
        wipeWalkState();
        return Constants.CHAIN_CODE_LEN;
    }

    /**
     * Derives the SLIP-10 Ed25519 leaf 32-byte private key at the given hardened-only path and
     * writes it into {@code outBuf} at {@code outOff}. Returns the number of bytes written (always
     * 32). The chain code at the leaf node is overwritten by the wipe in {@link #wipeWalkState}
     * after the copy and is therefore unavailable to the caller via this entry point — invoke
     * {@link #deriveChainCode} on the same path if both halves are needed.
     */
    public short deriveLeafKey(
            byte[] pathBuf, short pathOff, short depth, byte[] outBuf, short outOff) {
        walkPath(pathBuf, pathOff, depth);
        Util.arrayCopyNonAtomic(state, STATE_K_OFF, outBuf, outOff, SECRET_KEY_LEN);
        wipeWalkState();
        return SECRET_KEY_LEN;
    }

    private void walkPath(byte[] pathBuf, short pathOff, short depth) {
        if (depth < 0 || depth > Constants.HD_MAX_DEPTH) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        // Seed the working scalar+chain code from the master in one shot. STATE_K_OFF and
        // STATE_C_OFF are contiguous (0, 32) so the 64-byte pull-based copy lands the
        // k_master(32) || c_master(32) layout directly into state[0..64] (audit F-29).
        masterSeed.copySlip10MasterTo(state, STATE_K_OFF);
        for (short level = 0; level < depth; level++) {
            short idxOff = (short) (pathOff + level * Bip32.INDEX_LEN);
            if ((pathBuf[idxOff] & HARDENED_MASK) == 0) {
                // SLIP-10 Ed25519 forbids non-hardened derivation. Reject with
                // SW_CONDITIONS_NOT_SATISFIED — ISO 7816-4 6A86 is reserved for malformed APDU
                // headers, but the offending bit lives inside the data field, so 6985 is the
                // semantically correct status word (audit F-14).
                ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
            }
            ckdPriv(pathBuf, idxOff);
        }
    }

    private void wipeWalkState() {
        Util.arrayFillNonAtomic(state, STATE_K_OFF, SECRET_KEY_LEN, (byte) 0);
        Util.arrayFillNonAtomic(state, STATE_C_OFF, Constants.CHAIN_CODE_LEN, (byte) 0);
        Util.arrayFillNonAtomic(state, STATE_I_OFF, HASH_LEN, (byte) 0);
    }

    private void ckdPriv(byte[] pathBuf, short idxOff) {
        hmac.init(state, STATE_C_OFF, Constants.CHAIN_CODE_LEN);
        hmac.update(ZERO_BYTE, (short) 0, (short) 1);
        hmac.update(state, STATE_K_OFF, SECRET_KEY_LEN);
        hmac.doFinal(pathBuf, idxOff, Bip32.INDEX_LEN, state, STATE_I_OFF);

        Util.arrayCopyNonAtomic(state, STATE_I_OFF, state, STATE_K_OFF, SECRET_KEY_LEN);
        Util.arrayCopyNonAtomic(
                state,
                (short) (STATE_I_OFF + SECRET_KEY_LEN),
                state,
                STATE_C_OFF,
                Constants.CHAIN_CODE_LEN);
    }
}
