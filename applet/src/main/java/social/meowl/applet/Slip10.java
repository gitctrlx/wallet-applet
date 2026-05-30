/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * SLIP-10 Ed25519 hierarchical deterministic key derivation per <a
 * href="https://github.com/satoshilabs/slips/blob/master/slip-0010.md">SLIP-10</a> (hardened only):
 *
 * <pre>
 *   I = HMAC-SHA-512(c_par, 0x00 ‖ k_par ‖ ser32(i))
 *   k_i = I[0..32]
 *   c_i = I[32..64]
 * </pre>
 *
 * <p>A non-hardened index (top bit clear) raises {@link Constants#SW_CONDITIONS_NOT_SATISFIED} —
 * the safe reading of SLIP-10's "non-hardened derivation is not defined". The two derivation entry
 * points sitting on top of the shared walk are {@link #deriveLeafKey} (32-byte secret-key seed,
 * used by {@code SIGN_ED25519}) and {@link #deriveLeafKeyAndChainCode} (leaf key ‖ chain code from
 * a single walk, used by the Ed25519 branch of {@code EXPORT_XPUB}).
 */
public final class Slip10 {

    /** Hardened-bit mask of the top byte of a 32-bit big-endian index. */
    private static final byte HARDENED_MASK = (byte) 0x80;

    /** Constant prefix byte {@code 0x00} in the SLIP-10 HMAC data. */
    private static final byte[] ZERO_BYTE = {(byte) 0x00};

    private static final short STATE_K_OFF = (short) 0;
    private static final short STATE_C_OFF = (short) 32;
    private static final short STATE_I_OFF = (short) 64;
    private static final short STATE_LEN = (short) 128;

    private final MasterSeed masterSeed;
    private final HmacSha512 hmac;

    /** {@code k_cur(32) ‖ c_cur(32) ‖ I(64)} scratch. */
    private final byte[] state;

    /**
     * @param sharedHmac512 same engine used by {@link MasterSeed} and {@link Bip32}; safe to share
     *     because APDU dispatch is single-threaded.
     */
    public Slip10(MasterSeed masterSeed, HmacSha512 sharedHmac512) {
        this.masterSeed = masterSeed;
        this.hmac = sharedHmac512;
        this.state = JCSystem.makeTransientByteArray(STATE_LEN, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Derives the SLIP-10 Ed25519 leaf private key at the given hardened-only path. The chain code
     * is wiped along with the rest of the walk state; use {@link #deriveLeafKeyAndChainCode} when
     * both halves are needed.
     *
     * <p>The {@code try/finally} guarantees {@link #wipeWalkState()} runs even when {@link
     * #walkPath} throws on a non-hardened index, so a partial walk cannot leave the SLIP-10 master
     * (the entire Ed25519 wallet root) or an ancestor private key resident in {@link #state}
     * (NEWAUDIT-002, mirroring {@link Bip32#deriveLeafScalar}).
     *
     * @return 32
     */
    public short deriveLeafKey(
            byte[] pathBuf, short pathOff, short depth, byte[] outBuf, short outOff) {
        try {
            walkPath(pathBuf, pathOff, depth);
            Util.arrayCopyNonAtomic(state, STATE_K_OFF, outBuf, outOff, Constants.EC_SCALAR_LEN);
            return Constants.EC_SCALAR_LEN;
        } finally {
            wipeWalkState();
        }
    }

    /**
     * Derives the SLIP-10 Ed25519 leaf key and chain code in a single walk, writing {@code
     * [leaf_key(32) ‖ chain_code(32)]} to {@code outBuf}. The Ed25519 branch of {@code EXPORT_XPUB}
     * needs both halves; one walk instead of two halves the HMAC-SHA-512 chain cost (mirroring
     * {@link Bip32#derivePath}). Same wipe-on-throw contract as {@link #deriveLeafKey}.
     *
     * @return 64
     */
    public short deriveLeafKeyAndChainCode(
            byte[] pathBuf, short pathOff, short depth, byte[] outBuf, short outOff) {
        try {
            walkPath(pathBuf, pathOff, depth);
            Util.arrayCopyNonAtomic(state, STATE_K_OFF, outBuf, outOff, Constants.EC_SCALAR_LEN);
            Util.arrayCopyNonAtomic(
                    state,
                    STATE_C_OFF,
                    outBuf,
                    (short) (outOff + Constants.EC_SCALAR_LEN),
                    Constants.CHAIN_CODE_LEN);
            return (short) (Constants.EC_SCALAR_LEN + Constants.CHAIN_CODE_LEN);
        } finally {
            wipeWalkState();
        }
    }

    private void walkPath(byte[] pathBuf, short pathOff, short depth) {
        if (depth < 0 || depth > Constants.HD_MAX_DEPTH) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        // STATE_K_OFF and STATE_C_OFF are contiguous, so this 64-byte copy lands k(32) || c(32)
        // directly into state[0..64] in one shot.
        masterSeed.copySlip10MasterTo(state, STATE_K_OFF);
        for (short level = 0; level < depth; level++) {
            short idxOff = (short) (pathOff + level * Bip32.INDEX_LEN);
            if ((pathBuf[idxOff] & HARDENED_MASK) == 0) {
                // SLIP-10 Ed25519 forbids non-hardened derivation. 6985 (CONDITIONS_NOT_SATISFIED)
                // is the semantically correct SW since the offending bit lives in the data field,
                // not the APDU header (which would otherwise warrant 6A86).
                ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
            }
            ckdPriv(pathBuf, idxOff);
        }
    }

    /**
     * Wipes the entire walk-state scratch plus the shared HMAC engine's key slot. {@link #ckdPriv}
     * keys the HMAC on the running chain code, so without the {@link HmacSha512#reset()} the last
     * level's chain code would linger in the engine's {@code padded} buffer past the walk
     * (NEWAUDIT-008).
     */
    private void wipeWalkState() {
        Util.arrayFillNonAtomic(state, (short) 0, STATE_LEN, (byte) 0);
        hmac.reset();
    }

    private void ckdPriv(byte[] pathBuf, short idxOff) {
        hmac.init(state, STATE_C_OFF, Constants.CHAIN_CODE_LEN);
        hmac.update(ZERO_BYTE, (short) 0, (short) 1);
        hmac.update(state, STATE_K_OFF, Constants.EC_SCALAR_LEN);
        hmac.doFinal(pathBuf, idxOff, Bip32.INDEX_LEN, state, STATE_I_OFF);

        Util.arrayCopyNonAtomic(state, STATE_I_OFF, state, STATE_K_OFF, Constants.EC_SCALAR_LEN);
        Util.arrayCopyNonAtomic(
                state,
                (short) (STATE_I_OFF + Constants.EC_SCALAR_LEN),
                state,
                STATE_C_OFF,
                Constants.CHAIN_CODE_LEN);
    }
}
