/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.HMACKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

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
 * Constants#SW_INCORRECT_P1P2}; this is the safe interpretation of the spec's "non-hardened
 * derivation is not defined" rule.
 *
 * <p>Phase 4 exports the chain code only; the public-key computation requires Ed25519 scalar
 * multiplication which is implemented alongside Ed25519 signing in Phase 5. Callers requesting an
 * Ed25519 pubkey will receive {@link Constants#SW_INS_NOT_SUPPORTED} from {@link
 * MeowlApplet#handleExportXpub}, not a partial response.
 */
public final class Slip10 {

    /** Hardened-bit mask of the top byte of a 32-bit big-endian index. */
    private static final byte HARDENED_MASK = (byte) 0x80;

    /** Constant prefix byte {@code 0x00} in the SLIP-10 HMAC data. */
    private static final byte[] ZERO_BYTE = {(byte) 0x00};

    private static final short HASH_LEN = (short) 64;

    private final MasterSeed masterSeed;
    private final Signature hmac;
    private final HMACKey chainKey;

    /** {@code k_cur(32) || c_cur(32) || I(64)} scratch. */
    private final byte[] state;

    private static final short STATE_K_OFF = (short) 0;
    private static final short STATE_C_OFF = (short) 32;
    private static final short STATE_I_OFF = (short) 64;
    private static final short STATE_LEN = (short) 128;

    public Slip10(MasterSeed masterSeed) {
        this.masterSeed = masterSeed;
        try {
            this.hmac = Signature.getInstance(Signature.ALG_HMAC_SHA_512, false);
            this.chainKey =
                    (HMACKey)
                            KeyBuilder.buildKey(
                                    KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT,
                                    (short) (HASH_LEN * 8),
                                    false);
        } catch (Exception e) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
            throw new RuntimeException(); // unreachable
        }
        this.state = JCSystem.makeTransientByteArray(STATE_LEN, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Derives the SLIP-10 Ed25519 chain code at the given hardened-only path and writes it into
     * {@code outBuf} at {@code outOff}. Returns the number of bytes written (always 32).
     */
    public short deriveChainCode(
            byte[] pathBuf, short pathOff, short depth, byte[] outBuf, short outOff) {
        if (depth < 0 || depth > Constants.HD_MAX_DEPTH) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        // Seed from master.
        byte[] master = masterSeed.slip10Master();
        Util.arrayCopyNonAtomic(master, (short) 0, state, STATE_K_OFF, (short) 32);
        Util.arrayCopyNonAtomic(master, (short) 32, state, STATE_C_OFF, Constants.CHAIN_CODE_LEN);

        for (short level = 0; level < depth; level++) {
            short idxOff = (short) (pathOff + level * Bip32.INDEX_LEN);
            if ((pathBuf[idxOff] & HARDENED_MASK) == 0) {
                ISOException.throwIt(Constants.SW_INCORRECT_P1P2);
            }
            ckdPriv(pathBuf, idxOff);
        }

        Util.arrayCopyNonAtomic(state, STATE_C_OFF, outBuf, outOff, Constants.CHAIN_CODE_LEN);
        Util.arrayFillNonAtomic(state, STATE_K_OFF, (short) 32, (byte) 0);
        Util.arrayFillNonAtomic(state, STATE_I_OFF, HASH_LEN, (byte) 0);
        return Constants.CHAIN_CODE_LEN;
    }

    private void ckdPriv(byte[] pathBuf, short idxOff) {
        chainKey.setKey(state, STATE_C_OFF, Constants.CHAIN_CODE_LEN);
        hmac.init(chainKey, Signature.MODE_SIGN);
        hmac.update(ZERO_BYTE, (short) 0, (short) 1);
        hmac.update(state, STATE_K_OFF, (short) 32);
        hmac.sign(pathBuf, idxOff, Bip32.INDEX_LEN, state, STATE_I_OFF);

        Util.arrayCopyNonAtomic(state, STATE_I_OFF, state, STATE_K_OFF, (short) 32);
        Util.arrayCopyNonAtomic(
                state, (short) (STATE_I_OFF + 32), state, STATE_C_OFF, Constants.CHAIN_CODE_LEN);
    }
}
