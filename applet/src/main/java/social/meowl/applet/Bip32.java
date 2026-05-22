/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;

/**
 * BIP-32 hierarchical deterministic key derivation for secp256k1 ({@code CKDpriv} per <a
 * href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP-32</a>):
 *
 * <pre>
 *   hardened (i ≥ 2³¹):
 *     I = HMAC-SHA-512(c_par, 0x00 ‖ ser256(k_par) ‖ ser32(i))
 *   non-hardened:
 *     I = HMAC-SHA-512(c_par, serP(point(k_par)) ‖ ser32(i))
 *   I_L = I[0..32], I_R = I[32..64]
 *   k_i = (parse256(I_L) + k_par) mod n
 *   c_i = I_R
 *   require parse256(I_L) < n  AND  k_i != 0
 * </pre>
 *
 * <p>The non-hardened branch reuses {@code KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY} as a generic
 * scalar-multiplication primitive: feed the parent private key plus the base point {@code G},
 * recover the uncompressed parent pubkey and compress to {@code serP} form.
 *
 * <p>Intermediate state lives in a {@code CLEAR_ON_DESELECT} scratch so secrets vanish on deselect
 * even if the caller forgets to wipe.
 */
public final class Bip32 {

    /** Length of one derivation index in the wire format (32-bit BE). */
    public static final short INDEX_LEN = (short) 4;

    /** Hardened-bit mask of the top byte of an index. */
    private static final byte HARDENED_MASK = (byte) 0x80;

    /** HMAC-SHA-512 output length. */
    private static final short HASH_LEN = (short) 64;

    /** Hardened derivation prefix byte ({@code 0x00}); static so HMAC does not re-allocate. */
    private static final byte[] HARDENED_PREFIX = {(byte) 0x00};

    private final MasterSeed masterSeed;
    private final HmacSha hmac;

    /** Working buffer holding {@code k_cur || c_cur || I (64) || scratch_pub(65)}. */
    private final byte[] state;

    /** Curve setup used for non-hardened EC scalar multiplication. */
    private final ECPrivateKey scalarKey;

    private final KeyAgreement scalarMult;

    private static final short STATE_K_OFF = (short) 0; // 32
    private static final short STATE_C_OFF = (short) 32; // 32
    private static final short STATE_I_OFF = (short) 64; // 64 (HMAC output)
    private static final short STATE_PUB_OFF = (short) 128; // 65 (uncompressed point, non-hardened)
    private static final short STATE_LEN =
            (short) (STATE_PUB_OFF + Constants.EC_POINT_UNCOMPRESSED_LEN);

    /**
     * @param sharedHmac512 same engine handed to {@link MasterSeed} and {@link Slip10}; safe to
     *     share because APDU dispatch is single-threaded.
     */
    public Bip32(MasterSeed masterSeed, HmacSha sharedHmac512) {
        this.masterSeed = masterSeed;
        this.hmac = sharedHmac512;
        try {
            this.scalarMult = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
            // Prefer RAM-backed transient so the leaf scalar never lands in EEPROM; clearKey()
            // alone does not necessarily wipe EEPROM cells. Persistent only as a fallback for
            // cards that restrict TRANSIENT_DESELECT to symmetric keys.
            ECPrivateKey scalarKey;
            try {
                scalarKey =
                        (ECPrivateKey)
                                KeyBuilder.buildKey(
                                        KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                                        KeyBuilder.LENGTH_EC_FP_256,
                                        false);
            } catch (javacard.security.CryptoException e) {
                scalarKey =
                        (ECPrivateKey)
                                KeyBuilder.buildKey(
                                        KeyBuilder.TYPE_EC_FP_PRIVATE,
                                        KeyBuilder.LENGTH_EC_FP_256,
                                        false);
            }
            this.scalarKey = scalarKey;
            Secp256k1.setCurveParameters(this.scalarKey);
        } catch (Exception e) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
            throw new RuntimeException(); // unreachable
        }
        this.state = JCSystem.makeTransientByteArray(STATE_LEN, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Derives the BIP-32 child at the given path and writes {@code [compressed_pubkey(33) ‖
     * chain_code(32)]}. {@code depth == 0} returns the master xpub itself.
     *
     * @return {@code 65}
     */
    public short derivePath(
            byte[] pathBuf, short pathOff, short depth, byte[] outBuf, short outOff) {
        walkPathToLeaf(pathBuf, pathOff, depth);

        // Output: compressed pubkey || chain code.
        short pubLen = computePubkey(state, STATE_K_OFF, state, STATE_PUB_OFF);
        Util.arrayCopyNonAtomic(state, STATE_PUB_OFF, outBuf, outOff, pubLen);
        Util.arrayCopyNonAtomic(
                state, STATE_C_OFF, outBuf, (short) (outOff + pubLen), Constants.CHAIN_CODE_LEN);

        wipeTransientSecrets();
        return (short) (pubLen + Constants.CHAIN_CODE_LEN);
    }

    /**
     * Secret-exposing variant of {@link #derivePath}: writes the 32-byte big-endian leaf scalar to
     * {@code outBuf[outOff..+32]}. Caller MUST wipe the destination as soon as the scalar has been
     * consumed so it does not linger past the signing primitive's own scope.
     *
     * @return {@link ModN#LEN}
     */
    public short deriveLeafScalar(
            byte[] pathBuf, short pathOff, short depth, byte[] outBuf, short outOff) {
        walkPathToLeaf(pathBuf, pathOff, depth);
        Util.arrayCopyNonAtomic(state, STATE_K_OFF, outBuf, outOff, ModN.LEN);
        wipeTransientSecrets();
        return ModN.LEN;
    }

    /**
     * Walks the BIP-32 chain from the master to the leaf, leaving the leaf scalar in {@code
     * state[STATE_K_OFF..+32]} and the chain code in {@code state[STATE_C_OFF..+32]}.
     */
    private void walkPathToLeaf(byte[] pathBuf, short pathOff, short depth) {
        if (depth < 0 || depth > Constants.HD_MAX_DEPTH) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        // STATE_K_OFF and STATE_C_OFF are contiguous, so this 64-byte copy lands k(32) || c(32)
        // directly into state[0..64] in one shot.
        masterSeed.copyBip32MasterTo(state, STATE_K_OFF);

        for (short level = 0; level < depth; level++) {
            short idxOff = (short) (pathOff + level * INDEX_LEN);
            ckdPriv(pathBuf, idxOff);
        }
    }

    /**
     * Wipes every BIP-32 walk-state slot: the leaf scalar, the chain code (defence-in-depth — chain
     * code + parent pubkey derives all siblings), the last HMAC-SHA-512 output, the uncompressed
     * pubkey scratch, and the {@link ECPrivateKey} cell.
     */
    private void wipeTransientSecrets() {
        Util.arrayFillNonAtomic(state, (short) 0, STATE_LEN, (byte) 0);
        scalarKey.clearKey();
    }

    /**
     * One iteration of {@code CKDpriv}: state.{k,c} → state.{k,c}.
     *
     * <p>BIP-32 §"Specification: Key derivation" states that if {@code parse256(I_L) ≥ n} or
     * {@code k_i == 0}, the resulting key is invalid and the caller should proceed with the next
     * value for {@code i} (probability {@code < 2⁻¹²⁷}, unreachable in practice). We raise {@link
     * Constants#SW_CONDITIONS_NOT_SATISFIED} rather than auto-retrying so the applet never
     * silently changes the path the host requested — matching the behaviour of Trezor's {@code
     * hdnode_private_ckd} and libsecp256k1's {@code secp256k1_ec_seckey_tweak_add}.
     */
    private void ckdPriv(byte[] pathBuf, short idxOff) {
        boolean hardened = (pathBuf[idxOff] & HARDENED_MASK) != 0;

        // HMAC key = c_par.
        hmac.init(state, STATE_C_OFF, Constants.CHAIN_CODE_LEN);

        if (hardened) {
            // Data = 0x00 || ser256(k_par) || ser32(i)
            hmac.update(HARDENED_PREFIX, (short) 0, (short) 1);
            hmac.update(state, STATE_K_OFF, ModN.LEN);
        } else {
            // Data = serP(point(k_par)) || ser32(i)
            computeCompressedPubkey(state, STATE_K_OFF, state, STATE_PUB_OFF);
            hmac.update(state, STATE_PUB_OFF, Constants.EC_POINT_COMPRESSED_LEN);
        }
        hmac.doFinal(pathBuf, idxOff, INDEX_LEN, state, STATE_I_OFF);

        // Reject I_L >= n (BIP-32 §CKDpriv); host MUST retry with a different index.
        if (!ModN.lessThanN(state, STATE_I_OFF)) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        // k_i = (I_L + k_par) mod n; reject k_i == 0 (BIP-32 §CKDpriv).
        boolean zero = ModN.addMod(state, STATE_I_OFF, state, STATE_K_OFF, state, STATE_K_OFF);
        if (zero) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }

        // c_i = I_R
        Util.arrayCopyNonAtomic(
                state,
                (short) (STATE_I_OFF + ModN.LEN),
                state,
                STATE_C_OFF,
                Constants.CHAIN_CODE_LEN);
    }

    /**
     * SEC 1 §2.3.3 compressed encoding of {@code scalar · G}.
     *
     * @return {@link Constants#EC_POINT_COMPRESSED_LEN}
     */
    public short computePubkey(byte[] scalar, short scalarOff, byte[] outBuf, short outOff) {
        return computeCompressedPubkey(scalar, scalarOff, outBuf, outOff);
    }

    /**
     * Uncompressed encoding {@code 0x04 ‖ x ‖ y} of {@code scalar · G}; exposed for {@link Schnorr}
     * which needs the {@code y}-coordinate parity.
     *
     * @return {@link Constants#EC_POINT_UNCOMPRESSED_LEN}
     */
    public short scalarMultG(byte[] scalar, short scalarOff, byte[] outBuf, short outOff) {
        Secp256k1.setCurveParameters(scalarKey);
        scalarKey.setS(scalar, scalarOff, ModN.LEN);
        scalarMult.init(scalarKey);
        short uLen =
                scalarMult.generateSecret(
                        Secp256k1.PARAMS,
                        Secp256k1.OFFSET_G,
                        Constants.EC_POINT_UNCOMPRESSED_LEN,
                        outBuf,
                        outOff);
        if (uLen != Constants.EC_POINT_UNCOMPRESSED_LEN || outBuf[outOff] != (byte) 0x04) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        return Constants.EC_POINT_UNCOMPRESSED_LEN;
    }

    private short computeCompressedPubkey(
            byte[] scalar, short scalarOff, byte[] outBuf, short outOff) {
        // scalar·G into outBuf, then compress in place per SEC 1 §2.3.3: parity prefix from y_LSB.
        scalarMultG(scalar, scalarOff, outBuf, outOff);
        byte yLsb = outBuf[(short) (outOff + Constants.EC_POINT_UNCOMPRESSED_LEN - 1)];
        outBuf[outOff] = ((yLsb & 0x01) == 0) ? (byte) 0x02 : (byte) 0x03;
        Util.arrayFillNonAtomic(
                outBuf,
                (short) (outOff + Constants.EC_POINT_COMPRESSED_LEN),
                (short) (Constants.EC_POINT_UNCOMPRESSED_LEN - Constants.EC_POINT_COMPRESSED_LEN),
                (byte) 0);
        return Constants.EC_POINT_COMPRESSED_LEN;
    }
}
