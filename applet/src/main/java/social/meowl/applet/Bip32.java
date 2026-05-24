/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

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
 * <p>The non-hardened branch and the public-key export path both rely on a shared {@link EcPoint}
 * engine bound to secp256k1; the same engine is reused by {@link Schnorr}, so a single scalar-mult
 * fixture lives at applet-install time. Intermediate state lives in a {@code CLEAR_ON_DESELECT}
 * scratch so secrets vanish on deselect even if a caller forgets to wipe.
 */
public final class Bip32 {

    /** Length of one derivation index in the wire format (32-bit big-endian). */
    public static final short INDEX_LEN = (short) 4;

    /** Hardened-bit mask of the top byte of an index. */
    private static final byte HARDENED_MASK = (byte) 0x80;

    /** HMAC-SHA-512 output length. */
    private static final short HASH_LEN = (short) 64;

    /** Hardened derivation prefix byte ({@code 0x00}); static so HMAC does not re-allocate. */
    private static final byte[] HARDENED_PREFIX = {(byte) 0x00};

    private final MasterSeed masterSeed;
    private final HmacSha hmac;
    private final EcPoint secp256k1Ec;

    /** Walking buffer: {@code k_cur(32) ‖ c_cur(32) ‖ I(64) ‖ pub_scratch(65)}, total 193 bytes. */
    private final byte[] state;

    private static final short STATE_K_OFF = (short) 0;
    private static final short STATE_C_OFF = (short) 32;
    private static final short STATE_I_OFF = (short) 64;
    private static final short STATE_PUB_OFF = (short) 128;
    private static final short STATE_LEN =
            (short) (STATE_PUB_OFF + Constants.Ec.POINT_UNCOMPRESSED_LEN);

    /**
     * @param sharedHmac512 same engine handed to {@link MasterSeed} and {@link Slip10}; safe to
     *     share because APDU dispatch is single-threaded.
     */
    public Bip32(MasterSeed masterSeed, HmacSha sharedHmac512) {
        this.masterSeed = masterSeed;
        this.hmac = sharedHmac512;
        this.secp256k1Ec =
                new EcPoint(
                        new EcPoint.CurveSetup() {
                            @Override
                            public void apply(javacard.security.ECPrivateKey key) {
                                Secp256k1Curve.setCurveParameters(key);
                            }
                        },
                        Secp256k1Curve.PARAMS,
                        Secp256k1Curve.OFFSET_G,
                        Constants.Ec.POINT_UNCOMPRESSED_LEN,
                        (short) 256);
        this.state = JCSystem.makeTransientByteArray(STATE_LEN, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Exposes the shared secp256k1 scalar-mult engine. {@link Schnorr} reuses this so the applet
     * keeps a single {@link javacard.security.ECPrivateKey} slot for every secp256k1 scalar
     * operation.
     */
    public EcPoint secp256k1() {
        return secp256k1Ec;
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

        short pubLen = computePubkey(state, STATE_K_OFF, state, STATE_PUB_OFF);
        Util.arrayCopyNonAtomic(state, STATE_PUB_OFF, outBuf, outOff, pubLen);
        Util.arrayCopyNonAtomic(
                state, STATE_C_OFF, outBuf, (short) (outOff + pubLen), Constants.Hd.CHAIN_CODE_LEN);

        wipeTransientSecrets();
        return (short) (pubLen + Constants.Hd.CHAIN_CODE_LEN);
    }

    /**
     * Secret-exposing variant of {@link #derivePath}: writes the 32-byte big-endian leaf scalar to
     * {@code outBuf[outOff..+32]}. Caller MUST wipe the destination as soon as the scalar has been
     * consumed so it does not linger past the signing primitive's own scope.
     *
     * @return {@link Constants.Ec#SCALAR_LEN}
     */
    public short deriveLeafScalar(
            byte[] pathBuf, short pathOff, short depth, byte[] outBuf, short outOff) {
        walkPathToLeaf(pathBuf, pathOff, depth);
        Util.arrayCopyNonAtomic(state, STATE_K_OFF, outBuf, outOff, Constants.Ec.SCALAR_LEN);
        wipeTransientSecrets();
        return Constants.Ec.SCALAR_LEN;
    }

    /**
     * SEC 1 §2.3.3 compressed encoding of {@code scalar · G}.
     *
     * @return {@link Constants.Ec#POINT_COMPRESSED_LEN}
     */
    public short computePubkey(byte[] scalar, short scalarOff, byte[] outBuf, short outOff) {
        return computeCompressedPubkey(scalar, scalarOff, outBuf, outOff);
    }

    /**
     * Uncompressed encoding {@code 0x04 ‖ x ‖ y} of {@code scalar · G}. Exposed for {@link Schnorr}
     * which needs the {@code y}-coordinate parity.
     *
     * @return {@link Constants.Ec#POINT_UNCOMPRESSED_LEN}
     */
    public short scalarMultG(byte[] scalar, short scalarOff, byte[] outBuf, short outOff) {
        return secp256k1Ec.multiplyG(scalar, scalarOff, Constants.Ec.SCALAR_LEN, outBuf, outOff);
    }

    /**
     * Walks the BIP-32 chain from the master to the leaf, leaving the leaf scalar in {@code
     * state[STATE_K_OFF..+32]} and the chain code in {@code state[STATE_C_OFF..+32]}.
     */
    private void walkPathToLeaf(byte[] pathBuf, short pathOff, short depth) {
        if (depth < 0 || depth > Constants.Hd.MAX_DEPTH) {
            ISOException.throwIt(Constants.Sw.WRONG_LENGTH);
        }
        masterSeed.copyBip32MasterTo(state, STATE_K_OFF);

        for (short level = 0; level < depth; level++) {
            short idxOff = (short) (pathOff + level * INDEX_LEN);
            ckdPriv(pathBuf, idxOff);
        }
    }

    /**
     * Wipes every BIP-32 walk-state slot: the leaf scalar, the chain code (defence-in-depth — chain
     * code + parent pubkey derives all siblings), the last HMAC-SHA-512 output, the uncompressed
     * pubkey scratch, and the {@link EcPoint}'s {@code scalarKey} cell.
     */
    private void wipeTransientSecrets() {
        Util.arrayFillNonAtomic(state, (short) 0, STATE_LEN, (byte) 0);
        secp256k1Ec.wipe();
    }

    /**
     * One iteration of {@code CKDpriv}: state.{k,c} → state.{k,c}.
     *
     * <p>BIP-32 §"Specification: Key derivation" states that if {@code parse256(I_L) ≥ n} or {@code
     * k_i == 0}, the resulting key is invalid and the caller should proceed with the next value for
     * {@code i} (probability {@code < 2⁻¹²⁷}, unreachable in practice). We raise {@link
     * Constants.Sw#CONDITIONS_NOT_SATISFIED} rather than auto-retrying so the applet never silently
     * changes the path the host requested — matching the behaviour of Trezor's {@code
     * hdnode_private_ckd} and libsecp256k1's {@code secp256k1_ec_seckey_tweak_add}.
     */
    private void ckdPriv(byte[] pathBuf, short idxOff) {
        boolean hardened = (pathBuf[idxOff] & HARDENED_MASK) != 0;

        hmac.init(state, STATE_C_OFF, Constants.Hd.CHAIN_CODE_LEN);

        if (hardened) {
            hmac.update(HARDENED_PREFIX, (short) 0, (short) 1);
            hmac.update(state, STATE_K_OFF, Constants.Ec.SCALAR_LEN);
        } else {
            computeCompressedPubkey(state, STATE_K_OFF, state, STATE_PUB_OFF);
            hmac.update(state, STATE_PUB_OFF, Constants.Ec.POINT_COMPRESSED_LEN);
        }
        hmac.doFinal(pathBuf, idxOff, INDEX_LEN, state, STATE_I_OFF);

        if (BigNat.ctLessThan(
                        state, STATE_I_OFF, Secp256k1Curve.N, (short) 0, Constants.Ec.SCALAR_LEN)
                == 0) {
            ISOException.throwIt(Constants.Sw.CONDITIONS_NOT_SATISFIED);
        }
        BigNat.modAdd(
                state,
                STATE_I_OFF,
                state,
                STATE_K_OFF,
                Secp256k1Curve.N,
                (short) 0,
                state,
                STATE_K_OFF,
                Constants.Ec.SCALAR_LEN);
        if (BigNat.ctIsZero(state, STATE_K_OFF, Constants.Ec.SCALAR_LEN) != 0) {
            ISOException.throwIt(Constants.Sw.CONDITIONS_NOT_SATISFIED);
        }

        Util.arrayCopyNonAtomic(
                state,
                (short) (STATE_I_OFF + Constants.Ec.SCALAR_LEN),
                state,
                STATE_C_OFF,
                Constants.Hd.CHAIN_CODE_LEN);
    }

    private short computeCompressedPubkey(
            byte[] scalar, short scalarOff, byte[] outBuf, short outOff) {
        scalarMultG(scalar, scalarOff, outBuf, outOff);
        byte yLsb = outBuf[(short) (outOff + Constants.Ec.POINT_UNCOMPRESSED_LEN - 1)];
        outBuf[outOff] = ((yLsb & 0x01) == 0) ? (byte) 0x02 : (byte) 0x03;
        Util.arrayFillNonAtomic(
                outBuf,
                (short) (outOff + Constants.Ec.POINT_COMPRESSED_LEN),
                (short) (Constants.Ec.POINT_UNCOMPRESSED_LEN - Constants.Ec.POINT_COMPRESSED_LEN),
                (byte) 0);
        return Constants.Ec.POINT_COMPRESSED_LEN;
    }
}
