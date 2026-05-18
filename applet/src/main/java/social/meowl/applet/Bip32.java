/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.HMACKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

/**
 * BIP-32 hierarchical deterministic key derivation for secp256k1.
 *
 * <p>Implements {@code CKDpriv((k_par, c_par), i)} per <a
 * href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP-32</a>:
 *
 * <pre>
 *   hardened (i ≥ 2³¹):
 *     I = HMAC-SHA-512(c_par, 0x00 ‖ ser256(k_par) ‖ ser32(i))
 *   non-hardened:
 *     I = HMAC-SHA-512(c_par, serP(point(k_par)) ‖ ser32(i))
 *   I_L = I[0..32], I_R = I[32..64]
 *   k_i = (parse256(I_L) + k_par) mod n
 *   c_i = I_R
 *   require parse256(I_L) < n  AND  k_i != 0   (else: fail)
 * </pre>
 *
 * <p>The non-hardened branch computes {@code serP(point(k_par))} by running an EC scalar
 * multiplication {@code k_par * G} via {@code KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY}: the parent
 * private key is set as the agreement private, the base point {@code G} is fed as the "other-party
 * public key", and the resulting uncompressed point is the parent public key, which we compress to
 * {@code serP} form.
 *
 * <p>{@link #derivePath} walks an arbitrary-depth path. Intermediate scalars live in a {@code
 * CLEAR_ON_DESELECT} scratch so they vanish on deselect even if the caller forgets to wipe; the
 * public output is written into the caller-supplied buffer.
 */
public final class Bip32 {

    /** Length of one derivation index in the wire format (32-bit BE). */
    public static final short INDEX_LEN = (short) 4;

    /** Hardened-bit mask of the top byte of an index. */
    private static final byte HARDENED_MASK = (byte) 0x80;

    /** HMAC-SHA-512 output length. */
    private static final short HASH_LEN = (short) 64;

    /**
     * BIP-32 hardened derivation prefix byte ({@code 0x00}). Held as a static one-byte array so the
     * per-iteration HMAC does not allocate a fresh array on the JC heap each time.
     */
    private static final byte[] HARDENED_PREFIX = {(byte) 0x00};

    private final MasterSeed masterSeed;
    private final Signature hmac;
    private final HMACKey chainKey;

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

    public Bip32(MasterSeed masterSeed) {
        this.masterSeed = masterSeed;
        try {
            this.hmac = Signature.getInstance(Signature.ALG_HMAC_SHA_512, false);
            this.chainKey =
                    (HMACKey)
                            KeyBuilder.buildKey(
                                    KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT,
                                    (short) (HASH_LEN * 8),
                                    false);
            this.scalarMult = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
            // EEPROM-backed scalar key — TRANSIENT_DESELECT variants of EC private keys are
            // not universally supported (e.g. older JCardSim builds), so we use the persistent
            // form. The key value is rewritten on every derivation and is cleared by the
            // wipe path; no long-lived secret is ever stored here.
            this.scalarKey =
                    (ECPrivateKey)
                            KeyBuilder.buildKey(
                                    KeyBuilder.TYPE_EC_FP_PRIVATE,
                                    KeyBuilder.LENGTH_EC_FP_256,
                                    false);
            Secp256k1.setCurveParameters(this.scalarKey);
        } catch (Exception e) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
            throw new RuntimeException(); // unreachable
        }
        this.state = JCSystem.makeTransientByteArray(STATE_LEN, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Derives the BIP-32 child at the given path and writes {@code [compressed_pubkey(33) ‖
     * chain_code(32)]} into {@code outBuf} at {@code outOff}.
     *
     * <p>If {@code depth == 0} the master xpub itself is returned.
     *
     * @return the number of bytes written, i.e. {@code 65}
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
     * Derives the BIP-32 child private scalar at the given path and writes the 32-byte big-endian
     * scalar to {@code outBuf} at {@code outOff}.
     *
     * <p>This is the secret-exposing variant of {@link #derivePath}; it exists so that {@link
     * EcdsaK1} (and the upcoming Schnorr / pubkey-recovery callers) can pull the leaf scalar into
     * their own transient buffer just long enough to load it into an {@link ECPrivateKey} or to
     * feed it into a software signer. The caller MUST wipe {@code outBuf[outOff..+32]} as soon as
     * it has consumed the scalar — preferably alongside its own per-call cleanup, so the scalar
     * never lingers past the signing primitive's own scope.
     *
     * @return the number of bytes written, i.e. {@link ModN#LEN}
     */
    public short deriveLeafScalar(
            byte[] pathBuf, short pathOff, short depth, byte[] outBuf, short outOff) {
        walkPathToLeaf(pathBuf, pathOff, depth);
        Util.arrayCopyNonAtomic(state, STATE_K_OFF, outBuf, outOff, ModN.LEN);
        wipeTransientSecrets();
        return ModN.LEN;
    }

    /**
     * Walks the BIP-32 chain from the master to the leaf indicated by {@code pathBuf[pathOff ..
     * pathOff + 4*depth]}, leaving the leaf scalar in {@code state[STATE_K_OFF..K+32]} and the leaf
     * chain code in {@code state[STATE_C_OFF..C+32]}.
     */
    private void walkPathToLeaf(byte[] pathBuf, short pathOff, short depth) {
        if (depth < 0 || depth > Constants.HD_MAX_DEPTH) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        // Seed the working scalar+chain code from the master.
        byte[] master = masterSeed.bip32Master();
        Util.arrayCopyNonAtomic(master, (short) 0, state, STATE_K_OFF, ModN.LEN);
        Util.arrayCopyNonAtomic(master, ModN.LEN, state, STATE_C_OFF, Constants.CHAIN_CODE_LEN);

        for (short level = 0; level < depth; level++) {
            short idxOff = (short) (pathOff + level * INDEX_LEN);
            ckdPriv(pathBuf, idxOff);
        }
    }

    /**
     * Wipes every transient slot that touched a secret scalar:
     *
     * <ul>
     *   <li>{@code state[K_OFF..K_OFF+32]} — the leaf private scalar
     *   <li>{@code state[I_OFF..I_OFF+64]} — the last HMAC output (its left half is also a scalar)
     *   <li>{@code scalarKey} — the EEPROM-backed {@link ECPrivateKey} holding the leaf scalar used
     *       by the non-hardened branch
     * </ul>
     *
     * The chain code at {@code state[C_OFF]} and the public key at {@code state[PUB_OFF]} are
     * intentionally left in place — they are public outputs and the buffer is {@code
     * CLEAR_ON_DESELECT} regardless.
     */
    private void wipeTransientSecrets() {
        Util.arrayFillNonAtomic(state, STATE_K_OFF, ModN.LEN, (byte) 0);
        Util.arrayFillNonAtomic(state, STATE_I_OFF, HASH_LEN, (byte) 0);
        scalarKey.clearKey();
    }

    /** One iteration of {@code CKDpriv}: state.k/state.c → state.k/state.c. */
    private void ckdPriv(byte[] pathBuf, short idxOff) {
        boolean hardened = (pathBuf[idxOff] & HARDENED_MASK) != 0;

        // HMAC key = c_par.
        chainKey.setKey(state, STATE_C_OFF, Constants.CHAIN_CODE_LEN);
        hmac.init(chainKey, Signature.MODE_SIGN);

        if (hardened) {
            // Data = 0x00 || ser256(k_par) || ser32(i)
            hmac.update(HARDENED_PREFIX, (short) 0, (short) 1);
            hmac.update(state, STATE_K_OFF, ModN.LEN);
        } else {
            // Data = serP(point(k_par)) || ser32(i)
            computeCompressedPubkey(state, STATE_K_OFF, state, STATE_PUB_OFF);
            hmac.update(state, STATE_PUB_OFF, Constants.EC_POINT_COMPRESSED_LEN);
        }
        hmac.sign(pathBuf, idxOff, INDEX_LEN, state, STATE_I_OFF);

        // Validate I_L < n and k_i != 0; on failure surface a clean SW so the host can retry
        // with a different index.
        if (!ModN.lessThanN(state, STATE_I_OFF)) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
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
     * Writes the SEC 1 §2.3.3 compressed encoding of {@code scalar * G} into {@code outBuf}
     * starting at {@code outOff}.
     *
     * @return number of bytes written, {@link Constants#EC_POINT_COMPRESSED_LEN}
     */
    public short computePubkey(byte[] scalar, short scalarOff, byte[] outBuf, short outOff) {
        return computeCompressedPubkey(scalar, scalarOff, outBuf, outOff);
    }

    private short computeCompressedPubkey(
            byte[] scalar, short scalarOff, byte[] outBuf, short outOff) {
        // Curve parameters may have been dropped by a prior {@code clearKey()} (see comment in
        // the constructor). Re-install them every call; the underlying setX() are idempotent
        // and the cost (≤5 EEPROM writes) is negligible next to the EC scalar multiplication
        // that follows.
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
        // SEC 1 §2.3.3 compression: parity prefix from y_LSB, drop y.
        byte yLsb = outBuf[(short) (outOff + Constants.EC_POINT_UNCOMPRESSED_LEN - 1)];
        outBuf[outOff] = ((yLsb & 0x01) == 0) ? (byte) 0x02 : (byte) 0x03;
        // Zero the trailing y to avoid leaking residue.
        Util.arrayFillNonAtomic(
                outBuf,
                (short) (outOff + Constants.EC_POINT_COMPRESSED_LEN),
                (short) (Constants.EC_POINT_UNCOMPRESSED_LEN - Constants.EC_POINT_COMPRESSED_LEN),
                (byte) 0);
        return Constants.EC_POINT_COMPRESSED_LEN;
    }
}
