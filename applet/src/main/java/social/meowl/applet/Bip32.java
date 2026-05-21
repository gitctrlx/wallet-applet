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
     * @param sharedHmac512 the same engine handed to {@link MasterSeed} and {@link Slip10};
     *     instance reuse is safe because all consumers run on the single APDU dispatch thread.
     */
    public Bip32(MasterSeed masterSeed, HmacSha sharedHmac512) {
        this.masterSeed = masterSeed;
        this.hmac = sharedHmac512;
        try {
            this.scalarMult = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
            // Prefer the RAM-backed transient flavour so the derived leaf scalar never touches
            // EEPROM (audit C-2.02: a plain clearKey() does not necessarily wipe EEPROM cells on
            // every silicon, leaving a residue an attacker with physical access could recover).
            // Fall back to the persistent flavour only on cards that refuse the transient form
            // (some pre-3.0.5 JC silicon, and a handful of recent cards that restrict
            // TRANSIENT_DESELECT to symmetric keys).
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
     * Wipes every transient slot the BIP-32 walk touched, including the chain code and the
     * uncompressed public-key scratch.
     *
     * <ul>
     *   <li>{@code state[K_OFF..]} — the leaf private scalar.
     *   <li>{@code state[C_OFF..]} — the leaf chain code. Chain codes are usually treated as
     *       semi-public, but the BIP-32 derivation rule ({@code chain code + parent pubkey} → all
     *       sibling pubkeys; {@code chain code + one secret} → all sibling secrets) means a stale
     *       chain code lingering in transient memory across an APDU is a defense-in-depth gap.
     *       Trezor's {@code hdnode_clear} wipes everything; we mirror that, and align with {@link
     *       Slip10}'s wipe path which already does so (audit S3-03).
     *   <li>{@code state[I_OFF..]} — the last HMAC-SHA-512 output (its left half is a secret scalar
     *       candidate).
     *   <li>{@code state[PUB_OFF..]} — the uncompressed public-key scratch used by the non-hardened
     *       branch. Public material, but wiped for the same defense-in-depth rationale.
     *   <li>{@code scalarKey} — the {@link ECPrivateKey} holding the (transient or persistent) leaf
     *       scalar used by the non-hardened branch.
     * </ul>
     */
    private void wipeTransientSecrets() {
        Util.arrayFillNonAtomic(state, (short) 0, STATE_LEN, (byte) 0);
        scalarKey.clearKey();
    }

    /** One iteration of {@code CKDpriv}: state.k/state.c → state.k/state.c. */
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

    /**
     * Writes the uncompressed encoding {@code 0x04 ‖ x ‖ y} of {@code scalar * G} into {@code
     * outBuf} starting at {@code outOff}, and returns 65. The BIP-340 Schnorr signer needs the
     * {@code y}-coordinate to test the parity of the nonce point and the public key, so the
     * uncompressed form is exposed as a public helper rather than thrown away by {@link
     * #computeCompressedPubkey}.
     *
     * @return number of bytes written, {@link Constants#EC_POINT_UNCOMPRESSED_LEN}
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
        // Run scalar*G into outBuf, then compress in place per SEC 1 §2.3.3: parity prefix
        // derived from y_LSB, trailing y zeroed.
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
