/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.HMACKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;

/**
 * RFC 5869 HKDF-SHA-256.
 *
 * <p>Implements the two-stage HKDF construction on top of the native {@link
 * Signature#ALG_HMAC_SHA_256} primitive (available since JavaCard 3.0.4 and ubiquitously supported
 * in 3.0.5+ silicon):
 *
 * <ul>
 *   <li><b>Extract</b>: {@code PRK = HMAC-SHA-256(salt, IKM)} — concentrates input keying material
 *       into a 32-byte pseudo-random key.
 *   <li><b>Expand</b>: {@code OKM = T(1) ‖ T(2) ‖ … ‖ T(N)} where {@code T(i) = HMAC-SHA-256(PRK,
 *       T(i-1) ‖ info ‖ i)}. Produces up to {@code 255 × 32 = 8160} bytes of output keying
 *       material.
 * </ul>
 *
 * <p>All operations write into caller-supplied buffers. The class holds two single-purpose {@link
 * HMACKey} instances (one for the {@code salt} role, one for the {@code PRK} role) backed by {@code
 * TYPE_HMAC_TRANSIENT_DESELECT} so key material is cleared whenever the applet is deselected. A
 * small {@code CLEAR_ON_DESELECT} scratch buffer holds the running {@code T(i-1)} state during
 * {@link #expand(byte[], short, byte[], short, short)}.
 */
public final class Hkdf {

    /** Length of an HMAC-SHA-256 output, and the maximum length of one HKDF expansion block. */
    public static final short HASH_LEN = MessageDigest.LENGTH_SHA_256;

    /** Hard ceiling on a single HKDF expansion, per RFC 5869 §2.3. */
    public static final short MAX_EXPAND_LEN = (short) (255 * HASH_LEN);

    private final Signature hmac;
    private final HMACKey saltKey;
    private final HMACKey prkKey;
    private final byte[] prk;
    private final byte[] scratch;

    /**
     * One-byte transient buffer holding the HKDF counter byte {@code i} fed into the {@code T(i) =
     * HMAC(PRK, T(i-1) ‖ info ‖ i)} computation in {@link #expand}. Dedicated so we do not mutate
     * {@link #scratch} between {@code hmac.update(scratch, …)} and {@code hmac.sign(…)} — JC's
     * {@code Signature.update} is allowed by the spec to defer ingestion until the next sign(), and
     * that deferred ingestion would observe the post-mutation byte if we wrote into the same buffer
     * (audit M-1.14).
     */
    private final byte[] counterBuf;

    /** Instantiates an HKDF helper, allocating its transient state. */
    public Hkdf() {
        this.hmac = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
        // We use the longest reasonable key length the platform exposes; HMAC trims internally.
        this.saltKey =
                (HMACKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT,
                                (short) (HASH_LEN * 8),
                                false);
        this.prkKey =
                (HMACKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT,
                                (short) (HASH_LEN * 8),
                                false);
        this.prk =
                javacard.framework.JCSystem.makeTransientByteArray(
                        HASH_LEN, javacard.framework.JCSystem.CLEAR_ON_DESELECT);
        this.scratch =
                javacard.framework.JCSystem.makeTransientByteArray(
                        HASH_LEN, javacard.framework.JCSystem.CLEAR_ON_DESELECT);
        this.counterBuf =
                javacard.framework.JCSystem.makeTransientByteArray(
                        (short) 1, javacard.framework.JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * HKDF-Extract — derives a 32-byte pseudo-random key from input keying material.
     *
     * <p>Stores the resulting PRK internally so the subsequent {@link #expand(byte[], short,
     * byte[], short, short)} call uses it without an extra parameter. The PRK lives in transient
     * memory and is wiped on deselect.
     *
     * @param salt buffer holding the salt; if {@code saltLen == 0} a zero-filled buffer is used as
     *     per RFC 5869 §2.2
     * @param saltOffset offset of the salt within {@code salt}
     * @param saltLen length of the salt in bytes (must be {@code >= 0} and {@code <= 256})
     * @param ikm buffer holding the input keying material
     * @param ikmOffset offset of the IKM
     * @param ikmLen length of the IKM in bytes
     */
    public void extract(
            byte[] salt,
            short saltOffset,
            short saltLen,
            byte[] ikm,
            short ikmOffset,
            short ikmLen) {
        if (saltLen < 0 || saltLen > (short) 256 || ikmLen < 0) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        if (saltLen == 0) {
            // RFC 5869 §2.2: if salt is empty, use HashLen zero bytes.
            Util.arrayFillNonAtomic(scratch, (short) 0, HASH_LEN, (byte) 0);
            saltKey.setKey(scratch, (short) 0, HASH_LEN);
        } else {
            saltKey.setKey(salt, saltOffset, saltLen);
        }
        hmac.init(saltKey, Signature.MODE_SIGN);
        hmac.sign(ikm, ikmOffset, ikmLen, prk, (short) 0);
        prkKey.setKey(prk, (short) 0, HASH_LEN);
    }

    /**
     * HKDF-Expand — derives {@code length} bytes of output keying material from the PRK previously
     * computed via {@link #extract}.
     *
     * @param info context / application-specific info string; may be {@code null} and {@code
     *     infoLen == 0}
     * @param infoOffset offset of the info string
     * @param info_or_null possibly-null buffer (we accept a null buffer when {@code infoLen == 0})
     */
    public void expand(
            byte[] info_or_null,
            short infoOffset,
            short infoLen,
            byte[] out,
            short outOffset,
            short length) {
        if (length < 0 || length > MAX_EXPAND_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        if (info_or_null == null && infoLen != 0) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        if (out == null || outOffset < 0 || (short) (outOffset + length) > (short) out.length) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }

        // T(0) is empty; T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i).
        short remaining = length;
        short writeOffset = outOffset;
        byte counter = (byte) 0x01;
        boolean firstBlock = true;

        while (remaining > 0) {
            hmac.init(prkKey, Signature.MODE_SIGN);
            if (!firstBlock) {
                hmac.update(scratch, (short) 0, HASH_LEN);
            }
            if (infoLen > 0) {
                hmac.update(info_or_null, infoOffset, infoLen);
            }
            // Feed the counter byte from a dedicated 1-byte buffer (audit M-1.14): JC's
            // Signature.update is allowed to defer ingestion until sign(), so we must not mutate
            // scratch between the update() above and the sign() below if scratch is also the
            // input buffer.
            counterBuf[0] = counter;
            // We need T(i) as a contiguous 32-byte buffer for the next iteration's update().
            // Write into scratch first, then copy out (or directly into out when this is the last
            // partial block).
            hmac.sign(counterBuf, (short) 0, (short) 1, scratch, (short) 0);
            short take = remaining < HASH_LEN ? remaining : HASH_LEN;
            Util.arrayCopyNonAtomic(scratch, (short) 0, out, writeOffset, take);
            writeOffset += take;
            remaining -= take;
            counter++;
            firstBlock = false;
        }
    }

    /** Resets the PRK material. Called by the Secure Channel when a session is torn down. */
    public void reset() {
        saltKey.clearKey();
        prkKey.clearKey();
        Util.arrayFillNonAtomic(prk, (short) 0, HASH_LEN, (byte) 0);
        Util.arrayFillNonAtomic(scratch, (short) 0, HASH_LEN, (byte) 0);
        counterBuf[0] = 0;
    }
}
