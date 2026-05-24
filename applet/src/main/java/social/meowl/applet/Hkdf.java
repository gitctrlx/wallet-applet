/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * RFC 5869 HKDF-SHA-256.
 *
 * <p>Implements the two-stage HKDF construction on top of {@link HmacSha} so the same code path
 * works on every JC platform we target. {@link HmacSha} transparently selects the platform's native
 * HMAC primitive when available (jcardsim, JCOP3 J3H082, …) and otherwise falls back to the RFC
 * 2104 software construction over {@link MessageDigest#ALG_SHA_256} (J3R180 and the rest of the
 * JCOP4 SECID family that omits {@code Signature.ALG_HMAC_SHA_*} from the firmware).
 *
 * <ul>
 *   <li><b>Extract</b>: {@code PRK = HMAC-SHA-256(salt, IKM)} — concentrates input keying material
 *       into a 32-byte pseudo-random key.
 *   <li><b>Expand</b>: {@code OKM = T(1) ‖ T(2) ‖ … ‖ T(N)} where {@code T(i) = HMAC-SHA-256(PRK,
 *       T(i-1) ‖ info ‖ i)}. Produces up to {@code 255 × 32 = 8160} bytes of output keying
 *       material.
 * </ul>
 *
 * <p>All operations write into caller-supplied buffers. The class delegates the keyed compression
 * to a shared {@link HmacSha} engine handed in via the constructor, and holds a small {@link
 * JCSystem#CLEAR_ON_DESELECT} scratch buffer for the running {@code T(i-1)} state during {@link
 * #expand(byte[], short, byte[], short, short)}. The PRK is also held in DESELECT transient memory
 * so it is wiped automatically on session teardown.
 */
public final class Hkdf {

    /** Length of an HMAC-SHA-256 output, and the maximum length of one HKDF expansion block. */
    public static final short HASH_LEN = MessageDigest.LENGTH_SHA_256;

    /**
     * Hard ceiling on a single HKDF expansion, per RFC 5869 §2.3. Internal: only {@link #expand}
     * checks against it; callers stage at most 80 bytes.
     */
    private static final short MAX_EXPAND_LEN = (short) (255 * HASH_LEN);

    private final HmacSha hmac;
    private final byte[] prk;
    private final byte[] scratch;

    /**
     * One-byte transient buffer for the HKDF counter byte {@code i} fed into {@code T(i) =
     * HMAC(PRK, T(i-1) ‖ info ‖ i)}. Dedicated so we do not mutate {@link #scratch} between {@code
     * hmac.update} and {@code hmac.doFinal} — JC's underlying {@code Signature.update} may defer
     * ingestion, which would observe the post-mutation byte.
     */
    private final byte[] counterBuf;

    /**
     * @param sharedHmac256 a shared HMAC-SHA-256 engine. Hkdf does not own it: {@link
     *     SecureChannel} reuses the same instance for its envelope MAC. Safe because APDU dispatch
     *     is single-threaded.
     */
    public Hkdf(HmacSha sharedHmac256) {
        this.hmac = sharedHmac256;
        this.prk = JCSystem.makeTransientByteArray(HASH_LEN, JCSystem.CLEAR_ON_DESELECT);
        this.scratch = JCSystem.makeTransientByteArray(HASH_LEN, JCSystem.CLEAR_ON_DESELECT);
        this.counterBuf = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * HKDF-Extract — derives the 32-byte PRK from input keying material, stored internally for the
     * subsequent {@link #expand} call. PRK lives in transient memory and is wiped on deselect.
     *
     * @param salt buffer; {@code saltLen == 0} substitutes a zero-filled buffer per RFC 5869 §2.2
     * @param saltLen any non-negative length; the underlying HMAC absorbs arbitrary salt lengths
     */
    public void extract(
            byte[] salt,
            short saltOffset,
            short saltLen,
            byte[] ikm,
            short ikmOffset,
            short ikmLen) {
        if (saltLen < 0 || ikmLen < 0) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        if (saltLen == 0) {
            // RFC 5869 §2.2: if salt is empty, use HashLen zero bytes.
            Util.arrayFillNonAtomic(scratch, (short) 0, HASH_LEN, (byte) 0);
            hmac.init(scratch, (short) 0, HASH_LEN);
        } else {
            hmac.init(salt, saltOffset, saltLen);
        }
        hmac.doFinal(ikm, ikmOffset, ikmLen, prk, (short) 0);
    }

    /**
     * HKDF-Expand — derives {@code length} bytes of OKM from the PRK previously computed via {@link
     * #extract}.
     *
     * @param info may be {@code null} when {@code infoLen == 0} (RFC 5869 §2.3 empty info)
     * @param length requested OKM length in bytes; {@code 0 ≤ length ≤ 255 × HashLen}
     */
    public void expand(
            byte[] info,
            short infoOffset,
            short infoLen,
            byte[] out,
            short outOffset,
            short length) {
        if (length < 0 || length > MAX_EXPAND_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        if (info == null && infoLen != 0) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        Bounds.requireCapacity(out, outOffset, length);

        // T(0) is empty; T(i) = HMAC(PRK, T(i-1) ‖ info ‖ i).
        short remaining = length;
        short writeOffset = outOffset;
        byte counter = (byte) 0x01;
        boolean firstBlock = true;

        while (remaining > 0) {
            hmac.init(prk, (short) 0, HASH_LEN);
            if (!firstBlock) {
                hmac.update(scratch, (short) 0, HASH_LEN);
            }
            if (infoLen > 0) {
                hmac.update(info, infoOffset, infoLen);
            }
            counterBuf[0] = counter;
            // T(i) lands in scratch so the next iteration can prefix the new input with it.
            hmac.doFinal(counterBuf, (short) 0, (short) 1, scratch, (short) 0);
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
        hmac.reset();
        Util.arrayFillNonAtomic(prk, (short) 0, HASH_LEN, (byte) 0);
        Util.arrayFillNonAtomic(scratch, (short) 0, HASH_LEN, (byte) 0);
        counterBuf[0] = 0;
    }
}
