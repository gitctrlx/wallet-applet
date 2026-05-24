/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * HMAC-SHA-512 engine — RFC 2104 software implementation built on {@link MessageDigest}.
 *
 * <p>The target silicon (NXP J3R180, JC 3.0.5 Classic) reports neither {@code
 * Signature.ALG_HMAC_SHA_512} nor {@code TYPE_HMAC} in its algorithm catalogue (see {@code
 * 3rdparty/NXPJ3R180_NFC_1_ALGSUPPORT_*.csv}), so the only viable implementation is software. Every
 * HMAC-SHA-512 consumer ({@link MasterSeed}, {@link Bip32}, {@link Slip10}) drives this engine.
 * {@link SecureChannel} no longer participates — its KDF and MAC moved to AES-CMAC-128 via {@link
 * Kdf}, eliminating the need for an HMAC-SHA-256 sibling engine.
 *
 * <p>Algorithm — RFC 2104 with {@code B = 128} (SHA-512 block size), {@code ipad = 0x36}, {@code
 * opad = 0x5C}:
 *
 * <pre>
 *   K' = (|K| > 128) ? SHA-512(K) : K, zero-padded to 128 bytes
 *   inner = SHA-512((K' XOR ipad) || message)
 *   HMAC = SHA-512((K' XOR opad) || inner)
 * </pre>
 *
 * <p>The padded key and inner-hash slots live in {@link JCSystem#CLEAR_ON_DESELECT} memory.
 *
 * <p>API — mirrors {@link javacard.security.Signature}'s {@code init → update* → sign} cycle. Each
 * {@link #init} call resets all internal state.
 */
public final class HmacSha512 {

    /** SHA-512 block size in bytes. */
    private static final short BLOCK_LEN = (short) 128;

    /** SHA-512 output size in bytes. */
    private static final short HASH_LEN = (short) 64;

    private static final byte IPAD = (byte) 0x36;
    private static final byte OPAD = (byte) 0x5C;

    private final MessageDigest digest;

    /** Scratch holding {@code K'} (zero-padded to {@link #BLOCK_LEN}). */
    private final byte[] padded;

    /** Scratch holding the inner hash {@code H((K' XOR ipad) || message)}. */
    private final byte[] inner;

    /** Constructs an HMAC-SHA-512 engine, allocating its transient state. */
    public HmacSha512() {
        this.digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
        // CLEAR_ON_DESELECT (not CLEAR_ON_RESET) is required on cards (J3R180) whose install-time
        // CLEAR_ON_RESET pool is too small for the 192-byte transient footprint.
        this.padded = JCSystem.makeTransientByteArray(BLOCK_LEN, JCSystem.CLEAR_ON_DESELECT);
        this.inner = JCSystem.makeTransientByteArray(HASH_LEN, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Initialises the engine with a fresh key. Per RFC 2104 §2 keys longer than the block size are
     * pre-hashed, shorter keys are zero-padded.
     */
    public void init(byte[] keyBuf, short keyOff, short keyLen) {
        // RFC 2104: build K' in padded. Long-key (keyLen > BLOCK_LEN) pre-hashes; short-key
        // zero-pads. Guard the tail fill against keyLen == BLOCK_LEN (zero-length fill rejected).
        if (keyLen > BLOCK_LEN) {
            digest.reset();
            digest.doFinal(keyBuf, keyOff, keyLen, padded, (short) 0);
            Util.arrayFillNonAtomic(padded, HASH_LEN, (short) (BLOCK_LEN - HASH_LEN), (byte) 0);
        } else {
            Util.arrayCopyNonAtomic(keyBuf, keyOff, padded, (short) 0, keyLen);
            short tail = (short) (BLOCK_LEN - keyLen);
            if (tail > 0) {
                Util.arrayFillNonAtomic(padded, keyLen, tail, (byte) 0);
            }
        }

        // Prime the inner digest with (K' XOR ipad); mutate padded in place, hash, then restore
        // so the same buffer feeds the outer digest in doFinal without a second opadBlock copy.
        xorBlock(padded, IPAD);
        digest.reset();
        digest.update(padded, (short) 0, BLOCK_LEN);
        xorBlock(padded, IPAD);
    }

    /**
     * Feeds {@code len} bytes of message material into the running MAC. Multiple {@link #update}
     * calls accumulate into the same MAC; finalise with {@link #doFinal doFinal}.
     */
    public void update(byte[] inBuf, short inOff, short inLen) {
        digest.update(inBuf, inOff, inLen);
    }

    /**
     * Consumes the final {@code inLen} bytes, finishes the inner hash, runs the outer hash, and
     * writes the 64-byte HMAC tag into {@code outBuf} at {@code outOff}.
     *
     * @return tag length in bytes (always {@value #HASH_LEN})
     */
    public short doFinal(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
        // 1. inner = H((K' XOR ipad) || all_updates || inBuf[inOff..inOff+inLen])
        digest.doFinal(inBuf, inOff, inLen, inner, (short) 0);

        // 2. outer = H((K' XOR opad) || inner)
        xorBlock(padded, OPAD);
        digest.reset();
        digest.update(padded, (short) 0, BLOCK_LEN);
        digest.doFinal(inner, (short) 0, HASH_LEN, outBuf, outOff);
        xorBlock(padded, OPAD); // restore K' so reset() / re-init can wipe it cleanly

        // Wipe inner defensively so a missed reset() can't leak yesterday's MAC.
        Util.arrayFillNonAtomic(inner, (short) 0, HASH_LEN, (byte) 0);
        return HASH_LEN;
    }

    /**
     * Convenience one-shot {@link #init} + {@link #doFinal} for callers with the message in hand.
     */
    public short sign(
            byte[] keyBuf,
            short keyOff,
            short keyLen,
            byte[] msgBuf,
            short msgOff,
            short msgLen,
            byte[] outBuf,
            short outOff) {
        init(keyBuf, keyOff, keyLen);
        return doFinal(msgBuf, msgOff, msgLen, outBuf, outOff);
    }

    /** Wipes intermediate state and key material. Call at the end of any secret-touching flow. */
    public void reset() {
        Util.arrayFillNonAtomic(padded, (short) 0, BLOCK_LEN, (byte) 0);
        Util.arrayFillNonAtomic(inner, (short) 0, HASH_LEN, (byte) 0);
    }

    /** In-place XOR of {@code buf[0..BLOCK_LEN]} with {@code mask}. */
    private void xorBlock(byte[] buf, byte mask) {
        for (short i = 0; i < BLOCK_LEN; i++) {
            buf[i] ^= mask;
        }
    }
}
