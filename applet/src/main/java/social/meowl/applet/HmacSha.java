/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;

/**
 * HMAC-SHA-{256,512} engine, RFC 2104 software implementation built on {@link MessageDigest}.
 *
 * <p>The target silicon (NXP J3R180, JC 3.0.5 Classic) reports neither {@code
 * Signature.ALG_HMAC_SHA_*} nor {@code TYPE_HMAC*} in its algorithm catalogue (see {@code
 * 3rdparty/NXPJ3R180_NFC_1_ALGSUPPORT_*.csv}), so the only viable implementation is software. Every
 * HMAC consumer ({@link MasterSeed}, {@link Bip32}, {@link Slip10}) drives this engine. Note that
 * {@link SecureChannel} no longer routes through here — its KDF and MAC moved to AES-CMAC-128.
 *
 * <p>Algorithm — RFC 2104:
 *
 * <pre>
 *   K' = (|K| > B) ? H(K) : K, zero-padded to B bytes
 *   inner = H((K' XOR ipad) || message)
 *   HMAC = H((K' XOR opad) || inner)
 * </pre>
 *
 * with {@code B = 64} for SHA-256, {@code B = 128} for SHA-512, {@code ipad = 0x36}, {@code opad =
 * 0x5C}. The padded key and inner-hash slots live in {@link JCSystem#CLEAR_ON_DESELECT} memory.
 *
 * <p>API — mirrors {@link javacard.security.Signature}'s {@code init → update* → sign} cycle. Each
 * {@link #init} call resets all internal state.
 */
public final class HmacSha {

    /** Selects HMAC-SHA-256 ({@code B = 64}, output = 32 bytes). */
    public static final byte ALG_SHA_256 = (byte) 0x01;

    /** Selects HMAC-SHA-512 ({@code B = 128}, output = 64 bytes). */
    public static final byte ALG_SHA_512 = (byte) 0x02;

    private static final byte IPAD = (byte) 0x36;
    private static final byte OPAD = (byte) 0x5C;

    private final MessageDigest digest;
    private final short blockSize;
    private final short hashSize;

    /** Scratch holding {@code K'} (zero-padded to {@link #blockSize}). */
    private final byte[] padded;

    /** Scratch holding the inner hash {@code H((K' XOR ipad) || message)}. */
    private final byte[] inner;

    /**
     * Constructs an HMAC engine for {@code algorithm}, allocating its transient state.
     *
     * @param algorithm one of {@link #ALG_SHA_256} or {@link #ALG_SHA_512}
     * @throws CryptoException if {@code algorithm} or the underlying {@link MessageDigest} is not
     *     supported by the platform
     */
    public HmacSha(byte algorithm) {
        byte mdAlg;
        switch (algorithm) {
            case ALG_SHA_256:
                this.blockSize = (short) 64;
                this.hashSize = (short) 32;
                mdAlg = MessageDigest.ALG_SHA_256;
                break;
            case ALG_SHA_512:
                this.blockSize = (short) 128;
                this.hashSize = (short) 64;
                mdAlg = MessageDigest.ALG_SHA_512;
                break;
            default:
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                throw new RuntimeException(); // unreachable
        }

        this.digest = MessageDigest.getInstance(mdAlg, false);
        // CLEAR_ON_DESELECT (not CLEAR_ON_RESET) is required on cards (J3R180) whose install-time
        // CLEAR_ON_RESET pool is too small for both software engines (96 B + 192 B).
        this.padded = JCSystem.makeTransientByteArray(blockSize, JCSystem.CLEAR_ON_DESELECT);
        this.inner = JCSystem.makeTransientByteArray(hashSize, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Initialises the engine with a fresh key. Per RFC 2104 §2 keys longer than the block size are
     * pre-hashed, shorter keys are zero-padded.
     */
    public void init(byte[] keyBuf, short keyOff, short keyLen) {
        // RFC 2104: build K' in padded. Long-key (keyLen > blockSize) pre-hashes; short-key
        // zero-pads. Guard the tail fill against keyLen == blockSize (zero-length fill rejected).
        if (keyLen > blockSize) {
            digest.reset();
            digest.doFinal(keyBuf, keyOff, keyLen, padded, (short) 0);
            Util.arrayFillNonAtomic(padded, hashSize, (short) (blockSize - hashSize), (byte) 0);
        } else {
            Util.arrayCopyNonAtomic(keyBuf, keyOff, padded, (short) 0, keyLen);
            short tail = (short) (blockSize - keyLen);
            if (tail > 0) {
                Util.arrayFillNonAtomic(padded, keyLen, tail, (byte) 0);
            }
        }

        // Prime the inner digest with (K' XOR ipad); mutate padded in place, hash, then restore
        // so the same buffer feeds the outer digest in doFinal without a second opadBlock copy.
        xorBlock(padded, IPAD);
        digest.reset();
        digest.update(padded, (short) 0, blockSize);
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
     * writes the HMAC tag (32 bytes for SHA-256, 64 for SHA-512) into {@code outBuf} at {@code
     * outOff}.
     *
     * @return tag length in bytes
     */
    public short doFinal(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
        // 1. inner = H((K' XOR ipad) || all_updates || inBuf[inOff..inOff+inLen])
        digest.doFinal(inBuf, inOff, inLen, inner, (short) 0);

        // 2. outer = H((K' XOR opad) || inner)
        xorBlock(padded, OPAD);
        digest.reset();
        digest.update(padded, (short) 0, blockSize);
        digest.doFinal(inner, (short) 0, hashSize, outBuf, outOff);
        xorBlock(padded, OPAD); // restore K' so reset() / re-init can wipe it cleanly

        // Wipe inner defensively so a missed reset() can't leak yesterday's MAC.
        Util.arrayFillNonAtomic(inner, (short) 0, hashSize, (byte) 0);
        return hashSize;
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
        Util.arrayFillNonAtomic(padded, (short) 0, blockSize, (byte) 0);
        Util.arrayFillNonAtomic(inner, (short) 0, hashSize, (byte) 0);
    }

    /** In-place XOR of {@code buf[0..blockSize]} with {@code mask}. */
    private void xorBlock(byte[] buf, byte mask) {
        for (short i = 0; i < blockSize; i++) {
            buf[i] ^= mask;
        }
    }
}
