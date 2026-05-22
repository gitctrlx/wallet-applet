/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.HMACKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;

/**
 * HMAC-SHA-{256,512} engine that auto-selects between the JC platform's native implementation and
 * an RFC 2104 software fallback built on {@link MessageDigest}.
 *
 * <p>Several JCOP-4 SECID configurations (notably {@code J3R180}) omit {@code
 * Signature.ALG_HMAC_SHA_*} and {@code TYPE_HMAC*} from the firmware catalogue. This class hides
 * the "try-native-then-fall-back-to-software" decision so every HMAC consumer ({@link Hkdf}, {@link
 * MasterSeed}, {@link Bip32}, {@link Slip10}, {@link SecureChannel}) stays agnostic.
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
 * <p>API — mirrors {@link Signature}'s {@code init → update* → sign} cycle. Each {@link #init} call
 * resets all internal state.
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

    /** Native HMAC primitive; {@code null} when the platform refused to instantiate it. */
    private final Signature nativeSig;

    /** Native HMAC key holder; {@code null} on the software path. */
    private final HMACKey nativeKey;

    /**
     * Software-path scratch holding {@code K'} (zero-padded to {@link #blockSize}). {@code null} on
     * the native path so cards with working HMAC pay no RAM cost.
     */
    private final byte[] softKey;

    /** Software-path scratch holding the inner hash {@code H((K' XOR ipad) || message)}. */
    private final byte[] softInner;

    /**
     * Constructs an HMAC engine for {@code algorithm}, allocating its transient state.
     *
     * @param algorithm one of {@link #ALG_SHA_256} or {@link #ALG_SHA_512}
     * @throws CryptoException if {@code algorithm} or the underlying {@link MessageDigest} is not
     *     supported by the platform
     */
    public HmacSha(byte algorithm) {
        this(algorithm, false);
    }

    /**
     * Test-only factory forcing the software fallback path on platforms that do support native HMAC
     * (jcardsim). Production code uses the public single-argument constructor.
     */
    static HmacSha forceSoftware(byte algorithm) {
        return new HmacSha(algorithm, true);
    }

    private HmacSha(byte algorithm, boolean forceSoft) {
        byte mdAlg;
        byte sigAlg;
        switch (algorithm) {
            case ALG_SHA_256:
                this.blockSize = (short) 64;
                this.hashSize = (short) 32;
                mdAlg = MessageDigest.ALG_SHA_256;
                sigAlg = Signature.ALG_HMAC_SHA_256;
                break;
            case ALG_SHA_512:
                this.blockSize = (short) 128;
                this.hashSize = (short) 64;
                mdAlg = MessageDigest.ALG_SHA_512;
                sigAlg = Signature.ALG_HMAC_SHA_512;
                break;
            default:
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                throw new RuntimeException(); // unreachable
        }

        this.digest = MessageDigest.getInstance(mdAlg, false);

        Signature s = null;
        HMACKey k = null;
        if (!forceSoft) {
            try {
                s = Signature.getInstance(sigAlg, false);
                k =
                        (HMACKey)
                                KeyBuilder.buildKey(
                                        KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT,
                                        (short) (blockSize * 8),
                                        false);
            } catch (CryptoException e) {
                // Software fallback path: the platform does not implement HMAC natively.
                s = null;
                k = null;
            }
        }
        this.nativeSig = s;
        this.nativeKey = k;

        // Software-path buffers only when needed, so cards with native HMAC pay no RAM cost.
        // CLEAR_ON_DESELECT (not CLEAR_ON_RESET) is required on cards (J3R180) whose install-time
        // CLEAR_ON_RESET pool is too small for both software engines (96 B + 192 B).
        if (s == null) {
            this.softKey = JCSystem.makeTransientByteArray(blockSize, JCSystem.CLEAR_ON_DESELECT);
            this.softInner = JCSystem.makeTransientByteArray(hashSize, JCSystem.CLEAR_ON_DESELECT);
        } else {
            this.softKey = null;
            this.softInner = null;
        }
    }

    /** Returns the output length in bytes (32 for SHA-256, 64 for SHA-512). */
    public short getLength() {
        return hashSize;
    }

    /**
     * Initialises the engine with a fresh key. Per RFC 2104 §2 keys longer than the block size are
     * pre-hashed, shorter keys are zero-padded.
     */
    public void init(byte[] keyBuf, short keyOff, short keyLen) {
        if (nativeSig != null) {
            nativeKey.setKey(keyBuf, keyOff, keyLen);
            nativeSig.init(nativeKey, Signature.MODE_SIGN);
            return;
        }

        // RFC 2104: build K' in softKey. Long-key (keyLen > blockSize) pre-hashes; short-key
        // zero-pads. Guard the tail fill against keyLen == blockSize (zero-length fill rejected).
        if (keyLen > blockSize) {
            digest.reset();
            digest.doFinal(keyBuf, keyOff, keyLen, softKey, (short) 0);
            Util.arrayFillNonAtomic(softKey, hashSize, (short) (blockSize - hashSize), (byte) 0);
        } else {
            Util.arrayCopyNonAtomic(keyBuf, keyOff, softKey, (short) 0, keyLen);
            short tail = (short) (blockSize - keyLen);
            if (tail > 0) {
                Util.arrayFillNonAtomic(softKey, keyLen, tail, (byte) 0);
            }
        }

        // Prime the inner digest with (K' XOR ipad); mutate softKey in place, hash, then restore
        // so the same buffer feeds the outer digest in doFinal without a second opadBlock copy.
        xorBlock(softKey, IPAD);
        digest.reset();
        digest.update(softKey, (short) 0, blockSize);
        xorBlock(softKey, IPAD);
    }

    /**
     * Feeds {@code len} bytes of message material into the running MAC. Multiple {@link #update}
     * calls accumulate into the same MAC; finalise with {@link #doFinal doFinal}.
     */
    public void update(byte[] inBuf, short inOff, short inLen) {
        if (nativeSig != null) {
            nativeSig.update(inBuf, inOff, inLen);
        } else {
            digest.update(inBuf, inOff, inLen);
        }
    }

    /**
     * Consumes the final {@code inLen} bytes, finishes the inner hash, runs the outer hash, and
     * writes the {@link #getLength()}-byte HMAC into {@code outBuf} at {@code outOff}.
     *
     * @return {@link #getLength()}
     */
    public short doFinal(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
        if (nativeSig != null) {
            return nativeSig.sign(inBuf, inOff, inLen, outBuf, outOff);
        }

        // 1. inner = H((K' XOR ipad) || all_updates || inBuf[inOff..inOff+inLen])
        digest.doFinal(inBuf, inOff, inLen, softInner, (short) 0);

        // 2. outer = H((K' XOR opad) || inner)
        xorBlock(softKey, OPAD);
        digest.reset();
        digest.update(softKey, (short) 0, blockSize);
        digest.doFinal(softInner, (short) 0, hashSize, outBuf, outOff);
        xorBlock(softKey, OPAD); // restore K' so reset() / re-init can wipe it cleanly

        // Wipe inner defensively so a missed reset() can't leak yesterday's MAC.
        Util.arrayFillNonAtomic(softInner, (short) 0, hashSize, (byte) 0);
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
        if (nativeKey != null) {
            nativeKey.clearKey();
        }
        if (softKey != null) {
            Util.arrayFillNonAtomic(softKey, (short) 0, blockSize, (byte) 0);
        }
        if (softInner != null) {
            Util.arrayFillNonAtomic(softInner, (short) 0, hashSize, (byte) 0);
        }
    }

    /** In-place XOR of {@code buf[0..blockSize]} with {@code mask}. */
    private void xorBlock(byte[] buf, byte mask) {
        for (short i = 0; i < blockSize; i++) {
            buf[i] ^= mask;
        }
    }
}
