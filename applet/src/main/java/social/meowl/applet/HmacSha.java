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
 * HMAC-SHA-{256,512} engine that auto-selects between the JC platform's native HMAC implementation
 * (when available) and an RFC 2104 software fallback built on the platform's {@link MessageDigest}.
 *
 * <p><b>Why a dedicated class.</b> Several mainstream JCOP-4 SECID configurations (notably the
 * {@code J3R180} family that meowl targets) ship with the {@code Signature.ALG_HMAC_SHA_*} family
 * and the {@code TYPE_HMAC*} {@link KeyBuilder} types omitted from the firmware catalogue. A bare
 * {@code Signature.getInstance(ALG_HMAC_SHA_256)} therefore raises {@link CryptoException} with
 * {@link CryptoException#NO_SUCH_ALGORITHM} on those cards, which would make {@link Hkdf}, {@link
 * MasterSeed}, {@link Bip32} and {@link Slip10} unusable. This class encapsulates the
 * "try-native-then-fall-back-to-software" decision once so every HMAC consumer in the applet can
 * stay agnostic to the underlying mechanism.
 *
 * <p><b>Algorithm.</b> RFC 2104:
 *
 * <pre>
 *   K' = (|K| > B) ? H(K) : K, zero-padded to B bytes
 *   inner = H((K' XOR ipad) �?message)
 *   HMAC = H((K' XOR opad) �?inner)
 * </pre>
 *
 * with {@code B = 64} for SHA-256 and {@code B = 128} for SHA-512, {@code ipad = 0x36}, {@code opad
 * = 0x5C}.
 *
 * <p><b>Security.</b>
 *
 * <ul>
 *   <li>The padded key buffer {@code K'} and the inner-hash slot live in {@link
 *       JCSystem#CLEAR_ON_DESELECT} transient memory: they are wiped on every {@link #reset()} and
 *       implicitly cleared on card deselect, which is the strictest lifecycle that still permits
 *       the {@code init → update* → doFinal} sequence to span multiple APDUs of one session.
 *   <li>The XOR loop and the digest API are data-independent in their timing on every JC platform
 *       we target (J3R180's SHA-256 / SHA-512 are hardware-accelerated and constant-time per the
 *       NXP datasheet).
 *   <li>HMAC verification at the call sites uses {@link ConstantTime#equals} so a wire-side
 *       attacker observing only the response time cannot derive a faster-than-brute-force MAC
 *       distinguisher.
 * </ul>
 *
 * <p><b>API contract.</b> The class mirrors {@link Signature}'s {@code init(SIGN)} �?{@code
 * update*} �?{@code sign} cycle. Each {@link #init(byte[], short, short)} call resets all internal
 * state, so engines can be reused across distinct keys without leaking residue from earlier calls.
 *
 * <p><b>Reference implementation.</b> The software fallback follows the canonical pattern used by
 * {@code im.status.keycard.Crypto} in the {@code status-keycard} project (Status / Ethereum
 * hardware wallet). We extend it with full RFC 2104 long-key handling ({@code |K| > B}) and add
 * SHA-256 alongside SHA-512.
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
     * Software-path scratch holding {@code K'} (zero-padded to {@link #blockSize}). On the native
     * path this field is {@code null} so we do not pay the RAM cost on cards that have working
     * HMAC.
     */
    private final byte[] softKey;

    /** Software-path scratch holding the inner hash {@code H((K' XOR ipad) �?message)}. */
    private final byte[] softInner;

    /**
     * Constructs an HMAC engine for {@code algorithm}, allocating its transient state.
     *
     * @param algorithm one of {@link #ALG_SHA_256} or {@link #ALG_SHA_512}
     * @throws CryptoException if {@code algorithm} is not recognised, or if the underlying {@link
     *     MessageDigest} algorithm itself is not supported by the platform (in which case the card
     *     is unusable for any sane meowl flow regardless)
     */
    public HmacSha(byte algorithm) {
        this(algorithm, false);
    }

    /**
     * Package-private factory used by the test harness to exercise the software fallback path on a
     * platform that <em>does</em> support native HMAC (e.g. jcardsim). Production code never calls
     * this directly �?the public single-argument constructor lets the platform pick the fastest
     * available implementation.
     *
     * @param algorithm one of {@link #ALG_SHA_256} or {@link #ALG_SHA_512}
     * @param forceSoft if {@code true}, skip the native HMAC probe and force the RFC 2104 software
     *     path; if {@code false}, behave like the public constructor
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

        // Software-path buffers are only allocated when we are actually going to use them; this
        // keeps RAM consumption flat on jcardsim / cards with native HMAC. CLEAR_ON_DESELECT (not
        // CLEAR_ON_RESET) is mandatory on resource-constrained NFC SECID configurations such as
        // J3R180: the install-time CLEAR_ON_RESET pool there is too small to host two parallel
        // software HMAC engines (96 B + 192 B for SHA-256 + SHA-512), whereas the DESELECT pool
        // comfortably absorbs them. Lifecycle-wise an HMAC engine never needs to retain key
        // material across a deselect because every consumer (Hkdf, MasterSeed, SecureChannel)
        // re-keys via {@link #init} on every fresh session.
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
     * Initialises the engine with a fresh key. Subsequent {@link #update update}/{@link #doFinal
     * doFinal} calls authenticate the messages fed into them under this key.
     *
     * <p>The key length is unbounded in either direction; per RFC 2104 §2 keys longer than the
     * block size are pre-hashed, and shorter keys are zero-padded.
     */
    public void init(byte[] keyBuf, short keyOff, short keyLen) {
        if (nativeSig != null) {
            nativeKey.setKey(keyBuf, keyOff, keyLen);
            nativeSig.init(nativeKey, Signature.MODE_SIGN);
            return;
        }

        // RFC 2104: build K' in softKey. Note both fill operations need to be guarded against the
        // {@code len = 0} edge: {@code Util.arrayFillNonAtomic(buf, offset, 0, 0)} is rejected by
        // the JC spec when {@code offset == buf.length}, which happens when {@code keyLen} is
        // exactly the block size (no zero-padding needed).
        if (keyLen > blockSize) {
            digest.reset();
            digest.doFinal(keyBuf, keyOff, keyLen, softKey, (short) 0);
            // K' = H(K) �?0x00 * (blockSize - hashSize). For SHA-256 hashSize=32, blockSize=64;
            // for SHA-512 hashSize=64, blockSize=128 �?the difference is always > 0 so no guard.
            Util.arrayFillNonAtomic(softKey, hashSize, (short) (blockSize - hashSize), (byte) 0);
        } else {
            Util.arrayCopyNonAtomic(keyBuf, keyOff, softKey, (short) 0, keyLen);
            short tail = (short) (blockSize - keyLen);
            if (tail > 0) {
                Util.arrayFillNonAtomic(softKey, keyLen, tail, (byte) 0);
            }
        }

        // Prime the inner digest with (K' XOR ipad). We mutate softKey in place, hash, then
        // restore it so the same buffer feeds the outer digest in doFinal() without keeping an
        // additional opadBlock copy. The two XOR passes are O(blockSize) and constant-time.
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
     * Consumes the final {@code inLen} bytes of the message, finishes the inner hash, runs the
     * outer hash, and writes the full {@link #getLength()} HMAC into {@code outBuf} at {@code
     * outOff}.
     *
     * @return {@link #getLength()} (always �?included so call sites can chain output offsets the
     *     same way they do for {@link Signature#sign})
     */
    public short doFinal(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
        if (nativeSig != null) {
            return nativeSig.sign(inBuf, inOff, inLen, outBuf, outOff);
        }

        // 1. inner = H((K' XOR ipad) �?all_updates �?inBuf[inOff..inOff+inLen])
        digest.doFinal(inBuf, inOff, inLen, softInner, (short) 0);

        // 2. outer = H((K' XOR opad) �?inner)
        xorBlock(softKey, OPAD);
        digest.reset();
        digest.update(softKey, (short) 0, blockSize);
        digest.doFinal(softInner, (short) 0, hashSize, outBuf, outOff);
        xorBlock(softKey, OPAD); // restore K' so reset() / re-init can wipe it cleanly

        // 3. inner is the full hash output; its bytes are no longer secret (the MAC itself is
        // public per protocol) but we wipe defensively so a misuse where a caller forgets to
        // reset() does not leak yesterday's MAC over today's session.
        Util.arrayFillNonAtomic(softInner, (short) 0, hashSize, (byte) 0);
        return hashSize;
    }

    /**
     * Convenience one-shot: combines {@link #init init} + {@link #doFinal doFinal} for callers that
     * have the full message in a single buffer at the time the key is fed in.
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

    /**
     * Wipes the engine's intermediate state and key material. Call this at the end of any flow that
     * touches a long-lived secret so the residue does not survive into the next session.
     */
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

    /**
     * In-place XOR of every byte of {@code buf[0..blockSize]} with {@code mask}. The loop is
     * data-independent in its branch behaviour, hence constant-time on every JC platform we target.
     */
    private void xorBlock(byte[] buf, byte mask) {
        for (short i = 0; i < blockSize; i++) {
            buf[i] ^= mask;
        }
    }
}
