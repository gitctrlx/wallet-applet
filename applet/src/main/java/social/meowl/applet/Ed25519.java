/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * RFC 8032 Ed25519 signing primitive backed by the J3R180 EC coprocessor.
 *
 * <p>JavaCard 3.0.4 silicon exposes EC scalar multiplication only for short Weierstrass curves;
 * Ed25519's native group is twisted Edwards. The signing pipeline therefore routes the two scalar
 * multiplications ({@code A = s·G} and {@code R = r·G}) through {@link Wei25519} — the
 * Weierstrass-form expression of curve25519 — using {@link EcPoint} on top of {@link
 * javacard.security.KeyAgreement#ALG_EC_SVDP_DH_PLAIN_XY}, then maps each affine Wei25519 result
 * back to RFC 8032 §5.1.2 little-endian compressed form via {@link Wei25519#encodeEdwards}.
 *
 * <h2>Cofactor handling — the {@code (s/8) · (8G)} trick</h2>
 *
 * <p>The clamped Ed25519 private scalar {@code s} occupies bits 254..3 of a 256-bit integer, so
 * {@code 2²⁵⁴ ≤ s < 2²⁵⁵}. {@link Wei25519}'s prime subgroup order {@code ℓ = 2²⁵² + …} is
 * materially smaller; {@link javacard.security.ECPrivateKey#setS} rejects any scalar {@code ≥ r}.
 * Clamping guarantees {@code s ≡ 0 (mod 8)}, so the identity
 *
 * <pre>
 *   s · G = (s / 8) · (8 · G)
 * </pre>
 *
 * <p>lets the pipeline compute the EC product as one coprocessor call against {@link Wei25519#G8}.
 * The scalar {@code s/8} is below {@code ℓ}, so the hardware accepts every step.
 *
 * <h2>Wire contract</h2>
 *
 * <p>Input: {@code [SLIP-10 leaf priv(32), message(*)]}; the message is hashed internally so the
 * card never parses payloads (MEAP-6 hash-only invariant). Output: {@code R(32) ‖ S(32)} in RFC
 * 8032 §5.1.2 little-endian compressed form. Every intermediate lives in a shared transient scratch
 * wiped by a {@code finally} on every code path.
 *
 * <h2>Scratch layout</h2>
 *
 * <p>All state lives in a 609-byte slice of the shared {@code CLEAR_ON_DESELECT} pool owned by
 * {@link MeowlApplet}.
 *
 * <pre>
 *   [  0.. 64) HASH    — SHA-512 output / 64-byte k·s product
 *   [ 64.. 96) S_BE    — clamped private scalar s (big-endian)
 *   [ 96..128) A_ED    — Ed25519 LE-compressed public key A
 *   [128..160) R_ED    — Ed25519 LE-compressed nonce point R
 *   [160..192) R_BE    — ephemeral scalar r mod ℓ (big-endian)
 *   [192..224) K_BE    — challenge scalar k mod ℓ (big-endian)
 *   [224..256) S_OUT   — final S = (r + k·s) mod ℓ; transiently holds s/8 during EC mult
 *   [256..321) WEI_PT  — 65-byte Wei25519 uncompressed point staging
 *   [321..609) WORK    — workspace (Wei25519 encode / Barrett scratch)
 * </pre>
 */
public final class Ed25519 {

    /** Length of the leaf private key (= SLIP-10 leaf {@code k_i}). */
    public static final short PRIVATE_KEY_LEN = (short) 32;

    /** Length of the compressed Ed25519 public key (RFC 8032 §5.1.2 encoded form). */
    public static final short PUBLIC_KEY_LEN = (short) 32;

    /** Length of the encoded signature {@code R ‖ S}. */
    public static final short SIGNATURE_LEN = (short) 64;

    /**
     * Total scratch footprint required by the pipeline: {@code WORK_OFF (321) + Wei25519 encode
     * scratch (288) = 609} bytes. The compiler rejects forward references between the two static
     * constants on a JC-targeted converter; keep the value materialised here and sanity-checked
     * against the {@code WORK_OFF} declaration below.
     */
    public static final short SCRATCH_LEN = (short) (321 + Wei25519.ENCODE_SCRATCH_LEN);

    private static final short SHA512_LEN = (short) 64;
    private static final short SCALAR_LEN = (short) 32;

    private static final short HASH_OFF = (short) 0;
    private static final short S_BE_OFF = (short) 64;
    private static final short A_ED_OFF = (short) 96;
    private static final short R_ED_OFF = (short) 128;
    private static final short R_BE_OFF = (short) 160;
    private static final short K_BE_OFF = (short) 192;
    private static final short S_OUT_OFF = (short) 224;
    private static final short WEI_PT_OFF = (short) 256;
    private static final short WORK_OFF = (short) 321;

    private final MessageDigest sha512;
    private final EcPoint ec;
    private final Fp25519Inv inv;
    private final Barrett barrettL;
    private final byte[] scratch;

    /**
     * @param sharedScratch singleton transient scratch (≥ {@link #SCRATCH_LEN} bytes) allocated by
     *     {@link MeowlApplet}.
     * @param sharedInv shared RSA-NOPAD modular inverter (one per applet); safe to share since APDU
     *     dispatch is single-threaded.
     */
    public Ed25519(byte[] sharedScratch, Fp25519Inv sharedInv) {
        if ((short) sharedScratch.length < SCRATCH_LEN) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        try {
            this.sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
        } catch (Exception e) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
            throw new RuntimeException(); // unreachable
        }
        this.ec =
                new EcPoint(
                        new EcPoint.CurveSetup() {
                            @Override
                            public void apply(javacard.security.ECPrivateKey key) {
                                Wei25519.setCurveParameters(key);
                            }
                        },
                        Wei25519.G,
                        (short) 0,
                        Wei25519.POINT_UNCOMPRESSED_LEN,
                        (short) 256);
        this.inv = sharedInv;
        this.barrettL = new Barrett(Wei25519.L, (short) 0, Wei25519.MU_L, (short) 0);
        this.scratch = sharedScratch;
    }

    /**
     * Derives the compressed Ed25519 public key from the 32-byte leaf private key.
     *
     * @return {@link #PUBLIC_KEY_LEN}
     */
    public short publicKey(byte[] skBuf, short skOff, byte[] outBuf, short outOff) {
        try {
            expandPrivateKey(skBuf, skOff);
            scalarMultByPrivateScalar();
            Wei25519.encodeEdwards(scratch, WEI_PT_OFF, outBuf, outOff, inv, scratch, WORK_OFF);
            return PUBLIC_KEY_LEN;
        } finally {
            wipeScratch();
        }
    }

    /**
     * RFC 8032 §5.1.6 sign. Produces the 64-byte {@code R ‖ S} signature of {@code
     * msgBuf[msgOff..msgOff + msgLen]} under the SLIP-10 leaf private key {@code skBuf[skOff..+
     * 32]}.
     *
     * @return {@link #SIGNATURE_LEN}
     */
    public short sign(
            byte[] skBuf,
            short skOff,
            byte[] msgBuf,
            short msgOff,
            short msgLen,
            byte[] outBuf,
            short outOff) {
        try {
            // 1. h = SHA-512(sk); s ← clamp(h[0..32]) BE in S_BE; prefix = h[32..64] kept in
            //    HASH[32..64].
            expandPrivateKey(skBuf, skOff);

            // 2-3. A_wei = s · G_wei (via the (s/8)·(8G) trick); A_ed = encodeEdwards(A_wei).
            scalarMultByPrivateScalar();
            Wei25519.encodeEdwards(scratch, WEI_PT_OFF, scratch, A_ED_OFF, inv, scratch, WORK_OFF);

            // 4. r = SHA-512(prefix || msg) mod ℓ. The SHA-512 input contains the secret RFC 8032
            //    prefix, so the 64-byte dividend fed to Barrett is SECRET. Reverse LE → BE then
            //    reduce mod ℓ.
            sha512.reset();
            sha512.update(scratch, (short) (HASH_OFF + SCALAR_LEN), SCALAR_LEN);
            sha512.doFinal(msgBuf, msgOff, msgLen, scratch, HASH_OFF);
            reverseBytes(scratch, HASH_OFF, SHA512_LEN);
            barrettL.reduce(scratch, HASH_OFF, scratch, WORK_OFF, scratch, R_BE_OFF);

            // 5. R_wei = r · G_wei. r is already < ℓ so a single multiplyG suffices.
            ec.multiplyG(scratch, R_BE_OFF, SCALAR_LEN, scratch, WEI_PT_OFF);
            // 6. R_ed = encodeEdwards(R_wei).
            Wei25519.encodeEdwards(scratch, WEI_PT_OFF, scratch, R_ED_OFF, inv, scratch, WORK_OFF);

            // 7. k = SHA-512(R_ed || A_ed || msg) mod ℓ.
            sha512.reset();
            sha512.update(scratch, R_ED_OFF, SCALAR_LEN);
            sha512.update(scratch, A_ED_OFF, SCALAR_LEN);
            sha512.doFinal(msgBuf, msgOff, msgLen, scratch, HASH_OFF);
            reverseBytes(scratch, HASH_OFF, SHA512_LEN);
            barrettL.reduce(scratch, HASH_OFF, scratch, WORK_OFF, scratch, K_BE_OFF);

            // 8. S = (r + k · s) mod ℓ. The 64-byte k·s product is secret; Barrett-reduce it
            //    constant-time then add r and conditionally subtract ℓ.
            BigNat.mult(scratch, K_BE_OFF, scratch, S_BE_OFF, SCALAR_LEN, scratch, HASH_OFF);
            barrettL.reduce(
                    scratch, HASH_OFF, scratch, WORK_OFF, scratch, (short) (HASH_OFF + SCALAR_LEN));
            BigNat.copy(scratch, R_BE_OFF, scratch, S_OUT_OFF, SCALAR_LEN);
            boolean carry =
                    BigNat.add(
                            scratch,
                            S_OUT_OFF,
                            scratch,
                            (short) (HASH_OFF + SCALAR_LEN),
                            SCALAR_LEN);
            short carryMask = (short) (carry ? -1 : 0);
            short lessMask =
                    BigNat.ctLessThan(scratch, S_OUT_OFF, Wei25519.L, (short) 0, SCALAR_LEN);
            short reduceMask = (short) (carryMask | ~lessMask);
            BigNat.condSubInPlace(
                    scratch, S_OUT_OFF, Wei25519.L, (short) 0, SCALAR_LEN, reduceMask);

            // 9. Output R_ed || S_LE.
            Util.arrayCopyNonAtomic(scratch, R_ED_OFF, outBuf, outOff, SCALAR_LEN);
            for (short i = 0; i < SCALAR_LEN; i++) {
                outBuf[(short) (outOff + SCALAR_LEN + i)] =
                        scratch[(short) (S_OUT_OFF + SCALAR_LEN - 1 - i)];
            }
            return SIGNATURE_LEN;
        } finally {
            wipeScratch();
        }
    }

    private void scalarMultByPrivateScalar() {
        copyShiftRight3(scratch, S_BE_OFF, scratch, S_OUT_OFF);
        ec.multiplyPoint(
                scratch, S_OUT_OFF, SCALAR_LEN, Wei25519.G8, (short) 0, scratch, WEI_PT_OFF);
    }

    /**
     * Populates {@code S_BE} with the clamped private scalar (big-endian) and leaves the RFC 8032
     * prefix at {@code HASH[32..64]}. The clamped LE scalar at {@code HASH[0..32]} is zeroed after
     * the reversal so downstream {@code sha512.doFinal} calls can reuse the head of the hash slot.
     */
    private void expandPrivateKey(byte[] skBuf, short skOff) {
        sha512.reset();
        sha512.doFinal(skBuf, skOff, PRIVATE_KEY_LEN, scratch, HASH_OFF);
        scratch[HASH_OFF] &= (byte) 248;
        scratch[(short) (HASH_OFF + 31)] &= (byte) 127;
        scratch[(short) (HASH_OFF + 31)] |= (byte) 64;
        for (short i = 0; i < SCALAR_LEN; i++) {
            scratch[(short) (S_BE_OFF + i)] = scratch[(short) (HASH_OFF + SCALAR_LEN - 1 - i)];
        }
        Util.arrayFillNonAtomic(scratch, HASH_OFF, SCALAR_LEN, (byte) 0);
    }

    /**
     * {@code dst[..32] ← src[..32] >> 3}. Big-endian byte-by-byte right shift by 3 bits, carrying
     * the bits that fall out of each byte's bottom into the top of the next byte. The clamping step
     * in {@link #expandPrivateKey} guarantees the bottom 3 bits of {@code src} are zero, so {@code
     * dst} is the exact integer quotient.
     */
    private static void copyShiftRight3(byte[] src, short srcOff, byte[] dst, short dstOff) {
        short carry = 0;
        for (short i = 0; i < SCALAR_LEN; i++) {
            short b = (short) (src[(short) (srcOff + i)] & 0xFF);
            dst[(short) (dstOff + i)] = (byte) ((carry | (b >>> 3)) & 0xFF);
            carry = (short) ((b & 0x07) << 5);
        }
    }

    private static void reverseBytes(byte[] buf, short off, short len) {
        short half = (short) (len / 2);
        for (short i = 0; i < half; i++) {
            short lo = (short) (off + i);
            short hi = (short) (off + len - 1 - i);
            byte tmp = buf[lo];
            buf[lo] = buf[hi];
            buf[hi] = tmp;
        }
    }

    private void wipeScratch() {
        Util.arrayFillNonAtomic(scratch, (short) 0, SCRATCH_LEN, (byte) 0);
        ec.wipe();
    }
}
