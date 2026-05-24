/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.Util;

/**
 * Field arithmetic over the curve25519 prime {@code p = 2²⁵⁵ − 19}.
 *
 * <p>Used by {@link Wei25519} to perform the Edwards ↔ Weierstrass isomorphism after the hardware
 * EC coprocessor returns an affine Wei25519 point. The v1 {@code Field25519} class was the inner
 * loop of the software Edwards group law; in v2 only the encoding transformation lives here, so the
 * API is smaller. Scalar arithmetic ({@link #add}, {@link #sub}, {@link #neg}) delegates to {@link
 * BigNat}; multiplicative arithmetic ({@link #mul}, {@link #sqr}) uses schoolbook plus a
 * constant-time pseudo-Mersenne reducer that runs under 10 ms on J3R180 silicon. Modular inversion
 * is delegated to {@link Fp25519Inv} so the RSA dependency stays explicit.
 *
 * <h2>Representation</h2>
 *
 * <p>Every field element is a {@link #LEN}-byte big-endian unsigned integer in canonical {@code [0,
 * p)} form. Values arriving as raw schoolbook products MUST be canonicalised via {@link
 * #reducePseudoMersenne} before being fed back into the additive API.
 *
 * <h2>Timing model</h2>
 *
 * <p>Every method is constant-time over the operand bits. Additive helpers walk every byte
 * unconditionally and use mask-driven canonicalisation; multiplicative helpers use the constant-
 * time reducer below.
 */
public final class Fp25519 {

    /** Length of every field element / scratch slot, in bytes. */
    public static final short LEN = (short) 32;

    /** {@code p = 2²⁵⁵ − 19}, 32 bytes big-endian. */
    public static final byte[] P = {
        (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xED,
    };

    /** Scratch budget for {@link #mul} / {@link #sqr}: 64 bytes for the unreduced product. */
    public static final short MUL_SCRATCH_LEN = (short) 64;

    private Fp25519() {}

    /** {@code dst[..] ← src[..]} (32 bytes). */
    public static void copy(byte[] src, short srcOff, byte[] dst, short dstOff) {
        Util.arrayCopyNonAtomic(src, srcOff, dst, dstOff, LEN);
    }

    /** {@code dst[..] ← 0} (32 bytes). */
    public static void zero(byte[] dst, short dstOff) {
        Util.arrayFillNonAtomic(dst, dstOff, LEN, (byte) 0);
    }

    /** {@code dst[..] ← 1} (canonical 32-byte big-endian one). */
    public static void one(byte[] dst, short dstOff) {
        Util.arrayFillNonAtomic(dst, dstOff, LEN, (byte) 0);
        dst[(short) (dstOff + LEN - 1)] = (byte) 0x01;
    }

    /** Returns {@code true} iff {@code a == 0} in canonical form. Constant-time. */
    public static boolean isZero(byte[] a, short aOff) {
        return BigNat.ctIsZero(a, aOff, LEN) != 0;
    }

    /** Returns {@code true} iff bit 0 of canonical {@code a} is set. */
    public static boolean isOdd(byte[] a, short aOff) {
        return (a[(short) (aOff + LEN - 1)] & 0x01) != 0;
    }

    /** Constant-time equality of two canonical field elements. */
    public static boolean equals(byte[] a, short aOff, byte[] b, short bOff) {
        return BigNat.ctEquals(a, aOff, b, bOff, LEN);
    }

    /** {@code out ← (a + b) mod p}. Output may alias either input. Constant-time. */
    public static void add(byte[] a, short aOff, byte[] b, short bOff, byte[] out, short outOff) {
        BigNat.modAdd(a, aOff, b, bOff, P, (short) 0, out, outOff, LEN);
    }

    /** {@code out ← (a − b) mod p}. Output may alias either input. Constant-time. */
    public static void sub(byte[] a, short aOff, byte[] b, short bOff, byte[] out, short outOff) {
        BigNat.modSub(a, aOff, b, bOff, P, (short) 0, out, outOff, LEN);
    }

    /**
     * {@code out ← (−a) mod p}. Output may alias {@code a}. Constant-time: always runs {@code p −
     * a}; the {@code a == 0} corner case is masked back to {@code 0}.
     */
    public static void neg(byte[] a, short aOff, byte[] out, short outOff) {
        short borrow = 0;
        for (short i = (short) (LEN - 1); i >= 0; i--) {
            short pi = (short) (P[i] & BigNat.DIGIT_MASK);
            short ai = (short) (a[(short) (aOff + i)] & BigNat.DIGIT_MASK);
            short d = (short) (pi - ai - borrow);
            out[(short) (outOff + i)] = (byte) d;
            borrow = (short) ((d >>> 15) & 1);
        }
        short zeroMask = BigNat.ctIsZero(a, aOff, LEN);
        BigNat.ctSelectSub(out, outOff, P, (short) 0, LEN, zeroMask);
    }

    /**
     * {@code dst ← (a + 1) mod p}. Used by {@link Wei25519} for the {@code (u + 1)} denominator.
     * Output may alias {@code a}. Constant-time.
     */
    public static void increment(byte[] a, short aOff, byte[] dst, short dstOff) {
        short carry = 1;
        for (short i = (short) (LEN - 1); i >= 0; i--) {
            short sum = (short) ((a[(short) (aOff + i)] & BigNat.DIGIT_MASK) + carry);
            dst[(short) (dstOff + i)] = (byte) sum;
            carry = (short) ((sum >>> BigNat.DIGIT_BITS) & 0x01);
        }
        short geMask = (short) ~BigNat.ctLessThan(dst, dstOff, P, (short) 0, LEN);
        BigNat.ctSelectSub(dst, dstOff, P, (short) 0, LEN, geMask);
    }

    /**
     * {@code dst ← (a − 1) mod p}. Used by {@link Wei25519} for the {@code (u − 1)} numerator.
     * Output may alias {@code a}. Constant-time.
     */
    public static void decrement(byte[] a, short aOff, byte[] dst, short dstOff) {
        short borrow = 1;
        for (short i = (short) (LEN - 1); i >= 0; i--) {
            short diff = (short) ((a[(short) (aOff + i)] & BigNat.DIGIT_MASK) - borrow);
            dst[(short) (dstOff + i)] = (byte) diff;
            borrow = (short) ((diff >>> 15) & 1);
        }
        short addMask = (short) -borrow;
        BigNat.ctSelectAdd(dst, dstOff, P, (short) 0, LEN, addMask);
    }

    /**
     * {@code out ← (a · b) mod p}. {@code out} may alias {@code a} or {@code b}; {@code scratch}
     * must not alias either input.
     */
    public static void mul(
            byte[] a,
            short aOff,
            byte[] b,
            short bOff,
            byte[] out,
            short outOff,
            byte[] scratch,
            short scratchOff) {
        BigNat.mult(a, aOff, b, bOff, LEN, scratch, scratchOff);
        reducePseudoMersenne(scratch, scratchOff, out, outOff);
        Util.arrayFillNonAtomic(scratch, scratchOff, MUL_SCRATCH_LEN, (byte) 0);
    }

    /** {@code out ← (a · a) mod p}. Implemented as {@code mul(a, a)} for code-size minimality. */
    public static void sqr(
            byte[] a, short aOff, byte[] out, short outOff, byte[] scratch, short scratchOff) {
        mul(a, aOff, a, aOff, out, outOff, scratch, scratchOff);
    }

    /**
     * Constant-time pseudo-Mersenne reduction: writes {@code x mod p} to {@code dst[..32]} given
     * the 64-byte big-endian product {@code x ∈ [0, 2⁵¹²)} at {@code x[xOff..]}.
     *
     * <p>Folds using {@code 2²⁵⁶ ≡ 38 (mod p)}. Splits {@code x = x_hi · 2²⁵⁶ + x_lo} so {@code x ≡
     * 38·x_hi + x_lo (mod p)}. Four passes, each constant-time:
     *
     * <ol>
     *   <li>{@code r := (38·x_hi + x_lo) mod 2²⁵⁶}, capturing 6-bit carry {@code c₁ ∈ [0, 39]}.
     *   <li>{@code r += 38·c₁}; result {@code ≤ 2²⁵⁶ + 1481 < 2²⁵⁷}; new carry {@code c₂ ∈ {0, 1}}.
     *   <li>{@code r += 38·c₂}; if {@code c₂ = 1} the body is now {@code < 2²⁵⁶}; if {@code c₂ = 0}
     *       it is unchanged.
     *   <li>Two unconditional mask-driven {@code condSub(r, p)} passes. After the first {@code r ∈
     *       [0, 2p)}, after the second {@code r ∈ [0, p)}.
     * </ol>
     */
    public static void reducePseudoMersenne(byte[] x, short xOff, byte[] dst, short dstOff) {
        short carry = 0;
        for (short i = (short) (LEN - 1); i >= 0; i--) {
            short prod = (short) (38 * (x[(short) (xOff + i)] & BigNat.DIGIT_MASK));
            short sum =
                    (short)
                            ((x[(short) (xOff + LEN + i)] & BigNat.DIGIT_MASK)
                                    + (prod & BigNat.DIGIT_MASK)
                                    + carry);
            dst[(short) (dstOff + i)] = (byte) sum;
            carry =
                    (short)
                            (((prod >>> BigNat.DIGIT_BITS) & BigNat.DIGIT_MASK)
                                    + ((sum >>> BigNat.DIGIT_BITS) & BigNat.DIGIT_MASK));
        }
        short carry38 = (short) (38 * carry);
        short low = (short) (carry38 & BigNat.DIGIT_MASK);
        short high = (short) ((carry38 >>> BigNat.DIGIT_BITS) & BigNat.DIGIT_MASK);
        short sum = (short) ((dst[(short) (dstOff + LEN - 1)] & BigNat.DIGIT_MASK) + low);
        dst[(short) (dstOff + LEN - 1)] = (byte) sum;
        short c2 = (short) ((sum >>> BigNat.DIGIT_BITS) & 1);
        sum = (short) ((dst[(short) (dstOff + LEN - 2)] & BigNat.DIGIT_MASK) + high + c2);
        dst[(short) (dstOff + LEN - 2)] = (byte) sum;
        c2 = (short) ((sum >>> BigNat.DIGIT_BITS) & 1);
        for (short i = (short) (LEN - 3); i >= 0; i--) {
            sum = (short) ((dst[(short) (dstOff + i)] & BigNat.DIGIT_MASK) + c2);
            dst[(short) (dstOff + i)] = (byte) sum;
            c2 = (short) ((sum >>> BigNat.DIGIT_BITS) & 1);
        }
        short prod = (short) (38 * c2);
        sum = (short) ((dst[(short) (dstOff + LEN - 1)] & BigNat.DIGIT_MASK) + prod);
        dst[(short) (dstOff + LEN - 1)] = (byte) sum;
        short c3 = (short) ((sum >>> BigNat.DIGIT_BITS) & 1);
        for (short i = (short) (LEN - 2); i >= 0; i--) {
            sum = (short) ((dst[(short) (dstOff + i)] & BigNat.DIGIT_MASK) + c3);
            dst[(short) (dstOff + i)] = (byte) sum;
            c3 = (short) ((sum >>> BigNat.DIGIT_BITS) & 1);
        }
        short ge1 = (short) ~BigNat.ctLessThan(dst, dstOff, P, (short) 0, LEN);
        BigNat.ctSelectSub(dst, dstOff, P, (short) 0, LEN, ge1);
        short ge2 = (short) ~BigNat.ctLessThan(dst, dstOff, P, (short) 0, LEN);
        BigNat.ctSelectSub(dst, dstOff, P, (short) 0, LEN, ge2);
    }
}
