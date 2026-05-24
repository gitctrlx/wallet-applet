/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.Util;

/**
 * Multi-precision unsigned big-integer primitives over big-endian byte arrays.
 *
 * <p>JavaCard 3.0.4 ships no native {@code BigInteger}; every scalar arithmetic step the signing
 * primitives need lives here. All methods are static and operate on caller-supplied buffers; the
 * class holds no state. Aliasing the destination with an input is safe in every method: each byte
 * of every operand is read before the matching destination byte is written.
 *
 * <p>Operands are big-endian and sized in bytes via the {@code size} parameter. Most callers work
 * with 32-byte scalars; {@link #multAsymmetric} and the conditional helpers accept any size so
 * {@link Barrett}'s 33-byte intermediates share the same API.
 *
 * <h2>Timing model</h2>
 *
 * <ul>
 *   <li><b>Variable-time</b>: {@link #lessThan}, {@link #isZero}. These early-exit and MUST only be
 *       fed public material (host-provided lengths, recovered public points).
 *   <li><b>Constant-time</b>: every {@code ct*} primitive walks every byte unconditionally and uses
 *       a mask-driven select between two computed values.
 *   <li><b>Schedule-independent</b>: {@link #add}, {@link #sub}, {@link #mult}, {@link
 *       #multAsymmetric}, {@link #ctAddLowerHalf}, {@link #modAdd}, {@link #modSub}. The byte-level
 *       loop count is fixed by the {@code size} arguments alone; values flowing through the carry /
 *       borrow chain are data-dependent but the work pattern is not. Safe on secrets.
 * </ul>
 *
 * <p>Variable-time modular reduction is intentionally absent — use {@link Barrett} (constant-time,
 * pre-computed μ) for any {@code x mod m} where {@code x} or {@code m} is secret-derived. The v1
 * {@code Bignat.mod} long-division kernel was the source of audit finding A-16 and is gone.
 */
public final class BigNat {

    /** Mask used to widen a {@code byte} to an unsigned value in the {@code short} domain. */
    public static final short DIGIT_MASK = 0xFF;

    /** Bits per digit. The class works in radix {@code 2⁸}. */
    public static final short DIGIT_BITS = 8;

    private BigNat() {}

    /** {@code dst[..] ← src[..]} for {@code size} bytes. Thin wrapper over {@link Util}. */
    public static void copy(byte[] src, short srcOff, byte[] dst, short dstOff, short size) {
        Util.arrayCopyNonAtomic(src, srcOff, dst, dstOff, size);
    }

    /** {@code dst[..] ← 0} for {@code size} bytes. */
    public static void zero(byte[] dst, short dstOff, short size) {
        Util.arrayFillNonAtomic(dst, dstOff, size, (byte) 0);
    }

    /**
     * In-place unsigned addition: {@code x += y}; both operands are {@code size} bytes big-endian.
     * Destination may alias the source.
     *
     * @return {@code true} iff a carry propagated past the most-significant digit
     */
    public static boolean add(byte[] x, short xOff, byte[] y, short yOff, short size) {
        short carry = 0;
        for (short i = (short) (size - 1); i >= 0; i--) {
            short sum =
                    (short)
                            ((x[(short) (xOff + i)] & DIGIT_MASK)
                                    + (y[(short) (yOff + i)] & DIGIT_MASK)
                                    + carry);
            x[(short) (xOff + i)] = (byte) sum;
            carry = (short) ((sum >>> DIGIT_BITS) & 0x01);
        }
        return carry != 0;
    }

    /**
     * In-place unsigned subtraction: {@code x -= y}.
     *
     * @return {@code true} iff the subtraction underflowed
     */
    public static boolean sub(byte[] x, short xOff, byte[] y, short yOff, short size) {
        short borrow = 0;
        for (short i = (short) (size - 1); i >= 0; i--) {
            short diff =
                    (short)
                            ((x[(short) (xOff + i)] & DIGIT_MASK)
                                    - (y[(short) (yOff + i)] & DIGIT_MASK)
                                    - borrow);
            x[(short) (xOff + i)] = (byte) diff;
            borrow = (short) ((diff >>> 15) & 1);
        }
        return borrow != 0;
    }

    /**
     * Constant-time add of a half-width operand into the lower half of a full-width accumulator:
     * {@code x[xOff..xOff + 2·halfSize] += zeroExtend(y[yOff..yOff + halfSize])}.
     *
     * <p>The lower half performs a real byte-wise add; the upper half walks every byte propagating
     * the carry unconditionally rather than breaking out as soon as it settles. Used by {@link
     * Schnorr} to fold the ephemeral nonce {@code k} into the 64-byte {@code e·d} product without
     * exposing the carry-stop position of the secret sum.
     */
    public static void ctAddLowerHalf(byte[] x, short xOff, byte[] y, short yOff, short halfSize) {
        short carry = 0;
        for (short i = (short) (halfSize - 1); i >= 0; i--) {
            short sum =
                    (short)
                            ((x[(short) (xOff + halfSize + i)] & DIGIT_MASK)
                                    + (y[(short) (yOff + i)] & DIGIT_MASK)
                                    + carry);
            x[(short) (xOff + halfSize + i)] = (byte) sum;
            carry = (short) ((sum >>> DIGIT_BITS) & 0x01);
        }
        for (short i = (short) (halfSize - 1); i >= 0; i--) {
            short sum = (short) ((x[(short) (xOff + i)] & DIGIT_MASK) + carry);
            x[(short) (xOff + i)] = (byte) sum;
            carry = (short) ((sum >>> DIGIT_BITS) & 0x01);
        }
    }

    /**
     * Schoolbook unsigned multiplication: {@code z[zOff..zOff + 2·size] = x · y} for equal-width
     * operands. The destination is fully overwritten and MUST NOT alias either source.
     *
     * <p>For 32-byte operands this is 1024 byte-multiplies. On 32 MHz JC silicon this runs under 10
     * ms — comparable to a native ECDH on small scalars.
     */
    public static void mult(
            byte[] x, short xOff, byte[] y, short yOff, short size, byte[] z, short zOff) {
        multAsymmetric(x, xOff, size, y, yOff, size, z, zOff);
    }

    /**
     * Schoolbook unsigned multiplication of unequal-width operands: {@code z[zOff..zOff + xSize +
     * ySize] = x · y}. Used by {@link Barrett} for its 33×33 and 33×32 intermediates.
     *
     * <p>The destination MUST NOT alias either source. Schedule-independent over the operand bytes:
     * every {@code (i, j)} cell is visited regardless of byte values.
     */
    public static void multAsymmetric(
            byte[] x,
            short xOff,
            short xSize,
            byte[] y,
            short yOff,
            short ySize,
            byte[] z,
            short zOff) {
        Util.arrayFillNonAtomic(z, zOff, (short) (xSize + ySize), (byte) 0);
        for (short i = (short) (xSize - 1); i >= 0; i--) {
            short carry = 0;
            short xi = (short) (x[(short) (xOff + i)] & DIGIT_MASK);
            for (short j = (short) (ySize - 1); j >= 0; j--) {
                short yj = (short) (y[(short) (yOff + j)] & DIGIT_MASK);
                short prod = (short) (xi * yj);
                short k = (short) (zOff + i + j + 1);
                short sum = (short) ((z[k] & DIGIT_MASK) + (prod & DIGIT_MASK) + carry);
                z[k] = (byte) sum;
                carry =
                        (short)
                                (((prod >>> DIGIT_BITS) & DIGIT_MASK)
                                        + ((sum >>> DIGIT_BITS) & DIGIT_MASK));
            }
            short k = (short) (zOff + i);
            z[k] = (byte) ((z[k] & DIGIT_MASK) + carry);
        }
    }

    /**
     * Strict less-than comparison of two equal-size big-endian unsigned integers.
     *
     * <p><b>Variable-time</b>: exits on the first differing byte. MUST NOT be used on secret-
     * derived inputs; use {@link #ctLessThan} for those.
     */
    public static boolean lessThan(byte[] x, short xOff, byte[] y, short yOff, short size) {
        for (short i = 0; i < size; i++) {
            short xs = (short) (x[(short) (xOff + i)] & DIGIT_MASK);
            short ys = (short) (y[(short) (yOff + i)] & DIGIT_MASK);
            if (xs < ys) {
                return true;
            }
            if (xs > ys) {
                return false;
            }
        }
        return false;
    }

    /** Variable-time {@code x == 0}. Use {@link #ctIsZero} for secret-derived operands. */
    public static boolean isZero(byte[] x, short xOff, short size) {
        for (short i = 0; i < size; i++) {
            if (x[(short) (xOff + i)] != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Constant-time strict less-than: returns {@code -1} (0xFFFF) iff {@code x < y}, {@code 0}
     * otherwise. Performs the full trial-subtract; every byte is read MSB-to-LSB on every call.
     */
    public static short ctLessThan(byte[] x, short xOff, byte[] y, short yOff, short size) {
        short borrow = 0;
        for (short i = (short) (size - 1); i >= 0; i--) {
            short diff =
                    (short)
                            ((x[(short) (xOff + i)] & DIGIT_MASK)
                                    - (y[(short) (yOff + i)] & DIGIT_MASK)
                                    - borrow);
            borrow = (short) ((diff >>> 15) & 1);
        }
        return (short) -borrow;
    }

    /**
     * Constant-time {@code x == 0}: returns {@code -1} iff every byte is zero, {@code 0} otherwise.
     * Every intermediate stays in the {@code short} domain because the JC 3.0.5 CAP converter
     * rejects {@code int}-typed locals.
     */
    public static short ctIsZero(byte[] x, short xOff, short size) {
        short acc = 0;
        for (short i = 0; i < size; i++) {
            acc |= (short) (x[(short) (xOff + i)] & DIGIT_MASK);
        }
        short orNeg = (short) (acc | (short) -acc);
        short nonZero = (short) ((orNeg >>> 15) & 1);
        return (short) (nonZero - 1);
    }

    /**
     * Constant-time equality. XOR-accumulates every byte pair and only inspects the result once at
     * the end. Use for MAC tags, authenticator output, and signature equality checks where one side
     * is secret.
     */
    public static boolean ctEquals(byte[] x, short xOff, byte[] y, short yOff, short size) {
        byte diff = 0;
        for (short i = 0; i < size; i++) {
            diff |= (byte) (x[(short) (xOff + i)] ^ y[(short) (yOff + i)]);
        }
        return diff == 0;
    }

    /**
     * Mask-driven in-place subtract: {@code if (mask == -1) x -= y; else no-op}. Both buffers are
     * {@code size} bytes. The per-byte subtrahend is gated by the mask before the trial subtract,
     * so when {@code mask == 0} the operation reduces to a pure read-write of zero into the borrow
     * chain — same wall-clock as the active path.
     */
    public static void ctSelectSub(
            byte[] x, short xOff, byte[] y, short yOff, short size, short mask) {
        short borrow = 0;
        for (short i = (short) (size - 1); i >= 0; i--) {
            short yi = (short) ((y[(short) (yOff + i)] & DIGIT_MASK) & mask);
            short diff = (short) ((x[(short) (xOff + i)] & DIGIT_MASK) - yi - borrow);
            x[(short) (xOff + i)] = (byte) diff;
            borrow = (short) ((diff >>> 15) & 1);
        }
    }

    /** Mask-driven in-place add. Symmetric to {@link #ctSelectSub}. */
    public static void ctSelectAdd(
            byte[] x, short xOff, byte[] y, short yOff, short size, short mask) {
        short carry = 0;
        for (short i = (short) (size - 1); i >= 0; i--) {
            short yi = (short) ((y[(short) (yOff + i)] & DIGIT_MASK) & mask);
            short sum = (short) ((x[(short) (xOff + i)] & DIGIT_MASK) + yi + carry);
            x[(short) (xOff + i)] = (byte) sum;
            carry = (short) ((sum >>> DIGIT_BITS) & 1);
        }
    }

    /**
     * Mask-driven byte-wise conditional copy: {@code if (mask == -1) dst[..] = src[..]; else
     * no-op}. {@code mask} must be {@code -1} (0xFFFF) or {@code 0}.
     */
    public static void ctSelectCopy(
            byte[] dst, short dstOff, byte[] src, short srcOff, short size, short mask) {
        short keep = (short) ~mask;
        for (short i = 0; i < size; i++) {
            short s = (short) (src[(short) (srcOff + i)] & DIGIT_MASK);
            short d = (short) (dst[(short) (dstOff + i)] & DIGIT_MASK);
            dst[(short) (dstOff + i)] = (byte) ((s & mask) | (d & keep));
        }
    }

    /**
     * Mask-driven in-place modular negation: {@code if (mask == -1) a ← m − a; else no-op}. The
     * subtraction is always computed; only the per-byte write is mask-selected, so wall-clock is
     * independent of {@code mask}.
     *
     * <p>Caller MUST ensure {@code 0 ≤ a < m} on entry; the result inherits that invariant. Used by
     * {@link Schnorr} to flip the secret-derived nonce on the y-parity bit, and by ECDSA's
     * low-{@code s} normalisation.
     */
    public static void ctSelectNeg(
            byte[] a, short aOff, byte[] m, short mOff, short size, short mask) {
        short keep = (short) ~mask;
        short borrow = 0;
        for (short i = (short) (size - 1); i >= 0; i--) {
            short ai = (short) (a[(short) (aOff + i)] & DIGIT_MASK);
            short diff = (short) ((m[(short) (mOff + i)] & DIGIT_MASK) - ai - borrow);
            borrow = (short) ((diff >>> 15) & 1);
            a[(short) (aOff + i)] = (byte) ((diff & mask) | (ai & keep));
        }
    }

    /**
     * Constant-time modular add: {@code out ← (a + b) mod m}, every operand {@code size} bytes.
     * Inputs MUST be in {@code [0, m)}. Destination may alias either source.
     *
     * <p>Runs an unconditional add followed by one mask-driven conditional subtract of {@code m} —
     * the unreduced sum is in {@code [0, 2m)} so one subtract suffices.
     */
    public static void modAdd(
            byte[] a,
            short aOff,
            byte[] b,
            short bOff,
            byte[] m,
            short mOff,
            byte[] out,
            short outOff,
            short size) {
        short carry = 0;
        for (short i = (short) (size - 1); i >= 0; i--) {
            short sum =
                    (short)
                            ((a[(short) (aOff + i)] & DIGIT_MASK)
                                    + (b[(short) (bOff + i)] & DIGIT_MASK)
                                    + carry);
            out[(short) (outOff + i)] = (byte) sum;
            carry = (short) ((sum >>> DIGIT_BITS) & 0x01);
        }
        short carryMask = (short) -carry;
        short lessMask = ctLessThan(out, outOff, m, mOff, size);
        short reduceMask = (short) (carryMask | ~lessMask);
        ctSelectSub(out, outOff, m, mOff, size, reduceMask);
    }

    /**
     * Constant-time modular subtract: {@code out ← (a − b) mod m}. Inputs MUST be in {@code [0,
     * m)}; destination may alias either source.
     *
     * <p>Runs an unconditional byte-wise subtract; if the result underflowed, a mask-driven add of
     * {@code m} restores it into {@code [0, m)}.
     */
    public static void modSub(
            byte[] a,
            short aOff,
            byte[] b,
            short bOff,
            byte[] m,
            short mOff,
            byte[] out,
            short outOff,
            short size) {
        short borrow = 0;
        for (short i = (short) (size - 1); i >= 0; i--) {
            short diff =
                    (short)
                            ((a[(short) (aOff + i)] & DIGIT_MASK)
                                    - (b[(short) (bOff + i)] & DIGIT_MASK)
                                    - borrow);
            out[(short) (outOff + i)] = (byte) diff;
            borrow = (short) ((diff >>> 15) & 1);
        }
        short addMask = (short) -borrow;
        ctSelectAdd(out, outOff, m, mOff, size, addMask);
    }
}
