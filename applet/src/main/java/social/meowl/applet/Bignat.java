/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.Util;

/**
 * Multi-precision unsigned big-integer primitives over big-endian byte arrays.
 *
 * <p>JavaCard 3.0.5 ships no native {@code BigInteger}; the Schnorr and Ed25519 paths need
 * arbitrary-length add/sub with carry, 32-byte multiply, and variable-length modular reduction.
 * This class implements them in pure software.
 *
 * <p>{@link #mult} is a direct schoolbook multiplication. {@link #mod} and its helpers ({@link
 * #shiftBits}, {@link #shiftLesser}, {@link #timesMinus}, {@link #highestBit}) are adapted from <a
 * href="https://github.com/Toporin/SatochipApplet">Toporin's Satochip Biginteger</a>
 * (GPL-2.0-or-later, derived from the <a
 * href="https://www.cs.ru.nl/~erikpoll/papers/ovchip.pdf">Radboud OV-chip 2.0 Bignat</a>);
 * re-licensed to AGPL-3.0-or-later via the GPLv2 upgrade clause. See {@code REUSE.toml} for SPDX.
 *
 * <p>All operands are big-endian. All methods are static and operate on caller-supplied buffers.
 *
 * <p><b>Timing model.</b> The bulk kernels ({@link #add}, {@link #sub}, {@link #mult}, {@link
 * #mod}, {@link #lessThan}, {@link #isZero}) are <strong>not</strong> constant-time. Call them only
 * on (a) public material, (b) material mixed with sufficient randomness that the timing reveals no
 * secret bits, or (c) inside {@link Edwards25519#scalarMult} whose ladder runs on a randomised
 * projective coordinate ({@link Edwards25519#randomizeProjective}).
 *
 * <p>The mask-based helpers ({@link #condSubInPlace}, {@link #condAddInPlace}, {@link #ctLessThan},
 * {@link #ctIsZero}) are constant-time, following the libsodium / fiat-crypto "always do the work,
 * mask the result" pattern. Use these for reduction steps that touch secrets.
 */
public final class Bignat {

    private static final short DIGIT_MASK = 0xFF;
    private static final short DIGIT_LEN = 8;
    private static final short DOUBLE_DIGIT_LEN = 16;
    private static final short POSITIVE_DOUBLE_DIGIT_MASK = 0x7FFF;

    private Bignat() {}

    /**
     * Big-endian unsigned addition: {@code x[xOff..xOff+size] += y[yOff..yOff+size]}. The
     * destination ({@code x}) may overlap the source ({@code y}); the inner loop reads each input
     * byte before writing the corresponding output byte.
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
            carry = (short) ((sum >>> DIGIT_LEN) & 0x01);
        }
        return carry != 0;
    }

    /**
     * Big-endian unsigned subtraction: {@code x[xOff..xOff+size] -= y[yOff..yOff+size]}.
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
            borrow = (short) ((diff < 0) ? 1 : 0);
        }
        return borrow != 0;
    }

    /**
     * Strict less-than comparison of two equal-size big-endian unsigned integers.
     *
     * @return {@code true} iff {@code x[xOff..xOff+size] < y[yOff..yOff+size]}
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
        return false; // equal
    }

    /** Returns {@code true} iff every byte in {@code x[xOff..xOff+size]} is zero. */
    public static boolean isZero(byte[] x, short xOff, short size) {
        for (short i = 0; i < size; i++) {
            if (x[(short) (xOff + i)] != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Schoolbook unsigned multiplication: {@code z[zOff..zOff+2*size] = x · y}. The destination is
     * fully overwritten and must not alias either source. For 32-byte operands this is 1024
     * byte-multiplies on 32 MHz JC silicon — well under 10 ms.
     */
    public static void mult(
            byte[] x, short xOff, byte[] y, short yOff, short size, byte[] z, short zOff) {
        Util.arrayFillNonAtomic(z, zOff, (short) (size * 2), (byte) 0);
        for (short i = (short) (size - 1); i >= 0; i--) {
            short carry = 0;
            short xi = (short) (x[(short) (xOff + i)] & DIGIT_MASK);
            for (short j = (short) (size - 1); j >= 0; j--) {
                short yj = (short) (y[(short) (yOff + j)] & DIGIT_MASK);
                short prod = (short) (xi * yj);
                short k = (short) (zOff + i + j + 1);
                short sum = (short) ((z[k] & DIGIT_MASK) + (prod & DIGIT_MASK) + carry);
                z[k] = (byte) sum;
                carry =
                        (short)
                                (((prod >>> DIGIT_LEN) & DIGIT_MASK)
                                        + ((sum >>> DIGIT_LEN) & DIGIT_MASK));
            }
            // Propagate any leftover carry into the next column above.
            short k = (short) (zOff + i);
            z[k] = (byte) ((z[k] & DIGIT_MASK) + carry);
        }
    }

    /**
     * In-place schoolbook modular reduction: {@code dividend ← dividend mod divisor} (classical
     * long division over byte digits). On return, the {@code drSize}-byte remainder lives in the
     * trailing slot of the dividend; leading bytes are zero.
     *
     * <p>Caller invariants: {@code divisor != 0}, {@code dvSize ≥ drSize}, dividend holds the full
     * unreduced value.
     */
    public static void mod(
            byte[] dividend, short dvOff, short dvSize, byte[] divisor, short drOff, short drSize) {
        // Locate the first nonzero limb of the divisor; everything before it is treated as
        // structural zero for the shift accounting below.
        short divisorIndex = 0;
        while (divisorIndex < drSize && divisor[(short) (drOff + divisorIndex)] == 0) {
            divisorIndex++;
        }

        short divisorShift = (short) (dvSize - drSize + divisorIndex);
        short divisionRound = 0;

        short firstDivisorDigit = (short) (divisor[(short) (drOff + divisorIndex)] & DIGIT_MASK);
        short divisorBitShift = (short) (highestBit((short) (firstDivisorDigit + 1)) - 1);
        byte secondDivisorDigit =
                divisorIndex < (short) (drSize - 1)
                        ? divisor[(short) (drOff + divisorIndex + 1)]
                        : 0;
        byte thirdDivisorDigit =
                divisorIndex < (short) (drSize - 2)
                        ? divisor[(short) (drOff + divisorIndex + 2)]
                        : 0;

        short dividendDigits;
        short divisorDigit;
        short dividendBitShift;
        short bitShift;
        short multiple;

        while (divisorShift >= 0) {
            while (!shiftLesser(
                    dividend,
                    dvOff,
                    dvSize,
                    divisor,
                    drOff,
                    drSize,
                    divisorShift,
                    (short) (divisionRound > 0 ? divisionRound - 1 : 0))) {
                // The (shifted) divisor still fits into the partial dividend. Estimate a
                // conservative lower bound on the quotient digit and subtract that many copies of
                // the shifted divisor from the dividend.
                dividendDigits =
                        divisionRound == 0
                                ? 0
                                : (short)
                                        ((short) (dividend[(short) (dvOff + divisionRound - 1)])
                                                << DIGIT_LEN);
                dividendDigits |= (short) (dividend[(short) (dvOff + divisionRound)] & DIGIT_MASK);

                if (dividendDigits < 0) {
                    // The two-byte estimate overflows the signed range; right-shift both operands
                    // by one bit (equivalent to dividing both by 2, which preserves the quotient
                    // estimate) so the unsigned division below stays in the positive range.
                    dividendDigits = (short) ((dividendDigits >>> 1) & POSITIVE_DOUBLE_DIGIT_MASK);
                    divisorDigit = (short) ((firstDivisorDigit >>> 1) & POSITIVE_DOUBLE_DIGIT_MASK);
                } else {
                    // Left-shift both operands by the same amount to recover precision when the
                    // leading bytes are small. The +1 below avoids underflow in the divisor; we
                    // compensate by clamping multiple ≥ 1 outside the conditional.
                    dividendBitShift = (short) (highestBit(dividendDigits) - 1);
                    bitShift =
                            dividendBitShift <= divisorBitShift
                                    ? dividendBitShift
                                    : divisorBitShift;
                    dividendDigits =
                            shiftBits(
                                    dividendDigits,
                                    divisionRound < (short) (dvSize - 1)
                                            ? dividend[(short) (dvOff + divisionRound + 1)]
                                            : (byte) 0,
                                    divisionRound < (short) (dvSize - 2)
                                            ? dividend[(short) (dvOff + divisionRound + 2)]
                                            : (byte) 0,
                                    bitShift);
                    divisorDigit =
                            shiftBits(
                                    firstDivisorDigit,
                                    secondDivisorDigit,
                                    thirdDivisorDigit,
                                    bitShift);
                }

                multiple = (short) (dividendDigits / (short) (divisorDigit + 1));
                if (multiple < 1) {
                    multiple = 1;
                }
                timesMinus(dividend, dvOff, dvSize, divisor, drOff, drSize, divisorShift, multiple);
            }
            divisionRound++;
            divisorShift--;
        }
    }

    /** Index of the most significant 1 bit (0..15) of a 16-bit value; returns 16 for zero. */
    private static short highestBit(short x) {
        for (short i = 0; i < DOUBLE_DIGIT_LEN; i++) {
            if (x < 0) {
                return i;
            }
            x <<= 1;
        }
        return DOUBLE_DIGIT_LEN;
    }

    /**
     * Left-shifts the concatenation {@code high (16b) ‖ middle (8b) ‖ low (8b)} by {@code shift}
     * bits and returns the top 16 bits. {@link #mod} helper.
     */
    private static short shiftBits(short high, byte middle, byte low, short shift) {
        high <<= shift;
        byte mask = (byte) (DIGIT_MASK << (shift >= DIGIT_LEN ? 0 : (short) (DIGIT_LEN - shift)));
        short bits = (short) ((short) (middle & mask) & DIGIT_MASK);
        if (shift > DIGIT_LEN) {
            bits <<= (short) (shift - DIGIT_LEN);
        } else {
            bits >>>= (short) (DIGIT_LEN - shift);
        }
        high |= bits;
        if (shift <= DIGIT_LEN) {
            return high;
        }
        mask = (byte) (DIGIT_MASK << (DOUBLE_DIGIT_LEN - shift));
        bits = (short) ((((short) (low & mask) & DIGIT_MASK) >> (DOUBLE_DIGIT_LEN - shift)));
        high |= bits;
        return high;
    }

    /**
     * {@link #mod} helper: tests whether the divisor shifted by {@code shift} byte-positions is
     * strictly greater than the partial dividend, signalling "advance to next divisor position".
     */
    private static boolean shiftLesser(
            byte[] x,
            short xOff,
            short xSize,
            byte[] other,
            short otherOff,
            short otherSize,
            short shift,
            short start) {
        short j = (short) (otherSize + shift - xSize + start);
        short xShort;
        short otherShort;
        for (short i = start; i < xSize; i++, j++) {
            xShort = (short) (x[(short) (xOff + i)] & DIGIT_MASK);
            if (j >= 0 && j < otherSize) {
                otherShort = (short) (other[(short) (otherOff + j)] & DIGIT_MASK);
            } else {
                otherShort = 0;
            }
            if (xShort < otherShort) {
                return true;
            }
            if (xShort > otherShort) {
                return false;
            }
        }
        return false;
    }

    /**
     * Subtracts {@code multiple × (divisor << 8*shift)} from {@code dividend} in place. {@link
     * #mod} helper.
     */
    private static void timesMinus(
            byte[] dividend,
            short dvOff,
            short dvSize,
            byte[] divisor,
            short drOff,
            short drSize,
            short shift,
            short multiple) {
        short akku = 0;
        short subtractionResult;
        short i = (short) (dvSize - 1 - shift);
        short j = (short) (drSize - 1);
        for (; i >= 0 && j >= 0; i--, j--) {
            akku =
                    (short)
                            (akku
                                    + (short)
                                            (multiple
                                                    * (divisor[(short) (drOff + j)] & DIGIT_MASK)));
            subtractionResult =
                    (short) ((dividend[(short) (dvOff + i)] & DIGIT_MASK) - (akku & DIGIT_MASK));
            dividend[(short) (dvOff + i)] = (byte) (subtractionResult & DIGIT_MASK);
            akku = (short) ((akku >>> DIGIT_LEN) & DIGIT_MASK);
            if (subtractionResult < 0) {
                akku++;
            }
        }
        // Propagate the leftover borrow into the bytes above the divisor window.
        for (; i >= 0 && akku != 0; i--) {
            subtractionResult =
                    (short) ((dividend[(short) (dvOff + i)] & DIGIT_MASK) - (akku & DIGIT_MASK));
            dividend[(short) (dvOff + i)] = (byte) (subtractionResult & DIGIT_MASK);
            akku = (short) ((akku >>> DIGIT_LEN) & DIGIT_MASK);
            if (subtractionResult < 0) {
                akku++;
            }
        }
    }

    /**
     * Constant-time in-place subtract: {@code if (mask == -1) x -= y; else no-op}. {@code x} and
     * {@code y} are equal-length big-endian unsigned integers.
     */
    public static void condSubInPlace(
            byte[] x, short xOff, byte[] y, short yOff, short size, short mask) {
        short borrow = 0;
        for (short i = (short) (size - 1); i >= 0; i--) {
            short yi = (short) ((y[(short) (yOff + i)] & DIGIT_MASK) & mask);
            short diff = (short) ((x[(short) (xOff + i)] & DIGIT_MASK) - yi - borrow);
            x[(short) (xOff + i)] = (byte) diff;
            borrow = (short) ((diff >>> 15) & 1);
        }
    }

    /**
     * Constant-time in-place add: {@code if (mask == -1) x += y; else no-op}. {@code x} and {@code
     * y} are equal-length big-endian unsigned integers.
     */
    public static void condAddInPlace(
            byte[] x, short xOff, byte[] y, short yOff, short size, short mask) {
        short carry = 0;
        for (short i = (short) (size - 1); i >= 0; i--) {
            short yi = (short) ((y[(short) (yOff + i)] & DIGIT_MASK) & mask);
            short sum = (short) ((x[(short) (xOff + i)] & DIGIT_MASK) + yi + carry);
            x[(short) (xOff + i)] = (byte) sum;
            carry = (short) ((sum >>> DIGIT_LEN) & 1);
        }
    }

    /**
     * Constant-time strict less-than test on two equal-length big-endian unsigned integers. Returns
     * {@code -1} (0xFFFF) iff {@code x < y}; returns {@code 0} otherwise. The full
     * trial-subtraction always runs to completion: every byte is read in MSB-to-LSB order
     * regardless of where the operands first differ.
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
     * Constant-time {@code x == 0} predicate. Returns {@code -1} iff the buffer is all zero, {@code
     * 0} otherwise. Every intermediate stays in the short domain because the JC 3.0.5 CAP converter
     * rejects int-typed locals.
     */
    public static short ctIsZero(byte[] x, short xOff, short size) {
        // Byte-wise OR into a short; each contribution is an unsigned byte so no sign-extension.
        short acc = 0;
        for (short i = 0; i < size; i++) {
            acc |= (short) (x[(short) (xOff + i)] & DIGIT_MASK);
        }
        // Map acc -> {-1, 0}: (acc | -acc) has bit 15 set iff acc != 0; extract and subtract 1.
        short orNeg = (short) (acc | (short) -acc);
        short nonZero = (short) ((orNeg >>> 15) & 1);
        return (short) (nonZero - 1);
    }
}
