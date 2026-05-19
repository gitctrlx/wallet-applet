/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.Util;

/**
 * Multi-precision unsigned big-integer primitives over big-endian byte arrays.
 *
 * <p>JavaCard 3.0.5 ships no native {@code BigInteger} type and the only widely-supported
 * arithmetic primitive on numbers wider than 16 bits is the RSA modular exponentiation engine. The
 * Schnorr and Ed25519 signing paths need three primitive operations the JC platform does not
 * provide:
 *
 * <ul>
 *   <li>schoolbook addition / subtraction with carry on arbitrary-length operands;
 *   <li>32-byte × 32-byte → 64-byte multiplication for {@code e · d};
 *   <li>variable-length modular reduction for {@code (k + e · d) mod n}.
 * </ul>
 *
 * <p>This class implements those primitives in pure software. The schoolbook multiplication in
 * {@link #mult} is a direct meowl implementation. The schoolbook long-division algorithm in {@link
 * #mod}, plus the {@link #shiftBits}, {@link #shiftLesser}, {@link #timesMinus} and {@link
 * #highestBit} helpers it depends on, are adapted from <a
 * href="https://github.com/Toporin/SatochipApplet">Toporin's Satochip Biginteger</a> (copyright ©
 * 2015–2024 Toporin (Satochip), GPL-2.0-or-later), which is in turn derived from the <a
 * href="https://www.cs.ru.nl/~erikpoll/papers/ovchip.pdf">Radboud University OV-chip 2.0 Bignat</a>
 * (copyright © 2008–2009 Digital Security (DS) group, Radboud Universiteit Nijmegen,
 * GPL-2.0-or-later). Per the GPLv2-or-later upgrade clause this file inherits both upstream
 * copyrights and re-licenses to AGPL-3.0-or-later; the in-tree {@code REUSE.toml} records the
 * complete attribution chain in machine-readable form for SPDX tooling.
 *
 * <p>All operands are big-endian (most-significant byte at the lowest offset). All methods are
 * static and operate on caller-supplied buffers; this class holds no state of its own.
 *
 * <p><b>Performance note:</b> the operations here are deliberately not constant-time. The applet
 * uses {@link Bignat} only for material that is either already public after the call (Schnorr
 * {@code R.x}, {@code s}) or is mixed with sufficient randomness ({@code k}) that timing leakage is
 * not a recovery vector. Secret scalars are still loaded into hardware EC keys for the actual
 * elliptic-curve operations; {@link Bignat} only handles their numeric combinations.
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
     * Schoolbook unsigned multiplication: {@code z[zOff..zOff+2*size] = x[xOff..xOff+size] *
     * y[yOff..yOff+size]}. The destination is fully overwritten; it must not alias either source.
     *
     * <p>For 32-byte operands this performs 1024 byte-by-byte multiplications and the same number
     * of two-byte additions. On a 32 MHz JC silicon that is well under 10 ms, dominated by the
     * subsequent EC scalar-multiplication anyway.
     */
    public static void mult(
            byte[] x, short xOff, byte[] y, short yOff, short size, byte[] z, short zOff) {
        // Zero the destination first; the schoolbook accumulator below assumes z starts clean.
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
            short sum = (short) ((z[k] & DIGIT_MASK) + carry);
            z[k] = (byte) sum;
            // For schoolbook 32×32 the result fits in 64 bytes, so this carry is structurally 0
            // for our use case — but assert nothing here, the next iteration's outer loop runs
            // at index i-1, which writes to z[zOff + i - 1] anyway.
        }
    }

    /**
     * Schoolbook modular reduction in place: {@code dividend[dvOff..dvOff+dvSize] ←
     * dividend[dvOff..dvOff+dvSize] mod divisor[drOff..drOff+drSize]}.
     *
     * <p>After the call, the {@code drSize}-byte remainder lives in the trailing slot of the
     * dividend, namely {@code dividend[dvOff + dvSize - drSize .. dvOff + dvSize]}; the leading
     * {@code dvSize - drSize} bytes are zero. The divisor is read-only.
     *
     * <p>Algorithm: classical schoolbook long division over byte digits, adapted from the Toporin
     * Satochip Biginteger (itself a port of the Radboud University OV-chip 2.0 Bignat code). The
     * outer loop walks the divisor over every aligned position of the dividend; the inner loop
     * estimates the per-position quotient digit using the leading two bytes of the partial
     * remainder and the leading byte of the divisor (with a small bit-shift to recover precision
     * when those leading bytes are small).
     *
     * <p>Caller responsibility: {@code divisor} must be non-zero, {@code dvSize ≥ drSize}, and the
     * dividend buffer must contain the full unreduced value (no leading-zero stripping).
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

    /**
     * Index of the most significant 1 bit (0..15) of a 16-bit value, returning 16 for zero. Used by
     * {@link #mod} to estimate the bit-width of the leading divident / divisor digits before the
     * precision-recovering left-shift.
     */
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
     * bits and returns the most-significant 16 bits of the result. Helper for {@link #mod}; see the
     * OV-chip 2.0 Bignat documentation for the full derivation.
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
     * Tests whether the divisor — shifted left by {@code shift} byte-positions — is strictly
     * greater than the partial dividend at the current {@code start} round. Helper for {@link
     * #mod}: returns {@code true} iff "we should advance to the next divisor position".
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
     * Subtracts {@code multiple × (divisor << 8*shift)} from {@code dividend} in place. The inner
     * loop walks the divisor right-to-left over the partial dividend window, accumulating the
     * {@code multiple * digit} products and propagating borrow upward. Helper for {@link #mod}.
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
}
