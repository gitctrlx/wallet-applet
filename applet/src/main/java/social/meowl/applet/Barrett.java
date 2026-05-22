/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.Util;

/**
 * Constant-time Barrett reduction of a 512-bit dividend modulo a 256-bit modulus.
 *
 * <p>Each instance binds a specific modulus {@code m} and its pre-computed Barrett constant
 * {@code μ = ⌊2⁵¹² / m⌋}. The per-call cost is one 33×33 multiply, one 33×32 truncated multiply
 * and three constant-time 33-byte conditional subtracts — strictly data-independent in the byte
 * schedule. Replaces the v1 trio {@code Barrett}/{@code BarrettN}/{@code BarrettL}; one class with
 * one well-tested kernel suffices for every 256-bit modulus the applet reduces against.
 *
 * <h2>Algorithm</h2>
 *
 * <p>Standard Barrett (Handbook of Applied Cryptography, Algorithm 14.42) with {@code b = 2⁸} and
 * {@code k = 32}, so the radix-{@code b} representation lives natively in big-endian byte buffers:
 *
 * <pre>
 *   Inputs:  x  ∈ [0, 2⁵¹²)    (64-byte big-endian)
 *            m  ∈ (0, 2²⁵⁶)    (32-byte big-endian)
 *            μ  = ⌊2⁵¹² / m⌋   (33-byte big-endian)
 *
 *   1. q1 := x >> 248                (top 33 bytes of x, referenced in place)
 *   2. q2 := q1 · μ                  (33 × 33 → 66 bytes)
 *   3. q3 := q2 >> 264               (top 33 bytes of q2, referenced in place)  [≈ ⌊x/m⌋]
 *   4. r1 := x mod 2²⁶⁴              (bottom 33 bytes of x)
 *   5. r2 := (q3 · m) mod 2²⁶⁴       (bottom 33 bytes of the 33×32 product)
 *   6. r  := (r1 − r2) mod 2²⁶⁴      (33-byte subtract; borrow ≡ +2²⁶⁴ stays in the buffer)
 *   7. r  := r − k·m  for k ∈ {0,1,2,3}  (3 unconditional condSub passes)
 *   8. return low 32 bytes of r
 * </pre>
 *
 * <p>HAC 14.44 proves {@code q3 ≤ ⌊x/m⌋ ≤ q3 + 2}, hence {@code r ∈ [0, 3m)} and two subtractions
 * suffice. Three are always run to keep wall-clock data-independent; the third is a no-op when
 * {@code r < m}.
 *
 * <h2>Scratch layout</h2>
 *
 * <p>Caller supplies a single {@link #SCRATCH_LEN}-byte working area laid out as
 *
 * <pre>
 *   scratch[ 0.. 66): q2  (66-byte product of q1 · μ; q3 sits at scratch[0..33])
 *   scratch[66.. 99): r2  (33-byte truncated product q3 · m)
 *   scratch[99..132): r   (33-byte working remainder)
 * </pre>
 */
public final class Barrett {

    /** Minimum size of the scratch buffer the caller must provide to {@link #reduce}. */
    public static final short SCRATCH_LEN = 132;

    /** Byte length of a 256-bit modulus. */
    public static final short MODULUS_LEN = 32;

    /** Byte length of the 512-bit dividend (a · b for 32-byte a, b). */
    public static final short DIVIDEND_LEN = 64;

    /**
     * Byte length of the Barrett constant μ — one byte wider than the modulus to absorb
     * {@code 2⁵¹² / m > 2²⁵⁶} for m near {@code 2²⁵⁶}.
     */
    public static final short MU_LEN = 33;

    private static final short EXT_LEN = 33;
    private static final short Q2_OFF = (short) 0;
    private static final short R2_OFF = (short) 66;
    private static final short R_OFF = (short) 99;

    private final byte[] modulus;
    private final short modOff;
    private final byte[] mu;
    private final short muOff;

    /**
     * Binds a Barrett reducer to the given modulus and its pre-computed {@code μ}.
     *
     * @param modulus 32-byte big-endian modulus; referenced (not copied), so the caller MUST keep
     *     it stable and read-only for the lifetime of the reducer.
     * @param modOff start offset within {@code modulus}.
     * @param mu 33-byte big-endian Barrett constant {@code ⌊2⁵¹² / m⌋}; same lifetime requirement.
     * @param muOff start offset within {@code mu}.
     */
    public Barrett(byte[] modulus, short modOff, byte[] mu, short muOff) {
        this.modulus = modulus;
        this.modOff = modOff;
        this.mu = mu;
        this.muOff = muOff;
    }

    /**
     * Constant-time {@code dst[0..32] := x[0..64] mod m}.
     *
     * @param x 64-byte big-endian dividend, {@code 0 ≤ x < 2⁵¹²}; UNMODIFIED on return.
     * @param xOff start offset within {@code x}.
     * @param scratch caller-supplied workspace of at least {@link #SCRATCH_LEN} bytes; clobbered.
     * @param scOff start offset within {@code scratch}.
     * @param dst 32-byte big-endian output buffer; receives {@code x mod m}.
     * @param dstOff start offset within {@code dst}.
     */
    public void reduce(
            byte[] x, short xOff, byte[] scratch, short scOff, byte[] dst, short dstOff) {

        BigNat.multAsymmetric(
                x, xOff, EXT_LEN, mu, muOff, EXT_LEN, scratch, (short) (scOff + Q2_OFF));

        multTruncLo(
                scratch,
                (short) (scOff + Q2_OFF),
                EXT_LEN,
                modulus,
                modOff,
                MODULUS_LEN,
                scratch,
                (short) (scOff + R2_OFF),
                EXT_LEN);

        Util.arrayCopyNonAtomic(
                x,
                (short) (xOff + DIVIDEND_LEN - EXT_LEN),
                scratch,
                (short) (scOff + R_OFF),
                EXT_LEN);
        BigNat.sub(
                scratch, (short) (scOff + R_OFF), scratch, (short) (scOff + R2_OFF), EXT_LEN);

        condSub33(scratch, (short) (scOff + R_OFF));
        condSub33(scratch, (short) (scOff + R_OFF));
        condSub33(scratch, (short) (scOff + R_OFF));

        Util.arrayCopyNonAtomic(
                scratch, (short) (scOff + R_OFF + 1), dst, dstOff, MODULUS_LEN);
    }

    /**
     * Schoolbook unsigned multiply writing only the bottom {@code outSize} bytes of the
     * {@code xSize + ySize}-byte product. Columns whose contribution falls entirely outside the
     * requested window are skipped, with carries propagated correctly into the kept window. Used
     * for step 5 of Barrett where only the low 33 bytes of {@code q3 · m} are needed.
     */
    private static void multTruncLo(
            byte[] x,
            short xOff,
            short xSize,
            byte[] y,
            short yOff,
            short ySize,
            byte[] z,
            short zOff,
            short outSize) {
        Util.arrayFillNonAtomic(z, zOff, outSize, (byte) 0);
        for (short i = (short) (xSize - 1); i >= 0; i--) {
            short carry = 0;
            short xi = (short) (x[(short) (xOff + i)] & BigNat.DIGIT_MASK);
            for (short j = (short) (ySize - 1); j >= 0; j--) {
                short yj = (short) (y[(short) (yOff + j)] & BigNat.DIGIT_MASK);
                short prod = (short) (xi * yj);
                short kFull = (short) (i + j + 1);
                short kLo = (short) (kFull - (xSize + ySize - outSize));
                if (kLo < 0) {
                    continue;
                }
                short k = (short) (zOff + kLo);
                short sum =
                        (short) ((z[k] & BigNat.DIGIT_MASK) + (prod & BigNat.DIGIT_MASK) + carry);
                z[k] = (byte) sum;
                carry =
                        (short)
                                (((prod >>> BigNat.DIGIT_BITS) & BigNat.DIGIT_MASK)
                                        + ((sum >>> BigNat.DIGIT_BITS) & BigNat.DIGIT_MASK));
            }
            short kFull = i;
            short kLo = (short) (kFull - (xSize + ySize - outSize));
            if (kLo >= 0) {
                short k = (short) (zOff + kLo);
                z[k] = (byte) ((z[k] & BigNat.DIGIT_MASK) + carry);
            }
        }
    }

    /**
     * Constant-time conditional subtraction of a 32-byte modulus (zero-extended to 33 bytes) from
     * a 33-byte accumulator: if {@code r ≥ (0x00 ‖ m)} replace with {@code r − m}, otherwise leave
     * unchanged. Implements one iteration of step 7 of Barrett's algorithm.
     *
     * <p>Strategy: trial subtract runs unconditionally byte-wise. The borrow out of the top byte
     * is exactly the bit saying "we underflowed". That bit is sign-extended to a 16-bit mask and
     * fed to a mask-driven byte-wise add-back of {@code m}; when the mask is zero the add is a
     * no-op, when the mask is all-ones the add cancels the trial subtract exactly.
     */
    private void condSub33(byte[] r, short rOff) {
        short borrow = 0;
        for (short i = (short) (MODULUS_LEN - 1); i >= 0; i--) {
            short mi = (short) (modulus[(short) (modOff + i)] & BigNat.DIGIT_MASK);
            short diff = (short) ((r[(short) (rOff + 1 + i)] & BigNat.DIGIT_MASK) - mi - borrow);
            r[(short) (rOff + 1 + i)] = (byte) diff;
            borrow = (short) ((diff >>> 15) & 1);
        }
        short diff0 = (short) ((r[rOff] & BigNat.DIGIT_MASK) - borrow);
        r[rOff] = (byte) diff0;
        short fullBorrow = (short) ((diff0 >>> 15) & 1);
        short undoMask = (short) -fullBorrow;

        short carry = 0;
        for (short i = (short) (MODULUS_LEN - 1); i >= 0; i--) {
            short mi = (short) ((modulus[(short) (modOff + i)] & BigNat.DIGIT_MASK) & undoMask);
            short sum = (short) ((r[(short) (rOff + 1 + i)] & BigNat.DIGIT_MASK) + mi + carry);
            r[(short) (rOff + 1 + i)] = (byte) sum;
            carry = (short) ((sum >>> BigNat.DIGIT_BITS) & 1);
        }
        r[rOff] = (byte) ((r[rOff] & BigNat.DIGIT_MASK) + carry);
    }
}
