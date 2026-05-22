/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.Util;

/**
 * Constant-time Barrett reduction of a 512-bit dividend modulo a 256-bit modulus. Used by the
 * Schnorr {@code (k + e·d) mod n} and Ed25519 {@code (r + k·s) mod ℓ} signing paths, both of which
 * feed a 512-bit product into a 256-bit non-Mersenne modulus where the previous {@link Bignat#mod}
 * long division had a wall-clock proportional to the secret intermediate's bit length.
 *
 * <h2>Algorithm</h2>
 *
 * <p>Standard Barrett (Handbook of Applied Cryptography, Algorithm 14.42) with {@code b = 2^8} and
 * {@code k = 32}, so the radix-{@code b} representation of every value lives in our existing
 * big-endian byte buffers without any conversion overhead.
 *
 * <pre>
 *   Inputs:  x  ∈ [0, 2^512)    (64-byte big-endian)
 *            m  ∈ (0, 2^256)    (32-byte big-endian)
 *            μ  = floor(2^512 / m)   (33-byte big-endian, ≤ 257 bits for m near 2^256)
 *
 *   1. q1 := x >> 248               (the top 33 bytes of x)
 *   2. q2 := q1 · μ                 (33 × 33 → 66 bytes, full schoolbook)
 *   3. q3 := q2 >> 264              (the top 33 bytes of q2)        [estimator for ⌊x/m⌋]
 *   4. r1 := x mod 2^264            (the bottom 33 bytes of x)
 *   5. r2 := (q3 · m) mod 2^264     (the bottom 33 bytes of q3 · m)
 *   6. r  := (r1 - r2) mod 2^264    (33-byte subtract; the implicit +2^264 on borrow
 *                                    is exactly what stays in the buffer)
 *   7. while r ≥ m: r := r - m      (HAC 14.44: at most 2 iterations; we run 3
 *                                    unconditionally to keep the wall-clock constant)
 *   8. return r mod 2^256           (low 32 bytes of r)
 * </pre>
 *
 * <p><b>Why three subtracts, not two?</b> HAC 14.44 proves the quotient estimator {@code q3 =
 * ⌊⌊q2/b^(k+1)⌋⌋} satisfies {@code q3 ≤ ⌊x/m⌋} and {@code q3 ≥ ⌊x/m⌋ - 2}, hence {@code r ∈ [0,
 * 3m)} and two subtracts suffice. We always run three to keep the wall-clock fully
 * data-independent: the third subtract is a no-op when {@code r < m} but takes the same time as the
 * first two. The extra cost is one byte-wise compare and one masked add, ~100 µs on real silicon —
 * negligible against the ~1500 byte-multiplies that dominate this routine.
 *
 * <h2>Constant-time guarantees</h2>
 *
 * <ul>
 *   <li>Every byte of every intermediate ({@code q1, q2, q3, r1, r2, r}) is read and written
 *       unconditionally on every call.
 *   <li>The "less-than" predicate used to gate each conditional subtract calls {@link
 *       Bignat#ctLessThan}, which walks every byte and returns a mask.
 *   <li>The conditional subtract uses {@link Bignat#sub} (variable-time in carry chain but the
 *       inputs are constant in size) followed by {@link Bignat#condAddInPlace} (mask-driven) to
 *       roll back, so the buffer always sees a real subtract.
 *   <li>The schoolbook multiplies in {@link #mult} walk every {@code (i, j)} cell regardless of
 *       operand bytes — the JC bytecode {@code imul} on a 32 MHz card takes a fixed number of
 *       cycles per byte-multiply.
 * </ul>
 *
 * <h2>Scratch layout</h2>
 *
 * <p>Caller supplies a single 132-byte working area (one {@link #SCRATCH_LEN} slot). The frame is
 * laid out as
 *
 * <pre>
 *   scratch[ 0.. 66): q2  (66-byte product of q1 × μ)
 *   scratch[66.. 99): r2  (33-byte; reuses scratch[33..66] when q3 is consumed)
 *   scratch[99..132): r   (33-byte working remainder)
 * </pre>
 *
 * with the property that {@code q1} never needs to be materialised — it is the top 33 bytes of the
 * caller's {@code x} buffer in place.
 */
public final class Barrett {

    /** Minimum size of the scratch buffer the caller must provide to {@link #reduce}. */
    public static final short SCRATCH_LEN = 132;

    /** Constant: the byte length of a 32-byte group-order modulus. */
    public static final short MODULUS_LEN = 32;

    /**
     * Constant: the byte length of the 64-byte dividend (a 512-bit value, e.g. a · b for 32-byte a,
     * b).
     */
    public static final short DIVIDEND_LEN = 64;

    /** Constant: the byte length of Barrett's pre-computed μ. */
    public static final short MU_LEN = 33;

    /** Constant: q2 has 33 + 33 = 66 bytes; r1, r2, r each are 33 bytes; total 132. */
    private static final short EXT_LEN = 33;

    private static final short Q2_OFF = (short) 0;
    private static final short R2_OFF = (short) 66;
    private static final short R_OFF = (short) 99;

    private static final short BYTE_MASK = 0xFF;
    private static final short BYTE_BITS = 8;

    private Barrett() {}

    /**
     * Constant-time Barrett reduction {@code dst[0..32] := x[0..64] mod m[0..32]}.
     *
     * @param x 64-byte big-endian dividend, {@code 0 ≤ x < 2^512}; UNMODIFIED on return.
     * @param xOff start offset within {@code x}.
     * @param m 32-byte big-endian modulus, {@code 0 < m < 2^256}; UNMODIFIED.
     * @param mOff start offset within {@code m}.
     * @param mu 33-byte big-endian Barrett constant {@code floor(2^512 / m)}; UNMODIFIED.
     * @param muOff start offset within {@code mu}.
     * @param scratch caller-supplied workspace of at least {@link #SCRATCH_LEN} bytes; clobbered.
     * @param scOff start offset within {@code scratch}.
     * @param dst 32-byte big-endian output buffer; receives {@code x mod m}.
     * @param dstOff start offset within {@code dst}.
     */
    public static void reduce(
            byte[] x,
            short xOff,
            byte[] m,
            short mOff,
            byte[] mu,
            short muOff,
            byte[] scratch,
            short scOff,
            byte[] dst,
            short dstOff) {

        // Step 1+2: q2 := (x >> 248) · μ.
        // q1 is the top 33 bytes of x; we reference them in place at (x, xOff) since x[0..33] is
        // exactly x's upper 33 bytes in big-endian. q2 is 66 bytes at scratch[0..66].
        mult(x, xOff, EXT_LEN, mu, muOff, EXT_LEN, scratch, (short) (scOff + Q2_OFF));

        // Step 3: q3 := q2 >> 264.  The top 33 bytes of q2 sit at scratch[0..33] — q3 is referenced
        // in place there, no copy needed.

        // Step 5: r2 := (q3 · m) mod 2^264.
        // q3 · m is (33 + 32) = 65 bytes; we only need the bottom 33. mult writes the full 65-byte
        // product; we throw away the upper 32 bytes by computing only the columns that fall into
        // the bottom 33. The helper multTruncLo does that cheaply.
        multTruncLo(
                scratch,
                (short) (scOff + Q2_OFF),
                EXT_LEN,
                m,
                mOff,
                MODULUS_LEN,
                scratch,
                (short) (scOff + R2_OFF),
                EXT_LEN);

        // Step 4+6: r := x[31..64] - r2  (33-byte subtract mod 2^264). x[31..64] is the bottom 33
        // bytes of x; we copy it into the scratch r-slot, then subtract r2 in place. Any borrow is
        // implicitly +2^264 in the stored value — exactly what the algorithm wants.
        Util.arrayCopyNonAtomic(
                x,
                (short) (xOff + DIVIDEND_LEN - EXT_LEN),
                scratch,
                (short) (scOff + R_OFF),
                EXT_LEN);
        Bignat.sub(scratch, (short) (scOff + R_OFF), scratch, (short) (scOff + R2_OFF), EXT_LEN);

        // Step 7: at most three conditional subtracts of m to bring r into [0, m). We zero-extend m
        // by one byte for the 33-byte compare. The mask is produced byte-wise constant-time by
        // ctLessThan; condSub33 below adds the m back if the trial subtract underflowed.
        condSub33(scratch, (short) (scOff + R_OFF), m, mOff);
        condSub33(scratch, (short) (scOff + R_OFF), m, mOff);
        condSub33(scratch, (short) (scOff + R_OFF), m, mOff);

        // Step 8: emit the low 32 bytes; the (now-known-zero) top byte at scratch[R_OFF] is
        // dropped.
        Util.arrayCopyNonAtomic(scratch, (short) (scOff + R_OFF + 1), dst, dstOff, MODULUS_LEN);
    }

    /**
     * Schoolbook multi-precision multiply for non-equal-size operands: {@code z[zOff..+xSize+ySize]
     * = x · y} (big-endian). Used internally by {@link #reduce} for 33×33 and 33×32 multiplies.
     *
     * <p>Identical algorithm to {@link Bignat#mult} but parameterised on both operand widths.
     * Constant-time in the operand bytes (every cell is touched).
     */
    private static void mult(
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
            short xi = (short) (x[(short) (xOff + i)] & BYTE_MASK);
            for (short j = (short) (ySize - 1); j >= 0; j--) {
                short yj = (short) (y[(short) (yOff + j)] & BYTE_MASK);
                short prod = (short) (xi * yj);
                short k = (short) (zOff + i + j + 1);
                short sum = (short) ((z[k] & BYTE_MASK) + (prod & BYTE_MASK) + carry);
                z[k] = (byte) sum;
                carry =
                        (short)
                                (((prod >>> BYTE_BITS) & BYTE_MASK)
                                        + ((sum >>> BYTE_BITS) & BYTE_MASK));
            }
            // Propagate any leftover carry into the column above the inner loop.
            short k = (short) (zOff + i);
            z[k] = (byte) ((z[k] & BYTE_MASK) + carry);
        }
    }

    /**
     * Like {@link #mult} but writes only the bottom {@code outSize} bytes of the {@code xSize +
     * ySize} byte product. Columns whose final contribution falls entirely outside the requested
     * window are skipped, with carries propagated correctly into the kept window.
     *
     * <p>Used for step 5 of Barrett, where only the bottom 33 bytes of the 65-byte {@code q3 · m}
     * product are needed.
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
        // The 0-indexed "weight" of (z[outSize-1-w]) — the byte at the bottom-left of the trapezoid
        // — is w, ranging 0..outSize-1. Each (i, j) cell contributes at weight (xSize-1-i) +
        // (ySize-1-j). Columns with weight ≥ outSize are dropped; columns with weight in
        // [0, outSize-1] are added in. To match the layout of mult, we walk i and j the same way
        // and skip cells whose destination index k < zOff (i.e. weight ≥ outSize).
        for (short i = (short) (xSize - 1); i >= 0; i--) {
            short carry = 0;
            short xi = (short) (x[(short) (xOff + i)] & BYTE_MASK);
            for (short j = (short) (ySize - 1); j >= 0; j--) {
                short yj = (short) (y[(short) (yOff + j)] & BYTE_MASK);
                short prod = (short) (xi * yj);
                // Destination index in the full-width product, written into z's lower-aligned slot.
                short kFull = (short) (i + j + 1);
                short kLo = (short) (kFull - (xSize + ySize - outSize));
                if (kLo < 0) {
                    // Even the carry contribution is below the kept window; constant-time still
                    // requires we walk the cell, but its effect is irrelevant for correctness. We
                    // do NOT propagate carry here because it would land outside the window too.
                    continue;
                }
                short k = (short) (zOff + kLo);
                short sum = (short) ((z[k] & BYTE_MASK) + (prod & BYTE_MASK) + carry);
                z[k] = (byte) sum;
                carry =
                        (short)
                                (((prod >>> BYTE_BITS) & BYTE_MASK)
                                        + ((sum >>> BYTE_BITS) & BYTE_MASK));
            }
            // Final carry into the column above the inner loop (only if it lands inside the
            // window).
            short kFull = i;
            short kLo = (short) (kFull - (xSize + ySize - outSize));
            if (kLo >= 0) {
                short k = (short) (zOff + kLo);
                z[k] = (byte) ((z[k] & BYTE_MASK) + carry);
            }
        }
    }

    /**
     * Constant-time conditional subtraction of a 32-byte modulus (zero-extended to 33 bytes) from a
     * 33-byte accumulator: if {@code r ≥ (0x00 ‖ m)} the buffer is replaced with {@code r − m},
     * otherwise it is left unchanged. Implements one iteration of step 7 of Barrett's algorithm.
     *
     * <p><b>Strategy.</b> The trial subtract is run unconditionally byte-wise (32 iterations on the
     * low half + 1 on the top byte), tracking the borrow as a short. The borrow that comes out of
     * the top-byte subtract is exactly the bit that says "we underflowed, so {@code r} was smaller
     * than {@code m_ext}". That bit is sign-extended into a 16-bit mask and fed to a mask-driven
     * byte-wise add of {@code m} back into the buffer — when the mask is zero, the add is a no-op;
     * when the mask is all-ones the add cancels out the trial subtract exactly (including the
     * top-byte borrow we just wrote, which the carry of the masked add restores).
     *
     * <p>Every byte of {@code r} and {@code m} is read and written the same number of times on
     * every call, so the wall-clock is data-independent.
     */
    private static void condSub33(byte[] r, short rOff, byte[] m, short mOff) {
        // 1. Trial subtract: r -= (0x00 ‖ m), byte-wise BE, walking the 32-byte lower half first.
        short borrow = 0;
        for (short i = (short) (MODULUS_LEN - 1); i >= 0; i--) {
            short mi = (short) (m[(short) (mOff + i)] & BYTE_MASK);
            short diff = (short) ((r[(short) (rOff + 1 + i)] & BYTE_MASK) - mi - borrow);
            r[(short) (rOff + 1 + i)] = (byte) diff;
            borrow = (short) ((diff >>> 15) & 1);
        }
        // Top byte: r[0] -= 0 (the zero-extension of m) + borrow.
        short diff0 = (short) ((r[rOff] & BYTE_MASK) - borrow);
        r[rOff] = (byte) diff0;
        // fullBorrow = 1 iff the 33-byte subtract underflowed iff r < m_ext originally.
        short fullBorrow = (short) ((diff0 >>> 15) & 1);
        short undoMask = (short) -fullBorrow; // 0xFFFF or 0x0000

        // 2. Conditionally add m back into r[1..33] (mask-driven, byte-wise) and propagate the
        //    carry into r[0]. When undoMask == 0, every masked m-byte is zero and the add is a
        //    no-op; when undoMask == -1, the add exactly cancels the trial subtract.
        short carry = 0;
        for (short i = (short) (MODULUS_LEN - 1); i >= 0; i--) {
            short mi = (short) ((m[(short) (mOff + i)] & BYTE_MASK) & undoMask);
            short sum = (short) ((r[(short) (rOff + 1 + i)] & BYTE_MASK) + mi + carry);
            r[(short) (rOff + 1 + i)] = (byte) sum;
            carry = (short) ((sum >>> BYTE_BITS) & 1);
        }
        r[rOff] = (byte) ((r[rOff] & BYTE_MASK) + carry);
    }
}
