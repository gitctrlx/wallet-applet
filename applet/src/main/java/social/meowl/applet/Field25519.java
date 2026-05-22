/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.Util;

/**
 * Field arithmetic modulo {@code p = 2²⁵⁵ − 19}, the prime base field of {@code edwards25519}.
 *
 * <p>Field elements are 32-byte big-endian unsigned integers in canonical {@code [0, p)} form. All
 * methods are static and operate on caller-supplied buffers; output buffers may alias input buffers
 * (every method reads inputs before writing the output).
 *
 * <p>Multiplication is schoolbook 32×32 → 64 followed by a constant-time pseudo-Mersenne
 * reduction ({@link #reducePseudoMersenne}) exploiting {@code 2²⁵⁶ ≡ 38 (mod p)}. Squaring is
 * implemented as {@code mul(a, a)}. Inversion uses Fermat: {@code a⁻¹ = a^(p−2) mod p} via 254
 * left-to-right square-and-multiplies. RFC 8032 wire format is little-endian; this class works
 * in big-endian and the flip happens at the {@link Ed25519} boundary.
 *
 * <p><b>Timing model.</b> Every public method is fully constant-time. Additive helpers ({@link
 * #add}, {@link #sub}, {@link #neg}) walk every byte unconditionally and the conditional
 * p-reduction is mask-driven. {@link #mul} and {@link #sqr} use the constant-time pseudo-
 * Mersenne reducer instead of the variable-time {@link Bignat#mod} kernel — the latter's
 * iteration count was a function of the secret intermediate's bit length (audit A-17). The
 * exponent in {@link #inv} is the public constant {@code p − 2}, so the schedule is data-
 * independent.
 *
 * <p>The {@link Edwards25519#randomizeProjective} input blinding (Coron CHES 1999) is retained as
 * a defence-in-depth measure: even though every individual field operation is now constant-time,
 * the projective randomisation decorrelates the bit pattern of intermediate field elements from
 * the secret scalar bits, hardening against second-order side channels (power, EM).
 */
public final class Field25519 {

    /** Length of every field element / scratch slot, in bytes. */
    public static final short LEN = (short) 32;

    /** {@code p = 2²⁵⁵ − 19} as a 32-byte big-endian constant. */
    public static final byte[] FIELD_P = {
        (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xED,
    };

    /**
     * Scratch size required by {@link #mul} / {@link #sqr} / {@link #inv} — a 64-byte slot for the
     * unreduced product plus a 32-byte slot {@link #inv} uses to hold the running power.
     */
    public static final short SCRATCH_LEN = (short) 96;

    /** Scratch sub-offsets within the caller-supplied {@link #SCRATCH_LEN}-byte buffer. */
    private static final short SCR_PROD_OFF = (short) 0; // 64-byte product

    private static final short SCR_TMP_OFF = (short) 64; // 32-byte temporary

    private Field25519() {}

    /** {@code dst[..] ← src[..]}; both buffers are 32 bytes. */
    public static void copy(byte[] src, short srcOff, byte[] dst, short dstOff) {
        Util.arrayCopyNonAtomic(src, srcOff, dst, dstOff, LEN);
    }

    /** Sets {@code dst[..] ← 0} (32 bytes). */
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
        return Bignat.ctIsZero(a, aOff, LEN) != 0;
    }

    /** Returns {@code true} iff bit 0 of canonical {@code a} is set (i.e. {@code a} is odd). */
    public static boolean isOdd(byte[] a, short aOff) {
        return (a[(short) (aOff + LEN - 1)] & 0x01) != 0;
    }

    /**
     * Returns {@code true} iff {@code a == b} in canonical form. Constant-time: XOR-accumulates
     * every byte pair and only inspects the result once at the end.
     */
    public static boolean equals(byte[] a, short aOff, byte[] b, short bOff) {
        short acc = 0;
        for (short i = 0; i < LEN; i++) {
            acc |= (short) ((a[(short) (aOff + i)] ^ b[(short) (bOff + i)]) & 0xFF);
        }
        return acc == 0;
    }

    /**
     * {@code out ← (a + b) mod p}. Inputs in {@code [0, p)}. {@code out} may alias {@code a} or
     * {@code b}; the loop reads both operand bytes before writing the destination byte at the same
     * index so any aliasing pattern is safe. Constant-time.
     */
    public static void add(byte[] a, short aOff, byte[] b, short bOff, byte[] out, short outOff) {
        short carry = 0;
        for (short i = (short) (LEN - 1); i >= 0; i--) {
            short ai = (short) (a[(short) (aOff + i)] & 0xFF);
            short bi = (short) (b[(short) (bOff + i)] & 0xFF);
            short s = (short) (ai + bi + carry);
            out[(short) (outOff + i)] = (byte) s;
            carry = (short) ((s >> 8) & 1);
        }
        // Result is in [0, 2p). Reduce: subtract p iff (carry == 1) OR (out >= p).
        short carryMask = (short) -carry;
        short lessMask = Bignat.ctLessThan(out, outOff, FIELD_P, (short) 0, LEN);
        short reduceMask = (short) (carryMask | ~lessMask);
        Bignat.condSubInPlace(out, outOff, FIELD_P, (short) 0, LEN, reduceMask);
    }

    /**
     * {@code out ← (a − b) mod p}. Inputs in {@code [0, p)}. {@code out} may alias either input.
     * Constant-time.
     */
    public static void sub(byte[] a, short aOff, byte[] b, short bOff, byte[] out, short outOff) {
        short borrow = 0;
        for (short i = (short) (LEN - 1); i >= 0; i--) {
            short ai = (short) (a[(short) (aOff + i)] & 0xFF);
            short bi = (short) (b[(short) (bOff + i)] & 0xFF);
            short d = (short) (ai - bi - borrow);
            out[(short) (outOff + i)] = (byte) d;
            borrow = (short) ((d >> 8) & 1);
        }
        // borrow == 1 iff a < b; bring back into [0, p) via mask-driven condAdd.
        short addMask = (short) -borrow;
        Bignat.condAddInPlace(out, outOff, FIELD_P, (short) 0, LEN, addMask);
    }

    /**
     * {@code out ← (−a) mod p}. {@code out} may alias {@code a}. Constant-time: always runs the
     * {@code p − a} subtraction; the {@code a == 0} corner case is masked back to {@code 0}.
     */
    public static void neg(byte[] a, short aOff, byte[] out, short outOff) {
        // Unconditional p - a. When a == 0 this writes p into out; the mask below corrects it.
        short borrow = 0;
        for (short i = (short) (LEN - 1); i >= 0; i--) {
            short pi = (short) (FIELD_P[i] & 0xFF);
            short ai = (short) (a[(short) (aOff + i)] & 0xFF);
            short d = (short) (pi - ai - borrow);
            out[(short) (outOff + i)] = (byte) d;
            borrow = (short) ((d >> 8) & 1);
        }
        // If a was zero, out now holds p; subtract p to canonicalise to 0. Otherwise mask = 0.
        short zeroMask = Bignat.ctIsZero(a, aOff, LEN);
        Bignat.condSubInPlace(out, outOff, FIELD_P, (short) 0, LEN, zeroMask);
    }

    /**
     * {@code out ← (a · b) mod p}. Uses the 64-byte product slot in {@code scratch} during the
     * call. {@code out} may alias {@code a} or {@code b}.
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
        Bignat.mult(a, aOff, b, bOff, LEN, scratch, (short) (scratchOff + SCR_PROD_OFF));
        reducePseudoMersenne(scratch, (short) (scratchOff + SCR_PROD_OFF), out, outOff);
        // Wipe only the product slot; {@link #inv} parks the staged operand in the tmp slot.
        Util.arrayFillNonAtomic(
                scratch, (short) (scratchOff + SCR_PROD_OFF), (short) (LEN * 2), (byte) 0);
    }

    /**
     * Constant-time reduction of a 64-byte big-endian product modulo {@code p = 2²⁵⁵ − 19},
     * writing the canonical 32-byte residue to {@code dst}.
     *
     * <p><b>Algorithm.</b> Pseudo-Mersenne fold using {@code 2²⁵⁶ ≡ 38 (mod p)}. The 512-bit
     * input splits as {@code x = x_hi · 2²⁵⁶ + x_lo} with {@code 0 ≤ x_hi, x_lo < 2²⁵⁶}, so
     * {@code x ≡ 38·x_hi + x_lo (mod p)}. The reduction proceeds in four steps, each constant-
     * time in every byte of the input:
     *
     * <ol>
     *   <li>Compute {@code r = (38·x_hi + x_lo) mod 2²⁵⁶} byte-wise, tracking a 6-bit carry
     *       {@code c₁ ∈ [0, 39]} (the {@code 38·x_hi + x_lo} fits in 38 + 32 + small bits).
     *   <li>Fold the carry: {@code r ← r + 38·c₁}. Since {@code 38·c₁ ≤ 1482 ≤ 2¹¹}, the result
     *       is at most {@code 2²⁵⁶ + 1481 < 2²⁵⁷}; the new top-carry {@code c₂ ∈ {0, 1}}.
     *   <li>Fold again: {@code r ← r + 38·c₂}. If {@code c₂ = 1} the body was {@code ≤ 1481}
     *       before this step, so after adding {@code 38} the body is {@code ≤ 1519 < 2¹¹} and
     *       no further carry escapes; if {@code c₂ = 0} the body is unchanged. In both cases
     *       {@code r < 2²⁵⁶} after this step.
     *   <li>Run two unconditional mask-driven {@code condSub(r, p)} passes. After the first
     *       pass {@code r ∈ [0, 2p)}, after the second {@code r ∈ [0, p)}, regardless of which
     *       sub-range the post-fold value originally landed in.
     * </ol>
     *
     * <p><b>Constant-time argument.</b> Every iteration of every loop runs unconditionally. The
     * carry/borrow chains carry data-dependent values but their schedule (number of operations,
     * sequence of reads and writes) is fixed. {@link Bignat#condSubInPlace} is itself mask-
     * driven. There are no early exits.
     *
     * <p><b>Performance.</b> ~96 byte-ops for step 1, ~33 for step 2, ~33 for step 3, ~64 for
     * the two condSubs. Total ~226 byte-ops vs ~2 000 for the prior {@link Bignat#mod} kernel
     * (~8× speed-up on the typical curve operation, ~10× on the worst case the long-division
     * loop walked).
     *
     * @param x       64-byte big-endian product; UNMODIFIED on return.
     * @param xOff    start offset within {@code x}.
     * @param dst     32-byte big-endian output; receives {@code x mod p}.
     * @param dstOff  start offset within {@code dst}.
     */
    static void reducePseudoMersenne(byte[] x, short xOff, byte[] dst, short dstOff) {
        // Step 1: r = (38 · x_hi + x_lo) mod 2^256, c1 = (38 · x_hi + x_lo) >> 256.
        short carry = 0;
        for (short i = (short) (LEN - 1); i >= 0; i--) {
            short prod = (short) (38 * (x[(short) (xOff + i)] & 0xFF));
            short sum = (short) ((x[(short) (xOff + LEN + i)] & 0xFF) + (prod & 0xFF) + carry);
            dst[(short) (dstOff + i)] = (byte) sum;
            carry = (short) (((prod >>> 8) & 0xFF) + ((sum >>> 8) & 0xFF));
        }
        // Step 2: r += 38 · c1. carry ∈ [0, 39], 38·c1 ∈ [0, 1482] fits in two bytes.
        short carry38 = (short) (38 * carry);
        short low = (short) (carry38 & 0xFF);
        short high = (short) ((carry38 >>> 8) & 0xFF);
        short sum = (short) ((dst[(short) (dstOff + LEN - 1)] & 0xFF) + low);
        dst[(short) (dstOff + LEN - 1)] = (byte) sum;
        short c2 = (short) ((sum >>> 8) & 1);
        sum = (short) ((dst[(short) (dstOff + LEN - 2)] & 0xFF) + high + c2);
        dst[(short) (dstOff + LEN - 2)] = (byte) sum;
        c2 = (short) ((sum >>> 8) & 1);
        for (short i = (short) (LEN - 3); i >= 0; i--) {
            sum = (short) ((dst[(short) (dstOff + i)] & 0xFF) + c2);
            dst[(short) (dstOff + i)] = (byte) sum;
            c2 = (short) ((sum >>> 8) & 1);
        }
        // Step 3: r += 38 · c2. c2 ∈ {0, 1}; 38·c2 ∈ {0, 38} (one byte).
        short prod = (short) (38 * c2);
        sum = (short) ((dst[(short) (dstOff + LEN - 1)] & 0xFF) + prod);
        dst[(short) (dstOff + LEN - 1)] = (byte) sum;
        short c3 = (short) ((sum >>> 8) & 1);
        for (short i = (short) (LEN - 2); i >= 0; i--) {
            sum = (short) ((dst[(short) (dstOff + i)] & 0xFF) + c3);
            dst[(short) (dstOff + i)] = (byte) sum;
            c3 = (short) ((sum >>> 8) & 1);
        }
        // Step 4: two unconditional condSubs of p. After step 3 r ∈ [0, 2²⁵⁶), and since
        // 3p > 2²⁵⁶ but 2p = 2²⁵⁶ − 38, r could need up to 2 subs to land in [0, p).
        short ge1 = (short) ~Bignat.ctLessThan(dst, dstOff, FIELD_P, (short) 0, LEN);
        Bignat.condSubInPlace(dst, dstOff, FIELD_P, (short) 0, LEN, ge1);
        short ge2 = (short) ~Bignat.ctLessThan(dst, dstOff, FIELD_P, (short) 0, LEN);
        Bignat.condSubInPlace(dst, dstOff, FIELD_P, (short) 0, LEN, ge2);
    }

    /** {@code out ← (a · a) mod p}. Implemented as {@code mul(a, a)} for code-size minimality. */
    public static void sqr(
            byte[] a, short aOff, byte[] out, short outOff, byte[] scratch, short scratchOff) {
        mul(a, aOff, a, aOff, out, outOff, scratch, scratchOff);
    }

    /**
     * {@code out ← a⁻¹ mod p} via Fermat's {@code a^(p−2)}. Left-to-right square-and-multiply over
     * the public exponent {@code p − 2}, so the schedule is data-independent. {@code out} may alias
     * {@code a}.
     */
    public static void inv(
            byte[] a, short aOff, byte[] out, short outOff, byte[] scratch, short scratchOff) {
        // Stage `a` into a private 32-byte slot so out-aliases-a is safe.
        short tmpOff = (short) (scratchOff + SCR_TMP_OFF);
        copy(a, aOff, scratch, tmpOff);

        // Initialise running power r ← 1 in the output slot.
        one(out, outOff);

        // Exponent e = p − 2. p_minus_2 = FIELD_P − 2: same bytes as FIELD_P except the trailing
        // 0xED becomes 0xEB (since 0xED − 2 = 0xEB and there is no borrow).
        for (short byteIdx = 0; byteIdx < LEN; byteIdx++) {
            short eByte = (short) (FIELD_P[byteIdx] & 0xFF);
            if (byteIdx == (short) (LEN - 1)) {
                eByte = (short) (eByte - 2); // 0xED → 0xEB
            }
            for (short bit = 7; bit >= 0; bit--) {
                // r ← r²
                sqr(out, outOff, out, outOff, scratch, scratchOff);
                if (((eByte >> bit) & 1) != 0) {
                    // r ← r · a (using the staged copy so out can alias a originally).
                    mul(out, outOff, scratch, tmpOff, out, outOff, scratch, scratchOff);
                }
            }
        }
        // Wipe the staged-a slot.
        Util.arrayFillNonAtomic(scratch, tmpOff, LEN, (byte) 0);
    }
}
