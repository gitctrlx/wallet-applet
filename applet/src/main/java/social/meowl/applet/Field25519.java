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
 * <p>Multiplication is schoolbook 32×32 → 64 followed by long-division reduction against {@link
 * #FIELD_P}. Squaring is implemented as {@code mul(a, a)}. Inversion uses Fermat: {@code a⁻¹ =
 * a^(p−2) mod p} via 254 left-to-right square-and-multiplies. RFC 8032 wire format is little-
 * endian; this class works in big-endian and the flip happens at the {@link Ed25519} boundary.
 *
 * <p><b>Timing model.</b> Additive helpers ({@link #add}, {@link #sub}, {@link #neg}) are fully
 * constant-time: the add/sub and the conditional p-reduction (driven by a {@code -1}/{@code 0}
 * mask) always run. The exponent in {@link #inv} is the public constant {@code p − 2}, so the
 * schedule is data-independent.
 *
 * <p>The multiplicative kernels {@link #mul} / {@link #sqr} still pass through the variable-time
 * {@link Bignat#mod}. The SPA defence lives one level up in {@link Edwards25519#scalarMult}, which
 * blinds the input via {@link Edwards25519#randomizeProjective} (Coron CHES 1999) so every
 * intermediate fed into {@link Bignat#mod} is statistically decorrelated from the secret scalar.
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
        Bignat.mod(
                scratch,
                (short) (scratchOff + SCR_PROD_OFF),
                (short) (LEN * 2),
                FIELD_P,
                (short) 0,
                LEN);
        // Bignat.mod leaves the reduced value in the trailing 32 bytes of the dividend buffer.
        Util.arrayCopyNonAtomic(
                scratch, (short) (scratchOff + SCR_PROD_OFF + LEN), out, outOff, LEN);
        // Wipe only the product slot; {@link #inv} parks the staged operand in the tmp slot.
        Util.arrayFillNonAtomic(
                scratch, (short) (scratchOff + SCR_PROD_OFF), (short) (LEN * 2), (byte) 0);
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
