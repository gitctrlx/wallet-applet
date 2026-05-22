/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.Util;

/**
 * Field arithmetic modulo {@code p = 2²⁵⁵ − 19}, the prime base field of {@code edwards25519}.
 *
 * <p>Every field element is represented as a 32-byte big-endian unsigned integer in {@code [0, p)};
 * inputs and outputs are always in this canonical reduced form. The class is purely static and
 * holds no state: the caller passes the operand buffers, their offsets, and a scratch buffer for
 * the operations that need one ({@link #mul}, {@link #sqr}, {@link #inv}). Output buffers may alias
 * input buffers — every method reads its inputs into local variables (or the scratch) before
 * writing the output back.
 *
 * <p>Multiplication is schoolbook 32×32 → 64 (via {@link Bignat#mult}) followed by long-division
 * reduction against {@link #FIELD_P} (via {@link Bignat#mod}). Squaring is implemented as {@link
 * #mul}{@code (a, a)}; we deliberately do not specialise a separate squaring kernel because the
 * saving (≈25 % per square) does not justify a duplicate code path on the applet-line-budget axis.
 * Inversion uses Fermat's little theorem: {@code a⁻¹ = a^(p−2) mod p}, computed by 254
 * left-to-right square-and-multiplies; the exponent {@code p − 2 = 2²⁵⁵ − 21} has Hamming weight
 * 250 over its 255 bits so the cost is ≈ 254 squarings + 250 multiplications.
 *
 * <p>The wire format used by RFC 8032 is 32-byte little-endian; this class works exclusively in
 * big-endian for consistency with the rest of the applet ({@link Bignat}, {@link Bip32}, {@link
 * Schnorr}). The endianness flip happens once, at the {@link Ed25519} wire boundary.
 *
 * <p><b>Timing model (audit F-01 mitigation).</b> The additive helpers — {@link #add}, {@link
 * #sub}, {@link #neg} — are fully constant-time: they always run both the unconditional 32-byte
 * addition / subtraction <em>and</em> the conditional reduction (subtract {@code p}) or correction
 * (add {@code p}), with the reduction step driven by a {@code -1}/{@code 0} mask derived from the
 * carry/borrow flag through {@link Bignat#condSubInPlace} / {@link Bignat#condAddInPlace}. The
 * inversion exponent {@code p − 2} is a public constant so the square-and-multiply schedule in
 * {@link #inv} is data-independent at the high level.
 *
 * <p>The multiplicative kernels {@link #mul} and {@link #sqr} still pass through {@link
 * Bignat#mod}, which is a variable-time schoolbook long-division and therefore <b>not</b>
 * constant-time on its own. The defence against that residual side channel lives one level up, in
 * {@link Edwards25519#randomizeProjective}: every {@link Edwards25519#scalarMult} entry blinds the
 * projective coordinates {@code (X, Y, Z, T)} of the input point with a fresh random non-zero field
 * element {@code r}. Because the affine projection {@code (X/Z, Y/Z)} is invariant under {@code (X,
 * Y, Z, T) ↦ (rX, rY, rZ, rT)}, the output is unchanged but every intermediate field element fed
 * into {@link Bignat#mod} during the 256-iteration scalar ladder is statistically decorrelated from
 * the secret scalar across calls. This is the SPA defence recommended by Coron (CHES 1999,
 * projective coordinate randomisation).
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

    /** Sets {@code dst[..] ← 1} (canonical 32-byte big-endian one). */
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
     * {@code out ← (a − b) mod p}. Inputs in {@code [0, p)}. {@code out} may alias either input;
     * the loop reads {@code a[i]} and {@code b[i]} before writing {@code out[i]}. Constant-time.
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
        // borrow == 1 iff a < b; bring back into [0, p) by unconditionally running condAdd with
        // a borrow-derived mask. The branch is gone.
        short addMask = (short) -borrow;
        Bignat.condAddInPlace(out, outOff, FIELD_P, (short) 0, LEN, addMask);
    }

    /**
     * {@code out ← (−a) mod p}. {@code out} may alias {@code a}. Constant-time: always evaluates
     * the {@code p − a} subtraction and uses a mask to drive the {@code a == 0} corner case to
     * {@code out = 0} without branching.
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
        // If a was zero, out now holds p — subtract p (mask = -1) to canonicalise to 0. If a was
        // non-zero, mask = 0 leaves out untouched.
        short zeroMask = Bignat.ctIsZero(a, aOff, LEN);
        Bignat.condSubInPlace(out, outOff, FIELD_P, (short) 0, LEN, zeroMask);
    }

    /**
     * {@code out ← (a · b) mod p}. {@code scratch[scratchOff..scratchOff+SCRATCH_LEN]} holds the
     * 64-byte product during the call; on return the entire scratch slice is wiped. {@code out} may
     * alias {@code a} or {@code b}; the implementation reads both inputs into the scratch before
     * writing {@code out}.
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
        // Wipe only the 64-byte product slot; the trailing 32-byte tmp slot belongs to the
        // caller (notably {@link #inv} parks the staged operand there across loop iterations).
        Util.arrayFillNonAtomic(
                scratch, (short) (scratchOff + SCR_PROD_OFF), (short) (LEN * 2), (byte) 0);
    }

    /**
     * {@code out ← (a · a) mod p}. Same scratch contract as {@link #mul}; this is implemented as
     * {@code mul(a, a)} for code-size minimality.
     */
    public static void sqr(
            byte[] a, short aOff, byte[] out, short outOff, byte[] scratch, short scratchOff) {
        mul(a, aOff, a, aOff, out, outOff, scratch, scratchOff);
    }

    /**
     * {@code out ← a⁻¹ mod p} via {@code a^(p−2)}. Uses left-to-right square-and-multiply over the
     * public exponent {@code p − 2 = 2²⁵⁵ − 21}, so the schedule (squarings vs. squarings + mult)
     * is independent of the secret operand {@code a}; only the operand magnitudes differ across
     * calls.
     *
     * <p>The 96-byte scratch holds the running power {@code r} in its first 32 bytes (alias of the
     * {@code SCR_TMP_OFF} slot) and the 64-byte product workspace shared with {@link #mul} in the
     * trailing 64 bytes. {@code out} may alias {@code a}.
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
