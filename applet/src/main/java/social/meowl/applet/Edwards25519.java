/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.Util;

/**
 * Twisted-Edwards group operations for {@code edwards25519}.
 *
 * <p>The curve is {@code -x² + y² = 1 + d·x²·y² (mod p)} with {@code d = -121665/121666 mod p}.
 * Points are stored in extended projective coordinates {@code (X, Y, Z, T)} with {@code x = X/Z},
 * {@code y = Y/Z}, {@code T = X·Y/Z}; this lets the addition and doubling formulas dispense with
 * inversions until the final encoding step. The class is purely static and stateless: all working
 * memory is provided by the caller, and {@link Field25519} owns the underlying field arithmetic.
 *
 * <p>Memory layout — every point occupies {@link #POINT_LEN} = 128 contiguous big-endian bytes laid
 * out as {@code X(32) ‖ Y(32) ‖ Z(32) ‖ T(32)}. The output of {@link #pointAdd} and {@link
 * #pointDouble} is materialised at the very end (after every input byte has been read into
 * scratch), so the caller may freely alias the output with either input.
 *
 * <p>Formulas — addition {@code add-2008-hwcd-3} (9 multiplications) and doubling {@code
 * dbl-2008-hwcd} (3 squarings + 4 multiplications) from the Explicit-Formulas Database, specialised
 * for {@code a = -1}. Both are listed at <a
 * href="https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html">EFD</a>.
 *
 * <p>Scalar multiplication is a constant-time double-and-always-add over the full 256-bit scalar
 * range, which subsumes both the BIP-340-style 253-bit reduced scalars and the RFC 8032 secret
 * scalars (clamped into {@code [2²⁵⁴, 2²⁵⁵ − 8)}). Each of the 256 iterations performs exactly one
 * doubling and one addition, with the addend selected via byte-wise masking between the input point
 * and the identity element so the secret bit never branches the control flow.
 */
public final class Edwards25519 {

    /** Bytes per point in {@code (X, Y, Z, T)} extended-coordinate layout. */
    public static final short POINT_LEN = (short) 128;

    /** Bytes per encoded point in RFC 8032 §5.1.2 little-endian compressed form. */
    public static final short ENCODED_LEN = (short) 32;

    /** Sub-offsets of {@code X, Y, Z, T} within a {@link #POINT_LEN}-byte point buffer. */
    public static final short PT_X_OFF = (short) 0;

    public static final short PT_Y_OFF = (short) 32;
    public static final short PT_Z_OFF = (short) 64;
    public static final short PT_T_OFF = (short) 96;

    /**
     * Scratch budget for {@link #pointAdd} and {@link #pointDouble} — 9 field-element slots for
     * intermediates {@code A‥H + spare} plus a {@link Field25519#SCRATCH_LEN}-byte slot for every
     * field multiplication / inversion the formulas perform.
     */
    public static final short POINT_OP_SCRATCH_LEN = (short) (9 * 32 + Field25519.SCRATCH_LEN);

    /**
     * Scratch budget for {@link #scalarMult} — the {@link #POINT_OP_SCRATCH_LEN} buffer used by the
     * inner add/double pair plus a 128-byte scratch slot for the conditionally selected addend
     * point.
     */
    public static final short SCALAR_MULT_SCRATCH_LEN = (short) (POINT_OP_SCRATCH_LEN + POINT_LEN);

    /**
     * Scratch budget for {@link #encodePoint} — one Field25519 inversion buffer plus two field-
     * element slots ({@code Z⁻¹} and the affine {@code x}).
     */
    public static final short ENCODE_SCRATCH_LEN = (short) (Field25519.SCRATCH_LEN + 2 * 32);

    /** Sub-offsets of the 9 field temporaries within the point-op scratch slice. */
    private static final short A_OFF = (short) (0 * 32);

    private static final short B_OFF = (short) (1 * 32);
    private static final short C_OFF = (short) (2 * 32);
    private static final short D_OFF = (short) (3 * 32);
    private static final short E_OFF = (short) (4 * 32);
    private static final short F_OFF = (short) (5 * 32);
    private static final short G_OFF = (short) (6 * 32);
    private static final short H_OFF = (short) (7 * 32);
    private static final short SPARE_OFF = (short) (8 * 32);
    private static final short FIELD_SCR_OFF = (short) (9 * 32);

    /**
     * Edwards25519 curve constant {@code d = -121665/121666 mod p}, big-endian.
     *
     * <p>{@code d = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3}.
     */
    public static final byte[] D = {
        (byte) 0x52, (byte) 0x03, (byte) 0x6C, (byte) 0xEE,
        (byte) 0x2B, (byte) 0x6F, (byte) 0xFE, (byte) 0x73,
        (byte) 0x8C, (byte) 0xC7, (byte) 0x40, (byte) 0x79,
        (byte) 0x77, (byte) 0x79, (byte) 0xE8, (byte) 0x98,
        (byte) 0x00, (byte) 0x70, (byte) 0x0A, (byte) 0x4D,
        (byte) 0x41, (byte) 0x41, (byte) 0xD8, (byte) 0xAB,
        (byte) 0x75, (byte) 0xEB, (byte) 0x4D, (byte) 0xCA,
        (byte) 0x13, (byte) 0x59, (byte) 0x78, (byte) 0xA3,
    };

    /**
     * Pre-doubled curve constant {@code 2d mod p}, big-endian. Used by {@link #pointAdd} for the
     * {@code C ← T1 · 2d · T2} step so we save one field-multiplication per addition.
     *
     * <p>{@code 2d = 0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159}.
     */
    public static final byte[] D2 = {
        (byte) 0x24, (byte) 0x06, (byte) 0xD9, (byte) 0xDC,
        (byte) 0x56, (byte) 0xDF, (byte) 0xFC, (byte) 0xE7,
        (byte) 0x19, (byte) 0x8E, (byte) 0x80, (byte) 0xF2,
        (byte) 0xEE, (byte) 0xF3, (byte) 0xD1, (byte) 0x30,
        (byte) 0x00, (byte) 0xE0, (byte) 0x14, (byte) 0x9A,
        (byte) 0x82, (byte) 0x83, (byte) 0xB1, (byte) 0x56,
        (byte) 0xEB, (byte) 0xD6, (byte) 0x9B, (byte) 0x94,
        (byte) 0x26, (byte) 0xB2, (byte) 0xF1, (byte) 0x59,
    };

    /** Base-point {@code X} coordinate, big-endian. */
    private static final byte[] BASE_X = {
        (byte) 0x21, (byte) 0x69, (byte) 0x36, (byte) 0xD3,
        (byte) 0xCD, (byte) 0x6E, (byte) 0x53, (byte) 0xFE,
        (byte) 0xC0, (byte) 0xA4, (byte) 0xE2, (byte) 0x31,
        (byte) 0xFD, (byte) 0xD6, (byte) 0xDC, (byte) 0x5C,
        (byte) 0x69, (byte) 0x2C, (byte) 0xC7, (byte) 0x60,
        (byte) 0x95, (byte) 0x25, (byte) 0xA7, (byte) 0xB2,
        (byte) 0xC9, (byte) 0x56, (byte) 0x2D, (byte) 0x60,
        (byte) 0x8F, (byte) 0x25, (byte) 0xD5, (byte) 0x1A,
    };

    /** Base-point {@code Y} coordinate, big-endian. */
    private static final byte[] BASE_Y = {
        (byte) 0x66, (byte) 0x66, (byte) 0x66, (byte) 0x66,
        (byte) 0x66, (byte) 0x66, (byte) 0x66, (byte) 0x66,
        (byte) 0x66, (byte) 0x66, (byte) 0x66, (byte) 0x66,
        (byte) 0x66, (byte) 0x66, (byte) 0x66, (byte) 0x66,
        (byte) 0x66, (byte) 0x66, (byte) 0x66, (byte) 0x66,
        (byte) 0x66, (byte) 0x66, (byte) 0x66, (byte) 0x66,
        (byte) 0x66, (byte) 0x66, (byte) 0x66, (byte) 0x66,
        (byte) 0x66, (byte) 0x66, (byte) 0x66, (byte) 0x58,
    };

    /** Base-point {@code T = X · Y mod p}, big-endian (precomputed so {@code Z = 1}). */
    private static final byte[] BASE_T = {
        (byte) 0x67, (byte) 0x87, (byte) 0x5F, (byte) 0x0F,
        (byte) 0xD7, (byte) 0x8B, (byte) 0x76, (byte) 0x65,
        (byte) 0x66, (byte) 0xEA, (byte) 0x4E, (byte) 0x8E,
        (byte) 0x64, (byte) 0xAB, (byte) 0xE3, (byte) 0x7D,
        (byte) 0x20, (byte) 0xF0, (byte) 0x9F, (byte) 0x80,
        (byte) 0x77, (byte) 0x51, (byte) 0x52, (byte) 0xF5,
        (byte) 0x6D, (byte) 0xDE, (byte) 0x8A, (byte) 0xB3,
        (byte) 0xA5, (byte) 0xB7, (byte) 0xDD, (byte) 0xA3,
    };

    private Edwards25519() {}

    /** Writes the identity element {@code (0, 1, 1, 0)} into a 128-byte point slot. */
    public static void setIdentity(byte[] out, short outOff) {
        Util.arrayFillNonAtomic(out, outOff, POINT_LEN, (byte) 0);
        // Y = 1
        out[(short) (outOff + PT_Y_OFF + Field25519.LEN - 1)] = (byte) 0x01;
        // Z = 1
        out[(short) (outOff + PT_Z_OFF + Field25519.LEN - 1)] = (byte) 0x01;
        // X = T = 0 (already zeroed).
    }

    /** Writes the curve base point {@code B = (BASE_X, BASE_Y, 1, BASE_T)} into a 128-byte slot. */
    public static void setBase(byte[] out, short outOff) {
        Field25519.copy(BASE_X, (short) 0, out, (short) (outOff + PT_X_OFF));
        Field25519.copy(BASE_Y, (short) 0, out, (short) (outOff + PT_Y_OFF));
        Field25519.one(out, (short) (outOff + PT_Z_OFF));
        Field25519.copy(BASE_T, (short) 0, out, (short) (outOff + PT_T_OFF));
    }

    /** Copies a 128-byte point. */
    public static void copyPoint(byte[] src, short srcOff, byte[] dst, short dstOff) {
        Util.arrayCopyNonAtomic(src, srcOff, dst, dstOff, POINT_LEN);
    }

    /**
     * {@code out ← 2 · in} in extended coordinates. Output may alias the input — every byte of the
     * input is consumed before any byte of the output is written.
     */
    public static void pointDouble(
            byte[] out, short outOff, byte[] in, short inOff, byte[] scratch, short scratchOff) {
        short fScr = (short) (scratchOff + FIELD_SCR_OFF);

        // tmp ← X1 + Y1 (use SPARE_OFF as a 32-byte scratch slot for the temporary).
        Field25519.add(
                in, (short) (inOff + PT_X_OFF),
                in, (short) (inOff + PT_Y_OFF),
                scratch, (short) (scratchOff + SPARE_OFF));
        // A ← X1²
        Field25519.sqr(
                in, (short) (inOff + PT_X_OFF),
                scratch, (short) (scratchOff + A_OFF),
                scratch, fScr);
        // B ← Y1²
        Field25519.sqr(
                in, (short) (inOff + PT_Y_OFF),
                scratch, (short) (scratchOff + B_OFF),
                scratch, fScr);
        // C ← 2 · Z1²
        Field25519.sqr(
                in, (short) (inOff + PT_Z_OFF),
                scratch, (short) (scratchOff + C_OFF),
                scratch, fScr);
        Field25519.add(
                scratch, (short) (scratchOff + C_OFF),
                scratch, (short) (scratchOff + C_OFF),
                scratch, (short) (scratchOff + C_OFF));
        // tmp ← (X1 + Y1)²
        Field25519.sqr(
                scratch, (short) (scratchOff + SPARE_OFF),
                scratch, (short) (scratchOff + SPARE_OFF),
                scratch, fScr);
        // E ← (X1 + Y1)² − A − B
        Field25519.sub(
                scratch, (short) (scratchOff + SPARE_OFF),
                scratch, (short) (scratchOff + A_OFF),
                scratch, (short) (scratchOff + E_OFF));
        Field25519.sub(
                scratch, (short) (scratchOff + E_OFF),
                scratch, (short) (scratchOff + B_OFF),
                scratch, (short) (scratchOff + E_OFF));
        // D ← −A   (a = −1 in the twisted-Edwards equation)
        Field25519.neg(
                scratch, (short) (scratchOff + A_OFF),
                scratch, (short) (scratchOff + D_OFF));
        // G ← D + B = B − A
        Field25519.add(
                scratch, (short) (scratchOff + D_OFF),
                scratch, (short) (scratchOff + B_OFF),
                scratch, (short) (scratchOff + G_OFF));
        // H ← D − B = −(A + B)
        Field25519.sub(
                scratch, (short) (scratchOff + D_OFF),
                scratch, (short) (scratchOff + B_OFF),
                scratch, (short) (scratchOff + H_OFF));
        // F ← G − C
        Field25519.sub(
                scratch, (short) (scratchOff + G_OFF),
                scratch, (short) (scratchOff + C_OFF),
                scratch, (short) (scratchOff + F_OFF));
        // X3 ← E · F, Y3 ← G · H, T3 ← E · H, Z3 ← F · G  (write outputs last so out may alias in)
        Field25519.mul(
                scratch, (short) (scratchOff + E_OFF),
                scratch, (short) (scratchOff + F_OFF),
                out, (short) (outOff + PT_X_OFF),
                scratch, fScr);
        Field25519.mul(
                scratch, (short) (scratchOff + G_OFF),
                scratch, (short) (scratchOff + H_OFF),
                out, (short) (outOff + PT_Y_OFF),
                scratch, fScr);
        Field25519.mul(
                scratch, (short) (scratchOff + E_OFF),
                scratch, (short) (scratchOff + H_OFF),
                out, (short) (outOff + PT_T_OFF),
                scratch, fScr);
        Field25519.mul(
                scratch, (short) (scratchOff + F_OFF),
                scratch, (short) (scratchOff + G_OFF),
                out, (short) (outOff + PT_Z_OFF),
                scratch, fScr);
    }

    /** {@code out ← in1 + in2} in extended coordinates. Output may alias either input. */
    public static void pointAdd(
            byte[] out,
            short outOff,
            byte[] in1,
            short in1Off,
            byte[] in2,
            short in2Off,
            byte[] scratch,
            short scratchOff) {
        short fScr = (short) (scratchOff + FIELD_SCR_OFF);

        // A ← (Y1 − X1) · (Y2 − X2). Use A_OFF for (Y1 − X1) and SPARE_OFF for (Y2 − X2).
        Field25519.sub(
                in1, (short) (in1Off + PT_Y_OFF),
                in1, (short) (in1Off + PT_X_OFF),
                scratch, (short) (scratchOff + A_OFF));
        Field25519.sub(
                in2, (short) (in2Off + PT_Y_OFF),
                in2, (short) (in2Off + PT_X_OFF),
                scratch, (short) (scratchOff + SPARE_OFF));
        Field25519.mul(
                scratch, (short) (scratchOff + A_OFF),
                scratch, (short) (scratchOff + SPARE_OFF),
                scratch, (short) (scratchOff + A_OFF),
                scratch, fScr);
        // B ← (Y1 + X1) · (Y2 + X2). Reuse B_OFF and SPARE_OFF for the additive temporaries.
        Field25519.add(
                in1, (short) (in1Off + PT_Y_OFF),
                in1, (short) (in1Off + PT_X_OFF),
                scratch, (short) (scratchOff + B_OFF));
        Field25519.add(
                in2, (short) (in2Off + PT_Y_OFF),
                in2, (short) (in2Off + PT_X_OFF),
                scratch, (short) (scratchOff + SPARE_OFF));
        Field25519.mul(
                scratch, (short) (scratchOff + B_OFF),
                scratch, (short) (scratchOff + SPARE_OFF),
                scratch, (short) (scratchOff + B_OFF),
                scratch, fScr);
        // C ← T1 · 2d · T2.  Compute (2d · T1) into C_OFF, then multiply by T2.
        Field25519.mul(
                in1, (short) (in1Off + PT_T_OFF),
                D2, (short) 0,
                scratch, (short) (scratchOff + C_OFF),
                scratch, fScr);
        Field25519.mul(
                scratch, (short) (scratchOff + C_OFF),
                in2, (short) (in2Off + PT_T_OFF),
                scratch, (short) (scratchOff + C_OFF),
                scratch, fScr);
        // D ← Z1 · 2 · Z2. Compute Z1 · Z2 then double.
        Field25519.mul(
                in1, (short) (in1Off + PT_Z_OFF),
                in2, (short) (in2Off + PT_Z_OFF),
                scratch, (short) (scratchOff + D_OFF),
                scratch, fScr);
        Field25519.add(
                scratch, (short) (scratchOff + D_OFF),
                scratch, (short) (scratchOff + D_OFF),
                scratch, (short) (scratchOff + D_OFF));
        // E ← B − A, F ← D − C, G ← D + C, H ← B + A.
        Field25519.sub(
                scratch, (short) (scratchOff + B_OFF),
                scratch, (short) (scratchOff + A_OFF),
                scratch, (short) (scratchOff + E_OFF));
        Field25519.sub(
                scratch, (short) (scratchOff + D_OFF),
                scratch, (short) (scratchOff + C_OFF),
                scratch, (short) (scratchOff + F_OFF));
        Field25519.add(
                scratch, (short) (scratchOff + D_OFF),
                scratch, (short) (scratchOff + C_OFF),
                scratch, (short) (scratchOff + G_OFF));
        Field25519.add(
                scratch, (short) (scratchOff + B_OFF),
                scratch, (short) (scratchOff + A_OFF),
                scratch, (short) (scratchOff + H_OFF));
        // X3 ← E · F, Y3 ← G · H, T3 ← E · H, Z3 ← F · G — write to out last.
        Field25519.mul(
                scratch, (short) (scratchOff + E_OFF),
                scratch, (short) (scratchOff + F_OFF),
                out, (short) (outOff + PT_X_OFF),
                scratch, fScr);
        Field25519.mul(
                scratch, (short) (scratchOff + G_OFF),
                scratch, (short) (scratchOff + H_OFF),
                out, (short) (outOff + PT_Y_OFF),
                scratch, fScr);
        Field25519.mul(
                scratch, (short) (scratchOff + E_OFF),
                scratch, (short) (scratchOff + H_OFF),
                out, (short) (outOff + PT_T_OFF),
                scratch, fScr);
        Field25519.mul(
                scratch, (short) (scratchOff + F_OFF),
                scratch, (short) (scratchOff + G_OFF),
                out, (short) (outOff + PT_Z_OFF),
                scratch, fScr);
    }

    /**
     * Constant-time conditional copy: {@code dst ← (mask ? a : b)}. {@code mask} must be either
     * {@code 0xFF} (select {@code a}) or {@code 0x00} (select {@code b}); the bytewise AND/OR
     * pattern leaks no timing information about which branch was taken.
     */
    private static void conditionalCopy(
            byte[] dst,
            short dstOff,
            byte[] a,
            short aOff,
            byte[] b,
            short bOff,
            short len,
            byte mask) {
        for (short i = 0; i < len; i++) {
            short ai = (short) (a[(short) (aOff + i)] & 0xFF);
            short bi = (short) (b[(short) (bOff + i)] & 0xFF);
            short m = (short) (mask & 0xFF);
            dst[(short) (dstOff + i)] = (byte) ((ai & m) | (bi & (m ^ 0xFF)));
        }
    }

    /**
     * {@code out ← scalar · in} where {@code scalar} is interpreted as a 256-bit big-endian
     * unsigned integer. Output must not alias either {@code in} or {@code scalar}.
     *
     * <p>The implementation is a constant-time double-and-always-add over all 256 scalar bits: each
     * iteration unconditionally doubles the accumulator and adds either the input point or the
     * identity (selected via a {@link #conditionalCopy} of two equal-cost masks). This makes the
     * running time independent of the scalar's Hamming weight or value, which matters because the
     * same routine is invoked with secret scalars in {@link Ed25519}.
     */
    public static void scalarMult(
            byte[] scalar,
            short scalarOff,
            byte[] in,
            short inOff,
            byte[] out,
            short outOff,
            byte[] scratch,
            short scratchOff) {
        short addendOff = (short) (scratchOff + POINT_OP_SCRATCH_LEN);

        // Initialise the accumulator at the identity.
        setIdentity(out, outOff);

        // Stage the identity into the addend slot once; conditionalCopy will overwrite it as
        // needed each iteration. The identity is reset before each select so the (mask = 0)
        // branch always sees the identity at addendOff.
        for (short i = (short) 255; i >= 0; i--) {
            // R ← 2 · R
            pointDouble(out, outOff, out, outOff, scratch, scratchOff);

            // Extract bit i of the scalar (BE).
            short byteIdx = (short) (31 - (i >> 3));
            short bitInByte = (short) (i & 7);
            short bit = (short) ((scalar[(short) (scalarOff + byteIdx)] >>> bitInByte) & 1);
            byte mask = (byte) -bit; // 0x00 if bit == 0, 0xFF if bit == 1

            // addend ← (bit ? in : identity)
            setIdentity(scratch, addendOff);
            conditionalCopy(scratch, addendOff, in, inOff, scratch, addendOff, POINT_LEN, mask);

            // R ← R + addend
            pointAdd(out, outOff, out, outOff, scratch, addendOff, scratch, scratchOff);
        }
    }

    /**
     * Encodes the point at {@code (X, Y, Z, T)} into a 32-byte little-endian RFC 8032 §5.1.2
     * compressed form. The encoded form is {@code y_LE} with the high bit of byte 31 set to bit 0
     * of the affine {@code x = X · Z⁻¹}.
     */
    public static void encodePoint(
            byte[] in, short inOff, byte[] out, short outOff, byte[] scratch, short scratchOff) {
        short zInvOff = (short) (scratchOff + Field25519.SCRATCH_LEN);
        short xAffOff = (short) (scratchOff + Field25519.SCRATCH_LEN + 32);

        // zInv ← Z⁻¹
        Field25519.inv(
                in, (short) (inOff + PT_Z_OFF),
                scratch, zInvOff,
                scratch, scratchOff);
        // x_aff ← X · Z⁻¹  (kept in big-endian form)
        Field25519.mul(
                in, (short) (inOff + PT_X_OFF),
                scratch, zInvOff,
                scratch, xAffOff,
                scratch, scratchOff);
        // Encode y_aff = Y · Z⁻¹ into the output slot, in big-endian form first.
        Field25519.mul(
                in, (short) (inOff + PT_Y_OFF),
                scratch, zInvOff,
                out, outOff,
                scratch, scratchOff);
        // Reverse to little-endian in place.
        for (short i = 0; i < (short) (Field25519.LEN / 2); i++) {
            short lo = (short) (outOff + i);
            short hi = (short) (outOff + Field25519.LEN - 1 - i);
            byte tmp = out[lo];
            out[lo] = out[hi];
            out[hi] = tmp;
        }
        // Set bit 7 of the LE high byte (= byte 31 of out) to bit 0 of x_aff.
        // x_aff is BE; bit 0 lives in its last byte.
        byte xParity = (byte) ((scratch[(short) (xAffOff + Field25519.LEN - 1)] & 0x01) << 7);
        out[(short) (outOff + Field25519.LEN - 1)] |= xParity;

        // Wipe scratch.
        Util.arrayFillNonAtomic(scratch, scratchOff, ENCODE_SCRATCH_LEN, (byte) 0);
    }
}
