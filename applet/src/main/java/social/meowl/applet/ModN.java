/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

/**
 * Constant-size, <b>constant-time</b> modular arithmetic over the secp256k1 group order {@code n}.
 *
 * <p>JavaCard 3.0.5 exposes no native big-integer API, so the handful of mod-{@code n} operations
 * the applet needs (BIP-32 reduction and ECDSA low-{@code s} normalisation) have to be implemented
 * in user code. The class exposes:
 *
 * <ul>
 *   <li>{@link #addMod} — {@code (a + b) mod n}.
 *   <li>{@link #negateMod} — {@code n − a} (for ECDSA low-{@code s} flipping).
 *   <li>{@link #lessThanN} — {@code a < n} test.
 *   <li>{@link #lessThanHalfN} — {@code a ≤ n/2} test (low-{@code s} predicate).
 *   <li>{@link #isZero} — {@code a == 0} test.
 * </ul>
 *
 * <p>BIP-32 requires the derivation to fail when {@code parse256(I_L) ≥ n} or {@code k_i = 0}; the
 * caller ({@link Bip32}) invokes {@link #lessThanN} on {@code I_L} and {@link #isZero} on the
 * reduced sum to enforce that rule. ECDSA signing ({@link EcdsaK1}) uses {@link #lessThanHalfN}
 * plus {@link #negateMod} to enforce the BIP-62 / EIP-2 low-{@code s} canonical form.
 *
 * <p><b>Constant-time guarantee (audit F-03 mitigation).</b> Every operation here completes in a
 * fixed number of byte-level steps independent of the operand values:
 *
 * <ul>
 *   <li>{@link #addMod} performs an unconditional 32-byte add, an unconditional 32-byte trial
 *       subtraction, computes the "needs reduction" predicate from the carry/borrow flags as a
 *       mask, and uses {@link Bignat#condSubInPlace} to apply the reduction. No branch depends on
 *       the operands.
 *   <li>{@link #negateMod} is already branch-free.
 *   <li>{@link #lessThanN}, {@link #lessThanHalfN} and {@link #isZero} call {@link
 *       Bignat#ctLessThan} / {@link Bignat#ctIsZero}, both of which walk every byte
 *       unconditionally.
 * </ul>
 *
 * <p>The earlier revision of {@link #addMod} contained a branch on a carry/compare bit derived from
 * the parent private key on the BIP-32 non-hardened path; audit F-03 flagged this as a residual
 * physical timing oracle in the {@code (I_L + k_par) mod n} step. The current implementation eats
 * that side channel by always running both the add and the subtract.
 */
public final class ModN {

    /** secp256k1 group order {@code n} in big-endian, 32 bytes. SEC 2 v2.0 §2.4.1. */
    static final byte[] SECP256K1_N = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFE,
        (byte) 0xBA, (byte) 0xAE, (byte) 0xDC, (byte) 0xE6, (byte) 0xAF, (byte) 0x48, (byte) 0xA0,
                (byte) 0x3B,
        (byte) 0xBF, (byte) 0xD2, (byte) 0x5E, (byte) 0x8C, (byte) 0xD0, (byte) 0x36, (byte) 0x41,
                (byte) 0x41,
    };

    /**
     * {@code ⌊n / 2⌋} for the secp256k1 group order, big-endian, 32 bytes. Computed once as the
     * threshold for BIP-62 / EIP-2 low-{@code s} normalisation: {@code s ≤ ⌊n/2⌋} is the canonical
     * form, and any signature with {@code s > ⌊n/2⌋} must be transformed via {@code s ← n − s}.
     */
    static final byte[] SECP256K1_HALF_N = {
        (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF,
        (byte) 0x5D, (byte) 0x57, (byte) 0x6E, (byte) 0x73, (byte) 0x57, (byte) 0xA4, (byte) 0x50,
                (byte) 0x1D,
        (byte) 0xDF, (byte) 0xE9, (byte) 0x2F, (byte) 0x46, (byte) 0x68, (byte) 0x1B, (byte) 0x20,
                (byte) 0xA0,
    };

    /** Length of the secp256k1 scalar / mod-{@code n} operand in bytes. */
    static final short LEN = (short) 32;

    private ModN() {}

    /**
     * Computes {@code out = (a + b) mod n}, where {@code a}, {@code b} and {@code out} are 32-byte
     * big-endian unsigned integers. The destination may alias either source range.
     *
     * <p>The implementation is fully constant-time: both the 32-byte add and the conditional
     * 32-byte subtract of {@code n} always run, and the decision to apply the subtract is encoded
     * as a {@code -1}/{@code 0} mask consumed by {@link Bignat#condSubInPlace}. No branch depends
     * on the operands.
     *
     * @return {@code true} iff the result is zero (caller uses this to enforce BIP-32's "skip
     *     {@code k_i == 0}" rule)
     */
    public static boolean addMod(
            byte[] a, short aOff, byte[] b, short bOff, byte[] out, short outOff) {
        // Step 1: out = a + b, recording the byte-level carry.
        short carry = 0;
        for (short i = (short) (LEN - 1); i >= 0; i--) {
            short sum =
                    (short)
                            (((a[(short) (aOff + i)] & 0xFF))
                                    + ((b[(short) (bOff + i)] & 0xFF))
                                    + carry);
            out[(short) (outOff + i)] = (byte) sum;
            carry = (short) ((sum >>> 8) & 0x01);
        }

        // Step 2: build the reduction mask in constant time.
        //   We need to subtract n iff (carry == 1) OR (out >= n).
        //     carry == 1                  -> carryMask = -1
        //     out >= n  i.e. !(out < n)   -> notLessMask = -1
        //   reduceMask = carryMask | notLessMask, then condSubInPlace.
        //
        // Both operands are < n on entry (BIP-32 guarantees this for I_L and k_par), so the
        // unreduced sum is < 2n and a single subtraction of n is sufficient.
        short carryMask = (short) -carry;
        short lessMask = Bignat.ctLessThan(out, outOff, SECP256K1_N, (short) 0, LEN);
        short reduceMask = (short) (carryMask | ~lessMask);
        Bignat.condSubInPlace(out, outOff, SECP256K1_N, (short) 0, LEN, reduceMask);

        return isZero(out, outOff);
    }

    /**
     * Computes {@code a ← n − a} where {@code a} is a 32-byte big-endian unsigned integer in {@code
     * [1, n)}. Used by {@link EcdsaK1} to flip {@code s} into the low half of {@code n} when the JC
     * ECDSA implementation returned a high-{@code s} signature. The caller is responsible for
     * ensuring {@code a < n} on entry (the subtraction would otherwise wrap into the negative
     * range, which is meaningless mod {@code n}).
     */
    public static void negateMod(byte[] a, short aOff) {
        short borrow = 0;
        for (short i = (short) (LEN - 1); i >= 0; i--) {
            short diff =
                    (short) ((SECP256K1_N[i] & 0xFF) - (a[(short) (aOff + i)] & 0xFF) - borrow);
            a[(short) (aOff + i)] = (byte) diff;
            borrow = (short) ((diff < 0) ? 1 : 0);
        }
    }

    /**
     * Returns {@code true} iff the 32-byte big-endian operand at {@code a[off..off+32]} is strictly
     * less than the secp256k1 group order {@code n}. Used by BIP-32 to reject the
     * (negligible-probability) case {@code parse256(I_L) ≥ n}. Constant-time.
     */
    public static boolean lessThanN(byte[] a, short off) {
        return Bignat.ctLessThan(a, off, SECP256K1_N, (short) 0, LEN) != 0;
    }

    /**
     * Returns {@code true} iff the 32-byte big-endian operand at {@code a[off..off+32]} is less
     * than or equal to {@code ⌊n/2⌋}. Used by {@link EcdsaK1} to test whether an ECDSA {@code s}
     * value is in canonical (low-{@code s}) form. Equality with {@code ⌊n/2⌋} counts as low-{@code
     * s} (per BIP-62 / EIP-2): the predicate is the negation of the "high-{@code s}" condition
     * {@code s > ⌊n/2⌋}, computed as {@code !ctLessThan(halfN, a)} so the entire walk is
     * branch-free.
     */
    public static boolean lessThanHalfN(byte[] a, short off) {
        // a ≤ halfN  ⟺  !(halfN < a)
        return Bignat.ctLessThan(SECP256K1_HALF_N, (short) 0, a, off, LEN) == 0;
    }

    /** Returns {@code true} iff the 32-byte operand at {@code a[off..off+32]} is all zero. */
    public static boolean isZero(byte[] a, short off) {
        return Bignat.ctIsZero(a, off, LEN) != 0;
    }
}
