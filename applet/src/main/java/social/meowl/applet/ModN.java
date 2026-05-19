/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

/**
 * Constant-size modular arithmetic over the secp256k1 group order {@code n}.
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
 * <p>Algorithm for {@link #addMod}: standard add-with-carry plus a conditional one-step subtract.
 * Since both operands are guaranteed {@code < n} on call, the sum is at most {@code 2n − 2}, so a
 * single subtraction of {@code n} is sufficient to bring the result back below {@code n}. The
 * reduction branch itself depends only on a carry/compare bit derived from the public {@code I_L}
 * input (BIP-32 non-hardened derivation requires {@code k_par * G} to be returned as a public
 * output, so the sum {@code I_L + k_par mod n} need not be constant-time relative to the secret —
 * the leaked predicate is whether the unreduced sum overflowed, equivalent to comparing {@code I_L}
 * against {@code n − k_par}).
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

        // Step 2: if there was an overflow OR the result is >= n, subtract n once.
        // Compare even when no overflow — both inputs are < n so the unreduced sum is < 2n,
        // i.e. one subtraction of n is sufficient in all cases.
        boolean ge = carry == 1 || !lessThan(out, outOff, SECP256K1_N, (short) 0);
        if (ge) {
            short borrow = 0;
            for (short i = (short) (LEN - 1); i >= 0; i--) {
                short diff =
                        (short)
                                ((out[(short) (outOff + i)] & 0xFF)
                                        - (SECP256K1_N[i] & 0xFF)
                                        - borrow);
                out[(short) (outOff + i)] = (byte) diff;
                borrow = (short) ((diff < 0) ? 1 : 0);
            }
        }
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
     * (negligible-probability) case {@code parse256(I_L) ≥ n}.
     */
    public static boolean lessThanN(byte[] a, short off) {
        return lessThan(a, off, SECP256K1_N, (short) 0);
    }

    /**
     * Returns {@code true} iff the 32-byte big-endian operand at {@code a[off..off+32]} is less
     * than or equal to {@code ⌊n/2⌋}. Used by {@link EcdsaK1} to test whether an ECDSA {@code s}
     * value is in canonical (low-{@code s}) form. Equality with {@code ⌊n/2⌋} counts as low-s (per
     * BIP-62 / EIP-2): the predicate is the negation of the "high-{@code s}" condition {@code s >
     * ⌊n/2⌋}.
     */
    public static boolean lessThanHalfN(byte[] a, short off) {
        // a ≤ ⌊n/2⌋  ⟺  !(a > ⌊n/2⌋)  ⟺  a < ⌊n/2⌋ OR a == ⌊n/2⌋
        return lessThan(a, off, SECP256K1_HALF_N, (short) 0)
                || equal(a, off, SECP256K1_HALF_N, (short) 0);
    }

    /** Returns {@code true} iff the 32-byte operand at {@code a[off..off+32]} is all zero. */
    public static boolean isZero(byte[] a, short off) {
        byte acc = 0;
        for (short i = 0; i < LEN; i++) {
            acc |= a[(short) (off + i)];
        }
        return acc == 0;
    }

    private static boolean lessThan(byte[] a, short aOff, byte[] b, short bOff) {
        for (short i = 0; i < LEN; i++) {
            short av = (short) (a[(short) (aOff + i)] & 0xFF);
            short bv = (short) (b[(short) (bOff + i)] & 0xFF);
            if (av < bv) {
                return true;
            }
            if (av > bv) {
                return false;
            }
        }
        return false; // equal -> not strictly less
    }

    private static boolean equal(byte[] a, short aOff, byte[] b, short bOff) {
        for (short i = 0; i < LEN; i++) {
            if (a[(short) (aOff + i)] != b[(short) (bOff + i)]) {
                return false;
            }
        }
        return true;
    }
}
