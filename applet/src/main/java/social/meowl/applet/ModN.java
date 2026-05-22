/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

/**
 * Constant-size, <b>constant-time</b> modular arithmetic over the secp256k1 group order {@code n}.
 *
 * <p>JavaCard 3.0.5 exposes no native big-integer API, so the mod-{@code n} primitives the applet
 * needs (BIP-32 reduction, ECDSA low-{@code s} normalisation) live here:
 *
 * <ul>
 *   <li>{@link #addMod} — {@code (a + b) mod n}
 *   <li>{@link #negateMod} — {@code n − a} (ECDSA low-{@code s} flip)
 *   <li>{@link #lessThanN} — {@code a < n}
 *   <li>{@link #lessThanHalfN} — {@code a ≤ n/2} (low-{@code s} predicate)
 *   <li>{@link #isZero} — {@code a == 0}
 * </ul>
 *
 * <p>Every operation completes in a fixed number of byte-level steps independent of the operand
 * values: {@link #addMod} always runs both an unconditional add and a mask-driven trial subtract;
 * {@link #negateMod} is already branch-free; the predicates delegate to {@link Bignat#ctLessThan} /
 * {@link Bignat#ctIsZero} which walk every byte. This rules out the residual physical timing oracle
 * that an early branchful {@code (I_L + k_par) mod n} would have exposed on the BIP-32 non-hardened
 * path.
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
     * {@code out ← (a + b) mod n}, where every operand is 32-byte big-endian. The destination may
     * alias either source. Fully constant-time: both the 32-byte add and the conditional subtract
     * always run, with the reduction driven by a mask.
     *
     * @return {@code true} iff the result is zero (BIP-32 uses this to reject {@code k_i == 0})
     */
    public static boolean addMod(
            byte[] a, short aOff, byte[] b, short bOff, byte[] out, short outOff) {
        // 1. out = a + b, recording the byte-level carry.
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
        // 2. Subtract n iff (carry == 1) OR (out >= n). Both inputs are < n on entry, so the
        //    unreduced sum is < 2n and a single subtraction is sufficient.
        short carryMask = (short) -carry;
        short lessMask = Bignat.ctLessThan(out, outOff, SECP256K1_N, (short) 0, LEN);
        short reduceMask = (short) (carryMask | ~lessMask);
        Bignat.condSubInPlace(out, outOff, SECP256K1_N, (short) 0, LEN, reduceMask);

        return isZero(out, outOff);
    }

    /**
     * {@code a ← n − a} for {@code a ∈ [1, n)} (caller MUST enforce). Used by {@link EcdsaK1} to
     * flip a high-{@code s} signature into the low half of {@code n}. Branch-free: the borrow bit
     * is extracted as {@code (diff >>> 15) & 1} — {@code diff ∈ [-256, 255]} so its short sign bit
     * is set iff {@code diff < 0}.
     */
    public static void negateMod(byte[] a, short aOff) {
        negateModConditional(a, aOff, (short) -1);
    }

    /**
     * Conditional negation: when {@code mask == -1} (all ones) writes {@code a ← n − a}; when
     * {@code mask == 0} leaves {@code a} untouched. The full subtraction is <em>always</em>
     * computed and only the per-byte write is mask-selected — both code paths execute the same
     * 32 sub instructions and 32 stores, so the elapsed wall-clock is independent of {@code
     * mask}. Used by {@link Schnorr} to flip {@code k}/{@code d} on a secret-derived parity bit
     * without leaking that bit through a conditional branch (A-01).
     *
     * @param mask {@code -1} (i.e. {@code 0xFFFF}) to negate, {@code 0} to keep
     */
    public static void negateModConditional(byte[] a, short aOff, short mask) {
        short borrow = 0;
        for (short i = (short) (LEN - 1); i >= 0; i--) {
            short ai = (short) (a[(short) (aOff + i)] & 0xFF);
            short diff = (short) ((SECP256K1_N[i] & 0xFF) - ai - borrow);
            borrow = (short) ((diff >>> 15) & 1);
            // Always store: mask selects either (n - a)[i] or original a[i]. Both branches of
            // the select are evaluated above; the per-byte write itself is unconditional.
            a[(short) (aOff + i)] = (byte) ((diff & mask) | (ai & ~mask));
        }
    }

    /**
     * {@code a < n} test, constant-time. Used by BIP-32 to reject the (negligible-probability)
     * {@code parse256(I_L) ≥ n} case.
     */
    public static boolean lessThanN(byte[] a, short off) {
        return Bignat.ctLessThan(a, off, SECP256K1_N, (short) 0, LEN) != 0;
    }

    /**
     * {@code a ≤ ⌊n/2⌋} test (low-{@code s} predicate per BIP-62 / EIP-2). Branch-free via {@code
     * !ctLessThan(halfN, a)}.
     */
    public static boolean lessThanHalfN(byte[] a, short off) {
        return Bignat.ctLessThan(SECP256K1_HALF_N, (short) 0, a, off, LEN) == 0;
    }

    /** Returns {@code true} iff the 32-byte operand at {@code a[off..off+32]} is all zero. */
    public static boolean isZero(byte[] a, short off) {
        return Bignat.ctIsZero(a, off, LEN) != 0;
    }
}
