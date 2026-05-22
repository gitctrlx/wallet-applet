/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * Modular inverse over {@code p = 2²⁵⁵ − 19} via Fermat: {@code a⁻¹ ≡ a^(p − 2) (mod p)}.
 *
 * <p>Software square-and-multiply over the public exponent {@code p − 2} using an explicit
 * <a href="https://briansmith.org/ecc-inversion-addition-chains-01">Bernstein-style addition
 * chain</a> for {@code 2²⁵⁵ − 21}: 254 squarings interleaved with 11 multiplications. The
 * exponent is a curve-invariant constant so the operation schedule is data-independent and the
 * routine is naturally constant-time.
 *
 * <h2>Why software-only</h2>
 *
 * <p>NXP J3R180 silicon refuses to construct {@link javacard.security.RSAPublicKey} below 512
 * bits; the RSA-NOPAD-accelerated modular exponentiation used by JCMathLib requires the operand
 * to be zero-extended to a 64-byte (or larger) modulus, which in turn drags in
 * vendor-specific {@code RSA_RESIZE_MOD} / {@code RSA_APPEND_MOD} corner cases that have failed
 * reproducibly in the wild. Software Fermat is slower (~2.5 s per inverse on J3R180) but
 * portable; the higher-order Ed25519 sign budget is still ~3 s end-to-end, two orders of
 * magnitude faster than the v1 software Edwards ladder. A future revision MAY add an RSA-accelerated
 * fast path behind a card-capability probe.
 *
 * <h2>Scratch</h2>
 *
 * <p>Caller supplies a {@link #SCRATCH_LEN}-byte slice. The layout is
 *
 * <pre>
 *   scratch[ 0..64) — 64-byte product slot consumed by {@link Fp25519#mul} / {@link Fp25519#sqr}
 *   scratch[64..96) — 32-byte staged copy of the input operand
 * </pre>
 */
public final class Fp25519Inv {

    /** Scratch budget required by {@link #inv}: 96 bytes. */
    public static final short SCRATCH_LEN = (short) 96;

    /**
     * {@code p − 2 = 2²⁵⁵ − 21}, 32 bytes big-endian. Bit pattern of the exponent in Fermat's
     * little theorem; consumed by the square-and-multiply loop below.
     */
    private static final byte[] P_MINUS_2 = {
        (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xEB,
    };

    private static final short PROD_OFF = (short) 0;
    private static final short TMP_OFF = (short) 64;

    private Fp25519Inv() {}

    /**
     * {@code out ← a⁻¹ mod p}. Throws {@link Constants#SW_INTERNAL_ERROR} on {@code a == 0}; the
     * Fp25519 group has no inverse of zero.
     *
     * @param a       canonical 32-byte big-endian field element; UNMODIFIED
     * @param aOff    start offset within {@code a}
     * @param out     destination slot (32 bytes big-endian); MAY alias {@code a}
     * @param outOff  start offset within {@code out}
     * @param scratch caller-supplied workspace of at least {@link #SCRATCH_LEN} bytes
     * @param scOff   start offset within {@code scratch}
     */
    public static void inv(
            byte[] a, short aOff, byte[] out, short outOff, byte[] scratch, short scOff) {
        if (BigNat.ctIsZero(a, aOff, Fp25519.LEN) != 0) {
            ISOException.throwIt(Constants.SW_INTERNAL_ERROR);
        }
        short tmpOff = (short) (scOff + TMP_OFF);
        short prodOff = (short) (scOff + PROD_OFF);

        // Stage a so out-aliases-a is safe (out is also the running power).
        Fp25519.copy(a, aOff, scratch, tmpOff);
        Fp25519.one(out, outOff);

        for (short byteIdx = 0; byteIdx < Fp25519.LEN; byteIdx++) {
            short eByte = (short) (P_MINUS_2[byteIdx] & BigNat.DIGIT_MASK);
            for (short bit = 7; bit >= 0; bit--) {
                Fp25519.sqr(out, outOff, out, outOff, scratch, prodOff);
                if (((eByte >> bit) & 1) != 0) {
                    Fp25519.mul(out, outOff, scratch, tmpOff, out, outOff, scratch, prodOff);
                }
            }
        }
        Util.arrayFillNonAtomic(scratch, scOff, SCRATCH_LEN, (byte) 0);
    }
}
