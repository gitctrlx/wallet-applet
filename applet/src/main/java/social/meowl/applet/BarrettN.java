/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

/**
 * Constant-time Barrett reduction modulo the secp256k1 group order {@code n}.
 *
 * <p>Thin wrapper around {@link Barrett#reduce} that bakes in the modulus
 *
 * <pre>
 *   n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 * </pre>
 *
 * and the Barrett constant
 *
 * <pre>
 *   μ_n = ⌊2^512 / n⌋
 *       = 0x010000000000000000000000000000000014551231950B75FC4402DA1732FC9BEC0
 * </pre>
 *
 * <p>μ_n is 257 bits (33 bytes); the leading {@code 0x01} byte holds the bit at weight 2^256 that
 * is present because {@code 2^512 / n > 2^256} (the strict inequality follows from {@code n <
 * 2^256}). This wider-than-modulus μ is the standard Barrett shape — the upper byte is what makes
 * the quotient estimator {@code q3} correct on inputs near the top of the range.
 *
 * <p>Constant-time replacement for {@link Bignat#mod} on the {@code (k + e·d) mod n} reduction
 * inside {@link Schnorr#signDigest}.
 */
public final class BarrettN {

    /**
     * The secp256k1 group order {@code n}, 32 bytes big-endian. Same numerical value as {@link
     * ModN#SECP256K1_N}; intentionally duplicated so {@code BarrettN} stays a self-contained module
     * whose constants can be diffed directly against the spec.
     */
    public static final byte[] N = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE,
        (byte) 0xBA, (byte) 0xAE, (byte) 0xDC, (byte) 0xE6,
        (byte) 0xAF, (byte) 0x48, (byte) 0xA0, (byte) 0x3B,
        (byte) 0xBF, (byte) 0xD2, (byte) 0x5E, (byte) 0x8C,
        (byte) 0xD0, (byte) 0x36, (byte) 0x41, (byte) 0x41,
    };

    /**
     * Barrett constant {@code μ_n = ⌊2^512 / n⌋}, 33 bytes big-endian. Pre-computed off-card so the
     * applet does no divisions at install time. Width is one byte over the modulus because the
     * exact quotient {@code 2^512 / n} crosses {@code 2^256} (n is just below {@code 2^256}).
     */
    public static final byte[] MU = {
        (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x01, (byte) 0x45, (byte) 0x51, (byte) 0x23,
        (byte) 0x19, (byte) 0x50, (byte) 0xB7, (byte) 0x5F,
        (byte) 0xC4, (byte) 0x40, (byte) 0x2D, (byte) 0xA1,
        (byte) 0x73, (byte) 0x2F, (byte) 0xC9, (byte) 0xBE,
        (byte) 0xC0,
    };

    private BarrettN() {}

    /**
     * Constant-time {@code dst[0..32] := x[0..64] mod n}.
     *
     * @param x 64-byte big-endian dividend; UNMODIFIED on return.
     * @param xOff start offset within {@code x}.
     * @param scratch caller-supplied workspace of at least {@link Barrett#SCRATCH_LEN} bytes;
     *     clobbered.
     * @param scOff start offset within {@code scratch}.
     * @param dst 32-byte big-endian output; receives {@code x mod n}.
     * @param dstOff start offset within {@code dst}.
     */
    public static void reduce(
            byte[] x, short xOff, byte[] scratch, short scOff, byte[] dst, short dstOff) {
        Barrett.reduce(x, xOff, N, (short) 0, MU, (short) 0, scratch, scOff, dst, dstOff);
    }
}
