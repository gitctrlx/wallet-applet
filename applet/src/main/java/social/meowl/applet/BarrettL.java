/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

/**
 * Constant-time Barrett reduction modulo the Ed25519 group order {@code ℓ}.
 *
 * <p>Thin wrapper around {@link Barrett#reduce} that bakes in the modulus
 *
 * <pre>
 *   ℓ = 2^252 + 27742317777372353535851937790883648493
 *     = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
 * </pre>
 *
 * (RFC 8032 §5.1; in our internal storage we use big-endian byte order, which is the reverse of
 * the little-endian wire format Ed25519 uses on the message bytes — the conversion happens at the
 * {@link Ed25519} dispatcher boundary, not here.)
 *
 * <p>The Barrett constant
 *
 * <pre>
 *   μ_ℓ = ⌊2^512 / ℓ⌋
 *       = 0x0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEB2106215D086329A7ED9CE5A30A2C131B
 * </pre>
 *
 * <p>{@code ℓ} is approximately {@code 2^252.000000018}, so {@code 2^512 / ℓ ≈ 2^260}, and
 * therefore {@code μ_ℓ} occupies 260 bits (33 bytes with the top byte being {@code 0x0F}). This is
 * a wider μ than {@link BarrettN#MU} (whose modulus {@code n} is much closer to {@code 2^256}),
 * but the Barrett algorithm in {@link Barrett#reduce} accepts any 33-byte μ uniformly — the extra
 * width simply means more of the top bytes of μ are non-zero and the {@code q3} estimator's
 * partial-product matrix is denser.
 *
 * <p>Constant-time replacement for {@link Bignat#mod} on the {@code (r + k·s) mod ℓ} reduction
 * inside {@link Ed25519#signDigest}.
 */
public final class BarrettL {

    /**
     * The Ed25519 group order {@code ℓ = 2^252 + 27742317777372353535851937790883648493},
     * 32 bytes big-endian.
     */
    public static final byte[] L = {
            (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x14, (byte) 0xDE, (byte) 0xF9, (byte) 0xDE,
            (byte) 0xA2, (byte) 0xF7, (byte) 0x9C, (byte) 0xD6,
            (byte) 0x58, (byte) 0x12, (byte) 0x63, (byte) 0x1A,
            (byte) 0x5C, (byte) 0xF5, (byte) 0xD3, (byte) 0xED,
    };

    /**
     * Barrett constant {@code μ_ℓ = ⌊2^512 / ℓ⌋}, 33 bytes big-endian. Pre-computed off-card.
     */
    public static final byte[] MU = {
            (byte) 0x0F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xEB, (byte) 0x21, (byte) 0x06, (byte) 0x21,
            (byte) 0x5D, (byte) 0x08, (byte) 0x63, (byte) 0x29,
            (byte) 0xA7, (byte) 0xED, (byte) 0x9C, (byte) 0xE5,
            (byte) 0xA3, (byte) 0x0A, (byte) 0x2C, (byte) 0x13,
            (byte) 0x1B,
    };

    private BarrettL() {}

    /**
     * Constant-time {@code dst[0..32] := x[0..64] mod ℓ}.
     *
     * @param x        64-byte big-endian dividend; UNMODIFIED on return.
     * @param xOff     start offset within {@code x}.
     * @param scratch  caller-supplied workspace of at least {@link Barrett#SCRATCH_LEN} bytes;
     *     clobbered.
     * @param scOff    start offset within {@code scratch}.
     * @param dst      32-byte big-endian output; receives {@code x mod ℓ}.
     * @param dstOff   start offset within {@code dst}.
     */
    public static void reduce(
            byte[] x,
            short xOff,
            byte[] scratch,
            short scOff,
            byte[] dst,
            short dstOff) {
        Barrett.reduce(x, xOff, L, (short) 0, MU, (short) 0, scratch, scOff, dst, dstOff);
    }
}
