/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.Util;
import javacard.security.ECKey;

/**
 * Curve parameters and Edwards-25519 bijection for the Weierstrass form of curve25519.
 *
 * <p>Wei25519 is the short Weierstrass-form expression of curve25519 — same underlying group as
 * Edwards-25519, just a different parametrisation. Because JavaCard 3.0.4 silicon exposes EC scalar
 * multiplication only for short Weierstrass curves ({@link
 * javacard.security.KeyAgreement#ALG_EC_SVDP_DH_PLAIN_XY}), routing Ed25519 through Wei25519 is the
 * only way to get hardware EC acceleration on the standard EdDSA wire format. The dispatcher lives
 * in {@link Ed25519}.
 *
 * <h2>Edwards ↔ Weierstrass bijection</h2>
 *
 * <p>For an affine Wei25519 point {@code (X, Y)}, the corresponding RFC 8032 §5.1.2 little-endian
 * compressed Edwards-25519 encoding is derived by
 *
 * <pre>
 *   u    = X − a/3                          (mod p)
 *   x_ed = c · u · Y⁻¹                      (mod p)        — Edwards X
 *   y_ed = (u − 1) · (u + 1)⁻¹              (mod p)        — Edwards Y
 *
 *   encoded[0..32] = LE(y_ed) with bit 7 of byte 31 ← parity(x_ed)
 * </pre>
 *
 * <p>where {@code a/3 = A_DIV_3} and {@code c = sqrt(−(a + 2) / B) mod p = EDWARDS_C} are
 * curve-invariant constants pre-computed off-card. The bijection costs two modular inversions plus
 * three modular multiplications per encode; with the {@link Fp25519Inv} RSA path each inversion is
 * ~56 ms on J3R180, so the full encode completes in ~150 ms.
 *
 * <p>Curve parameters reproduce the values published in <a
 * href="https://github.com/OpenCryptoProject/JCMathLib/blob/master/applet/src/main/java/opencrypto/jcmathlib/curves/Wei25519.java">JCMathLib
 * Wei25519</a>; the bijection constants are reproduced from <a
 * href="https://github.com/dufkan/JCEd25519/blob/master/applet/src/main/java/jced25519/Consts.java">JCEd25519
 * Consts</a> (both MIT-licensed). Independent derivation from the public math (BoringSSL's {@code
 * ed25519_to_curve25519}) yields the same values.
 */
public final class Wei25519 {

    /** Cofactor of the underlying curve25519 group (= 8). */
    public static final short COFACTOR = 8;

    /** Length of every Wei25519 coordinate / scalar / Ed25519 encoded element, in bytes. */
    public static final short COORD_LEN = (short) 32;

    /** Length of an uncompressed Wei25519 point: {@code 0x04 ‖ X ‖ Y}. */
    public static final short POINT_UNCOMPRESSED_LEN = (short) 65;

    /** Weierstrass {@code a}, 32 bytes big-endian. */
    public static final byte[] A = {
        (byte) 0x2a, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0x98,
        (byte) 0x49, (byte) 0x14, (byte) 0xa1, (byte) 0x44,
    };

    /** Weierstrass {@code b}, 32 bytes big-endian. */
    public static final byte[] B = {
        (byte) 0x7b, (byte) 0x42, (byte) 0x5e, (byte) 0xd0,
        (byte) 0x97, (byte) 0xb4, (byte) 0x25, (byte) 0xed,
        (byte) 0x09, (byte) 0x7b, (byte) 0x42, (byte) 0x5e,
        (byte) 0xd0, (byte) 0x97, (byte) 0xb4, (byte) 0x25,
        (byte) 0xed, (byte) 0x09, (byte) 0x7b, (byte) 0x42,
        (byte) 0x5e, (byte) 0xd0, (byte) 0x97, (byte) 0xb4,
        (byte) 0x26, (byte) 0x0b, (byte) 0x5e, (byte) 0x9c,
        (byte) 0x77, (byte) 0x10, (byte) 0xc8, (byte) 0x64,
    };

    /** Wei25519 base point in uncompressed form {@code 0x04 ‖ Gx ‖ Gy}, 65 bytes big-endian. */
    public static final byte[] G = {
        (byte) 0x04,
        (byte) 0x2a,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xaa,
        (byte) 0xad,
        (byte) 0x24,
        (byte) 0x5a,
        (byte) 0x20,
        (byte) 0xae,
        (byte) 0x19,
        (byte) 0xa1,
        (byte) 0xb8,
        (byte) 0xa0,
        (byte) 0x86,
        (byte) 0xb4,
        (byte) 0xe0,
        (byte) 0x1e,
        (byte) 0xdd,
        (byte) 0x2c,
        (byte) 0x77,
        (byte) 0x48,
        (byte) 0xd1,
        (byte) 0x4c,
        (byte) 0x92,
        (byte) 0x3d,
        (byte) 0x4d,
        (byte) 0x7e,
        (byte) 0x6d,
        (byte) 0x7c,
        (byte) 0x61,
        (byte) 0xb2,
        (byte) 0x29,
        (byte) 0xe9,
        (byte) 0xc5,
        (byte) 0xa2,
        (byte) 0x7e,
        (byte) 0xce,
        (byte) 0xd3,
        (byte) 0xd9,
    };

    /**
     * Precomputed {@code 8 · G} in uncompressed Wei25519 form, 65 bytes big-endian. {@link Ed25519}
     * uses this to compute {@code s · G} as {@code (s/8) · (8G)} in one hardware scalar
     * multiplication, since clamped Ed25519 scalars are always divisible by 8.
     */
    public static final byte[] G8 = {
        (byte) 0x04,
        (byte) 0x52,
        (byte) 0x0a,
        (byte) 0x51,
        (byte) 0x82,
        (byte) 0x55,
        (byte) 0x81,
        (byte) 0x06,
        (byte) 0xd8,
        (byte) 0x82,
        (byte) 0xe6,
        (byte) 0x32,
        (byte) 0xf8,
        (byte) 0x73,
        (byte) 0x61,
        (byte) 0x07,
        (byte) 0x4c,
        (byte) 0x25,
        (byte) 0x23,
        (byte) 0x98,
        (byte) 0x75,
        (byte) 0x58,
        (byte) 0x1f,
        (byte) 0x53,
        (byte) 0xc9,
        (byte) 0x9c,
        (byte) 0x1c,
        (byte) 0x1a,
        (byte) 0x97,
        (byte) 0xf3,
        (byte) 0x76,
        (byte) 0xbd,
        (byte) 0xb9,
        (byte) 0x1f,
        (byte) 0x7a,
        (byte) 0x44,
        (byte) 0x45,
        (byte) 0x70,
        (byte) 0x46,
        (byte) 0xc6,
        (byte) 0x1b,
        (byte) 0x72,
        (byte) 0x30,
        (byte) 0xbb,
        (byte) 0x96,
        (byte) 0xbf,
        (byte) 0x99,
        (byte) 0x4f,
        (byte) 0x73,
        (byte) 0xb0,
        (byte) 0xb8,
        (byte) 0x63,
        (byte) 0x98,
        (byte) 0x8f,
        (byte) 0x3a,
        (byte) 0x6e,
        (byte) 0x06,
        (byte) 0x3a,
        (byte) 0xd6,
        (byte) 0x92,
        (byte) 0x91,
        (byte) 0x60,
        (byte) 0x8d,
        (byte) 0x78,
        (byte) 0xd5,
    };

    /**
     * Ed25519 prime subgroup order {@code ℓ = 2²⁵² + 27742317777372353535851937790883648493}.
     *
     * <p>This is the order {@link javacard.security.ECPrivateKey#setR} is fed for both Wei25519
     * scalar mult and Ed25519 signing. The native key cofactor is forced to {@code 1}; Ed25519
     * cofactor handling is performed explicitly by {@link Ed25519}'s {@code (s/8)·(8G)}
     * scalar-multiplication sequence.
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

    /** Barrett constant {@code μ_ℓ = ⌊2⁵¹² / ℓ⌋}, 33 bytes big-endian. */
    public static final byte[] MU_L = {
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

    /**
     * Bijection constant {@code a/3 mod p}: the value the Weierstrass {@code X} coordinate is
     * shifted by before mapping into Edwards form. 32 bytes big-endian.
     */
    private static final byte[] A_DIV_3 = {
        (byte) 0x2a, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
        (byte) 0xaa, (byte) 0xad, (byte) 0x24, (byte) 0x51,
    };

    /**
     * Bijection constant {@code c = sqrt(−(a + 2) / B) mod p}: the scaling factor applied to the
     * Wei25519 {@code X} coordinate when computing the Edwards {@code x_ed}. 32 bytes big-endian.
     */
    private static final byte[] EDWARDS_C = {
        (byte) 0x70, (byte) 0xd9, (byte) 0x12, (byte) 0x0b,
        (byte) 0x9f, (byte) 0x5f, (byte) 0xf9, (byte) 0x44,
        (byte) 0x2d, (byte) 0x84, (byte) 0xf7, (byte) 0x23,
        (byte) 0xfc, (byte) 0x03, (byte) 0xb0, (byte) 0x81,
        (byte) 0x3a, (byte) 0x5e, (byte) 0x2c, (byte) 0x2e,
        (byte) 0xb4, (byte) 0x82, (byte) 0xe5, (byte) 0x7d,
        (byte) 0x33, (byte) 0x91, (byte) 0xfb, (byte) 0x55,
        (byte) 0x00, (byte) 0xba, (byte) 0x81, (byte) 0xe7,
    };

    /**
     * Scratch slot layout (caller-supplied workspace for {@link #encodeEdwards}). Total = {@value
     * #ENCODE_SCRATCH_LEN} bytes.
     *
     * <pre>
     *   [  0..32)  U_OFF       — u = X_wei − a/3   (Fp25519 element)
     *   [ 32..64)  YINV_OFF    — Y_wei⁻¹           (Fp25519 element)
     *   [ 64..96)  XED_OFF     — x_ed              (Fp25519 element)
     *   [ 96..128) NUM_OFF     — (u − 1)           (Fp25519 element)
     *   [128..160) DEN_OFF     — (u + 1)⁻¹         (Fp25519 element)
     *   [160..288) INV_SCRATCH — RSA-NOPAD workspace for Fp25519Inv (128 bytes)
     * </pre>
     */
    public static final short ENCODE_SCRATCH_LEN = (short) 288;

    private static final short U_OFF = (short) 0;
    private static final short YINV_OFF = (short) 32;
    private static final short XED_OFF = (short) 64;
    private static final short NUM_OFF = (short) 96;
    private static final short DEN_OFF = (short) 128;
    private static final short INV_SCRATCH_OFF = (short) 160;

    private Wei25519() {}

    /** Configures {@code key} with the Wei25519 parameters (works on both private/public). */
    public static void setCurveParameters(ECKey key) {
        key.setFieldFP(Fp25519.P, (short) 0, Fp25519.LEN);
        key.setA(A, (short) 0, Fp25519.LEN);
        key.setB(B, (short) 0, Fp25519.LEN);
        key.setR(L, (short) 0, Fp25519.LEN);
        key.setG(G, (short) 0, POINT_UNCOMPRESSED_LEN);
        key.setK((short) 1);
    }

    /**
     * Encodes a Wei25519 affine point into the 32-byte RFC 8032 §5.1.2 Edwards form.
     *
     * @param wei uncompressed Wei25519 point {@code 0x04 ‖ X ‖ Y}, 65 bytes; UNMODIFIED.
     * @param weiOff start offset within {@code wei}.
     * @param out destination buffer for the 32-byte LE-compressed Ed25519 encoding.
     * @param outOff start offset within {@code out}.
     * @param inv shared modular inverter (RSA-NOPAD accelerated).
     * @param scratch caller-supplied workspace, at least {@link #ENCODE_SCRATCH_LEN} bytes.
     * @param scratchOff start offset within {@code scratch}.
     */
    public static void encodeEdwards(
            byte[] wei,
            short weiOff,
            byte[] out,
            short outOff,
            Fp25519Inv inv,
            byte[] scratch,
            short scratchOff) {

        short xWeiOff = (short) (weiOff + 1);
        short yWeiOff = (short) (weiOff + 1 + Fp25519.LEN);

        short uOff = (short) (scratchOff + U_OFF);
        short yInvOff = (short) (scratchOff + YINV_OFF);
        short xEdOff = (short) (scratchOff + XED_OFF);
        short numOff = (short) (scratchOff + NUM_OFF);
        short denOff = (short) (scratchOff + DEN_OFF);
        short invScrOff = (short) (scratchOff + INV_SCRATCH_OFF);

        // u = X_wei − a/3 (mod p)
        Fp25519.sub(wei, xWeiOff, A_DIV_3, (short) 0, scratch, uOff);

        // x_ed = c · u · Y_wei⁻¹ (mod p)
        inv.inv(wei, yWeiOff, scratch, yInvOff, scratch, invScrOff);
        Fp25519.mul(scratch, uOff, EDWARDS_C, (short) 0, scratch, xEdOff, scratch, invScrOff);
        Fp25519.mul(scratch, xEdOff, scratch, yInvOff, scratch, xEdOff, scratch, invScrOff);

        // y_ed = (u − 1) · (u + 1)⁻¹ (mod p)
        Fp25519.decrement(scratch, uOff, scratch, numOff);
        Fp25519.increment(scratch, uOff, scratch, denOff);
        inv.inv(scratch, denOff, scratch, denOff, scratch, invScrOff);
        Fp25519.mul(scratch, numOff, scratch, denOff, scratch, denOff, scratch, invScrOff);

        // Output: y_ed as little-endian + parity(x_ed) packed into bit 7 of byte 31.
        for (short i = 0; i < Fp25519.LEN; i++) {
            out[(short) (outOff + i)] = scratch[(short) (denOff + Fp25519.LEN - 1 - i)];
        }
        byte parityBit = (byte) ((scratch[(short) (xEdOff + Fp25519.LEN - 1)] & 0x01) << 7);
        out[(short) (outOff + Fp25519.LEN - 1)] |= parityBit;

        Util.arrayFillNonAtomic(scratch, scratchOff, ENCODE_SCRATCH_LEN, (byte) 0);
    }
}
