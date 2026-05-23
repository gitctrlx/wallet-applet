/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.util.HexFormat;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Pins {@link Wei25519#encodeEdwards} — the Weierstrass → Edwards bijection that lets the hardware
 * EC coprocessor produce RFC 8032 §5.1.2 compressed public keys.
 *
 * <p>The oracle is RFC 8032 §7.1: each row is {@code (secret_key, expected_ed25519_pubkey)}. The
 * test (a) recovers the clamped Ed25519 scalar from the secret key per RFC 8032 §5.1.5, (b) lifts
 * the scalar to a Wei25519 affine point via a BouncyCastle Weierstrass curve built from the
 * applet's own {@code p / a / b / G / ℓ} constants, and (c) asserts that {@link
 * Wei25519#encodeEdwards} maps that affine point to the expected Ed25519 pubkey byte-for- byte.
 * Three vectors exercise the encoder's parity / low-X / high-X branches; five vectors give a
 * comfortable safety margin.
 */
class Wei25519Test {

    private static final HexFormat HEX = HexFormat.of();

    private static final ECCurve.Fp WEI25519 = buildWeierstrassCurve();

    private static ECCurve.Fp buildWeierstrassCurve() {
        BigInteger p = new BigInteger(1, Fp25519.P);
        BigInteger a = new BigInteger(1, Wei25519.A);
        BigInteger b = new BigInteger(1, Wei25519.B);
        BigInteger l = new BigInteger(1, Wei25519.L);
        ECCurve.Fp curve = new ECCurve.Fp(p, a, b, l, BigInteger.valueOf(Wei25519.COFACTOR));
        // Sanity check: G must lie on the curve we just built.
        ECPoint g = curve.decodePoint(Wei25519.G).normalize();
        if (!g.isValid()) {
            throw new IllegalStateException("Wei25519 base point fails BC validation");
        }
        return curve;
    }

    /** RFC 8032 §7.1 secret-key / Ed25519-pubkey pairs (subset that hits every encode branch). */
    private static final String[][] RFC_8032_VECTORS = {
        {
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        },
        {
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        },
        {
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
        },
        {
            "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
            "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"
        },
        {
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"
        },
    };

    /**
     * Derives the clamped Ed25519 scalar per RFC 8032 §5.1.5. Clamping zeros bits 0-2 and 255, then
     * sets bit 254 — equivalent to {@code s ≡ 0 (mod 8)} and {@code 2²⁵⁴ ≤ s < 2²⁵⁵}.
     */
    private static BigInteger clampedScalar(byte[] secretKey) throws Exception {
        java.security.MessageDigest sha512 = java.security.MessageDigest.getInstance("SHA-512");
        byte[] h = sha512.digest(secretKey);
        h[0] &= (byte) 248;
        h[31] &= (byte) 127;
        h[31] |= (byte) 64;
        byte[] be = new byte[32];
        for (int i = 0; i < 32; i++) {
            be[i] = h[31 - i];
        }
        return new BigInteger(1, be);
    }

    /**
     * Computes {@code s · G} on Wei25519 via BouncyCastle, returning the 65-byte uncompressed form.
     */
    private static byte[] scalarMultG(BigInteger scalar) {
        ECPoint result = WEI25519.decodePoint(Wei25519.G).multiply(scalar).normalize();
        return result.getEncoded(false);
    }

    @Test
    @DisplayName("G8 pins the precomputed Wei25519 eightfold base point")
    void precomputedG8() {
        ECPoint expected =
                WEI25519.decodePoint(Wei25519.G).multiply(BigInteger.valueOf(8)).normalize();
        assertArrayEquals(expected.getEncoded(false), Wei25519.G8);
    }

    @Test
    @DisplayName("RFC 8032 §7.1 vectors round-trip through Wei25519.encodeEdwards")
    void rfc8032Vectors() throws Exception {
        Fp25519Inv inverter = new Fp25519Inv();
        byte[] scratch = new byte[Wei25519.ENCODE_SCRATCH_LEN];
        byte[] encoded = new byte[32];
        for (String[] vec : RFC_8032_VECTORS) {
            byte[] sk = HEX.parseHex(vec[0]);
            byte[] expectedPub = HEX.parseHex(vec[1]);
            byte[] weiPoint = scalarMultG(clampedScalar(sk));

            Wei25519.encodeEdwards(
                    weiPoint, (short) 0, encoded, (short) 0, inverter, scratch, (short) 0);

            assertArrayEquals(
                    expectedPub,
                    encoded,
                    "Wei25519.encodeEdwards must reproduce RFC 8032 pubkey for sk = " + vec[0]);
        }
    }

    @Test
    @DisplayName("encodeEdwards wipes its caller-supplied scratch before returning")
    void scratchIsWiped() throws Exception {
        Fp25519Inv inverter = new Fp25519Inv();
        byte[] scratch = new byte[Wei25519.ENCODE_SCRATCH_LEN];
        byte[] encoded = new byte[32];
        byte[] sk = HEX.parseHex(RFC_8032_VECTORS[0][0]);
        byte[] weiPoint = scalarMultG(clampedScalar(sk));

        Wei25519.encodeEdwards(
                weiPoint, (short) 0, encoded, (short) 0, inverter, scratch, (short) 0);

        for (int i = 0; i < scratch.length; i++) {
            assertEquals(0, scratch[i], "scratch byte " + i + " not wiped");
        }
    }
}
