/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

/**
 * Validates {@link BarrettN} — constant-time Barrett reduction modulo the secp256k1 group order
 * {@code n}. The kernel is {@link Barrett#reduce}; this suite pins both the kernel correctness and
 * the {@code (n, μ_n)} constants baked into {@link BarrettN}.
 *
 * <p>The reference is the JDK's {@link BigInteger#mod} so each test case is independently
 * checkable against the published secp256k1 group order. We cover
 *
 * <ul>
 *   <li>headline edge cases: 0, 1, n−1, n, n+1, 2^256−1, 2^512−1, k·n for k = 1..3 and k·n ± 1;
 *   <li>1 000 randomised 64-byte dividends to surface any carry-propagation or quotient-estimator
 *       bug missed by the targeted cases;
 *   <li>32-byte products of two random 256-bit operands (the canonical Barrett input shape from
 *       Schnorr's {@code e·d} and Ed25519's {@code k·s}).
 * </ul>
 *
 * <p>The BIP-340 test-vector suite ({@code SchnorrK1Test}) provides the upstream cryptographic
 * confirmation since {@link Schnorr#signDigest} routes its final reduction through {@link
 * BarrettN#reduce}: any error here would translate to invalid Schnorr signatures.
 */
class BarrettNTest {

    /** The secp256k1 group order, the same constant {@link BarrettN#N} bakes in. */
    private static final BigInteger N =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    private static final SecureRandom RNG = new SecureRandom();

    @Test
    @DisplayName("BarrettN constant: BarrettN.N matches the secp256k1 group order bit-for-bit")
    void nConstantPinned() {
        assertArrayEquals(bigIntToFixed(N, 32), BarrettN.N);
    }

    @Test
    @DisplayName("BarrettN constant: BarrettN.MU = floor(2^512 / n) bit-for-bit")
    void muConstantPinned() {
        BigInteger muExpected = BigInteger.ONE.shiftLeft(512).divide(N);
        assertEquals(257, muExpected.bitLength(), "μ_n must be exactly 257 bits");
        byte[] muRaw = muExpected.toByteArray();
        byte[] mu33 = new byte[33];
        int copy = Math.min(muRaw.length, 33);
        System.arraycopy(muRaw, muRaw.length - copy, mu33, 33 - copy, copy);
        assertArrayEquals(mu33, BarrettN.MU);
    }

    @Test
    @DisplayName("reduce(0) = 0")
    void reduceZero() {
        assertReducesTo(BigInteger.ZERO, BigInteger.ZERO);
    }

    @Test
    @DisplayName("reduce(1) = 1")
    void reduceOne() {
        assertReducesTo(BigInteger.ONE, BigInteger.ONE);
    }

    @Test
    @DisplayName("reduce(n - 1) = n - 1 (largest residue, identity case)")
    void reduceNMinusOne() {
        assertReducesTo(N.subtract(BigInteger.ONE), N.subtract(BigInteger.ONE));
    }

    @Test
    @DisplayName("reduce(n) = 0 (boundary: exactly the modulus)")
    void reduceExactlyN() {
        assertReducesTo(N, BigInteger.ZERO);
    }

    @Test
    @DisplayName("reduce(n + 1) = 1 (boundary: one above the modulus)")
    void reduceNPlusOne() {
        assertReducesTo(N.add(BigInteger.ONE), BigInteger.ONE);
    }

    @Test
    @DisplayName("reduce(2^256 - 1) = (2^256 - 1) mod n (all-ones bottom half)")
    void reduceAllOnes256() {
        BigInteger x = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
        assertReducesTo(x, x.mod(N));
    }

    @Test
    @DisplayName("reduce(2^512 - 1) = (2^512 - 1) mod n (largest 512-bit dividend)")
    void reduceAllOnes512() {
        BigInteger x = BigInteger.ONE.shiftLeft(512).subtract(BigInteger.ONE);
        assertReducesTo(x, x.mod(N));
    }

    @Test
    @DisplayName("reduce(k · n) = 0 for k = 1..3 (exact multiples)")
    void reduceExactMultiples() {
        for (int k = 1; k <= 3; k++) {
            BigInteger x = N.multiply(BigInteger.valueOf(k));
            if (x.bitLength() > 512) continue; // guard, won't trigger for k ≤ 3
            assertReducesTo(x, BigInteger.ZERO, "k = " + k);
        }
    }

    @Test
    @DisplayName("reduce(k · n - 1) = n - 1 for k = 1..3 (just below an exact multiple)")
    void reduceJustBelowMultiples() {
        for (int k = 1; k <= 3; k++) {
            BigInteger x = N.multiply(BigInteger.valueOf(k)).subtract(BigInteger.ONE);
            if (x.bitLength() > 512) continue;
            assertReducesTo(x, N.subtract(BigInteger.ONE), "k = " + k);
        }
    }

    @Test
    @DisplayName("reduce(k · n + 1) = 1 for k = 1..3 (just above an exact multiple)")
    void reduceJustAboveMultiples() {
        for (int k = 1; k <= 3; k++) {
            BigInteger x = N.multiply(BigInteger.valueOf(k)).add(BigInteger.ONE);
            if (x.bitLength() > 512) continue;
            assertReducesTo(x, BigInteger.ONE, "k = " + k);
        }
    }

    @Test
    @DisplayName("reduce(2 · n - 1): hits the second of the three trial subtracts")
    void reduceForcesTwoSubtracts() {
        BigInteger x = N.shiftLeft(1).subtract(BigInteger.ONE);
        assertReducesTo(x, N.subtract(BigInteger.ONE));
    }

    @Test
    @DisplayName("reduce(2^256): dividend just above the modulus range")
    void reducePowerOf256() {
        BigInteger x = BigInteger.ONE.shiftLeft(256);
        assertReducesTo(x, x.mod(N));
    }

    @Test
    @DisplayName("reduce((n - 1)^2): canonical Schnorr e·d-like input")
    void reduceNMinusOneSquared() {
        BigInteger x = N.subtract(BigInteger.ONE).multiply(N.subtract(BigInteger.ONE));
        assertReducesTo(x, x.mod(N));
    }

    @RepeatedTest(1000)
    @DisplayName("reduce(random 512-bit dividend) matches BigInteger.mod (1 000 differentials)")
    void reduceRandomDividends() {
        byte[] xBytes = new byte[64];
        RNG.nextBytes(xBytes);
        BigInteger x = new BigInteger(1, xBytes);
        assertReducesTo(x, x.mod(N));
    }

    @RepeatedTest(200)
    @DisplayName("reduce(random a · b): canonical Schnorr / Ed25519 input shape")
    void reduceRandomProducts() {
        byte[] aBytes = new byte[32];
        byte[] bBytes = new byte[32];
        RNG.nextBytes(aBytes);
        RNG.nextBytes(bBytes);
        BigInteger a = new BigInteger(1, aBytes);
        BigInteger b = new BigInteger(1, bBytes);
        BigInteger x = a.multiply(b);
        assertReducesTo(x, x.mod(N));
    }

    @Test
    @DisplayName("reduce honours non-zero scratch and dst offsets")
    void reduceHonoursOffsets() {
        // Place x in the middle of a 128-byte backing buffer; same for scratch and dst. Surrounding
        // sentinel bytes must NOT change.
        byte[] xBacking = new byte[128];
        byte[] x = bigIntToFixed(N.subtract(BigInteger.TWO), 64);
        System.arraycopy(x, 0, xBacking, 32, 64);
        // Sentinels around x:
        for (int i = 0; i < 32; i++) xBacking[i] = (byte) 0xAA;
        for (int i = 96; i < 128; i++) xBacking[i] = (byte) 0xBB;

        byte[] scratchBacking = new byte[200];
        for (int i = 0; i < 200; i++) scratchBacking[i] = (byte) 0xCC;

        byte[] dstBacking = new byte[64];
        for (int i = 0; i < 64; i++) dstBacking[i] = (byte) 0xDD;

        BarrettN.reduce(xBacking, (short) 32, scratchBacking, (short) 16, dstBacking, (short) 16);

        // x left intact:
        for (int i = 0; i < 32; i++) assertEquals((byte) 0xAA, xBacking[i], "x prefix " + i);
        for (int i = 96; i < 128; i++) assertEquals((byte) 0xBB, xBacking[i], "x suffix " + i);
        byte[] xAfter = new byte[64];
        System.arraycopy(xBacking, 32, xAfter, 0, 64);
        assertArrayEquals(x, xAfter, "x must not be modified");

        // dst prefix/suffix sentinels intact:
        for (int i = 0; i < 16; i++) assertEquals((byte) 0xDD, dstBacking[i], "dst prefix " + i);
        for (int i = 48; i < 64; i++) assertEquals((byte) 0xDD, dstBacking[i], "dst suffix " + i);

        // dst[16..48] == (n - 2) mod n = n - 2.
        byte[] expected = bigIntToFixed(N.subtract(BigInteger.TWO), 32);
        byte[] got = new byte[32];
        System.arraycopy(dstBacking, 16, got, 0, 32);
        assertArrayEquals(expected, got);
    }

    private static void assertReducesTo(BigInteger x, BigInteger expected) {
        assertReducesTo(x, expected, "x=0x" + x.toString(16));
    }

    private static void assertReducesTo(BigInteger x, BigInteger expected, String message) {
        byte[] xBuf = bigIntToFixed(x, 64);
        byte[] scratch = new byte[Barrett.SCRATCH_LEN];
        byte[] dst = new byte[32];
        BarrettN.reduce(xBuf, (short) 0, scratch, (short) 0, dst, (short) 0);
        byte[] expectedBytes = bigIntToFixed(expected, 32);
        assertArrayEquals(expectedBytes, dst, message);
    }

    private static byte[] bigIntToFixed(BigInteger v, int len) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[len];
        if (raw.length > len) {
            System.arraycopy(raw, raw.length - len, out, 0, len);
        } else {
            System.arraycopy(raw, 0, out, len - raw.length, raw.length);
        }
        return out;
    }
}
