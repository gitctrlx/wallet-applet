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
 * Validates {@link BarrettL} — constant-time Barrett reduction modulo the Ed25519 group order
 * {@code ℓ = 2^252 + 27742317777372353535851937790883648493}. Mirrors the structure of {@code
 * BarrettNTest} so the two suites give equal coverage to both moduli.
 *
 * <p>{@code ℓ} has 253 bits, so {@code μ_ℓ = ⌊2^512 / ℓ⌋} has 260 bits (top byte {@code 0x0F},
 * one nibble of which is non-zero). This is a wider μ than {@code μ_n}, exercising more of the
 * {@code q3 · m} multiply matrix. The headline KAT set therefore overlaps with {@code
 * BarrettNTest} cases but the failure modes are different — a regression in carry handling at
 * the 257..260 bit positions of q3 would surface here first.
 */
class BarrettLTest {

    /** Ed25519 group order {@code ℓ}, the constant {@link BarrettL#L} bakes in. */
    private static final BigInteger L =
            BigInteger.ONE.shiftLeft(252)
                    .add(new BigInteger("14def9dea2f79cd65812631a5cf5d3ed", 16));

    private static final SecureRandom RNG = new SecureRandom();

    @Test
    @DisplayName("BarrettL constant: BarrettL.L matches the Ed25519 group order bit-for-bit")
    void lConstantPinned() {
        assertArrayEquals(bigIntToFixed(L, 32), BarrettL.L);
    }

    @Test
    @DisplayName("BarrettL constant: BarrettL.MU = floor(2^512 / ℓ) bit-for-bit (260 bits, 33 bytes)")
    void muConstantPinned() {
        BigInteger muExpected = BigInteger.ONE.shiftLeft(512).divide(L);
        assertEquals(260, muExpected.bitLength(), "μ_ℓ must be exactly 260 bits");
        byte[] muRaw = muExpected.toByteArray();
        byte[] mu33 = new byte[33];
        int copy = Math.min(muRaw.length, 33);
        System.arraycopy(muRaw, muRaw.length - copy, mu33, 33 - copy, copy);
        assertArrayEquals(mu33, BarrettL.MU);
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
    @DisplayName("reduce(ℓ - 1) = ℓ - 1")
    void reduceLMinusOne() {
        assertReducesTo(L.subtract(BigInteger.ONE), L.subtract(BigInteger.ONE));
    }

    @Test
    @DisplayName("reduce(ℓ) = 0")
    void reduceExactlyL() {
        assertReducesTo(L, BigInteger.ZERO);
    }

    @Test
    @DisplayName("reduce(ℓ + 1) = 1")
    void reduceLPlusOne() {
        assertReducesTo(L.add(BigInteger.ONE), BigInteger.ONE);
    }

    @Test
    @DisplayName("reduce(2^256 - 1) = (2^256 - 1) mod ℓ")
    void reduceAllOnes256() {
        BigInteger x = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
        assertReducesTo(x, x.mod(L));
    }

    @Test
    @DisplayName("reduce(2^512 - 1) = (2^512 - 1) mod ℓ (largest 512-bit dividend)")
    void reduceAllOnes512() {
        BigInteger x = BigInteger.ONE.shiftLeft(512).subtract(BigInteger.ONE);
        assertReducesTo(x, x.mod(L));
    }

    @Test
    @DisplayName("reduce(k · ℓ) = 0 for k = 1..3")
    void reduceExactMultiples() {
        for (int k = 1; k <= 3; k++) {
            BigInteger x = L.multiply(BigInteger.valueOf(k));
            assertReducesTo(x, BigInteger.ZERO, "k = " + k);
        }
    }

    @Test
    @DisplayName("reduce(k · ℓ - 1) = ℓ - 1 for k = 1..3")
    void reduceJustBelowMultiples() {
        for (int k = 1; k <= 3; k++) {
            BigInteger x = L.multiply(BigInteger.valueOf(k)).subtract(BigInteger.ONE);
            assertReducesTo(x, L.subtract(BigInteger.ONE), "k = " + k);
        }
    }

    @Test
    @DisplayName("reduce(k · ℓ + 1) = 1 for k = 1..3")
    void reduceJustAboveMultiples() {
        for (int k = 1; k <= 3; k++) {
            BigInteger x = L.multiply(BigInteger.valueOf(k)).add(BigInteger.ONE);
            assertReducesTo(x, BigInteger.ONE, "k = " + k);
        }
    }

    @Test
    @DisplayName("reduce(2 · ℓ - 1): hits at least one trial subtract")
    void reduceForcesSubtracts() {
        BigInteger x = L.shiftLeft(1).subtract(BigInteger.ONE);
        assertReducesTo(x, L.subtract(BigInteger.ONE));
    }

    @Test
    @DisplayName("reduce(2^252): exactly the modulus radix")
    void reducePowerOf252() {
        BigInteger x = BigInteger.ONE.shiftLeft(252);
        assertReducesTo(x, x.mod(L));
    }

    @Test
    @DisplayName("reduce((ℓ - 1)^2): canonical Ed25519 k·s-like input")
    void reduceLMinusOneSquared() {
        BigInteger x = L.subtract(BigInteger.ONE).multiply(L.subtract(BigInteger.ONE));
        assertReducesTo(x, x.mod(L));
    }

    @RepeatedTest(1000)
    @DisplayName("reduce(random 512-bit dividend) matches BigInteger.mod (1 000 differentials)")
    void reduceRandomDividends() {
        byte[] xBytes = new byte[64];
        RNG.nextBytes(xBytes);
        BigInteger x = new BigInteger(1, xBytes);
        assertReducesTo(x, x.mod(L));
    }

    @RepeatedTest(200)
    @DisplayName("reduce(random a · b): canonical Ed25519 input shape")
    void reduceRandomProducts() {
        byte[] aBytes = new byte[32];
        byte[] bBytes = new byte[32];
        RNG.nextBytes(aBytes);
        RNG.nextBytes(bBytes);
        BigInteger a = new BigInteger(1, aBytes);
        BigInteger b = new BigInteger(1, bBytes);
        BigInteger x = a.multiply(b);
        assertReducesTo(x, x.mod(L));
    }

    @Test
    @DisplayName("reduce honours non-zero scratch and dst offsets")
    void reduceHonoursOffsets() {
        byte[] xBacking = new byte[128];
        byte[] x = bigIntToFixed(L.subtract(BigInteger.TWO), 64);
        System.arraycopy(x, 0, xBacking, 32, 64);
        for (int i = 0; i < 32; i++) xBacking[i] = (byte) 0xAA;
        for (int i = 96; i < 128; i++) xBacking[i] = (byte) 0xBB;

        byte[] scratchBacking = new byte[200];
        for (int i = 0; i < 200; i++) scratchBacking[i] = (byte) 0xCC;

        byte[] dstBacking = new byte[64];
        for (int i = 0; i < 64; i++) dstBacking[i] = (byte) 0xDD;

        BarrettL.reduce(xBacking, (short) 32, scratchBacking, (short) 16, dstBacking, (short) 16);

        for (int i = 0; i < 32; i++) assertEquals((byte) 0xAA, xBacking[i], "x prefix " + i);
        for (int i = 96; i < 128; i++) assertEquals((byte) 0xBB, xBacking[i], "x suffix " + i);
        byte[] xAfter = new byte[64];
        System.arraycopy(xBacking, 32, xAfter, 0, 64);
        assertArrayEquals(x, xAfter, "x must not be modified");

        for (int i = 0; i < 16; i++) assertEquals((byte) 0xDD, dstBacking[i], "dst prefix " + i);
        for (int i = 48; i < 64; i++) assertEquals((byte) 0xDD, dstBacking[i], "dst suffix " + i);

        byte[] expected = bigIntToFixed(L.subtract(BigInteger.TWO), 32);
        byte[] got = new byte[32];
        System.arraycopy(dstBacking, 16, got, 0, 32);
        assertArrayEquals(expected, got);
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private static void assertReducesTo(BigInteger x, BigInteger expected) {
        assertReducesTo(x, expected, "x=0x" + x.toString(16));
    }

    private static void assertReducesTo(BigInteger x, BigInteger expected, String message) {
        byte[] xBuf = bigIntToFixed(x, 64);
        byte[] scratch = new byte[Barrett.SCRATCH_LEN];
        byte[] dst = new byte[32];
        BarrettL.reduce(xBuf, (short) 0, scratch, (short) 0, dst, (short) 0);
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
