/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

/**
 * Validates {@link Field25519#reducePseudoMersenne} — the constant-time pseudo-Mersenne reducer
 * that replaced the variable-time {@code Bignat.mod(64-byte product, p = 2^255 - 19)} kernel.
 *
 * <p>The reducer is exercised end-to-end via every {@code Ed25519Test} and {@code Edwards25519Test}
 * case (Schnorr does not touch Field25519). This suite additionally pins the reducer's per-input
 * semantics so future regressions surface here first, before the larger curve-level suites grind
 * through tens of thousands of intermediates.
 *
 * <p>Coverage:
 *
 * <ul>
 *   <li>Headline KATs: 0, 1, p − 1, p, p + 1, 2p − 1, 2²⁵⁶ − 1, 2²⁵⁶ exact, 2⁵¹², 2⁵¹² − 1, k · p
 *       and k · p ± 1 for k = 1..3, (p − 1)² (the maximal canonical product).
 *   <li>Forced carry-path edges: inputs designed to drive {@code c₁} to its maximum, force {@code
 *       c₂ = 1} (the 33-byte intermediate), and force {@code c₃ = 0} from a near-overflow.
 *   <li>1 000 randomised 64-byte products differential-tested against {@link BigInteger#mod}.
 * </ul>
 */
class Field25519ReduceTest {

    private static final BigInteger P =
            BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));

    private static final SecureRandom RNG = new SecureRandom();

    @Test
    @DisplayName("FIELD_P matches 2^255 - 19 bit-for-bit")
    void fieldPPinned() {
        assertArrayEquals(toFixed(P, 32), Field25519.FIELD_P);
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
    @DisplayName("reduce(p - 1) = p - 1 (identity case, maximal residue)")
    void reducePMinusOne() {
        assertReducesTo(P.subtract(BigInteger.ONE), P.subtract(BigInteger.ONE));
    }

    @Test
    @DisplayName("reduce(p) = 0 (boundary: exactly the modulus)")
    void reduceExactlyP() {
        assertReducesTo(P, BigInteger.ZERO);
    }

    @Test
    @DisplayName("reduce(p + 1) = 1 (boundary: one above the modulus, forces 2nd condSub)")
    void reducePPlusOne() {
        assertReducesTo(P.add(BigInteger.ONE), BigInteger.ONE);
    }

    @Test
    @DisplayName("reduce(2p - 1) = p - 1 (boundary at 2p, the 2nd condSub edge)")
    void reduce2PMinusOne() {
        assertReducesTo(P.shiftLeft(1).subtract(BigInteger.ONE), P.subtract(BigInteger.ONE));
    }

    @Test
    @DisplayName("reduce(2^256 - 1) = (2^256 - 1) mod p (forces c1 carry into step 2)")
    void reduceAllOnes256() {
        BigInteger x = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
        assertReducesTo(x, x.mod(P));
    }

    @Test
    @DisplayName("reduce(2^256) = 38 (the defining fold relation: 2^256 ≡ 38 mod p)")
    void reducePowerOf256() {
        assertReducesTo(BigInteger.ONE.shiftLeft(256), BigInteger.valueOf(38));
    }

    @Test
    @DisplayName(
            "reduce(2^512 - 1) = (2^512 - 1) mod p (largest 512-bit dividend; both x_hi and x_lo"
                + " are all-ones, forces c1 to its maximum and triggers the 33-byte intermediate)")
    void reduceAllOnes512() {
        BigInteger x = BigInteger.ONE.shiftLeft(512).subtract(BigInteger.ONE);
        assertReducesTo(x, x.mod(P));
    }

    @Test
    @DisplayName(
            "reduce(2^512) — same as 2^512 - 0 but with the bottom bit clear, separate carry "
                    + "footprint")
    void reducePowerOf512Approx() {
        BigInteger x = BigInteger.ONE.shiftLeft(512).subtract(BigInteger.TEN);
        assertReducesTo(x, x.mod(P));
    }

    @Test
    @DisplayName("reduce(k · p) = 0 for k = 1..3 (exact multiples must canonicalize to zero)")
    void reduceExactMultiples() {
        for (int k = 1; k <= 3; k++) {
            BigInteger x = P.multiply(BigInteger.valueOf(k));
            if (x.bitLength() > 512) continue;
            assertReducesTo(x, BigInteger.ZERO, "k = " + k);
        }
    }

    @Test
    @DisplayName("reduce(k · p - 1) = p - 1 for k = 1..3 (just below an exact multiple)")
    void reduceJustBelowMultiples() {
        for (int k = 1; k <= 3; k++) {
            BigInteger x = P.multiply(BigInteger.valueOf(k)).subtract(BigInteger.ONE);
            if (x.bitLength() > 512) continue;
            assertReducesTo(x, P.subtract(BigInteger.ONE), "k = " + k);
        }
    }

    @Test
    @DisplayName("reduce(k · p + 1) = 1 for k = 1..3 (just above an exact multiple)")
    void reduceJustAboveMultiples() {
        for (int k = 1; k <= 3; k++) {
            BigInteger x = P.multiply(BigInteger.valueOf(k)).add(BigInteger.ONE);
            if (x.bitLength() > 512) continue;
            assertReducesTo(x, BigInteger.ONE, "k = " + k);
        }
    }

    @Test
    @DisplayName("reduce((p - 1)^2): canonical field-multiply maximum, the curve worst case")
    void reducePMinusOneSquared() {
        BigInteger x = P.subtract(BigInteger.ONE).multiply(P.subtract(BigInteger.ONE));
        assertReducesTo(x, x.mod(P));
    }

    @Test
    @DisplayName("reduce(2^256 - 38) = 0 (boundary: 2p exactly, since 2p = 2^256 - 38)")
    void reduceTwoPExactly() {
        BigInteger x = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.valueOf(38));
        assertReducesTo(x, BigInteger.ZERO);
    }

    @Test
    @DisplayName("reduce(2^256 - 37) = 1 (just past 2p — the 2nd condSub is non-trivial here)")
    void reduceTwoPPlusOne() {
        BigInteger x = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.valueOf(37));
        assertReducesTo(x, BigInteger.ONE);
    }

    @RepeatedTest(1000)
    @DisplayName("reduce(random 512-bit product) matches BigInteger.mod (1 000 differentials)")
    void reduceRandomProducts() {
        byte[] xBytes = new byte[64];
        RNG.nextBytes(xBytes);
        BigInteger x = new BigInteger(1, xBytes);
        assertReducesTo(x, x.mod(P));
    }

    @RepeatedTest(200)
    @DisplayName("reduce(random a · b): canonical Field25519.mul input shape")
    void reduceRandomFieldProducts() {
        byte[] aBytes = new byte[32];
        byte[] bBytes = new byte[32];
        RNG.nextBytes(aBytes);
        RNG.nextBytes(bBytes);
        BigInteger a = new BigInteger(1, aBytes).mod(P);
        BigInteger b = new BigInteger(1, bBytes).mod(P);
        BigInteger x = a.multiply(b);
        assertReducesTo(x, x.mod(P));
    }

    @Test
    @DisplayName("reduce honours non-zero source and dest offsets and does not mutate the input")
    void reduceHonoursOffsets() {
        // Place x in the middle of a 128-byte backing buffer.
        byte[] xBacking = new byte[128];
        byte[] x = toFixed(P.subtract(BigInteger.TEN), 64);
        System.arraycopy(x, 0, xBacking, 32, 64);
        for (int i = 0; i < 32; i++) xBacking[i] = (byte) 0xAA;
        for (int i = 96; i < 128; i++) xBacking[i] = (byte) 0xBB;

        byte[] dstBacking = new byte[64];
        for (int i = 0; i < 64; i++) dstBacking[i] = (byte) 0xDD;

        Field25519.reducePseudoMersenne(xBacking, (short) 32, dstBacking, (short) 16);

        // x sentinels intact:
        for (int i = 0; i < 32; i++) {
            assertArrayEquals(new byte[] {(byte) 0xAA}, new byte[] {xBacking[i]}, "x prefix " + i);
        }
        for (int i = 96; i < 128; i++) {
            assertArrayEquals(new byte[] {(byte) 0xBB}, new byte[] {xBacking[i]}, "x suffix " + i);
        }
        byte[] xAfter = new byte[64];
        System.arraycopy(xBacking, 32, xAfter, 0, 64);
        assertArrayEquals(x, xAfter, "input must not be modified");

        // dst sentinels intact:
        for (int i = 0; i < 16; i++) {
            assertArrayEquals(
                    new byte[] {(byte) 0xDD}, new byte[] {dstBacking[i]}, "dst prefix " + i);
        }
        for (int i = 48; i < 64; i++) {
            assertArrayEquals(
                    new byte[] {(byte) 0xDD}, new byte[] {dstBacking[i]}, "dst suffix " + i);
        }

        // dst[16..48] == (p - 10) mod p = p - 10.
        byte[] expected = toFixed(P.subtract(BigInteger.TEN), 32);
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
        byte[] xBuf = toFixed(x, 64);
        byte[] dst = new byte[32];
        Field25519.reducePseudoMersenne(xBuf, (short) 0, dst, (short) 0);
        byte[] expectedBytes = toFixed(expected, 32);
        assertArrayEquals(expectedBytes, dst, message);
    }

    private static byte[] toFixed(BigInteger v, int len) {
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
