/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Known-answer regression tests for {@link ModN} — the bespoke 256-bit modular-arithmetic helper
 * that backs the BIP-32 reduction {@code k_i = (parse256(I_L) + k_par) mod n}. Independent coverage
 * matters here because {@code ModN} is the only piece of cryptographic code in the applet that we
 * are not borrowing from a JC-provided primitive, and a silent off-by-one in either the
 * carry-propagation or the conditional subtract would only surface as wrong derived keys at the
 * BIP-32-vector level.
 *
 * <p>The reference values are computed with {@link BigInteger} so each KAT is independently
 * checkable against the secp256k1 group order.
 */
class ModNTest {

    /**
     * secp256k1 group order — the same constant as {@link ModN#SECP256K1_N}, expressed as a {@link
     * BigInteger} so the reference computation does not borrow from the unit under test.
     */
    private static final BigInteger N =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    /* ── lessThanN ───────────────────────────────────────────────────────────────────────── */

    @Test
    @DisplayName("lessThanN: 0 < n is true")
    void lessThanZero() {
        assertTrue(ModN.lessThanN(repeat((byte) 0), (short) 0));
    }

    @Test
    @DisplayName("lessThanN: n − 1 < n is true (the largest valid scalar)")
    void lessThanNMinus1() {
        byte[] a = bigIntToFixed(N.subtract(BigInteger.ONE), 32);
        assertTrue(ModN.lessThanN(a, (short) 0));
    }

    @Test
    @DisplayName("lessThanN: n is NOT strictly less than itself")
    void lessThanNExact() {
        byte[] a = bigIntToFixed(N, 32);
        assertFalse(ModN.lessThanN(a, (short) 0));
    }

    @Test
    @DisplayName("lessThanN: n + 1 is NOT less than n")
    void lessThanNPlus1() {
        byte[] a = bigIntToFixed(N.add(BigInteger.ONE), 32);
        assertFalse(ModN.lessThanN(a, (short) 0));
    }

    @Test
    @DisplayName("lessThanN: 2²⁵⁶ − 1 (all 0xFF) is NOT less than n")
    void lessThanNAllFf() {
        assertFalse(ModN.lessThanN(repeat((byte) 0xFF), (short) 0));
    }

    /* ── isZero ──────────────────────────────────────────────────────────────────────────── */

    @Test
    @DisplayName("isZero: all-zero buffer reports zero")
    void isZeroAllZero() {
        assertTrue(ModN.isZero(repeat((byte) 0), (short) 0));
    }

    @Test
    @DisplayName("isZero: single 0x01 in the LSB position is non-zero")
    void isZeroLsbOne() {
        byte[] a = repeat((byte) 0);
        a[31] = 1;
        assertFalse(ModN.isZero(a, (short) 0));
    }

    @Test
    @DisplayName("isZero: single 0x80 in the MSB position is non-zero")
    void isZeroMsbHigh() {
        byte[] a = repeat((byte) 0);
        a[0] = (byte) 0x80;
        assertFalse(ModN.isZero(a, (short) 0));
    }

    /* ── addMod ──────────────────────────────────────────────────────────────────────────── */

    @Test
    @DisplayName("addMod: 0 + 0 = 0 (returns isZero=true)")
    void addZeroPlusZero() {
        byte[] out = new byte[32];
        boolean isZero =
                ModN.addMod(
                        repeat((byte) 0), (short) 0, repeat((byte) 0), (short) 0, out, (short) 0);
        assertTrue(isZero);
        assertArrayEquals(repeat((byte) 0), out);
    }

    @Test
    @DisplayName("addMod: 0 + (n−1) = n−1 (no reduction)")
    void addZeroPlusNMinus1() {
        byte[] a = repeat((byte) 0);
        byte[] b = bigIntToFixed(N.subtract(BigInteger.ONE), 32);
        byte[] out = new byte[32];
        boolean isZero = ModN.addMod(a, (short) 0, b, (short) 0, out, (short) 0);
        assertFalse(isZero);
        assertArrayEquals(b, out);
    }

    @Test
    @DisplayName("addMod: (n−1) + 1 = 0 (exact reduction, returns isZero=true)")
    void addNMinus1Plus1() {
        byte[] a = bigIntToFixed(N.subtract(BigInteger.ONE), 32);
        byte[] b = bigIntToFixed(BigInteger.ONE, 32);
        byte[] out = new byte[32];
        boolean isZero = ModN.addMod(a, (short) 0, b, (short) 0, out, (short) 0);
        assertTrue(isZero);
        assertArrayEquals(repeat((byte) 0), out);
    }

    @Test
    @DisplayName("addMod: (n−1) + 2 = 1 (one-step reduction)")
    void addNMinus1Plus2() {
        byte[] a = bigIntToFixed(N.subtract(BigInteger.ONE), 32);
        byte[] b = bigIntToFixed(BigInteger.TWO, 32);
        byte[] out = new byte[32];
        boolean isZero = ModN.addMod(a, (short) 0, b, (short) 0, out, (short) 0);
        assertFalse(isZero);
        assertArrayEquals(bigIntToFixed(BigInteger.ONE, 32), out);
    }

    @Test
    @DisplayName(
            "addMod: (n−1) + (n−1) = n−2 (largest sum, requires the byte carry to be respected)")
    void addNMinus1PlusNMinus1() {
        byte[] a = bigIntToFixed(N.subtract(BigInteger.ONE), 32);
        byte[] out = new byte[32];
        boolean isZero = ModN.addMod(a, (short) 0, a, (short) 0, out, (short) 0);
        assertFalse(isZero);
        assertArrayEquals(bigIntToFixed(N.subtract(BigInteger.TWO), 32), out);
    }

    @Test
    @DisplayName("addMod: 1 + (n−2) = n−1 (no reduction, dense bytes)")
    void addOnePlusNMinus2() {
        byte[] a = bigIntToFixed(BigInteger.ONE, 32);
        byte[] b = bigIntToFixed(N.subtract(BigInteger.TWO), 32);
        byte[] out = new byte[32];
        boolean isZero = ModN.addMod(a, (short) 0, b, (short) 0, out, (short) 0);
        assertFalse(isZero);
        assertArrayEquals(bigIntToFixed(N.subtract(BigInteger.ONE), 32), out);
    }

    @Test
    @DisplayName("addMod: aliased a == out (in-place destination) preserves correct result")
    void addAliasedAOut() {
        byte[] aOut = bigIntToFixed(N.subtract(BigInteger.ONE), 32);
        byte[] b = bigIntToFixed(BigInteger.ONE, 32);
        boolean isZero = ModN.addMod(aOut, (short) 0, b, (short) 0, aOut, (short) 0);
        assertTrue(isZero);
        assertArrayEquals(repeat((byte) 0), aOut);
    }

    @Test
    @DisplayName("addMod: aliased b == out preserves correct result (write-through ordering)")
    void addAliasedBOut() {
        byte[] a = bigIntToFixed(BigInteger.ONE, 32);
        byte[] bOut = bigIntToFixed(N.subtract(BigInteger.ONE), 32);
        boolean isZero = ModN.addMod(a, (short) 0, bOut, (short) 0, bOut, (short) 0);
        assertTrue(isZero);
        assertArrayEquals(repeat((byte) 0), bOut);
    }

    @Test
    @DisplayName("addMod: 50 randomised inputs match BigInteger reference")
    void addRandomized() {
        SecureRandom rng = new SecureRandom();
        for (int trial = 0; trial < 50; trial++) {
            BigInteger aBi = randomScalar(rng);
            BigInteger bBi = randomScalar(rng);
            byte[] a = bigIntToFixed(aBi, 32);
            byte[] b = bigIntToFixed(bBi, 32);
            byte[] out = new byte[32];
            boolean isZero = ModN.addMod(a, (short) 0, b, (short) 0, out, (short) 0);
            BigInteger expected = aBi.add(bBi).mod(N);
            assertArrayEquals(
                    bigIntToFixed(expected, 32),
                    out,
                    "trial " + trial + " a=" + aBi.toString(16) + " b=" + bBi.toString(16));
            assertTrue(
                    isZero == (expected.signum() == 0), "trial " + trial + " isZero flag mismatch");
        }
    }

    @Test
    @DisplayName("addMod: offsets > 0 (within larger backing buffers) are handled correctly")
    void addOffsetSlots() {
        byte[] backing = new byte[160];
        byte[] aBytes = bigIntToFixed(N.subtract(BigInteger.ONE), 32);
        byte[] bBytes = bigIntToFixed(BigInteger.TWO, 32);
        System.arraycopy(aBytes, 0, backing, 32, 32);
        System.arraycopy(bBytes, 0, backing, 96, 32);
        boolean isZero =
                ModN.addMod(backing, (short) 32, backing, (short) 96, backing, (short) 128);
        assertFalse(isZero);
        byte[] outSlice = new byte[32];
        System.arraycopy(backing, 128, outSlice, 0, 32);
        assertArrayEquals(bigIntToFixed(BigInteger.ONE, 32), outSlice);
    }

    /* ── helpers ──────────────────────────────────────────────────────────────────────────── */

    private static byte[] repeat(byte v) {
        byte[] out = new byte[32];
        for (int i = 0; i < out.length; i++) out[i] = v;
        return out;
    }

    private static byte[] bigIntToFixed(BigInteger n, int len) {
        byte[] raw =
                n.signum() < 0
                        ? n.add(BigInteger.ONE.shiftLeft(8 * len)).toByteArray()
                        : n.toByteArray();
        if (raw.length == len) return raw;
        byte[] out = new byte[len];
        if (raw.length > len) System.arraycopy(raw, raw.length - len, out, 0, len);
        else System.arraycopy(raw, 0, out, len - raw.length, raw.length);
        return out;
    }

    private static BigInteger randomScalar(SecureRandom rng) {
        // Uniform in [0, n) — biased discard, but the bias is negligible in 50 trials.
        BigInteger candidate;
        byte[] buf = new byte[32];
        do {
            rng.nextBytes(buf);
            candidate = new BigInteger(1, buf);
        } while (candidate.compareTo(N) >= 0);
        return candidate;
    }
}
