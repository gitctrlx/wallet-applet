/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

/**
 * Pure-Java tests for the multi-precision {@link Bignat} primitives.
 *
 * <p>Cross-references every operation against the JDK's {@link BigInteger} as the oracle: random
 * 32-byte inputs, repeated 200× per primitive to cover edge cases (small operands, near-modulus
 * values, leading zero limbs, etc.).
 */
class BignatTest {

    private static final SecureRandom RNG = new SecureRandom();
    private static final BigInteger SECP256K1_N =
            new BigInteger(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    @RepeatedTest(200)
    @DisplayName("add: 32-byte unsigned addition matches BigInteger")
    void addMatches() {
        byte[] a = randomBytes(32);
        byte[] b = randomBytes(32);
        BigInteger expected = unsigned(a).add(unsigned(b));
        boolean expectedCarry = expected.bitLength() > 256;
        byte[] result = a.clone();
        boolean carry = Bignat.add(result, (short) 0, b, (short) 0, (short) 32);
        assertEquals(expectedCarry, carry, "carry mismatch");
        BigInteger gotMod = unsigned(result);
        BigInteger expectedMod = expected.mod(BigInteger.ONE.shiftLeft(256));
        assertEquals(expectedMod, gotMod);
    }

    @RepeatedTest(200)
    @DisplayName("sub: 32-byte unsigned subtraction matches BigInteger")
    void subMatches() {
        byte[] a = randomBytes(32);
        byte[] b = randomBytes(32);
        BigInteger expected = unsigned(a).subtract(unsigned(b));
        boolean expectedBorrow = expected.signum() < 0;
        byte[] result = a.clone();
        boolean borrow = Bignat.sub(result, (short) 0, b, (short) 0, (short) 32);
        assertEquals(expectedBorrow, borrow);
        BigInteger gotMod = unsigned(result);
        BigInteger expectedMod = expected.mod(BigInteger.ONE.shiftLeft(256));
        assertEquals(expectedMod, gotMod);
    }

    @Test
    @DisplayName("lessThan: strict less-than matches BigInteger.compareTo")
    void lessThanMatches() {
        for (int i = 0; i < 100; i++) {
            byte[] a = randomBytes(32);
            byte[] b = randomBytes(32);
            boolean expected = unsigned(a).compareTo(unsigned(b)) < 0;
            assertEquals(expected, Bignat.lessThan(a, (short) 0, b, (short) 0, (short) 32));
        }
        // Equal case must not be reported as strictly less.
        byte[] x = randomBytes(32);
        assertFalse(Bignat.lessThan(x, (short) 0, x, (short) 0, (short) 32));
    }

    @Test
    @DisplayName("isZero: detects all-zero buffer of any size")
    void isZeroDetects() {
        byte[] z = new byte[64];
        assertTrue(Bignat.isZero(z, (short) 0, (short) 64));
        z[33] = 1;
        assertFalse(Bignat.isZero(z, (short) 0, (short) 64));
        // A nonzero byte outside the [off, off+size) window must not affect the result.
        z[0] = 0x55;
        assertTrue(Bignat.isZero(z, (short) 1, (short) 32));
    }

    @RepeatedTest(200)
    @DisplayName("mult: 32×32 → 64 schoolbook multiplication matches BigInteger")
    void multMatches() {
        byte[] a = randomBytes(32);
        byte[] b = randomBytes(32);
        byte[] z = new byte[64];
        Bignat.mult(a, (short) 0, b, (short) 0, (short) 32, z, (short) 0);
        BigInteger expected = unsigned(a).multiply(unsigned(b));
        BigInteger got = unsigned(z);
        assertEquals(expected, got);
    }

    @RepeatedTest(200)
    @DisplayName("mod: 64-byte dividend mod 32-byte divisor (n) matches BigInteger.mod")
    void modMatches() {
        byte[] dividend = randomBytes(64);
        byte[] divisor = bigIntToFixed(SECP256K1_N, 32);
        byte[] dvCopy = dividend.clone();
        Bignat.mod(dvCopy, (short) 0, (short) 64, divisor, (short) 0, (short) 32);
        // The remainder occupies the last 32 bytes; the leading 32 bytes must be zero.
        byte[] remainder = Arrays.copyOfRange(dvCopy, 32, 64);
        byte[] leadingZeros = Arrays.copyOfRange(dvCopy, 0, 32);
        assertArrayEquals(new byte[32], leadingZeros, "leading bytes must be zeroed");
        BigInteger expected = unsigned(dividend).mod(SECP256K1_N);
        BigInteger got = unsigned(remainder);
        assertEquals(expected, got);
    }

    @Test
    @DisplayName("mod: edge cases — dividend < divisor, dividend == divisor, all zero")
    void modEdgeCases() {
        byte[] divisor = bigIntToFixed(SECP256K1_N, 32);
        // Dividend < divisor → unchanged in the trailing 32 bytes (after the schoolbook walks
        // realise no subtraction is needed).
        byte[] small = new byte[64];
        small[63] = 0x07;
        byte[] expected = small.clone();
        Bignat.mod(small, (short) 0, (short) 64, divisor, (short) 0, (short) 32);
        assertArrayEquals(expected, small, "dividend < divisor must remain unchanged");

        // Dividend == divisor (zero-extended to 64 bytes) → result == 0.
        byte[] eq = new byte[64];
        System.arraycopy(divisor, 0, eq, 32, 32);
        Bignat.mod(eq, (short) 0, (short) 64, divisor, (short) 0, (short) 32);
        assertArrayEquals(new byte[64], eq);

        // All-zero dividend → result == 0.
        byte[] zero = new byte[64];
        Bignat.mod(zero, (short) 0, (short) 64, divisor, (short) 0, (short) 32);
        assertArrayEquals(new byte[64], zero);
    }

    @RepeatedTest(50)
    @DisplayName("mult + mod composition: (e * d) mod n matches BigInteger")
    void multThenModMatches() {
        byte[] e = randomBytes(32);
        byte[] d = randomBytes(32);
        BigInteger expected = unsigned(e).multiply(unsigned(d)).mod(SECP256K1_N);
        byte[] z = new byte[64];
        Bignat.mult(e, (short) 0, d, (short) 0, (short) 32, z, (short) 0);
        byte[] divisor = bigIntToFixed(SECP256K1_N, 32);
        Bignat.mod(z, (short) 0, (short) 64, divisor, (short) 0, (short) 32);
        BigInteger got = unsigned(Arrays.copyOfRange(z, 32, 64));
        assertEquals(expected, got);
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    private static BigInteger unsigned(byte[] b) {
        return new BigInteger(1, b);
    }

    private static byte[] bigIntToFixed(BigInteger n, int len) {
        byte[] raw = n.toByteArray();
        if (raw.length == len) return raw;
        byte[] out = new byte[len];
        if (raw.length > len) System.arraycopy(raw, raw.length - len, out, 0, len);
        else System.arraycopy(raw, 0, out, len - raw.length, raw.length);
        return out;
    }
}
