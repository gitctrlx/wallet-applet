/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.wallet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.math.BigInteger;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Differential tests for {@link Fp25519} against {@link BigInteger} mod {@code p = 2²⁵⁵ − 19}.
 * Covers additive helpers, the schoolbook multiply + pseudo-Mersenne reducer, and the {@code (u ±
 * 1)} corner cases consumed by {@link Wei25519}. The software Fermat inverse in {@code Fp25519Inv}
 * is exercised end-to-end on physical silicon by every ECDSA / Ed25519 / Schnorr signing test (each
 * signature pass invokes the inverter); there is no in-JVM unit-test path because jcardsim's RSA
 * backend rejects the prime modulus the inverter loads.
 */
class Fp25519Test {

    private static final BigInteger P = new BigInteger(1, Fp25519.P);
    private static final Random RNG = new Random(0xFEED);

    private static byte[] beBytes(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[Fp25519.LEN];
        if (raw.length <= Fp25519.LEN) {
            System.arraycopy(raw, 0, out, Fp25519.LEN - raw.length, raw.length);
        } else {
            System.arraycopy(raw, raw.length - Fp25519.LEN, out, 0, Fp25519.LEN);
        }
        return out;
    }

    private static BigInteger randomFieldElement() {
        return new BigInteger(254, RNG).mod(P);
    }

    @Nested
    @DisplayName("additive helpers match BigInteger oracle")
    class Additive {

        @Test
        @DisplayName("sub over 100 random pairs")
        void sub() {
            byte[] out = new byte[Fp25519.LEN];
            for (int i = 0; i < 100; i++) {
                BigInteger a = randomFieldElement();
                BigInteger b = randomFieldElement();
                Fp25519.sub(beBytes(a), (short) 0, beBytes(b), (short) 0, out, (short) 0);
                assertArrayEquals(beBytes(a.subtract(b).mod(P)), out);
            }
        }

        @Test
        @DisplayName("increment / decrement handle the (u ± 1) corners used by Wei25519")
        void incDec() {
            byte[] out = new byte[Fp25519.LEN];
            Fp25519.increment(Fp25519.P, (short) 0, out, (short) 0);
            assertArrayEquals(beBytes(BigInteger.ONE), out, "increment(p) wraps to 1");
            byte[] zero = new byte[Fp25519.LEN];
            Fp25519.decrement(zero, (short) 0, out, (short) 0);
            assertArrayEquals(
                    beBytes(P.subtract(BigInteger.ONE)), out, "decrement(0) wraps to p − 1");
            byte[] one = new byte[Fp25519.LEN];
            one[Fp25519.LEN - 1] = 1;
            Fp25519.decrement(one, (short) 0, out, (short) 0);
            assertArrayEquals(beBytes(BigInteger.ZERO), out, "decrement(1) is 0");
        }
    }

    @Nested
    @DisplayName("multiplicative helpers match BigInteger oracle")
    class Multiplicative {

        @Test
        @DisplayName("mul over 50 random pairs")
        void mul() {
            byte[] out = new byte[Fp25519.LEN];
            byte[] scratch = new byte[Fp25519.MUL_SCRATCH_LEN];
            for (int i = 0; i < 50; i++) {
                BigInteger a = randomFieldElement();
                BigInteger b = randomFieldElement();
                Fp25519.mul(
                        beBytes(a),
                        (short) 0,
                        beBytes(b),
                        (short) 0,
                        out,
                        (short) 0,
                        scratch,
                        (short) 0);
                assertArrayEquals(beBytes(a.multiply(b).mod(P)), out);
            }
        }
    }
}
