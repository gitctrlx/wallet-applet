/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Functional tests for {@link ConstantTime#equals}. Correctness is the entire contract — the
 * constant-time property cannot be observed by black-box JVM tests, only by reviewing the
 * implementation, which the test suite cross-references in its comments.
 */
class ConstantTimeTest {

    @Nested
    @DisplayName("equals(): correctness across the equality decision space")
    class Equals {

        @Test
        @DisplayName("equal arrays of various lengths compare equal")
        void equalArrays() {
            byte[] a = new byte[256];
            byte[] b = new byte[256];
            for (int i = 0; i < a.length; i++) {
                a[i] = (byte) i;
                b[i] = (byte) i;
            }
            for (short len : new short[] {1, 16, 32, 33, 64, 128, 200, 256}) {
                assertTrue(
                        ConstantTime.equals(a, (short) 0, b, (short) 0, len),
                        "len=" + len + " must compare equal");
            }
        }

        @Test
        @DisplayName("a single mismatching byte at any position makes equality false")
        void anyMismatchPositionIsDetected() {
            byte[] a = new byte[32];
            byte[] b = new byte[32];
            // For each byte position, set b[i] to differ and ensure the function flags it.
            for (int i = 0; i < 32; i++) {
                a[i] = 0;
                b[i] = 1;
                assertFalse(
                        ConstantTime.equals(a, (short) 0, b, (short) 0, (short) 32),
                        "mismatch at index " + i + " must be detected");
                b[i] = 0;
            }
        }

        @Test
        @DisplayName("multiple mismatching bytes are all OR-folded into non-equality")
        void multipleMismatches() {
            byte[] a = new byte[64];
            byte[] b = new byte[64];
            // Sprinkle several mismatches.
            b[0] = 0x42;
            b[15] = 0x42;
            b[31] = 0x42;
            b[63] = 0x42;
            assertFalse(
                    ConstantTime.equals(a, (short) 0, b, (short) 0, (short) 64),
                    "any mismatch must yield non-equality");
        }

        @Test
        @DisplayName("offsets are respected")
        void offsetsAreRespected() {
            byte[] a = {0, 1, 2, 3, 4, 5, 6, 7};
            byte[] b = {99, 99, 2, 3, 4, 5, 99, 99};
            // Compare a[2..6] with b[2..6] — both equal "2,3,4,5".
            assertTrue(ConstantTime.equals(a, (short) 2, b, (short) 2, (short) 4));
            // Compare a[0..4] with b[0..4] — differ at 0 and 1.
            assertFalse(ConstantTime.equals(a, (short) 0, b, (short) 0, (short) 4));
        }

        @Test
        @DisplayName("length zero is trivially equal")
        void zeroLengthEqual() {
            byte[] a = {1, 2, 3};
            byte[] b = {4, 5, 6};
            assertTrue(ConstantTime.equals(a, (short) 0, b, (short) 0, (short) 0));
        }

        @Test
        @DisplayName("high-bit byte values do not cause sign-extension bugs")
        void highBitBytesAreHandled() {
            byte[] a = {(byte) 0xFF, (byte) 0x80, 0x7F, 0x00};
            byte[] b = {(byte) 0xFF, (byte) 0x80, 0x7F, 0x00};
            assertTrue(ConstantTime.equals(a, (short) 0, b, (short) 0, (short) 4));

            // Flip a single high bit and ensure detection — common regression in naive
            // implementations that accidentally compare via int promotion.
            b[1] = (byte) 0x81;
            assertFalse(ConstantTime.equals(a, (short) 0, b, (short) 0, (short) 4));
        }
    }
}
