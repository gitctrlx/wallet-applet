/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

/**
 * Audit F-41 regression: pin the invariants of the random projective-coordinate blinding that
 * underpins {@link Ed25519#sign}'s residual-SPA countermeasure (Coron CHES 1999 §3.1).
 *
 * <p>The Edwards25519 group element {@code (X, Y, Z, T)} represents the affine point {@code (X/Z,
 * Y/Z)}. Multiplying every coordinate by a non-zero field element {@code r} produces an equivalent
 * representative of the same group element. The two properties this file pins are:
 *
 * <ul>
 *   <li>{@link Edwards25519#randomizeProjective} preserves the affine encoding (random blinding
 *       MUST NOT change the point it represents);
 *   <li>blinding by {@code r = 1} is a no-op (sanity check that the multiplication writes the
 *       correct sub-slots).
 * </ul>
 *
 * <p>Together with F-32 (fixed {@link Ed25519#blindBasePoint} control flow), these tests close the
 * testing gap that previously left the F-01 mitigation core unverified outside the integration loop
 * {@link Ed25519SigningTest}.
 */
class RandomizeProjectiveTest {

    private static final BigInteger P =
            BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final SecureRandom RNG = new SecureRandom();

    @RepeatedTest(50)
    @DisplayName("randomizeProjective preserves the affine encoding of the base point")
    void preservesBaseEncoding() {
        byte[] point = new byte[Edwards25519.POINT_LEN];
        Edwards25519.setBase(point, (short) 0);

        byte[] encScratch = new byte[Edwards25519.ENCODE_SCRATCH_LEN];
        byte[] originalEnc = new byte[Edwards25519.ENCODED_LEN];
        Edwards25519.encodePoint(point, (short) 0, originalEnc, (short) 0, encScratch, (short) 0);

        byte[] blind = drawNonZeroFieldElement();
        byte[] opScratch = new byte[Edwards25519.POINT_OP_SCRATCH_LEN];
        Edwards25519.randomizeProjective(point, (short) 0, blind, (short) 0, opScratch, (short) 0);

        byte[] blindedEnc = new byte[Edwards25519.ENCODED_LEN];
        Edwards25519.encodePoint(point, (short) 0, blindedEnc, (short) 0, encScratch, (short) 0);

        assertArrayEquals(
                originalEnc,
                blindedEnc,
                "Coron projective randomisation MUST preserve the affine encoding of B");
    }

    @RepeatedTest(20)
    @DisplayName("randomizeProjective preserves encoding of 2·B (sanity beyond just the base)")
    void preservesEncodingOfDouble() {
        byte[] point = new byte[Edwards25519.POINT_LEN];
        Edwards25519.setBase(point, (short) 0);
        byte[] opScratch = new byte[Edwards25519.POINT_OP_SCRATCH_LEN];
        Edwards25519.pointDouble(point, (short) 0, point, (short) 0, opScratch, (short) 0);

        byte[] encScratch = new byte[Edwards25519.ENCODE_SCRATCH_LEN];
        byte[] originalEnc = new byte[Edwards25519.ENCODED_LEN];
        Edwards25519.encodePoint(point, (short) 0, originalEnc, (short) 0, encScratch, (short) 0);

        byte[] blind = drawNonZeroFieldElement();
        Edwards25519.randomizeProjective(point, (short) 0, blind, (short) 0, opScratch, (short) 0);

        byte[] blindedEnc = new byte[Edwards25519.ENCODED_LEN];
        Edwards25519.encodePoint(point, (short) 0, blindedEnc, (short) 0, encScratch, (short) 0);

        assertArrayEquals(originalEnc, blindedEnc);
    }

    @Test
    @DisplayName("randomizeProjective with blind = 1 leaves the four sub-slots untouched")
    void blindOneIsNoOp() {
        byte[] point = new byte[Edwards25519.POINT_LEN];
        Edwards25519.setBase(point, (short) 0);
        byte[] before = point.clone();

        byte[] blind = new byte[Field25519.LEN];
        blind[Field25519.LEN - 1] = 1;
        byte[] opScratch = new byte[Edwards25519.POINT_OP_SCRATCH_LEN];
        Edwards25519.randomizeProjective(point, (short) 0, blind, (short) 0, opScratch, (short) 0);

        assertArrayEquals(
                before,
                point,
                "scaling every coordinate by 1 must leave the extended-form representation"
                        + " byte-identical");
    }

    @Test
    @DisplayName("randomizeProjective with a non-trivial blind actually changes the Z coordinate")
    void nonTrivialBlindChangesZ() {
        byte[] point = new byte[Edwards25519.POINT_LEN];
        Edwards25519.setBase(point, (short) 0);
        byte[] zBefore = new byte[Field25519.LEN];
        System.arraycopy(point, Edwards25519.PT_Z_OFF, zBefore, 0, Field25519.LEN);

        byte[] blind = new byte[Field25519.LEN];
        blind[Field25519.LEN - 1] = 2;
        byte[] opScratch = new byte[Edwards25519.POINT_OP_SCRATCH_LEN];
        Edwards25519.randomizeProjective(point, (short) 0, blind, (short) 0, opScratch, (short) 0);

        byte[] zAfter = new byte[Field25519.LEN];
        System.arraycopy(point, Edwards25519.PT_Z_OFF, zAfter, 0, Field25519.LEN);
        boolean changed = false;
        for (int i = 0; i < Field25519.LEN; i++) {
            if (zBefore[i] != zAfter[i]) {
                changed = true;
                break;
            }
        }
        assertTrue(
                changed,
                "Z coordinate must change when blind != 1 (otherwise the multiplication"
                        + " degenerated to a copy)");
    }

    private static byte[] drawNonZeroFieldElement() {
        while (true) {
            byte[] raw = new byte[Field25519.LEN];
            RNG.nextBytes(raw);
            raw[0] &= 0x7F;
            BigInteger v = new BigInteger(1, raw);
            if (v.signum() != 0 && v.compareTo(P) < 0) {
                return raw;
            }
        }
    }
}
