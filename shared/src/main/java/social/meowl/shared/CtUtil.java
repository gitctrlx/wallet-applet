/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.shared;

/**
 * Constant-time byte-array primitives shared across meowl applets.
 *
 * <p>Extracted from {@code BigNat} so the Secure Channel and the backup applet can perform
 * timing-safe comparisons without dragging in the full multi-precision arithmetic class. Every
 * method walks all {@code size} bytes unconditionally and folds the verdict into a single
 * accumulator inspected once at the end; every intermediate stays in the {@code short} domain
 * because the JavaCard 3.0.5 CAP converter rejects {@code int}-typed locals.
 */
public final class CtUtil {

    /** Mask widening a {@code byte} to an unsigned value in the {@code short} domain. */
    private static final short DIGIT_MASK = 0xFF;

    private CtUtil() {}

    /**
     * Constant-time equality. XOR-accumulates every byte pair and only inspects the result once at
     * the end. Use for MAC tags, authenticator output and signature equality checks where one side
     * is secret.
     */
    public static boolean ctEquals(byte[] x, short xOff, byte[] y, short yOff, short size) {
        byte diff = 0;
        for (short i = 0; i < size; i++) {
            diff |= (byte) (x[(short) (xOff + i)] ^ y[(short) (yOff + i)]);
        }
        return diff == 0;
    }

    /**
     * Constant-time strict less-than: returns {@code -1} (0xFFFF) iff {@code x < y}, {@code 0}
     * otherwise. Performs the full trial-subtract, reading every byte MSB-to-LSB on every call.
     */
    public static short ctLessThan(byte[] x, short xOff, byte[] y, short yOff, short size) {
        short borrow = 0;
        for (short i = (short) (size - 1); i >= 0; i--) {
            short diff =
                    (short)
                            ((x[(short) (xOff + i)] & DIGIT_MASK)
                                    - (y[(short) (yOff + i)] & DIGIT_MASK)
                                    - borrow);
            borrow = (short) ((diff >>> 15) & 1);
        }
        return (short) -borrow;
    }

    /**
     * Constant-time {@code x == 0}: returns {@code -1} iff every byte is zero, {@code 0} otherwise.
     */
    public static short ctIsZero(byte[] x, short xOff, short size) {
        short acc = 0;
        for (short i = 0; i < size; i++) {
            acc |= (short) (x[(short) (xOff + i)] & DIGIT_MASK);
        }
        short orNeg = (short) (acc | (short) -acc);
        short nonZero = (short) ((orNeg >>> 15) & 1);
        return (short) (nonZero - 1);
    }
}
