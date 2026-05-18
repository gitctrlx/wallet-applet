/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

/**
 * Constant-time byte-array operations.
 *
 * <p>The JavaCard 3.x specification for {@link javacard.framework.Util#arrayCompare} only
 * guarantees that the comparison is performed <em>from left to right</em> and returns a ternary
 * result; it explicitly does <strong>not</strong> guarantee constant-time execution. A
 * short-circuit on first mismatch would leak the index of the first differing byte to a timing
 * adversary, which is a textbook flaw in MAC tag verification and similar secrecy-critical paths.
 *
 * <p>This class provides operations whose execution time depends only on the public length
 * parameter, never on the data values. The implementation accumulates a difference via bitwise XOR
 * and OR over every byte in the range, then collapses the accumulator to a single equality decision
 * at the very end.
 *
 * <p>Usage discipline:
 *
 * <ul>
 *   <li>Use this for MAC / signature / authenticator tag verification.
 *   <li>Use this for any equality check where the right-hand side is a secret.
 *   <li>Do <em>not</em> use this for ordering decisions; the API intentionally returns only
 *       equality / non-equality, never less-than / greater-than.
 * </ul>
 */
public final class ConstantTime {

    private ConstantTime() {}

    /**
     * Returns {@code true} iff {@code a[aOffset .. aOffset+length]} equals {@code b[bOffset ..
     * bOffset+length]}, in time independent of where the first mismatch occurs.
     *
     * <p>The implementation always reads exactly {@code length} bytes from each array, ORs the
     * per-byte XOR differences into a single accumulator, and decides equality from that
     * accumulator. The branch on the final accumulator is unavoidable, but it depends only on the
     * length (a public parameter) and the equality bit (the secret), which is the standard
     * formulation in cryptographic literature.
     *
     * <p>The caller must ensure that both ranges are well-formed; out-of-bounds accesses will raise
     * {@link ArrayIndexOutOfBoundsException} as with any other JavaCard array access.
     */
    public static boolean equals(byte[] a, short aOffset, byte[] b, short bOffset, short length) {
        byte diff = 0;
        for (short i = 0; i < length; i++) {
            diff |= (byte) (a[(short) (aOffset + i)] ^ b[(short) (bOffset + i)]);
        }
        return diff == 0;
    }
}
