/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

/**
 * Constant-time byte-array equality. Use this for MAC, signature and authenticator tag
 * verification (or any equality check where one side is secret); {@link
 * javacard.framework.Util#arrayCompare} is left-to-right ternary and leaks the position of the
 * first mismatch through timing.
 */
public final class ConstantTime {

    private ConstantTime() {}

    /**
     * Returns {@code true} iff {@code a[aOffset .. aOffset+length]} equals {@code b[bOffset ..
     * bOffset+length]}, in time independent of the data. Reads exactly {@code length} bytes from
     * each array, ORs the per-byte XOR differences into an accumulator, then collapses to one
     * equality decision.
     */
    public static boolean equals(byte[] a, short aOffset, byte[] b, short bOffset, short length) {
        byte diff = 0;
        for (short i = 0; i < length; i++) {
            diff |= (byte) (a[(short) (aOffset + i)] ^ b[(short) (bOffset + i)]);
        }
        return diff == 0;
    }
}
