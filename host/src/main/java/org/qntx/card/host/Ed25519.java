// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

/**
 * Host-side helpers for {@code SIGN_ED25519} (spec/protocol.md §9.11, §12.3): assembling the
 * challenge stream the card hashes, joining the two protocol outputs into an RFC 8032 signature and
 * verifying it under the encoded Ed25519 public key.
 */
public final class Ed25519 {
    private Ed25519() {}

    /**
     * The challenge stream {@code encode(R) ‖ encode(A) ‖ M} the card hashes over {@code begin ‖
     * update* ‖ finish} (§12.3); the host sends only {@code M}, the card prepends its own {@code
     * encode(R)} and {@code encode(A)}.
     */
    public static byte[] stream(byte[] encodedR, byte[] encodedA, byte[] message) {
        byte[] out = new byte[encodedR.length + encodedA.length + message.length];
        System.arraycopy(encodedR, 0, out, 0, encodedR.length);
        System.arraycopy(encodedA, 0, out, encodedR.length, encodedA.length);
        System.arraycopy(message, 0, out, encodedR.length + encodedA.length, message.length);
        return out;
    }

    /** The RFC 8032 signature {@code encode(R) ‖ le32(S)} of the two card outputs (§12.3). */
    public static byte[] signature(byte[] encodedR, byte[] sLe32) {
        byte[] out = new byte[encodedR.length + sLe32.length];
        System.arraycopy(encodedR, 0, out, 0, encodedR.length);
        System.arraycopy(sLe32, 0, out, encodedR.length, sLe32.length);
        return out;
    }

    /**
     * RFC 8032 verification of the 64-byte {@code encode(R) ‖ le32(S)} signature under the 32-byte
     * encoded public key {@code encodedA}; {@code false} on every failure (§10.4).
     */
    public static boolean verify(byte[] encodedA, byte[] message, byte[] signature) {
        if (encodedA == null
                || encodedA.length != 32
                || signature == null
                || signature.length != 64) {
            return false;
        }
        try {
            return org.bouncycastle.math.ec.rfc8032.Ed25519.verify(
                    signature, 0, encodedA, 0, message, 0, message.length);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
