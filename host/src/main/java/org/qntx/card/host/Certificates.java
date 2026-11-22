// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The certificate format of spec/protocol.md §5.2: {@code cert(97) = A(33) ‖ r(32) ‖ s(32)} where
 * {@code (r, s) = Sign(caPrivate, "qntx-card/v1/cert" ‖ A)}.
 */
public final class Certificates {
    /** The §5.2 message label, ASCII without terminator. */
    public static final byte[] LABEL_CERT = "qntx-card/v1/cert".getBytes(StandardCharsets.US_ASCII);

    private Certificates() {}

    /** Issues {@code cert} for the compressed identity key {@code a} under {@code caPrivate}. */
    public static byte[] issue(BigInteger caPrivate, byte[] a) {
        byte[] rs = Crypto.sign(caPrivate, Crypto.sha256(LABEL_CERT, a));
        byte[] cert = new byte[97];
        System.arraycopy(a, 0, cert, 0, 33);
        System.arraycopy(rs, 0, cert, 33, 64);
        return cert;
    }

    /**
     * {@code Verify(anchor, "qntx-card/v1/cert" ‖ A, r ‖ s)}: {@code anchor} is the CA public key
     * uncompressed (65 bytes); false when the certificate is malformed, {@code r}/{@code s} are out
     * of range or the signature does not verify.
     */
    public static boolean verify(byte[] anchor, byte[] cert) {
        if (anchor == null || anchor.length != 65 || cert == null || cert.length != 97) {
            return false;
        }
        byte[] a = Arrays.copyOf(cert, 33);
        byte[] rs = Arrays.copyOfRange(cert, 33, 97);
        return Crypto.verify(anchor, Crypto.sha256(LABEL_CERT, a), rs);
    }
}
