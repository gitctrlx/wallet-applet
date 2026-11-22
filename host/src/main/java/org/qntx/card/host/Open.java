// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

/**
 * The host side of OPEN (§8.1): a fresh ephemeral key, the request APDU and the checks of the
 * 226-byte response — certificate against the trusted anchors, then the session signature — before
 * the shared keys are derived. Any failure throws {@link CardNotGenuineException}.
 */
public final class Open {
    /** The §8.1 session signature label, ASCII without terminator. */
    public static final byte[] LABEL_SESSION =
            "qntx-card/v1/session".getBytes(StandardCharsets.US_ASCII);

    /** The §8.1 key-derivation label, ASCII without terminator. */
    public static final byte[] LABEL_KDF_SESSION =
            "qntx-card/v1/kdf-session".getBytes(StandardCharsets.US_ASCII);

    private Open() {}

    /** An OPEN request: the command APDU and the ephemeral private scalar (32 bytes). */
    public record Request(byte[] apdu, byte[] secret) {}

    /** Builds {@code 80 10 00 00 41 ‖ hostEph ‖ 00} with a fresh scalar in {@code [1, n−1]}. */
    public static Request request(SecureRandom random) {
        BigInteger x;
        do {
            x = new BigInteger(256, random);
        } while (x.signum() <= 0 || x.compareTo(Crypto.N) >= 0);
        byte[] secret = new byte[32];
        byte[] b = x.toByteArray();
        System.arraycopy(
                b,
                Math.max(0, b.length - 32),
                secret,
                Math.max(0, 32 - b.length),
                Math.min(b.length, 32));
        byte[] hostEph = Crypto.publicKey(x);
        byte[] apdu = new byte[5 + 65 + 1];
        apdu[0] = (byte) 0x80;
        apdu[1] = 0x10;
        apdu[4] = 65;
        System.arraycopy(hostEph, 0, apdu, 5, 65);
        return new Request(apdu, secret);
    }

    /**
     * Checks the card's OPEN response and derives the session: outer {@code 9000}, exactly 226
     * bytes, {@code cert} under one of {@code anchors} (§5.2), {@code Verify(A, "qntx-card/v1/
     * session" ‖ hostEph ‖ cardEph ‖ A, sig)}, then {@code Z} and the KDF keys. {@code secret} is
     * the ephemeral scalar of {@code request} and is overwritten.
     */
    public static Session response(
            byte[] secret, byte[] request, byte[] rapdu, List<byte[]> anchors)
            throws CardNotGenuineException {
        if (rapdu.length < 2
                || ((rapdu[rapdu.length - 2] & 0xFF) << 8 | rapdu[rapdu.length - 1] & 0xFF)
                        != 0x9000) {
            throw new CardNotGenuineException("OPEN status is not 9000");
        }
        if (rapdu.length != 228) {
            throw new CardNotGenuineException("OPEN response must be 226 bytes");
        }
        byte[] cardEph = Arrays.copyOf(rapdu, 65);
        byte[] sig = Arrays.copyOfRange(rapdu, 65, 129);
        byte[] cert = Arrays.copyOfRange(rapdu, 129, 226);
        boolean certified = false;
        for (byte[] anchor : anchors) {
            if (Certificates.verify(anchor, cert)) {
                certified = true;
            }
        }
        if (!certified) {
            throw new CardNotGenuineException("certificate under no trusted anchor");
        }
        byte[] a = Arrays.copyOf(cert, 33);
        byte[] hostEph = Arrays.copyOfRange(request, 5, 70);
        byte[] th = Crypto.sha256(LABEL_SESSION, hostEph, cardEph, a);
        byte[] aPoint;
        try {
            aPoint = Crypto.decompress(a);
        } catch (IllegalArgumentException e) {
            throw new CardNotGenuineException("identity is not a curve point");
        }
        if (!Crypto.verify(aPoint, th, sig)) {
            throw new CardNotGenuineException("session signature invalid");
        }
        byte[] zPoint;
        try {
            zPoint = Crypto.multiply(new BigInteger(1, secret), cardEph);
        } catch (IllegalArgumentException e) {
            throw new CardNotGenuineException("cardEph is not a curve point");
        }
        if (zPoint == null) {
            throw new CardNotGenuineException("shared point at infinity");
        }
        byte[] z = Arrays.copyOfRange(zPoint, 1, 33);
        byte[] keys = Crypto.kdf(z, LABEL_KDF_SESSION, th, 64);
        Session session =
                new Session(
                        a,
                        cert,
                        Arrays.copyOfRange(keys, 0, 16),
                        Arrays.copyOfRange(keys, 16, 32),
                        Arrays.copyOfRange(keys, 32, 48),
                        Arrays.copyOfRange(keys, 48, 64),
                        0);
        Arrays.fill(keys, (byte) 0);
        Arrays.fill(z, (byte) 0);
        Arrays.fill(secret, (byte) 0);
        return session;
    }
}
