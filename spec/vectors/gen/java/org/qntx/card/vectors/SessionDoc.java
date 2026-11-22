// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * {@code session.json}: one fully deterministic OPEN exchange (spec/protocol.md §8.1–8.2) — fixed
 * host and card ephemerals, the certified identity of cert.json's card1 under ca1, the transcript
 * hash {@code TH}, the shared secret {@code Z}, the RFC 6979 session signature and the four record
 * keys — plus the response variants {@code Open.response} MUST reject (§8.1).
 */
final class SessionDoc {
    private static final byte[] LABEL = Vec.ascii("qntx-card/v1/session");
    private static final byte[] KDF_LABEL = Vec.ascii("qntx-card/v1/kdf-session");

    private SessionDoc() {}

    static Object document() {
        byte[] caPublic = Crypto.publicKey(CertDoc.CA1);
        byte[] a = Crypto.compress(Crypto.publicKey(CertDoc.CARD1));
        byte[] cert = Certificates.issue(CertDoc.CA1, a);

        BigInteger hostPrivate = Cards.scalar("session/host");
        BigInteger cardPrivate = Cards.scalar("session/card");
        byte[] hostEph = Crypto.publicKey(hostPrivate);
        byte[] cardEph = Crypto.publicKey(cardPrivate);

        byte[] th = Crypto.sha256(LABEL, hostEph, cardEph, a);
        byte[] zPoint = Crypto.multiply(cardPrivate, hostEph);
        byte[] z = Arrays.copyOfRange(zPoint, 1, 33);
        byte[] sig = Crypto.sign(CertDoc.CARD1, th);
        byte[] keys = Crypto.kdf(z, KDF_LABEL, th, 64);

        byte[] request = apdu(hostEph);
        byte[] response = response(cardEph, sig, cert);

        // each rejected response MUST make Open.response throw (§8.1 host checks)
        BigInteger card2 = CertDoc.CARD2;
        byte[] a2 = Crypto.compress(Crypto.publicKey(card2));
        byte[] cert2 = Certificates.issue(CertDoc.CA1, a2);
        byte[] certUnderCa2 = Certificates.issue(CertDoc.CA2, a);
        byte[] flippedEph = cardEph.clone();
        flippedEph[33] ^= 1;
        List<Object> rejected =
                List.of(
                        reject(
                                "other-certified-key",
                                response(cardEph, Crypto.sign(card2, th), cert)),
                        reject(
                                "other-cert-signature-over-this-A",
                                response(cardEph, Crypto.sign(card2, th), cert2)),
                        reject("cert-under-other-ca", response(cardEph, sig, certUnderCa2)),
                        reject("flipped-cardEph", response(flippedEph, sig, cert)));

        return Vec.object(
                "label", Vec.hex(LABEL),
                "kdfLabel", Vec.hex(KDF_LABEL),
                "ca", Vec.hex(caPublic),
                "identity",
                        Vec.object(
                                "private", Vec.hex(Vec.scalar(CertDoc.CARD1)),
                                "compressed", Vec.hex(a)),
                "cert", Vec.hex(cert),
                "hostPrivate", Vec.hex(Vec.scalar(hostPrivate)),
                "hostEph", Vec.hex(hostEph),
                "cardPrivate", Vec.hex(Vec.scalar(cardPrivate)),
                "cardEph", Vec.hex(cardEph),
                "th", Vec.hex(th),
                "z", Vec.hex(z),
                "sig", Vec.hex(sig),
                "kce", Vec.hex(Arrays.copyOfRange(keys, 0, 16)),
                "kcm", Vec.hex(Arrays.copyOfRange(keys, 16, 32)),
                "kre", Vec.hex(Arrays.copyOfRange(keys, 32, 48)),
                "krm", Vec.hex(Arrays.copyOfRange(keys, 48, 64)),
                "request", Vec.hex(request),
                "response", Vec.hex(response),
                "rejected", rejected);
    }

    /** {@code 80 10 00 00 41 ‖ hostEph ‖ 00} (§8.1). */
    private static byte[] apdu(byte[] hostEph) {
        byte[] out = new byte[5 + 65 + 1];
        out[0] = (byte) 0x80;
        out[1] = 0x10;
        out[4] = 65;
        System.arraycopy(hostEph, 0, out, 5, 65);
        return out;
    }

    /** {@code cardEph(65) ‖ sig(64) ‖ cert(97) ‖ 9000} (§8.1). */
    private static byte[] response(byte[] cardEph, byte[] sig, byte[] cert) {
        byte[] out = new byte[65 + 64 + 97 + 2];
        System.arraycopy(cardEph, 0, out, 0, 65);
        System.arraycopy(sig, 0, out, 65, 64);
        System.arraycopy(cert, 0, out, 129, 97);
        out[226] = (byte) 0x90;
        return out;
    }

    private static Object reject(String name, byte[] response) {
        return Vec.object("name", name, "response", Vec.hex(response));
    }
}
