// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * {@link Transfer} command encoders and response decoders against BouncyCastle-made cards: the
 * identities, link keys and signatures are produced with {@link Crypto}, never by the applet.
 */
final class TransferTest {
    private static final SecureRandom RND = new SecureRandom();

    private static BigInteger scalar() {
        BigInteger s;
        do {
            s = new BigInteger(256, RND);
        } while (s.signum() == 0 || s.compareTo(Crypto.N) >= 0);
        return s;
    }

    /** A made-up card: identity scalar, compressed {@code A} and certificate. */
    private static BigInteger idPrivate = scalar();

    private static final byte[] A = Crypto.compress(Crypto.publicKey(idPrivate));
    private static final byte[] CERT = Certificates.issue(new BigInteger("7"), A);

    private static byte[] offerResponse(BigInteger linkPrivate) {
        byte[] lk = Crypto.publicKey(linkPrivate);
        byte[] sig = Crypto.sign(idPrivate, Crypto.sha256(concat(Transfer.LABEL_OFFER, lk)));
        return concat(lk, sig);
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    @Test
    void encodersProduceTheSpecLayout() {
        assertEquals(0, Transfer.offer().length);
        byte[] cert = new byte[97];
        byte[] offer = new byte[129];
        byte[] head = new byte[129];
        byte[] data = Transfer.export0(cert, offer);
        assertEquals(226, data.length);
        assertArrayEquals(cert, Arrays.copyOf(data, 97));
        assertArrayEquals(offer, Arrays.copyOfRange(data, 97, 226));
        data = Transfer.import0(cert, head);
        assertEquals(226, data.length);
        assertArrayEquals(head, Arrays.copyOfRange(data, 97, 226));
        byte[] h = new byte[32];
        assertArrayEquals(h, Transfer.export1(h));
        byte[] payload = new byte[176];
        assertArrayEquals(payload, Transfer.import1(payload));
        assertThrows(IllegalArgumentException.class, () -> Transfer.import1(new byte[159]));
        assertThrows(IllegalArgumentException.class, () -> Transfer.export1(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> Transfer.export0(new byte[96], offer));
    }

    @Test
    void decodeOfferVerifiesTheSignature() throws Exception {
        byte[] resp = offerResponse(scalar());
        Transfer.Offer o = Transfer.decodeOffer(resp, CERT);
        assertArrayEquals(Arrays.copyOf(resp, 65), o.lk());
        assertArrayEquals(Arrays.copyOfRange(resp, 65, 129), o.sig());
    }

    @Test
    void decodeOfferRejectsTampering() {
        byte[] resp = offerResponse(scalar());
        byte[] bad = resp.clone();
        bad[128] ^= 1;
        assertThrows(CardNotGenuineException.class, () -> Transfer.decodeOffer(bad, CERT));
        byte[] shortResp = Arrays.copyOf(resp, 128);
        assertThrows(CardNotGenuineException.class, () -> Transfer.decodeOffer(shortResp, CERT));
        // a signature under another identity
        byte[] lk = Crypto.publicKey(scalar());
        byte[] foreignSig = Crypto.sign(scalar(), Crypto.sha256(concat(Transfer.LABEL_OFFER, lk)));
        assertThrows(
                CardNotGenuineException.class,
                () -> Transfer.decodeOffer(concat(lk, foreignSig), CERT));
    }

    @Test
    void decodeExportHeadVerifiesTheTranscript() throws Exception {
        byte[] e = Crypto.publicKey(scalar());
        byte[] lkT = Crypto.publicKey(scalar());
        byte[] m = concat(Transfer.LABEL_EXPORT, A, Arrays.copyOf(CERT, 33), lkT, e);
        byte[] sig = Crypto.sign(idPrivate, Crypto.sha256(m));
        Transfer.ExportHead head = Transfer.decodeExportHead(concat(e, sig), CERT, CERT, lkT);
        assertArrayEquals(e, head.e());
        assertArrayEquals(sig, head.sig());
    }

    @Test
    void decodeExportHeadRejectsAWrongMessage() {
        byte[] e = Crypto.publicKey(scalar());
        byte[] lkT = Crypto.publicKey(scalar());
        byte[] otherLk = Crypto.publicKey(scalar());
        // signed for a different link key than the one presented
        byte[] m = concat(Transfer.LABEL_EXPORT, A, Arrays.copyOf(CERT, 33), otherLk, e);
        byte[] sig = Crypto.sign(idPrivate, Crypto.sha256(m));
        assertThrows(
                CardNotGenuineException.class,
                () -> Transfer.decodeExportHead(concat(e, sig), CERT, CERT, lkT));
    }

    @Test
    void decodeExportPayloadChecksLength() throws Exception {
        byte[] resp = new byte[176];
        RND.nextBytes(resp);
        Transfer.ExportPayload p = Transfer.decodeExportPayload(resp);
        assertArrayEquals(Arrays.copyOf(resp, 160), p.ct());
        assertArrayEquals(Arrays.copyOfRange(resp, 160, 176), p.tag());
        assertEquals(144, Transfer.decodeExportPayload(new byte[160]).ct().length);
        assertThrows(
                CardNotGenuineException.class, () -> Transfer.decodeExportPayload(new byte[159]));
        assertThrows(
                CardNotGenuineException.class, () -> Transfer.decodeExportPayload(new byte[177]));
    }
}
