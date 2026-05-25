/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet.testkit;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import social.meowl.applet.Constants;
import social.meowl.applet.cardclient.CardClient;
import social.meowl.applet.sc.KdfCmacHost;

/**
 * Host-side reference Secure Channel client for end-to-end test suites. Mirrors MEAP-2 byte-for-
 * byte: ECDH on secp256k1 → AES-CMAC-128 KBKDF → AES-256-CBC + AES-CMAC-128 record layer.
 *
 * <p>Open a session with {@link #open(CardClient)}; thereafter use {@link #sendInnerExpectOk} for
 * happy-path inner APDUs and {@link #sendInner} when the test needs to inspect a non-{@code 9000}
 * status word. The implementation deliberately re-derives every primitive on top of BouncyCastle so
 * tests do not depend on the production {@code tools/proto/SecureChannelClient} — keeping host and
 * card sides reachable through independent code paths preserves the byte-for-byte cross-check value
 * of these suites.
 */
public final class HostSession {

    private final CardClient card;
    private final byte[] kEnc;
    private final byte[] kMac;
    private long counter;

    private HostSession(CardClient card, byte[] kEnc, byte[] kMac) {
        this.card = card;
        this.kEnc = kEnc;
        this.kMac = kMac;
        this.counter = 0L;
    }

    /**
     * Performs the INIT_SECURE_CHANNEL handshake and derives the session keys. Does <em>not</em>
     * verify the card's signature over {@code [card_eph_pub || client_eph_pub]} — suites that need
     * to assert handshake integrity (notably {@code SecureChannelTest}) keep their own bespoke
     * Session helper for that reason.
     */
    public static HostSession open(CardClient card) {
        BigInteger clientPriv;
        do {
            byte[] cand = new byte[32];
            TestConstants.RANDOM.nextBytes(cand);
            clientPriv = new BigInteger(1, cand);
        } while (clientPriv.signum() == 0
                || clientPriv.compareTo(TestConstants.SECP256K1.getN()) >= 0);
        ECPoint clientPub = TestConstants.SECP256K1.getG().multiply(clientPriv).normalize();
        byte[] clientPubEnc = clientPub.getEncoded(false);

        ResponseAPDU resp =
                card.transmit(
                        new CommandAPDU(
                                TestConstants.CLA,
                                TestConstants.INS_INIT_SC,
                                0x00,
                                0x00,
                                clientPubEnc));
        if (resp.getSW() != 0x9000) {
            throw new IllegalStateException(
                    "INIT_SECURE_CHANNEL failed: SW=" + Integer.toHexString(resp.getSW()));
        }
        byte[] body = resp.getData();
        byte[] cardEphPub = Arrays.copyOfRange(body, 0, Constants.EC_POINT_UNCOMPRESSED_LEN);

        ECPoint cardPub = TestConstants.SECP256K1.getCurve().decodePoint(cardEphPub).normalize();
        byte[] sharedX =
                bigIntToFixed(
                        cardPub.multiply(clientPriv).normalize().getAffineXCoord().toBigInteger(),
                        32);
        byte[] clientX = Arrays.copyOfRange(clientPubEnc, 1, 33);
        byte[] cardX = Arrays.copyOfRange(cardEphPub, 1, 33);
        byte[] salt = concat(clientX, cardX);
        byte[] prk = KdfCmacHost.extract(salt, sharedX);
        byte[] okm = KdfCmacHost.expand(prk, TestConstants.KDF_INFO, 32 + 16 + 16);
        return new HostSession(
                card, Arrays.copyOfRange(okm, 0, 32), Arrays.copyOfRange(okm, 32, 48));
    }

    /** Wraps {@code plaintext} into an {@code OPEN_SECURE_CHANNEL} envelope with monotonic IV. */
    public byte[] encryptForCard(byte[] plaintext) {
        counter++;
        byte[] iv = ivFromCounter(counter);
        byte[] padded = pkcs5Pad(plaintext);
        byte[] ct;
        try {
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kEnc, "AES"), new IvParameterSpec(iv));
            ct = c.doFinal(padded);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-CBC encrypt failed", e);
        }

        int lc = iv.length + ct.length + Constants.SC_MAC_LEN;
        byte[] header = {
            (byte) TestConstants.CLA, (byte) TestConstants.INS_OPEN_SC, 0x00, 0x00, (byte) lc
        };
        byte[] tag = aesCmac(kMac, header, iv, ct);
        return concat3(iv, ct, tag);
    }

    /** Verifies the card's outbound MAC and returns the decrypted inner payload. */
    public byte[] decryptFromCard(byte[] envelope) {
        byte[] iv = Arrays.copyOfRange(envelope, 0, Constants.SC_BLOCK_LEN);
        byte[] ct =
                Arrays.copyOfRange(
                        envelope, Constants.SC_BLOCK_LEN, envelope.length - Constants.SC_MAC_LEN);
        byte[] tag =
                Arrays.copyOfRange(
                        envelope, envelope.length - Constants.SC_MAC_LEN, envelope.length);
        byte[] expected = aesCmac(kMac, new byte[] {(byte) 0xFF}, iv, ct);
        if (!Arrays.equals(expected, tag)) {
            throw new IllegalStateException("outbound MAC mismatch");
        }
        try {
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kEnc, "AES"), new IvParameterSpec(iv));
            byte[] padded = c.doFinal(ct);
            int padLen = padded[padded.length - 1] & 0xFF;
            return Arrays.copyOfRange(padded, 0, padded.length - padLen);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-CBC decrypt failed", e);
        }
    }

    /**
     * Sends an inner APDU and returns the raw {@link ResponseAPDU}. Use this overload when a test
     * needs to inspect a non-{@code 9000} status word; otherwise prefer {@link #sendInnerExpectOk}.
     */
    public ResponseAPDU sendInner(byte ins, byte p1, byte p2, byte[] data) {
        byte[] inner = innerApdu(ins, p1, p2, data);
        byte[] envelope = encryptForCard(inner);
        return card.transmit(
                new CommandAPDU(
                        TestConstants.CLA, TestConstants.INS_OPEN_SC, 0x00, 0x00, envelope));
    }

    /** Sends an inner APDU, asserts {@code SW=9000}, and returns the decrypted response payload. */
    public byte[] sendInnerExpectOk(byte ins, byte p1, byte p2, byte[] data) {
        ResponseAPDU r = sendInner(ins, p1, p2, data);
        if (r.getSW() != 0x9000) {
            throw new IllegalStateException(
                    "inner INS 0x"
                            + Integer.toHexString(ins & 0xFF)
                            + " expected 9000 but got SW="
                            + Integer.toHexString(r.getSW()));
        }
        return decryptFromCard(r.getData());
    }

    private static byte[] innerApdu(byte ins, byte p1, byte p2, byte[] data) {
        byte[] out = new byte[5 + data.length];
        out[0] = Constants.CLA_MEOWL;
        out[1] = ins;
        out[2] = p1;
        out[3] = p2;
        out[4] = (byte) data.length;
        System.arraycopy(data, 0, out, 5, data.length);
        return out;
    }

    private static byte[] ivFromCounter(long counter) {
        byte[] iv = new byte[Constants.SC_BLOCK_LEN];
        for (int i = 0; i < 8; i++) {
            iv[Constants.SC_BLOCK_LEN - 1 - i] = (byte) ((counter >>> (8 * i)) & 0xFF);
        }
        return iv;
    }

    private static byte[] aesCmac(byte[] key, byte[]... parts) {
        try {
            Mac m = Mac.getInstance("AESCMAC", BouncyCastleProvider.PROVIDER_NAME);
            m.init(new SecretKeySpec(key, "AES"));
            for (byte[] p : parts) m.update(p);
            return m.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-CMAC-128 unavailable", e);
        }
    }

    private static byte[] pkcs5Pad(byte[] in) {
        int pad = Constants.SC_BLOCK_LEN - (in.length % Constants.SC_BLOCK_LEN);
        byte[] out = Arrays.copyOf(in, in.length + pad);
        for (int i = in.length; i < out.length; i++) out[i] = (byte) pad;
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] concat3(byte[] a, byte[] b, byte[] c) {
        byte[] out = new byte[a.length + b.length + c.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        System.arraycopy(c, 0, out, a.length + b.length, c.length);
        return out;
    }

    private static byte[] bigIntToFixed(BigInteger n, int len) {
        byte[] raw = n.toByteArray();
        if (raw.length == len) return raw;
        byte[] out = new byte[len];
        if (raw.length > len) System.arraycopy(raw, raw.length - len, out, 0, len);
        else System.arraycopy(raw, 0, out, len - raw.length, raw.length);
        return out;
    }
}
