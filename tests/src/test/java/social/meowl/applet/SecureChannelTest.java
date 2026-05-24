/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import social.meowl.applet.cardclient.CardClient;
import social.meowl.applet.cardclient.CardClientFactory;

/**
 * End-to-end Secure Channel tests driving MeowlApplet through {@link CardClient}.
 *
 * <p>Verifies the entire handshake (ECDH + HKDF-SHA-256 + authentikey ECDSA signature) and the
 * envelope round-trip (encrypt, MAC, IV monotonicity, replay defense). Tagged {@code real-card}
 * because the simulator backend cannot install the post-Phase-1 applet.
 */
@Tag("real-card")
class SecureChannelTest {

    private static final byte[] APPLET_AID_BYTES = {
        (byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x01
    };

    private static final int CLA = Constants.CLA_MEOWL & 0xFF;
    private static final int INS_INIT_SC = Constants.INS_INIT_SECURE_CHANNEL & 0xFF;
    private static final int INS_OPEN_SC = Constants.INS_OPEN_SECURE_CHANNEL & 0xFF;
    private static final int INS_GET_AUTHENTIKEY = Constants.INS_GET_AUTHENTIKEY & 0xFF;

    private static final X9ECParameters SECP256K1 = CustomNamedCurves.getByName("secp256k1");
    private static final byte[] HKDF_INFO = "meowl-sc-v1".getBytes();

    private static final SecureRandom RANDOM = new SecureRandom();

    private CardClient card;

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() {
        card = CardClientFactory.create(APPLET_AID_BYTES);
    }

    @AfterEach
    void tearDown() {
        if (card != null) {
            card.close();
        }
    }

    @Test
    @DisplayName("handshake returns card ephemeral pubkey + authentikey-signed payload")
    void handshakeShape() {
        Session session = openSession();
        assertEquals(Constants.EC_POINT_UNCOMPRESSED_LEN, session.cardEphPub.length);
        assertEquals(0x04, session.cardEphPub[0] & 0xFF);
        assertTrue(session.signature.length > 0, "signature must be non-empty DER");
    }

    @Test
    @DisplayName("authentikey signature verifies over (cardEphPub || clientEphPub)")
    void authentikeySignatureVerifies() throws Exception {
        Session session = openSession();
        // Independently fetch the authentikey to verify the handshake signature against it.
        byte[] authentikeyPub = compressedAuthentikey();

        byte[] message = concat(session.cardEphPub, session.clientEphPub);
        boolean ok = EcdsaVerifier.verifySecp256k1(authentikeyPub, message, session.signature);
        assertTrue(ok, "authentikey ECDSA signature must verify");
    }

    @Test
    @DisplayName("envelope round-trip: inner EXPORT_PKI_PUBKEY returns the authentikey")
    void envelopeRoundTripExportPubkey() throws Exception {
        Session session = openSession();
        // Inner APDU: CLA INS P1 P2 LC = MEOWL EXPORT_PKI_PUBKEY 0 0 0 (no data).
        byte[] innerApdu =
                bytes(
                        Constants.CLA_MEOWL & 0xFF,
                        Constants.INS_EXPORT_PKI_PUBKEY & 0xFF,
                        0x00,
                        0x00,
                        0x00);
        byte[] envelope = session.encryptForCard(innerApdu);
        ResponseAPDU resp = transmit(INS_OPEN_SC, 0x00, 0x00, envelope);
        assertEquals(0x9000, resp.getSW(), "envelope must be accepted");
        byte[] decrypted = session.decryptFromCard(resp.getData());
        // Compare against the direct GET_AUTHENTIKEY response which is exposed outside the
        // Secure Channel — they must return the exact same 33-byte compressed point.
        byte[] direct = transmit(INS_GET_AUTHENTIKEY, 0x00, 0x00, null).getData();
        assertArrayEquals(direct, decrypted, "inner EXPORT_PKI_PUBKEY must equal GET_AUTHENTIKEY");
    }

    @Test
    @DisplayName("replay attack: re-sending the same envelope is rejected")
    void replayRejected() throws Exception {
        Session session = openSession();
        byte[] innerApdu =
                bytes(
                        Constants.CLA_MEOWL & 0xFF,
                        Constants.INS_EXPORT_PKI_PUBKEY & 0xFF,
                        0x00,
                        0x00,
                        0x00);
        byte[] envelope = session.encryptForCard(innerApdu);
        assertEquals(0x9000, transmit(INS_OPEN_SC, 0x00, 0x00, envelope).getSW());
        // Same IV → must trip the strictly-increasing check.
        ResponseAPDU replay = transmit(INS_OPEN_SC, 0x00, 0x00, envelope);
        assertEquals(Constants.SW_SECURE_CHANNEL_FAILED & 0xFFFF, replay.getSW());
    }

    @Test
    @DisplayName(
            "replay attack does NOT tear down the session: a follow-up legitimate envelope "
                    + "still succeeds with the existing keys")
    void replayDoesNotKillSession() throws Exception {
        // A stale-IV replay must be rejected (SW=6FB2) without disturbing the session keys.
        // Otherwise an attacker without K_mac could force a host re-handshake on every replayed
        // envelope — a free DoS lever. Session teardown is reserved for the post-MAC-failure
        // branch, which signals a genuine integrity event.
        Session session = openSession();
        byte[] innerApdu =
                bytes(
                        Constants.CLA_MEOWL & 0xFF,
                        Constants.INS_EXPORT_PKI_PUBKEY & 0xFF,
                        0x00,
                        0x00,
                        0x00);
        // 1. Send the first envelope — succeeds.
        byte[] env1 = session.encryptForCard(innerApdu);
        assertEquals(0x9000, transmit(INS_OPEN_SC, 0x00, 0x00, env1).getSW());

        // 2. Replay the same envelope — must fail with 6FB2 (stale IV).
        ResponseAPDU replay = transmit(INS_OPEN_SC, 0x00, 0x00, env1);
        assertEquals(Constants.SW_SECURE_CHANNEL_FAILED & 0xFFFF, replay.getSW());

        // 3. Build a fresh envelope under the SAME session keys — must succeed. If the replay
        //    above had reset the card-side keys, the MAC of this fresh envelope would not match
        //    and the card would return 6FB1 (SW_SECURE_CHANNEL_REQUIRED).
        byte[] env2 = session.encryptForCard(innerApdu);
        ResponseAPDU resp = transmit(INS_OPEN_SC, 0x00, 0x00, env2);
        assertEquals(0x9000, resp.getSW(), "session must survive an unauthenticated replay");
    }

    @Test
    @DisplayName("tampered MAC: any 1-bit flip in the ciphertext invalidates the envelope")
    void tamperedMacRejected() throws Exception {
        Session session = openSession();
        byte[] innerApdu =
                bytes(
                        Constants.CLA_MEOWL & 0xFF,
                        Constants.INS_EXPORT_PKI_PUBKEY & 0xFF,
                        0x00,
                        0x00,
                        0x00);
        byte[] envelope = session.encryptForCard(innerApdu);
        // Flip a bit somewhere in the ciphertext (not IV, not MAC).
        envelope[Constants.SC_BLOCK_LEN + 1] ^= (byte) 0x01;
        ResponseAPDU resp = transmit(INS_OPEN_SC, 0x00, 0x00, envelope);
        assertEquals(Constants.SW_SECURE_CHANNEL_FAILED & 0xFFFF, resp.getSW());
    }

    @Test
    @DisplayName("envelope before handshake: card returns SW_SECURE_CHANNEL_REQUIRED")
    void envelopeBeforeHandshake() {
        // We construct a clearly-invalid envelope; what matters is the card refuses to look at it.
        byte[] garbage =
                new byte[Constants.SC_BLOCK_LEN + Constants.SC_BLOCK_LEN + Constants.SC_MAC_LEN];
        ResponseAPDU resp = transmit(INS_OPEN_SC, 0x00, 0x00, garbage);
        assertEquals(Constants.SW_SECURE_CHANNEL_REQUIRED & 0xFFFF, resp.getSW());
    }

    @Test
    @DisplayName("handshake with non-0x04 prefix byte is rejected with 6FB2")
    void handshakeNonZeroFourPrefixIsCryptoFailure() {
        // 65-byte body of the right length but with a corrupted prefix: MEAP-2 §57 says this
        // must be reported as a cryptographic check failure (6FB2), not as a length error
        // (6700), since the length itself is well-formed and only the cryptographic structure
        // is wrong.
        byte[] body = new byte[Constants.EC_POINT_UNCOMPRESSED_LEN];
        body[0] = (byte) 0x02; // wrong prefix
        ResponseAPDU resp = transmit(INS_INIT_SC, 0x00, 0x00, body);
        assertEquals(Constants.SW_SECURE_CHANNEL_FAILED & 0xFFFF, resp.getSW());
    }

    @Test
    @DisplayName("handshake with wrong-length body is rejected with 6700 (length, not crypto)")
    void handshakeWrongLengthIsWrongLength() {
        // 60-byte body — too short for an uncompressed secp256k1 point: surfaces as 6700,
        // distinct from the crypto-failure path above.
        byte[] body = new byte[60];
        ResponseAPDU resp = transmit(INS_INIT_SC, 0x00, 0x00, body);
        assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, resp.getSW());
    }

    @Test
    @DisplayName("failed handshake clears the session and allows a fresh handshake")
    void failedHandshakeClearsSessionAndAllowsFreshHandshake() throws Exception {
        Session session = openSession();
        byte[] innerApdu =
                bytes(
                        Constants.CLA_MEOWL & 0xFF,
                        Constants.INS_EXPORT_PKI_PUBKEY & 0xFF,
                        0x00,
                        0x00,
                        0x00);
        assertEquals(
                0x9000,
                transmit(INS_OPEN_SC, 0x00, 0x00, session.encryptForCard(innerApdu)).getSW());

        byte[] invalidPoint = new byte[Constants.EC_POINT_UNCOMPRESSED_LEN];
        invalidPoint[0] = (byte) 0x04;
        ResponseAPDU failed = transmit(INS_INIT_SC, 0x00, 0x00, invalidPoint);
        assertEquals(Constants.SW_SECURE_CHANNEL_FAILED & 0xFFFF, failed.getSW());

        ResponseAPDU oldSession =
                transmit(INS_OPEN_SC, 0x00, 0x00, session.encryptForCard(innerApdu));
        assertEquals(Constants.SW_SECURE_CHANNEL_REQUIRED & 0xFFFF, oldSession.getSW());

        Session fresh = openSession();
        ResponseAPDU resp = transmit(INS_OPEN_SC, 0x00, 0x00, fresh.encryptForCard(innerApdu));
        assertEquals(0x9000, resp.getSW());
    }

    @Test
    @DisplayName(
            "envelope with stale IV and garbage MAC is rejected with 6FB2 without "
                    + "MAC computation")
    void replayBeforeMacCheck() throws Exception {
        Session session = openSession();
        byte[] innerApdu =
                bytes(
                        Constants.CLA_MEOWL & 0xFF,
                        Constants.INS_EXPORT_PKI_PUBKEY & 0xFF,
                        0x00,
                        0x00,
                        0x00);
        byte[] envelope = session.encryptForCard(innerApdu);
        // First envelope must succeed.
        assertEquals(0x9000, transmit(INS_OPEN_SC, 0x00, 0x00, envelope).getSW());

        // Replay the IV but with a corrupted MAC. The card must reject on the IV check before
        // it ever touches HMAC, so the bogus MAC is irrelevant — the SW must still be 6FB2.
        envelope[envelope.length - 1] ^= (byte) 0xAA;
        ResponseAPDU resp = transmit(INS_OPEN_SC, 0x00, 0x00, envelope);
        assertEquals(Constants.SW_SECURE_CHANNEL_FAILED & 0xFFFF, resp.getSW());
    }

    @Test
    @DisplayName("KDF vector pinned in MEAP-2 §Test Vectors matches the host-side HKDF reference")
    void kdfVectorMatchesPinnedExpectation() {
        byte[] clientX = filled((byte) 0x11, 32);
        byte[] cardX = filled((byte) 0x22, 32);
        byte[] sharedX = filled((byte) 0x33, 32);
        byte[] salt = concat(clientX, cardX);
        byte[] prk = HkdfSha256.extract(salt, sharedX);
        byte[] okm = HkdfSha256.expand(prk, HKDF_INFO, 32 + 32 + 16);

        assertEquals(
                "27d5c053aba7808dccba40fc66bfa0094129483e592db687e7345ec0550da58e",
                hex(prk),
                "PRK must match the value pinned in MEAP-2 §Test Vectors §KDF vector");
        assertEquals(
                "6189c1be9f1bb2feb34f38887be5e37f8360d16ba16f845cba9827dc6e8d1d3c",
                hex(Arrays.copyOfRange(okm, 0, 32)),
                "K_enc must match MEAP-2 §Test Vectors §KDF vector");
        assertEquals(
                "e22e70e0bc34d1e073d444dacc8f3065195571aef13ff7232387c8cf70432317",
                hex(Arrays.copyOfRange(okm, 32, 64)),
                "K_mac must match MEAP-2 §Test Vectors §KDF vector");
        assertEquals(
                "215d786fc0934b749621541e7203add4",
                hex(Arrays.copyOfRange(okm, 64, 80)),
                "IV_base must match MEAP-2 §Test Vectors §KDF vector");
    }

    @Test
    @DisplayName("two consecutive envelopes succeed with monotonically increasing IVs")
    void twoEnvelopesMonotonicIv() throws Exception {
        Session session = openSession();
        byte[] innerApdu =
                bytes(
                        Constants.CLA_MEOWL & 0xFF,
                        Constants.INS_EXPORT_PKI_PUBKEY & 0xFF,
                        0x00,
                        0x00,
                        0x00);
        ResponseAPDU first = transmit(INS_OPEN_SC, 0x00, 0x00, session.encryptForCard(innerApdu));
        ResponseAPDU second = transmit(INS_OPEN_SC, 0x00, 0x00, session.encryptForCard(innerApdu));
        assertEquals(0x9000, first.getSW());
        assertEquals(0x9000, second.getSW());
        // Sanity: outbound IVs from the card must differ between the two responses.
        byte[] iv1 = Arrays.copyOfRange(first.getData(), 0, Constants.SC_BLOCK_LEN);
        byte[] iv2 = Arrays.copyOfRange(second.getData(), 0, Constants.SC_BLOCK_LEN);
        assertNotEquals(hex(iv1), hex(iv2));
    }

    private byte[] compressedAuthentikey() {
        ResponseAPDU resp = transmit(INS_GET_AUTHENTIKEY, 0x00, 0x00, null);
        assertEquals(0x9000, resp.getSW());
        return resp.getData();
    }

    private Session openSession() {
        // 1. Generate a client ephemeral keypair on secp256k1.
        BigInteger clientPriv;
        ECPoint clientPub;
        do {
            byte[] candidate = new byte[32];
            RANDOM.nextBytes(candidate);
            clientPriv = new BigInteger(1, candidate);
        } while (clientPriv.signum() == 0 || clientPriv.compareTo(SECP256K1.getN()) >= 0);
        clientPub = SECP256K1.getG().multiply(clientPriv).normalize();
        byte[] clientPubEnc = clientPub.getEncoded(false); // 0x04 || x || y

        // 2. Send INIT_SECURE_CHANNEL.
        ResponseAPDU resp = transmit(INS_INIT_SC, 0x00, 0x00, clientPubEnc);
        assertEquals(0x9000, resp.getSW(), "handshake must succeed");
        byte[] body = resp.getData();
        byte[] cardEphPub = Arrays.copyOfRange(body, 0, Constants.EC_POINT_UNCOMPRESSED_LEN);
        short sigLen =
                (short)
                        (((body[Constants.EC_POINT_UNCOMPRESSED_LEN] & 0xFF) << 8)
                                | (body[Constants.EC_POINT_UNCOMPRESSED_LEN + 1] & 0xFF));
        byte[] signature =
                Arrays.copyOfRange(
                        body,
                        Constants.EC_POINT_UNCOMPRESSED_LEN + 2,
                        Constants.EC_POINT_UNCOMPRESSED_LEN + 2 + sigLen);

        // 3. Derive shared secret on the host side.
        ECPoint cardPub = SECP256K1.getCurve().decodePoint(cardEphPub).normalize();
        ECPoint sharedPoint = cardPub.multiply(clientPriv).normalize();
        byte[] sharedX = bigIntToFixed(sharedPoint.getAffineXCoord().toBigInteger(), 32);
        byte[] clientX = Arrays.copyOfRange(clientPubEnc, 1, 33);
        byte[] cardX = Arrays.copyOfRange(cardEphPub, 1, 33);
        byte[] salt = concat(clientX, cardX);
        byte[] prk = HkdfSha256.extract(salt, sharedX);
        byte[] okm = HkdfSha256.expand(prk, HKDF_INFO, 32 + 32 + 16);
        byte[] kEnc = Arrays.copyOfRange(okm, 0, 32);
        byte[] kMac = Arrays.copyOfRange(okm, 32, 64);
        byte[] ivBase = Arrays.copyOfRange(okm, 64, 80);

        return new Session(clientPubEnc, cardEphPub, signature, kEnc, kMac, ivBase);
    }

    private ResponseAPDU transmit(int ins, int p1, int p2, byte[] data) {
        CommandAPDU cmd =
                data == null
                        ? new CommandAPDU(CLA, ins, p1, p2)
                        : new CommandAPDU(CLA, ins, p1, p2, data);
        return card.transmit(cmd);
    }

    private static byte[] bytes(int... ints) {
        byte[] out = new byte[ints.length];
        for (int i = 0; i < ints.length; i++) {
            out[i] = (byte) ints[i];
        }
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] filled(byte value, int length) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }

    private static byte[] bigIntToFixed(BigInteger n, int len) {
        byte[] raw = n.toByteArray();
        if (raw.length == len) {
            return raw;
        }
        byte[] out = new byte[len];
        if (raw.length > len) {
            System.arraycopy(raw, raw.length - len, out, 0, len);
        } else {
            System.arraycopy(raw, 0, out, len - raw.length, raw.length);
        }
        return out;
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /** Per-session client state derived from the handshake. */
    private static final class Session {
        final byte[] clientEphPub;
        final byte[] cardEphPub;
        final byte[] signature;
        final byte[] kEnc;
        final byte[] kMac;
        final byte[] ivBase;
        long inboundCounter;
        long outboundCounter;

        Session(
                byte[] clientEphPub,
                byte[] cardEphPub,
                byte[] signature,
                byte[] kEnc,
                byte[] kMac,
                byte[] ivBase) {
            this.clientEphPub = clientEphPub;
            this.cardEphPub = cardEphPub;
            this.signature = signature;
            this.kEnc = kEnc;
            this.kMac = kMac;
            this.ivBase = ivBase;
            this.inboundCounter = 0L;
            this.outboundCounter = 0L;
        }

        byte[] encryptForCard(byte[] plaintext) throws Exception {
            inboundCounter++;
            byte[] iv = ivFromCounter(inboundCounter);
            byte[] padded = pkcs5Pad(plaintext);
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(
                    Cipher.ENCRYPT_MODE, new SecretKeySpec(kEnc, "AES"), new IvParameterSpec(iv));
            byte[] ct = cipher.doFinal(padded);

            // MAC = HMAC-SHA256(K_mac, [CLA INS P1 P2 LC] ‖ IV ‖ ct)[0..16].
            int lc = iv.length + ct.length + Constants.SC_MAC_LEN;
            byte[] header = {(byte) CLA, (byte) INS_OPEN_SC, 0x00, 0x00, (byte) lc};
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(kMac, "HmacSHA256"));
            mac.update(header);
            mac.update(iv);
            mac.update(ct);
            byte[] fullTag = mac.doFinal();
            byte[] tag = Arrays.copyOf(fullTag, Constants.SC_MAC_LEN);

            return concat(concat(iv, ct), tag);
        }

        byte[] decryptFromCard(byte[] envelope) throws Exception {
            byte[] iv = Arrays.copyOfRange(envelope, 0, Constants.SC_BLOCK_LEN);
            byte[] ct =
                    Arrays.copyOfRange(
                            envelope,
                            Constants.SC_BLOCK_LEN,
                            envelope.length - Constants.SC_MAC_LEN);
            byte[] tag =
                    Arrays.copyOfRange(
                            envelope, envelope.length - Constants.SC_MAC_LEN, envelope.length);

            // Verify MAC = HMAC-SHA256(K_mac, 0xFF ‖ IV ‖ ct)[0..16].
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(kMac, "HmacSHA256"));
            mac.update((byte) 0xFF);
            mac.update(iv);
            mac.update(ct);
            byte[] expected = Arrays.copyOf(mac.doFinal(), Constants.SC_MAC_LEN);
            if (!Arrays.equals(expected, tag)) {
                throw new IllegalStateException("response MAC mismatch");
            }

            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE, new SecretKeySpec(kEnc, "AES"), new IvParameterSpec(iv));
            byte[] padded = cipher.doFinal(ct);
            return pkcs5Unpad(padded);
        }

        private byte[] ivFromCounter(long counter) {
            byte[] iv = new byte[Constants.SC_BLOCK_LEN];
            // Big-endian counter into the last 8 bytes; first 8 zero. The card's
            // strictly-increasing
            // check operates on the full 16-byte buffer.
            for (int i = 0; i < 8; i++) {
                iv[Constants.SC_BLOCK_LEN - 1 - i] = (byte) ((counter >>> (8 * i)) & 0xFF);
            }
            return iv;
        }

        private static byte[] pkcs5Pad(byte[] in) {
            int rem = in.length % Constants.SC_BLOCK_LEN;
            int padLen = Constants.SC_BLOCK_LEN - rem;
            byte[] out = new byte[in.length + padLen];
            System.arraycopy(in, 0, out, 0, in.length);
            for (int i = in.length; i < out.length; i++) {
                out[i] = (byte) padLen;
            }
            return out;
        }

        private static byte[] pkcs5Unpad(byte[] padded) {
            int padLen = padded[padded.length - 1] & 0xFF;
            return Arrays.copyOfRange(padded, 0, padded.length - padLen);
        }
    }

    /** Minimal RFC 5869 HKDF-SHA-256 helper for tests. */
    private static final class HkdfSha256 {
        static byte[] extract(byte[] salt, byte[] ikm) {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(salt.length == 0 ? new byte[32] : salt, "HmacSHA256"));
                return mac.doFinal(ikm);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        static byte[] expand(byte[] prk, byte[] info, int length) {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                byte[] out = new byte[length];
                byte[] prev = new byte[0];
                int pos = 0;
                byte counter = 1;
                while (pos < length) {
                    mac.init(new SecretKeySpec(prk, "HmacSHA256"));
                    mac.update(prev);
                    mac.update(info);
                    mac.update(counter);
                    prev = mac.doFinal();
                    int take = Math.min(prev.length, length - pos);
                    System.arraycopy(prev, 0, out, pos, take);
                    pos += take;
                    counter++;
                }
                return out;
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    /** Verifies a DER-encoded ECDSA signature over secp256k1 produced from a SHA-256 digest. */
    private static final class EcdsaVerifier {
        static boolean verifySecp256k1(byte[] compressedPubkey, byte[] message, byte[] derSig)
                throws Exception {
            ECPoint point = SECP256K1.getCurve().decodePoint(compressedPubkey).normalize();
            java.security.spec.ECPoint w =
                    new java.security.spec.ECPoint(
                            point.getAffineXCoord().toBigInteger(),
                            point.getAffineYCoord().toBigInteger());
            java.security.spec.EllipticCurve curve =
                    new java.security.spec.EllipticCurve(
                            new java.security.spec.ECFieldFp(
                                    SECP256K1.getCurve().getField().getCharacteristic()),
                            SECP256K1.getCurve().getA().toBigInteger(),
                            SECP256K1.getCurve().getB().toBigInteger());
            java.security.spec.ECParameterSpec params =
                    new java.security.spec.ECParameterSpec(
                            curve,
                            new java.security.spec.ECPoint(
                                    SECP256K1.getG().getAffineXCoord().toBigInteger(),
                                    SECP256K1.getG().getAffineYCoord().toBigInteger()),
                            SECP256K1.getN(),
                            SECP256K1.getH().intValue());
            java.security.spec.ECPublicKeySpec spec =
                    new java.security.spec.ECPublicKeySpec(w, params);
            java.security.KeyFactory kf =
                    java.security.KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            java.security.PublicKey pub = kf.generatePublic(spec);
            java.security.Signature sig =
                    java.security.Signature.getInstance(
                            "SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME);
            sig.initVerify(pub);
            sig.update(message);
            return sig.verify(derSig);
        }
    }
}
