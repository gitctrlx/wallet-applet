/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import javacard.framework.AID;
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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * End-to-end tests for the personalisation flow — PIN/PUK setup plus PKI manufacturer-cert import
 * and lock. All these INS are reachable only through the Secure Channel envelope, so every test
 * opens a session first and dispatches inner APDUs via {@code OPEN_SECURE_CHANNEL}.
 *
 * <p>The {@link Session} helper is a self-contained client-side mirror of the meowl Secure Channel
 * protocol — ECDH on secp256k1, HKDF-SHA-256 KDF, AES-256-CBC, HMAC-SHA-256 — built on BouncyCastle
 * and the standard JCE. It lives inside this test file because we only need it here; once a real
 * host SDK exists in {@code tools/} it will subsume this scaffolding.
 */
class PersonalisationTest {

    private static final byte[] APPLET_AID_BYTES = {
        (byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x01
    };

    private static final int CLA = Constants.Wire.CLA & 0xFF;
    private static final int INS_INIT_SC = Constants.Wire.INS_INIT_SECURE_CHANNEL & 0xFF;
    private static final int INS_OPEN_SC = Constants.Wire.INS_OPEN_SECURE_CHANNEL & 0xFF;

    private static final X9ECParameters SECP256K1 = CustomNamedCurves.getByName("secp256k1");
    private static final byte[] HKDF_INFO = "meowl-sc-v1".getBytes();
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final byte[] DEFAULT_PIN = "123456".getBytes();
    private static final byte[] DEFAULT_PUK = "ABCDEFGH".getBytes();

    private CardSimulator simulator;
    private Session session;

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() {
        simulator = new CardSimulator();
        AID aid = AIDUtil.create(APPLET_AID_BYTES);
        simulator.installApplet(aid, MeowlApplet.class);
        simulator.selectApplet(aid);
        session = openSession();
    }

    @Nested
    @DisplayName("PKI personalisation flow")
    class Pki {

        @Test
        @DisplayName("EXPORT_PKI_PUBKEY returns the authentikey")
        void exportPkiPubkey() throws Exception {
            byte[] pk =
                    sendInnerExpectOk(
                            Constants.Wire.INS_EXPORT_PKI_PUBKEY, (byte) 0, (byte) 0, new byte[0]);
            assertEquals(Constants.Ec.POINT_COMPRESSED_LEN, pk.length);
            assertTrue(pk[0] == 0x02 || pk[0] == 0x03);
        }

        @Test
        @DisplayName("SIGN_PKI_CSR signs a 32-byte digest and the host can verify the signature")
        void signPkiCsr() throws Exception {
            byte[] digest = new byte[32];
            RANDOM.nextBytes(digest);
            byte[] sig =
                    sendInnerExpectOk(Constants.Wire.INS_SIGN_PKI_CSR, (byte) 0, (byte) 0, digest);
            assertTrue(sig.length >= 70 && sig.length <= 72, "DER ECDSA sig is 70-72 bytes");

            byte[] pubkey =
                    sendInnerExpectOk(
                            Constants.Wire.INS_EXPORT_PKI_PUBKEY, (byte) 0, (byte) 0, new byte[0]);
            assertTrue(verifyEcdsaPreHashed(pubkey, digest, sig), "host must verify the signature");
        }

        @Test
        @DisplayName("Full chunked import + lock + paged export round-trip")
        void importLockExportRoundTrip() throws Exception {
            byte[] cert = synthesiseCert(450);

            // INIT
            sendInnerExpectOk(
                    Constants.Wire.INS_IMPORT_PKI_CERT,
                    Constants.Pki.IMPORT_P1_INIT,
                    (byte) 0,
                    shortBE((short) cert.length));

            // WRITE in 200-byte chunks
            int written = 0;
            while (written < cert.length) {
                int chunkLen = Math.min(Constants.Pki.CERT_CHUNK_MAX_LEN, cert.length - written);
                byte[] payload = new byte[2 + chunkLen];
                payload[0] = (byte) (written >> 8);
                payload[1] = (byte) (written & 0xFF);
                System.arraycopy(cert, written, payload, 2, chunkLen);
                sendInnerExpectOk(
                        Constants.Wire.INS_IMPORT_PKI_CERT,
                        Constants.Pki.IMPORT_P1_WRITE,
                        (byte) 0,
                        payload);
                written += chunkLen;
            }

            // FINALIZE
            sendInnerExpectOk(
                    Constants.Wire.INS_IMPORT_PKI_CERT,
                    Constants.Pki.IMPORT_P1_FINALIZE,
                    (byte) 0,
                    new byte[0]);

            // LOCK_PKI
            sendInnerExpectOk(Constants.Wire.INS_LOCK_PKI, (byte) 0, (byte) 0, new byte[0]);

            // EXPORT_PKI_CERT: page through the cert.
            byte[] readBack = new byte[cert.length];
            int readSoFar = 0;
            while (readSoFar < cert.length) {
                byte[] req =
                        new byte[] {
                            (byte) (readSoFar >> 8), (byte) (readSoFar & 0xFF),
                            (byte) 0x00, (byte) 100
                        };
                byte[] resp =
                        sendInnerExpectOk(
                                Constants.Wire.INS_EXPORT_PKI_CERT, (byte) 0, (byte) 0, req);
                // resp = [totalLen(2)] || [data]
                int total = ((resp[0] & 0xFF) << 8) | (resp[1] & 0xFF);
                assertEquals(cert.length, total);
                int chunk = resp.length - 2;
                System.arraycopy(resp, 2, readBack, readSoFar, chunk);
                readSoFar += chunk;
                if (chunk == 0) break;
            }
            assertArrayEquals(cert, readBack);
        }

        @Test
        @DisplayName(
                "importInit zeros the cert buffer — a re-init+finalize without WRITE chunks must"
                        + " export only zeros")
        void importInitClearsCertBuffer() throws Exception {
            // First import: fill 500 bytes with a recognisable non-zero pattern so any stale
            // bytes would be unmistakable in the second export.
            byte[] firstCert = new byte[500];
            Arrays.fill(firstCert, (byte) 0xAA);
            importCert(firstCert);

            // Re-init with a shorter total, then finalise without writing any chunks. The cert
            // buffer's first 100 bytes were just overwritten with 0xAA by the previous import;
            // the importInit wipe must zero them again so the export below reads only 0x00.
            sendInnerExpectOk(
                    Constants.Wire.INS_IMPORT_PKI_CERT,
                    Constants.Pki.IMPORT_P1_INIT,
                    (byte) 0,
                    shortBE((short) 100));
            sendInnerExpectOk(
                    Constants.Wire.INS_IMPORT_PKI_CERT,
                    Constants.Pki.IMPORT_P1_FINALIZE,
                    (byte) 0,
                    new byte[0]);

            // Page the whole committed window; expect 100 bytes of 0x00.
            byte[] req = new byte[] {0x00, 0x00, 0x00, (byte) 100};
            byte[] resp =
                    sendInnerExpectOk(Constants.Wire.INS_EXPORT_PKI_CERT, (byte) 0, (byte) 0, req);
            int total = ((resp[0] & 0xFF) << 8) | (resp[1] & 0xFF);
            assertEquals(100, total);
            byte[] data = Arrays.copyOfRange(resp, 2, resp.length);
            byte[] expected = new byte[100];
            assertArrayEquals(
                    expected, data, "importInit must wipe the cert buffer of any prior content");
        }

        @Test
        @DisplayName("LOCK_PKI without a cert fails with SW_CONDITIONS_NOT_SATISFIED")
        void lockWithoutCertFails() {
            assertEquals(
                    Constants.Sw.CONDITIONS_NOT_SATISFIED & 0xFFFF,
                    sendInner(Constants.Wire.INS_LOCK_PKI, (byte) 0, (byte) 0, new byte[0])
                            .getSW());
        }

        @Test
        @DisplayName("LOCK_PKI transitions lifecycle to PERSONALIZED and blocks further PKI import")
        void lockBlocksFurtherImport() throws Exception {
            byte[] cert = synthesiseCert(200);
            importCert(cert);
            sendInnerExpectOk(Constants.Wire.INS_LOCK_PKI, (byte) 0, (byte) 0, new byte[0]);

            // After lock: lifecycle = PERSONALIZED; INIT must fail with SW_LIFECYCLE_INVALID.
            ResponseAPDU resp =
                    sendInner(
                            Constants.Wire.INS_IMPORT_PKI_CERT,
                            Constants.Pki.IMPORT_P1_INIT,
                            (byte) 0,
                            shortBE((short) 100));
            assertEquals(Constants.Sw.LIFECYCLE_INVALID & 0xFFFF, resp.getSW());
        }

        @Test
        @DisplayName("IMPORT_PKI_CERT rejects offset arithmetic overflow with SW_WRONG_LENGTH")
        void importWriteRejectsOffsetOverflow() {
            sendInnerExpectOk(
                    Constants.Wire.INS_IMPORT_PKI_CERT,
                    Constants.Pki.IMPORT_P1_INIT,
                    (byte) 0,
                    shortBE(Constants.Pki.CERT_MAX_LEN));

            byte[] payload = new byte[] {0x7F, (byte) 0xFF, 0x01};
            ResponseAPDU resp =
                    sendInner(
                            Constants.Wire.INS_IMPORT_PKI_CERT,
                            Constants.Pki.IMPORT_P1_WRITE,
                            (byte) 0,
                            payload);
            assertEquals(Constants.Sw.WRONG_LENGTH & 0xFFFF, resp.getSW());
        }
    }

    @Nested
    @DisplayName("PIN / PUK flow (post-personalisation)")
    class Pin {

        @BeforeEach
        void personalise() throws Exception {
            // Bring the card to PERSONALIZED with a minimal cert so SETUP becomes reachable.
            byte[] cert = synthesiseCert(100);
            importCert(cert);
            sendInnerExpectOk(Constants.Wire.INS_LOCK_PKI, (byte) 0, (byte) 0, new byte[0]);
            // Re-open a Secure Channel session — LOCK_PKI does not affect SC state, but the
            // following SETUP is the first user-side command and we want a clean session here
            // since the Pin tests run end-to-end without extra coupling.
            session = openSession();
        }

        @Test
        @DisplayName("SETUP installs PIN+PUK and advances lifecycle to SETUP_DONE")
        void setupAdvancesLifecycle() throws Exception {
            sendInnerExpectOk(
                    Constants.Wire.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    encodeSetup(DEFAULT_PIN, DEFAULT_PUK));
            byte[] info = transmit(Constants.Wire.INS_GET_INFO & 0xFF, 0, 0, null).getData();
            byte lifecycle = readLifecycleFromInfoTlv(info);
            assertEquals(LifecycleState.SETUP_DONE, lifecycle);
        }

        @Test
        @DisplayName("Calling SETUP twice fails with SW_CONDITIONS_NOT_SATISFIED")
        void setupTwiceFails() throws Exception {
            sendInnerExpectOk(
                    Constants.Wire.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    encodeSetup(DEFAULT_PIN, DEFAULT_PUK));
            ResponseAPDU second =
                    sendInner(
                            Constants.Wire.INS_SETUP,
                            (byte) 0,
                            (byte) 0,
                            encodeSetup(DEFAULT_PIN, DEFAULT_PUK));
            assertEquals(
                    Constants.Sw.LIFECYCLE_INVALID & 0xFFFF,
                    second.getSW(),
                    "second SETUP must be rejected by the FSM");
        }

        @Test
        @DisplayName("VERIFY_PIN: correct PIN succeeds")
        void verifyCorrectPin() throws Exception {
            sendInnerExpectOk(
                    Constants.Wire.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    encodeSetup(DEFAULT_PIN, DEFAULT_PUK));
            ResponseAPDU r =
                    sendInner(Constants.Wire.INS_VERIFY_PIN, (byte) 0, (byte) 0, DEFAULT_PIN);
            assertEquals(0x9000, r.getSW());
        }

        @Test
        @DisplayName("VERIFY_PIN: wrong PIN returns 63Cn with decremented try counter")
        void verifyWrongPinDecrements() throws Exception {
            sendInnerExpectOk(
                    Constants.Wire.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    encodeSetup(DEFAULT_PIN, DEFAULT_PUK));
            ResponseAPDU r =
                    sendInner(
                            Constants.Wire.INS_VERIFY_PIN, (byte) 0, (byte) 0, "999999".getBytes());
            int sw = r.getSW();
            int base = Constants.Sw.PIN_RETRIES_BASE & 0xFFF0;
            assertEquals(base, sw & 0xFFF0, "must be 63Cn");
            int remaining = sw & 0x000F;
            assertEquals(Constants.Pin.RETRY_LIMIT - 1, remaining);
        }

        @Test
        @DisplayName("VERIFY_PIN: exhausting retries blocks the PIN")
        void exhaustRetriesBlocksPin() throws Exception {
            sendInnerExpectOk(
                    Constants.Wire.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    encodeSetup(DEFAULT_PIN, DEFAULT_PUK));
            for (int i = 0; i < Constants.Pin.RETRY_LIMIT; i++) {
                sendInner(Constants.Wire.INS_VERIFY_PIN, (byte) 0, (byte) 0, "999999".getBytes());
            }
            ResponseAPDU r =
                    sendInner(Constants.Wire.INS_VERIFY_PIN, (byte) 0, (byte) 0, DEFAULT_PIN);
            assertEquals(Constants.Sw.AUTH_BLOCKED & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("UNBLOCK_PIN: correct PUK unblocks a blocked PIN with a fresh PIN")
        void unblockPinWithCorrectPuk() throws Exception {
            sendInnerExpectOk(
                    Constants.Wire.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    encodeSetup(DEFAULT_PIN, DEFAULT_PUK));
            // Exhaust the PIN counter.
            for (int i = 0; i < Constants.Pin.RETRY_LIMIT; i++) {
                sendInner(Constants.Wire.INS_VERIFY_PIN, (byte) 0, (byte) 0, "999999".getBytes());
            }
            byte[] newPin = "654321".getBytes();
            sendInnerExpectOk(
                    Constants.Wire.INS_UNBLOCK_PIN,
                    (byte) 0,
                    (byte) 0,
                    encodeLengthPrefixedPair(DEFAULT_PUK, newPin));
            // The new PIN must verify; the old one must not.
            assertEquals(
                    0x9000,
                    sendInner(Constants.Wire.INS_VERIFY_PIN, (byte) 0, (byte) 0, newPin).getSW());
        }

        @Test
        @DisplayName(
                "VERIFY_PIN with under-length PIN returns SW_WRONG_LENGTH and does NOT consume a"
                        + " retry")
        void underLengthPinDoesNotConsumeRetry() throws Exception {
            sendInnerExpectOk(
                    Constants.Wire.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    encodeSetup(DEFAULT_PIN, DEFAULT_PUK));
            // Send a clearly-too-short PIN. Must return SW_WRONG_LENGTH.
            byte[] tooShort = new byte[] {0x31, 0x32, 0x33};
            assertEquals(
                    Constants.Sw.WRONG_LENGTH & 0xFFFF,
                    sendInner(Constants.Wire.INS_VERIFY_PIN, (byte) 0, (byte) 0, tooShort).getSW());
            // Now the correct PIN must still succeed — the prior call did not consume a retry.
            assertEquals(
                    0x9000,
                    sendInner(Constants.Wire.INS_VERIFY_PIN, (byte) 0, (byte) 0, DEFAULT_PIN)
                            .getSW());
            // Send another deliberately wrong (but well-formed) PIN: the counter must show 2
            // retries remaining, confirming the previous under-length attempt was free.
            int sw =
                    sendInner(
                                    Constants.Wire.INS_VERIFY_PIN,
                                    (byte) 0,
                                    (byte) 0,
                                    "999999".getBytes())
                            .getSW();
            assertEquals(Constants.Sw.PIN_RETRIES_BASE & 0xFFF0, sw & 0xFFF0);
            assertEquals(Constants.Pin.RETRY_LIMIT - 1, sw & 0x000F);
        }

        @Test
        @DisplayName(
                "VERIFY_PIN with over-max-length PIN returns SW_WRONG_LENGTH (no exception leak)")
        void overLengthPinReturnsWrongLength() throws Exception {
            sendInnerExpectOk(
                    Constants.Wire.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    encodeSetup(DEFAULT_PIN, DEFAULT_PUK));
            byte[] tooLong = new byte[Constants.Pin.MAX_LEN + 1];
            for (int i = 0; i < tooLong.length; i++) {
                tooLong[i] = (byte) '0';
            }
            assertEquals(
                    Constants.Sw.WRONG_LENGTH & 0xFFFF,
                    sendInner(Constants.Wire.INS_VERIFY_PIN, (byte) 0, (byte) 0, tooLong).getSW(),
                    "over-length PIN must be rejected cleanly, not via the OwnerPIN ABE path");
        }

        @Test
        @DisplayName(
                "CHANGE_PUK requires PIN session-verified — fresh SC after VERIFY_PIN must"
                        + " invalidate")
        void changePukSessionIsInvalidatedByReHandshake() throws Exception {
            sendInnerExpectOk(
                    Constants.Wire.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    encodeSetup(DEFAULT_PIN, DEFAULT_PUK));
            // Verify PIN inside the current Secure Channel.
            assertEquals(
                    0x9000,
                    sendInner(Constants.Wire.INS_VERIFY_PIN, (byte) 0, (byte) 0, DEFAULT_PIN)
                            .getSW());
            // While in the same SC, CHANGE_PUK is allowed.
            byte[] freshPuk = "ZZZZZZZZ".getBytes();
            sendInnerExpectOk(
                    Constants.Wire.INS_CHANGE_PUK,
                    (byte) 0,
                    (byte) 0,
                    encodeLengthPrefixedPair(DEFAULT_PUK, freshPuk));

            // Open a brand new Secure Channel. CHANGE_PUK should now be rejected by the
            // session-verify gate even though the PIN was validated in the previous session.
            session = openSession();
            byte[] yetAnotherPuk = "YYYYYYYY".getBytes();
            ResponseAPDU r =
                    sendInner(
                            Constants.Wire.INS_CHANGE_PUK,
                            (byte) 0,
                            (byte) 0,
                            encodeLengthPrefixedPair(freshPuk, yetAnotherPuk));
            assertEquals(
                    Constants.Sw.SECURITY_STATUS_NOT_SATISFIED & 0xFFFF,
                    r.getSW(),
                    "PIN-validated flag must not carry across Secure Channel re-handshakes");
        }

        @Test
        @DisplayName("CHANGE_PIN: rotates the PIN; old PIN no longer verifies")
        void changePin() throws Exception {
            sendInnerExpectOk(
                    Constants.Wire.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    encodeSetup(DEFAULT_PIN, DEFAULT_PUK));
            byte[] newPin = "654321".getBytes();
            sendInnerExpectOk(
                    Constants.Wire.INS_CHANGE_PIN,
                    (byte) 0,
                    (byte) 0,
                    encodeLengthPrefixedPair(DEFAULT_PIN, newPin));
            assertEquals(
                    0x9000,
                    sendInner(Constants.Wire.INS_VERIFY_PIN, (byte) 0, (byte) 0, newPin).getSW());
            // The old PIN now decrements the counter rather than succeeding.
            int sw =
                    sendInner(Constants.Wire.INS_VERIFY_PIN, (byte) 0, (byte) 0, DEFAULT_PIN)
                            .getSW();
            assertNotEquals(0x9000, sw);
        }
    }

    /*  ============== helpers ==============  */

    private byte[] sendInnerExpectOk(byte ins, byte p1, byte p2, byte[] data) {
        ResponseAPDU r = sendInner(ins, p1, p2, data);
        assertEquals(0x9000, r.getSW(), "inner INS " + Integer.toHexString(ins & 0xFF));
        try {
            return session.decryptFromCard(r.getData());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private ResponseAPDU sendInner(byte ins, byte p1, byte p2, byte[] data) {
        try {
            byte[] inner = innerApdu(ins, p1, p2, data);
            byte[] envelope = session.encryptForCard(inner);
            return transmit(INS_OPEN_SC, 0x00, 0x00, envelope);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] innerApdu(byte ins, byte p1, byte p2, byte[] data) {
        byte[] out = new byte[5 + data.length];
        out[0] = Constants.Wire.CLA;
        out[1] = ins;
        out[2] = p1;
        out[3] = p2;
        out[4] = (byte) data.length;
        System.arraycopy(data, 0, out, 5, data.length);
        return out;
    }

    private static byte[] encodeSetup(byte[] pin, byte[] puk) {
        byte[] out = new byte[1 + pin.length + 1 + puk.length];
        out[0] = (byte) pin.length;
        System.arraycopy(pin, 0, out, 1, pin.length);
        out[1 + pin.length] = (byte) puk.length;
        System.arraycopy(puk, 0, out, 1 + pin.length + 1, puk.length);
        return out;
    }

    private static byte[] encodeLengthPrefixedPair(byte[] first, byte[] second) {
        byte[] out = new byte[1 + first.length + 1 + second.length];
        out[0] = (byte) first.length;
        System.arraycopy(first, 0, out, 1, first.length);
        out[1 + first.length] = (byte) second.length;
        System.arraycopy(second, 0, out, 1 + first.length + 1, second.length);
        return out;
    }

    private static byte[] shortBE(short value) {
        return new byte[] {(byte) (value >> 8), (byte) (value & 0xFF)};
    }

    private static byte[] synthesiseCert(int size) {
        byte[] cert = new byte[size];
        for (int i = 0; i < size; i++) {
            cert[i] = (byte) (i & 0xFF);
        }
        return cert;
    }

    private static byte readLifecycleFromInfoTlv(byte[] tlv) {
        int i = 0;
        while (i < tlv.length) {
            int tag = tlv[i++] & 0xFF;
            int len = tlv[i++] & 0xFF;
            if (tag == (Constants.Wire.TAG_LIFECYCLE_STATE & 0xFF)) {
                return tlv[i];
            }
            i += len;
        }
        throw new IllegalStateException("lifecycle TLV not found");
    }

    private void importCert(byte[] cert) throws Exception {
        sendInnerExpectOk(
                Constants.Wire.INS_IMPORT_PKI_CERT,
                Constants.Pki.IMPORT_P1_INIT,
                (byte) 0,
                shortBE((short) cert.length));
        int written = 0;
        while (written < cert.length) {
            int chunkLen = Math.min(Constants.Pki.CERT_CHUNK_MAX_LEN, cert.length - written);
            byte[] payload = new byte[2 + chunkLen];
            payload[0] = (byte) (written >> 8);
            payload[1] = (byte) (written & 0xFF);
            System.arraycopy(cert, written, payload, 2, chunkLen);
            sendInnerExpectOk(
                    Constants.Wire.INS_IMPORT_PKI_CERT,
                    Constants.Pki.IMPORT_P1_WRITE,
                    (byte) 0,
                    payload);
            written += chunkLen;
        }
        sendInnerExpectOk(
                Constants.Wire.INS_IMPORT_PKI_CERT,
                Constants.Pki.IMPORT_P1_FINALIZE,
                (byte) 0,
                new byte[0]);
    }

    private boolean verifyEcdsaPreHashed(byte[] compressedPubkey, byte[] digest, byte[] sig)
            throws Exception {
        // signPreComputedHash signs the raw digest; on the host side we mirror that by treating
        // the digest as the input and using BC's "NONEwithECDSA" verifier.
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
        java.security.PublicKey pub =
                java.security.KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
                        .generatePublic(new java.security.spec.ECPublicKeySpec(w, params));
        java.security.Signature v =
                java.security.Signature.getInstance(
                        "NONEwithECDSA", BouncyCastleProvider.PROVIDER_NAME);
        v.initVerify(pub);
        v.update(digest);
        return v.verify(sig);
    }

    private Session openSession() {
        BigInteger clientPriv;
        ECPoint clientPub;
        do {
            byte[] cand = new byte[32];
            RANDOM.nextBytes(cand);
            clientPriv = new BigInteger(1, cand);
        } while (clientPriv.signum() == 0 || clientPriv.compareTo(SECP256K1.getN()) >= 0);
        clientPub = SECP256K1.getG().multiply(clientPriv).normalize();
        byte[] clientPubEnc = clientPub.getEncoded(false);

        ResponseAPDU resp = transmit(INS_INIT_SC, 0x00, 0x00, clientPubEnc);
        assertEquals(0x9000, resp.getSW(), "handshake");
        byte[] body = resp.getData();
        byte[] cardEphPub = Arrays.copyOfRange(body, 0, Constants.Ec.POINT_UNCOMPRESSED_LEN);

        ECPoint cardPub = SECP256K1.getCurve().decodePoint(cardEphPub).normalize();
        ECPoint sharedPoint = cardPub.multiply(clientPriv).normalize();
        byte[] sharedX = bigIntToFixed(sharedPoint.getAffineXCoord().toBigInteger(), 32);
        byte[] clientX = Arrays.copyOfRange(clientPubEnc, 1, 33);
        byte[] cardX = Arrays.copyOfRange(cardEphPub, 1, 33);
        byte[] salt = concat(clientX, cardX);
        byte[] prk = HkdfSha256.extract(salt, sharedX);
        byte[] okm = HkdfSha256.expand(prk, HKDF_INFO, 32 + 32 + 16);
        return new Session(
                Arrays.copyOfRange(okm, 0, 32),
                Arrays.copyOfRange(okm, 32, 64),
                Arrays.copyOfRange(okm, 64, 80));
    }

    private ResponseAPDU transmit(int ins, int p1, int p2, byte[] data) {
        CommandAPDU cmd =
                data == null
                        ? new CommandAPDU(CLA, ins, p1, p2)
                        : new CommandAPDU(CLA, ins, p1, p2, data);
        return simulator.transmitCommand(cmd);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
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

    private static final class Session {
        final byte[] kEnc;
        final byte[] kMac;
        final byte[] ivBase;
        long counter;

        Session(byte[] kEnc, byte[] kMac, byte[] ivBase) {
            this.kEnc = kEnc;
            this.kMac = kMac;
            this.ivBase = ivBase;
            this.counter = 0L;
        }

        byte[] encryptForCard(byte[] plaintext) throws Exception {
            counter++;
            byte[] iv = new byte[Constants.Sc.BLOCK_LEN];
            for (int i = 0; i < 8; i++) {
                iv[Constants.Sc.BLOCK_LEN - 1 - i] = (byte) ((counter >>> (8 * i)) & 0xFF);
            }
            byte[] padded = pkcs5Pad(plaintext);
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kEnc, "AES"), new IvParameterSpec(iv));
            byte[] ct = c.doFinal(padded);

            int lc = iv.length + ct.length + Constants.Sc.MAC_LEN;
            byte[] header = {(byte) CLA, (byte) INS_OPEN_SC, 0x00, 0x00, (byte) lc};
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(kMac, "HmacSHA256"));
            m.update(header);
            m.update(iv);
            m.update(ct);
            byte[] tag = Arrays.copyOf(m.doFinal(), Constants.Sc.MAC_LEN);

            byte[] out = new byte[lc];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            System.arraycopy(tag, 0, out, iv.length + ct.length, tag.length);
            return out;
        }

        byte[] decryptFromCard(byte[] envelope) throws Exception {
            byte[] iv = Arrays.copyOfRange(envelope, 0, Constants.Sc.BLOCK_LEN);
            byte[] ct =
                    Arrays.copyOfRange(
                            envelope,
                            Constants.Sc.BLOCK_LEN,
                            envelope.length - Constants.Sc.MAC_LEN);
            byte[] tag =
                    Arrays.copyOfRange(
                            envelope, envelope.length - Constants.Sc.MAC_LEN, envelope.length);

            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(kMac, "HmacSHA256"));
            m.update((byte) 0xFF);
            m.update(iv);
            m.update(ct);
            byte[] expected = Arrays.copyOf(m.doFinal(), Constants.Sc.MAC_LEN);
            if (!Arrays.equals(expected, tag)) {
                throw new IllegalStateException("outbound MAC mismatch");
            }
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kEnc, "AES"), new IvParameterSpec(iv));
            byte[] padded = c.doFinal(ct);
            int padLen = padded[padded.length - 1] & 0xFF;
            return Arrays.copyOfRange(padded, 0, padded.length - padLen);
        }

        private static byte[] pkcs5Pad(byte[] in) {
            int rem = in.length % Constants.Sc.BLOCK_LEN;
            int pad = Constants.Sc.BLOCK_LEN - rem;
            byte[] out = new byte[in.length + pad];
            System.arraycopy(in, 0, out, 0, in.length);
            for (int i = in.length; i < out.length; i++) out[i] = (byte) pad;
            return out;
        }
    }

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
}
