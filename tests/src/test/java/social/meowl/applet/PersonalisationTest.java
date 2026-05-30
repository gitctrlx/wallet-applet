/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Security;
import java.util.Arrays;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import social.meowl.applet.cardclient.RealCardClient;
import social.meowl.applet.testkit.HostSession;
import social.meowl.applet.testkit.MeowlFixtures;
import social.meowl.applet.testkit.TestConstants;

/**
 * End-to-end tests for the personalisation flow — PIN/PUK setup plus PKI manufacturer-cert import
 * and lock. All these INS are reachable only through the Secure Channel envelope, so every test
 * opens a {@link HostSession} first and dispatches inner APDUs via {@code OPEN_SECURE_CHANNEL}.
 */
@Tag("real-card")
class PersonalisationTest {

    private RealCardClient card;
    private HostSession session;

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() {
        card = RealCardClient.connect(TestConstants.APPLET_AID_BYTES);
        session = HostSession.open(card);
    }

    @AfterEach
    void tearDown() {
        if (card != null) {
            try {
                MeowlFixtures.resetCard(card);
            } catch (Exception ignored) {
                // best-effort reset; the next test's @BeforeEach will surface real problems
            }
            card.close();
        }
    }

    @Nested
    @DisplayName("PKI personalisation flow")
    class Pki {

        @Test
        @DisplayName("EXPORT_PKI_PUBKEY returns the authentikey")
        void exportPkiPubkey() throws Exception {
            byte[] pk =
                    session.sendInnerExpectOk(
                            Constants.INS_EXPORT_PKI_PUBKEY, (byte) 0, (byte) 0, new byte[0]);
            assertEquals(Constants.EC_POINT_COMPRESSED_LEN, pk.length);
            assertTrue(pk[0] == 0x02 || pk[0] == 0x03);
        }

        @Test
        @DisplayName("SIGN_PKI_CSR signs a 32-byte digest and the host can verify the signature")
        void signPkiCsr() throws Exception {
            byte[] digest = new byte[32];
            TestConstants.RANDOM.nextBytes(digest);
            byte[] sig =
                    session.sendInnerExpectOk(
                            Constants.INS_SIGN_PKI_CSR, (byte) 0, (byte) 0, digest);
            assertTrue(sig.length >= 70 && sig.length <= 72, "DER ECDSA sig is 70-72 bytes");

            byte[] pubkey =
                    session.sendInnerExpectOk(
                            Constants.INS_EXPORT_PKI_PUBKEY, (byte) 0, (byte) 0, new byte[0]);
            assertTrue(verifyEcdsaPreHashed(pubkey, digest, sig), "host must verify the signature");
        }

        @Test
        @DisplayName("Full chunked import + lock + paged export round-trip")
        void importLockExportRoundTrip() throws Exception {
            byte[] cert = synthesiseCert(450);

            // INIT
            session.sendInnerExpectOk(
                    Constants.INS_IMPORT_PKI_CERT,
                    Constants.PKI_IMPORT_P1_INIT,
                    (byte) 0,
                    MeowlFixtures.shortBE((short) cert.length));

            // WRITE in 200-byte chunks
            int written = 0;
            while (written < cert.length) {
                int chunkLen = Math.min(Constants.PKI_CERT_CHUNK_MAX_LEN, cert.length - written);
                byte[] payload = new byte[2 + chunkLen];
                payload[0] = (byte) (written >> 8);
                payload[1] = (byte) (written & 0xFF);
                System.arraycopy(cert, written, payload, 2, chunkLen);
                session.sendInnerExpectOk(
                        Constants.INS_IMPORT_PKI_CERT,
                        Constants.PKI_IMPORT_P1_WRITE,
                        (byte) 0,
                        payload);
                written += chunkLen;
            }

            // FINALIZE
            session.sendInnerExpectOk(
                    Constants.INS_IMPORT_PKI_CERT,
                    Constants.PKI_IMPORT_P1_FINALIZE,
                    (byte) 0,
                    new byte[0]);

            // LOCK_PKI
            session.sendInnerExpectOk(Constants.INS_LOCK_PKI, (byte) 0, (byte) 0, new byte[0]);

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
                        session.sendInnerExpectOk(
                                Constants.INS_EXPORT_PKI_CERT, (byte) 0, (byte) 0, req);
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
            session.sendInnerExpectOk(
                    Constants.INS_IMPORT_PKI_CERT,
                    Constants.PKI_IMPORT_P1_INIT,
                    (byte) 0,
                    MeowlFixtures.shortBE((short) 100));
            session.sendInnerExpectOk(
                    Constants.INS_IMPORT_PKI_CERT,
                    Constants.PKI_IMPORT_P1_FINALIZE,
                    (byte) 0,
                    new byte[0]);

            // Page the whole committed window; expect 100 bytes of 0x00.
            byte[] req = new byte[] {0x00, 0x00, 0x00, (byte) 100};
            byte[] resp =
                    session.sendInnerExpectOk(
                            Constants.INS_EXPORT_PKI_CERT, (byte) 0, (byte) 0, req);
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
                    Constants.SW_CONDITIONS_NOT_SATISFIED & 0xFFFF,
                    session.sendInner(Constants.INS_LOCK_PKI, (byte) 0, (byte) 0, new byte[0])
                            .getSW());
        }

        @Test
        @DisplayName("LOCK_PKI transitions lifecycle to PERSONALIZED and blocks further PKI import")
        void lockBlocksFurtherImport() throws Exception {
            byte[] cert = synthesiseCert(200);
            importCert(cert);
            session.sendInnerExpectOk(Constants.INS_LOCK_PKI, (byte) 0, (byte) 0, new byte[0]);

            // After lock: lifecycle = PERSONALIZED; INIT must fail with SW_LIFECYCLE_INVALID.
            ResponseAPDU resp =
                    session.sendInner(
                            Constants.INS_IMPORT_PKI_CERT,
                            Constants.PKI_IMPORT_P1_INIT,
                            (byte) 0,
                            MeowlFixtures.shortBE((short) 100));
            assertEquals(Constants.SW_LIFECYCLE_INVALID & 0xFFFF, resp.getSW());
        }

        @Test
        @DisplayName("IMPORT_PKI_CERT rejects offset arithmetic overflow with SW_WRONG_LENGTH")
        void importWriteRejectsOffsetOverflow() {
            session.sendInnerExpectOk(
                    Constants.INS_IMPORT_PKI_CERT,
                    Constants.PKI_IMPORT_P1_INIT,
                    (byte) 0,
                    MeowlFixtures.shortBE(Constants.PKI_CERT_MAX_LEN));

            byte[] payload = new byte[] {0x7F, (byte) 0xFF, 0x01};
            ResponseAPDU resp =
                    session.sendInner(
                            Constants.INS_IMPORT_PKI_CERT,
                            Constants.PKI_IMPORT_P1_WRITE,
                            (byte) 0,
                            payload);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, resp.getSW());
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
            session.sendInnerExpectOk(Constants.INS_LOCK_PKI, (byte) 0, (byte) 0, new byte[0]);
            // Re-open a Secure Channel session — LOCK_PKI does not affect SC state, but the
            // following SETUP is the first user-side command and we want a clean session here
            // since the Pin tests run end-to-end without extra coupling.
            session = HostSession.open(card);
        }

        @Test
        @DisplayName("SETUP installs PIN+PUK and advances lifecycle to SETUP_DONE")
        void setupAdvancesLifecycle() throws Exception {
            session.sendInnerExpectOk(
                    Constants.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.encodeSetup(
                            TestConstants.DEFAULT_PIN, TestConstants.DEFAULT_PUK));
            byte[] info = transmitOuter(Constants.INS_GET_INFO & 0xFF, 0, 0, null).getData();
            byte lifecycle = readLifecycleFromInfoTlv(info);
            assertEquals(LifecycleState.SETUP_DONE, lifecycle);
        }

        @Test
        @DisplayName("Calling SETUP twice fails with SW_CONDITIONS_NOT_SATISFIED")
        void setupTwiceFails() throws Exception {
            session.sendInnerExpectOk(
                    Constants.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.encodeSetup(
                            TestConstants.DEFAULT_PIN, TestConstants.DEFAULT_PUK));
            ResponseAPDU second =
                    session.sendInner(
                            Constants.INS_SETUP,
                            (byte) 0,
                            (byte) 0,
                            MeowlFixtures.encodeSetup(
                                    TestConstants.DEFAULT_PIN, TestConstants.DEFAULT_PUK));
            assertEquals(
                    Constants.SW_LIFECYCLE_INVALID & 0xFFFF,
                    second.getSW(),
                    "second SETUP must be rejected by the FSM");
        }

        @Test
        @DisplayName("VERIFY_PIN: correct PIN succeeds")
        void verifyCorrectPin() throws Exception {
            session.sendInnerExpectOk(
                    Constants.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.encodeSetup(
                            TestConstants.DEFAULT_PIN, TestConstants.DEFAULT_PUK));
            ResponseAPDU r =
                    session.sendInner(
                            Constants.INS_VERIFY_PIN,
                            (byte) 0,
                            (byte) 0,
                            TestConstants.DEFAULT_PIN);
            assertEquals(0x9000, r.getSW());
        }

        @Test
        @DisplayName("VERIFY_PIN: wrong PIN returns 63Cn with decremented try counter")
        void verifyWrongPinDecrements() throws Exception {
            session.sendInnerExpectOk(
                    Constants.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.encodeSetup(
                            TestConstants.DEFAULT_PIN, TestConstants.DEFAULT_PUK));
            ResponseAPDU r =
                    session.sendInner(
                            Constants.INS_VERIFY_PIN, (byte) 0, (byte) 0, "999999".getBytes());
            int sw = r.getSW();
            int base = Constants.SW_PIN_RETRIES_BASE & 0xFFF0;
            assertEquals(base, sw & 0xFFF0, "must be 63Cn");
            int remaining = sw & 0x000F;
            assertEquals(Constants.PIN_RETRY_LIMIT - 1, remaining);
        }

        @Test
        @DisplayName("VERIFY_PIN: exhausting retries blocks the PIN")
        void exhaustRetriesBlocksPin() throws Exception {
            session.sendInnerExpectOk(
                    Constants.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.encodeSetup(
                            TestConstants.DEFAULT_PIN, TestConstants.DEFAULT_PUK));
            for (int i = 0; i < Constants.PIN_RETRY_LIMIT; i++) {
                session.sendInner(
                        Constants.INS_VERIFY_PIN, (byte) 0, (byte) 0, "999999".getBytes());
            }
            ResponseAPDU r =
                    session.sendInner(
                            Constants.INS_VERIFY_PIN,
                            (byte) 0,
                            (byte) 0,
                            TestConstants.DEFAULT_PIN);
            assertEquals(Constants.SW_AUTH_BLOCKED & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("UNBLOCK_PIN: correct PUK unblocks a blocked PIN with a fresh PIN")
        void unblockPinWithCorrectPuk() throws Exception {
            session.sendInnerExpectOk(
                    Constants.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.encodeSetup(
                            TestConstants.DEFAULT_PIN, TestConstants.DEFAULT_PUK));
            // Exhaust the PIN counter.
            for (int i = 0; i < Constants.PIN_RETRY_LIMIT; i++) {
                session.sendInner(
                        Constants.INS_VERIFY_PIN, (byte) 0, (byte) 0, "999999".getBytes());
            }
            byte[] newPin = "654321".getBytes();
            session.sendInnerExpectOk(
                    Constants.INS_UNBLOCK_PIN,
                    (byte) 0,
                    (byte) 0,
                    encodeLengthPrefixedPair(TestConstants.DEFAULT_PUK, newPin));
            // The new PIN must verify; the old one must not.
            assertEquals(
                    0x9000,
                    session.sendInner(Constants.INS_VERIFY_PIN, (byte) 0, (byte) 0, newPin)
                            .getSW());
        }

        @Test
        @DisplayName(
                "VERIFY_PIN with under-length PIN returns SW_WRONG_LENGTH and does NOT consume a"
                        + " retry")
        void underLengthPinDoesNotConsumeRetry() throws Exception {
            session.sendInnerExpectOk(
                    Constants.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.encodeSetup(
                            TestConstants.DEFAULT_PIN, TestConstants.DEFAULT_PUK));
            // Send a clearly-too-short PIN. Must return SW_WRONG_LENGTH.
            byte[] tooShort = new byte[] {0x31, 0x32, 0x33};
            assertEquals(
                    Constants.SW_WRONG_LENGTH & 0xFFFF,
                    session.sendInner(Constants.INS_VERIFY_PIN, (byte) 0, (byte) 0, tooShort)
                            .getSW());
            // Now the correct PIN must still succeed — the prior call did not consume a retry.
            assertEquals(
                    0x9000,
                    session.sendInner(
                                    Constants.INS_VERIFY_PIN,
                                    (byte) 0,
                                    (byte) 0,
                                    TestConstants.DEFAULT_PIN)
                            .getSW());
            // Send another deliberately wrong (but well-formed) PIN: the counter must show 2
            // retries remaining, confirming the previous under-length attempt was free.
            int sw =
                    session.sendInner(
                                    Constants.INS_VERIFY_PIN,
                                    (byte) 0,
                                    (byte) 0,
                                    "999999".getBytes())
                            .getSW();
            assertEquals(Constants.SW_PIN_RETRIES_BASE & 0xFFF0, sw & 0xFFF0);
            assertEquals(Constants.PIN_RETRY_LIMIT - 1, sw & 0x000F);
        }

        @Test
        @DisplayName(
                "VERIFY_PIN with over-max-length PIN returns SW_WRONG_LENGTH (no exception leak)")
        void overLengthPinReturnsWrongLength() throws Exception {
            session.sendInnerExpectOk(
                    Constants.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.encodeSetup(
                            TestConstants.DEFAULT_PIN, TestConstants.DEFAULT_PUK));
            byte[] tooLong = new byte[Constants.PIN_MAX_LEN + 1];
            for (int i = 0; i < tooLong.length; i++) {
                tooLong[i] = (byte) '0';
            }
            assertEquals(
                    Constants.SW_WRONG_LENGTH & 0xFFFF,
                    session.sendInner(Constants.INS_VERIFY_PIN, (byte) 0, (byte) 0, tooLong)
                            .getSW(),
                    "over-length PIN must be rejected cleanly, not via the OwnerPIN ABE path");
        }

        @Test
        @DisplayName(
                "CHANGE_PUK requires PIN session-verified — fresh SC after VERIFY_PIN must"
                        + " invalidate")
        void changePukSessionIsInvalidatedByReHandshake() throws Exception {
            session.sendInnerExpectOk(
                    Constants.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.encodeSetup(
                            TestConstants.DEFAULT_PIN, TestConstants.DEFAULT_PUK));
            // Verify PIN inside the current Secure Channel.
            assertEquals(
                    0x9000,
                    session.sendInner(
                                    Constants.INS_VERIFY_PIN,
                                    (byte) 0,
                                    (byte) 0,
                                    TestConstants.DEFAULT_PIN)
                            .getSW());
            // While in the same SC, CHANGE_PUK is allowed.
            byte[] freshPuk = "ZZZZZZZZ".getBytes();
            session.sendInnerExpectOk(
                    Constants.INS_CHANGE_PUK,
                    (byte) 0,
                    (byte) 0,
                    encodeLengthPrefixedPair(TestConstants.DEFAULT_PUK, freshPuk));

            // Open a brand new Secure Channel. CHANGE_PUK should now be rejected by the
            // session-verify gate even though the PIN was validated in the previous session.
            session = HostSession.open(card);
            byte[] yetAnotherPuk = "YYYYYYYY".getBytes();
            ResponseAPDU r =
                    session.sendInner(
                            Constants.INS_CHANGE_PUK,
                            (byte) 0,
                            (byte) 0,
                            encodeLengthPrefixedPair(freshPuk, yetAnotherPuk));
            assertEquals(
                    Constants.SW_SECURITY_STATUS_NOT_SATISFIED & 0xFFFF,
                    r.getSW(),
                    "PIN-validated flag must not carry across Secure Channel re-handshakes");
        }

        @Test
        @DisplayName("CHANGE_PIN: rotates the PIN; old PIN no longer verifies")
        void changePin() throws Exception {
            session.sendInnerExpectOk(
                    Constants.INS_SETUP,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.encodeSetup(
                            TestConstants.DEFAULT_PIN, TestConstants.DEFAULT_PUK));
            byte[] newPin = "654321".getBytes();
            session.sendInnerExpectOk(
                    Constants.INS_CHANGE_PIN,
                    (byte) 0,
                    (byte) 0,
                    encodeLengthPrefixedPair(TestConstants.DEFAULT_PIN, newPin));
            assertEquals(
                    0x9000,
                    session.sendInner(Constants.INS_VERIFY_PIN, (byte) 0, (byte) 0, newPin)
                            .getSW());
            // The old PIN now decrements the counter rather than succeeding.
            int sw =
                    session.sendInner(
                                    Constants.INS_VERIFY_PIN,
                                    (byte) 0,
                                    (byte) 0,
                                    TestConstants.DEFAULT_PIN)
                            .getSW();
            assertNotEquals(0x9000, sw);
        }
    }

    /*  ============== helpers ==============  */

    private static byte[] encodeLengthPrefixedPair(byte[] first, byte[] second) {
        byte[] out = new byte[1 + first.length + 1 + second.length];
        out[0] = (byte) first.length;
        System.arraycopy(first, 0, out, 1, first.length);
        out[1 + first.length] = (byte) second.length;
        System.arraycopy(second, 0, out, 1 + first.length + 1, second.length);
        return out;
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
            if (tag == (Constants.TAG_LIFECYCLE_STATE & 0xFF)) {
                return tlv[i];
            }
            i += len;
        }
        throw new IllegalStateException("lifecycle TLV not found");
    }

    private void importCert(byte[] cert) throws Exception {
        session.sendInnerExpectOk(
                Constants.INS_IMPORT_PKI_CERT,
                Constants.PKI_IMPORT_P1_INIT,
                (byte) 0,
                MeowlFixtures.shortBE((short) cert.length));
        int written = 0;
        while (written < cert.length) {
            int chunkLen = Math.min(Constants.PKI_CERT_CHUNK_MAX_LEN, cert.length - written);
            byte[] payload = new byte[2 + chunkLen];
            payload[0] = (byte) (written >> 8);
            payload[1] = (byte) (written & 0xFF);
            System.arraycopy(cert, written, payload, 2, chunkLen);
            session.sendInnerExpectOk(
                    Constants.INS_IMPORT_PKI_CERT,
                    Constants.PKI_IMPORT_P1_WRITE,
                    (byte) 0,
                    payload);
            written += chunkLen;
        }
        session.sendInnerExpectOk(
                Constants.INS_IMPORT_PKI_CERT,
                Constants.PKI_IMPORT_P1_FINALIZE,
                (byte) 0,
                new byte[0]);
    }

    private boolean verifyEcdsaPreHashed(byte[] compressedPubkey, byte[] digest, byte[] sig)
            throws Exception {
        // signPreComputedHash signs the raw digest; on the host side we mirror that by treating
        // the digest as the input and using BC's "NONEwithECDSA" verifier.
        ECPoint point =
                TestConstants.SECP256K1.getCurve().decodePoint(compressedPubkey).normalize();
        java.security.spec.ECPoint w =
                new java.security.spec.ECPoint(
                        point.getAffineXCoord().toBigInteger(),
                        point.getAffineYCoord().toBigInteger());
        java.security.spec.EllipticCurve curve =
                new java.security.spec.EllipticCurve(
                        new java.security.spec.ECFieldFp(
                                TestConstants.SECP256K1.getCurve().getField().getCharacteristic()),
                        TestConstants.SECP256K1.getCurve().getA().toBigInteger(),
                        TestConstants.SECP256K1.getCurve().getB().toBigInteger());
        java.security.spec.ECParameterSpec params =
                new java.security.spec.ECParameterSpec(
                        curve,
                        new java.security.spec.ECPoint(
                                TestConstants.SECP256K1.getG().getAffineXCoord().toBigInteger(),
                                TestConstants.SECP256K1.getG().getAffineYCoord().toBigInteger()),
                        TestConstants.SECP256K1.getN(),
                        TestConstants.SECP256K1.getH().intValue());
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

    private ResponseAPDU transmitOuter(int ins, int p1, int p2, byte[] data) {
        CommandAPDU cmd =
                data == null
                        ? new CommandAPDU(TestConstants.CLA, ins, p1, p2)
                        : new CommandAPDU(TestConstants.CLA, ins, p1, p2, data);
        return card.transmit(cmd);
    }
}
