/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import social.meowl.applet.cardclient.CardClient;
import social.meowl.applet.cardclient.CardClientFactory;
import social.meowl.applet.testkit.HostSession;
import social.meowl.applet.testkit.MeowlFixtures;
import social.meowl.applet.testkit.TestConstants;

/**
 * End-to-end tests for the {@code SIGN_ED25519} primitive — RFC 8032 Ed25519 signing under a
 * SLIP-10-derived key.
 *
 * <p>Every card-produced signature is checked against the JDK's built-in {@code Ed25519} verifier
 * (Java 15+, no BouncyCastle dependency needed for the verify path) using the compressed public key
 * that {@code EXPORT_XPUB} returns for the same path. The card derives deterministic signatures (no
 * aux randomness), so the test also pins the {@code (sk, M) → sig} mapping against itself across
 * repeated calls.
 *
 * <p>The SLIP-10 vector 1 seed is also exercised by {@link HdDerivationTest} so the public-key half
 * can be cross-checked against the official SLIP-10 reference vectors — the same pubkeys {@link
 * HdDerivationTest} expects from {@code EXPORT_XPUB} are the ones whose signatures the JDK verifier
 * accepts here, closing the loop {@code seed → SLIP-10 → leaf k → A = s·B → sign}.
 */
@Tag("real-card")
class Ed25519SigningTest {

    /**
     * SLIP-10 Vector 1 seed — identical to BIP-32 Vector 1, reused from {@link HdDerivationTest}.
     */
    private static final byte[] SLIP10_VECTOR_1_SEED = TestConstants.BIP32_VECTOR_1_SEED;

    /** A short, fixed sample payload used by most non-edge tests. */
    private static final byte[] SAMPLE_MESSAGE = "Hello, meowl Ed25519!".getBytes();

    /** X.509 SubjectPublicKeyInfo prefix that wraps a 32-byte Ed25519 RFC 8032 pubkey. */
    private static final byte[] ED25519_X509_PREFIX = {
        (byte) 0x30, (byte) 0x2A, (byte) 0x30, (byte) 0x05,
        (byte) 0x06, (byte) 0x03, (byte) 0x2B, (byte) 0x65,
        (byte) 0x70, (byte) 0x03, (byte) 0x21, (byte) 0x00,
    };

    /** PKCS8 PrivateKeyInfo prefix that wraps a 32-byte Ed25519 RFC 8032 raw private key. */
    private static final byte[] ED25519_PKCS8_PREFIX = {
        (byte) 0x30, (byte) 0x2E, (byte) 0x02, (byte) 0x01,
        (byte) 0x00, (byte) 0x30, (byte) 0x05, (byte) 0x06,
        (byte) 0x03, (byte) 0x2B, (byte) 0x65, (byte) 0x70,
        (byte) 0x04, (byte) 0x22, (byte) 0x04, (byte) 0x20,
    };

    private CardClient card;
    private HostSession session;

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        card = CardClientFactory.create(TestConstants.APPLET_AID_BYTES);
        session = MeowlFixtures.bringToSetupDoneAndVerifyPin(card);
        session.sendInnerExpectOk(
                Constants.INS_IMPORT_SEED,
                (byte) 0,
                (byte) 0,
                MeowlFixtures.prefixLen(SLIP10_VECTOR_1_SEED));
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
    @DisplayName("Signature verifies with the JDK Ed25519 implementation across path depths")
    class SignVerify {

        @Test
        @DisplayName("Sign at the master path m — JDK verifier accepts")
        void signAtMaster() throws Exception {
            int[] path = {};
            byte[] pk = ed25519Pubkey(path);
            byte[] sig = signEd25519(path, SAMPLE_MESSAGE);
            assertEquals(Ed25519.SIGNATURE_LEN, sig.length);
            assertTrue(jdkVerify(pk, SAMPLE_MESSAGE, sig));
        }

        @Test
        @DisplayName("Sign at hardened child m/0H — JDK verifier accepts")
        void signAtHardenedChild() throws Exception {
            int[] path = {0x80000000};
            byte[] pk = ed25519Pubkey(path);
            byte[] sig = signEd25519(path, SAMPLE_MESSAGE);
            assertTrue(jdkVerify(pk, SAMPLE_MESSAGE, sig));
        }

        @Test
        @DisplayName("Sign at deep mixed-hardened path — JDK verifier accepts")
        void signAtDeepPath() throws Exception {
            // SLIP-10 forbids non-hardened indices on ed25519, so every level is hardened.
            int[] path = {0x80000000, 0x80000001, 0x80000002, 0x80000003, 0x80000004};
            byte[] pk = ed25519Pubkey(path);
            byte[] sig = signEd25519(path, SAMPLE_MESSAGE);
            assertTrue(jdkVerify(pk, SAMPLE_MESSAGE, sig));
        }
    }

    @Nested
    @DisplayName("Message-length coverage — zero, one byte, large, and random sizes")
    class MessageLengths {

        @Test
        @DisplayName("Empty message — RFC 8032 explicitly supports |M| = 0")
        void emptyMessage() throws Exception {
            int[] path = {0x80000000};
            byte[] pk = ed25519Pubkey(path);
            byte[] sig = signEd25519(path, new byte[0]);
            assertTrue(jdkVerify(pk, new byte[0], sig));
        }

        @Test
        @DisplayName("Single-byte message")
        void singleByteMessage() throws Exception {
            int[] path = {0x80000000};
            byte[] pk = ed25519Pubkey(path);
            byte[] sig = signEd25519(path, new byte[] {0x42});
            assertTrue(jdkVerify(pk, new byte[] {0x42}, sig));
        }

        @Test
        @DisplayName("32-byte message — same length as a hash digest")
        void thirtyTwoByteMessage() throws Exception {
            int[] path = {0x80000000};
            byte[] msg = new byte[32];
            TestConstants.RANDOM.nextBytes(msg);
            byte[] pk = ed25519Pubkey(path);
            byte[] sig = signEd25519(path, msg);
            assertTrue(jdkVerify(pk, msg, sig));
        }

        @Test
        @DisplayName("Random short messages — every length 0..64 verifies")
        void randomShortMessages() throws Exception {
            int[] path = {0x80000000};
            byte[] pk = ed25519Pubkey(path);
            for (int len = 0; len <= 64; len++) {
                byte[] msg = new byte[len];
                TestConstants.RANDOM.nextBytes(msg);
                byte[] sig = signEd25519(path, msg);
                assertTrue(jdkVerify(pk, msg, sig), "len=" + len);
            }
        }
    }

    @Nested
    @DisplayName("Determinism — RFC 8032 mandates (sk, M) → sig is deterministic")
    class Determinism {

        @Test
        @DisplayName("Two signatures at the same path and message are byte-identical")
        void deterministicSignatures() {
            int[] path = {0x80000000};
            byte[] sig1 = signEd25519(path, SAMPLE_MESSAGE);
            byte[] sig2 = signEd25519(path, SAMPLE_MESSAGE);
            assertArrayEquals(sig1, sig2, "Ed25519 must be deterministic across calls");
        }

        @Test
        @DisplayName("Different messages produce different signatures (under the same key)")
        void differentMessages() {
            int[] path = {0x80000000};
            byte[] sig1 = signEd25519(path, SAMPLE_MESSAGE);
            byte[] sig2 = signEd25519(path, "Hello, meowl Ed25519?".getBytes());
            assertFalse(
                    Arrays.equals(sig1, sig2), "different messages must produce different sigs");
        }
    }

    @Nested
    @DisplayName("SLIP-10 vector cross-check — pubkey matches the official SLIP-10 vectors")
    class Slip10Crosscheck {

        @Test
        @DisplayName("Vector 1 / m — pubkey is a4b285…88ed and the matching signature verifies")
        void vector1Master() throws Exception {
            int[] path = {};
            byte[] pk = ed25519Pubkey(path);
            assertArrayEquals(
                    TestConstants.parseHex(
                            "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"),
                    pk);
            byte[] sig = signEd25519(path, SAMPLE_MESSAGE);
            assertTrue(jdkVerify(pk, SAMPLE_MESSAGE, sig));
        }

        @Test
        @DisplayName("Vector 1 / m/0H — pubkey is 8c8a13…350c and the matching signature verifies")
        void vector1ZeroHardened() throws Exception {
            int[] path = {0x80000000};
            byte[] pk = ed25519Pubkey(path);
            assertArrayEquals(
                    TestConstants.parseHex(
                            "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"),
                    pk);
            byte[] sig = signEd25519(path, SAMPLE_MESSAGE);
            assertTrue(jdkVerify(pk, SAMPLE_MESSAGE, sig));
        }
    }

    @Nested
    @DisplayName("Negative paths and tamper detection")
    class Negative {

        @Test
        @DisplayName("Tampered signature is rejected by the verifier (sanity-check the test rig)")
        void tamperedSigRejected() throws Exception {
            int[] path = {0x80000000};
            byte[] pk = ed25519Pubkey(path);
            byte[] sig = signEd25519(path, SAMPLE_MESSAGE);
            sig[0] ^= 0x01;
            assertFalse(jdkVerify(pk, SAMPLE_MESSAGE, sig));
        }

        @Test
        @DisplayName("Verifying with the wrong pubkey fails")
        void wrongPubkeyRejected() throws Exception {
            int[] path = {0x80000000};
            byte[] pk = ed25519Pubkey(path);
            byte[] sig = signEd25519(path, SAMPLE_MESSAGE);
            // Use the pubkey at a different path — the resulting sig is valid for `path` but
            // must not verify under another path's pubkey.
            byte[] otherPk = ed25519Pubkey(new int[] {0x80000001});
            assertFalse(jdkVerify(otherPk, SAMPLE_MESSAGE, sig));
        }

        @Test
        @DisplayName("depth > HD_MAX_DEPTH is rejected with SW_WRONG_LENGTH")
        void depthTooDeep() {
            int[] tooDeep = new int[Constants.HD_MAX_DEPTH + 1];
            for (int i = 0; i < tooDeep.length; i++) tooDeep[i] = 0x80000000 | i;
            ResponseAPDU r = signEd25519Resp(tooDeep, SAMPLE_MESSAGE);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("Empty request body is rejected with SW_WRONG_LENGTH")
        void emptyRequest() {
            ResponseAPDU r =
                    session.sendInner(Constants.INS_SIGN_ED25519, (byte) 0, (byte) 0, new byte[0]);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("Declared depth exceeds available bytes — SW_WRONG_LENGTH")
        void truncatedPath() {
            // depth byte claims 2 levels but we only supply a 4-byte path slice.
            byte[] req = new byte[1 + 4];
            req[0] = 2;
            ResponseAPDU r = session.sendInner(Constants.INS_SIGN_ED25519, (byte) 0, (byte) 0, req);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName(
                "SLIP-10 non-hardened index in the path is rejected with"
                        + " SW_CONDITIONS_NOT_SATISFIED")
        void nonHardenedRejected() {
            // 6985 (conditions not satisfied) is the semantically correct status word — 6A86
            // (incorrect P1/P2) is reserved for malformed APDU headers, not for policy
            // violations carried inside the inner data field.
            ResponseAPDU r = signEd25519Resp(new int[] {0}, SAMPLE_MESSAGE);
            assertEquals(Constants.SW_CONDITIONS_NOT_SATISFIED & 0xFFFF, r.getSW());
        }
    }

    @Nested
    @DisplayName("Lifecycle and PIN gating — same contract as the other sign primitives")
    class Lifecycle {

        @Test
        @DisplayName("SIGN_ED25519 before seed is loaded → SW_LIFECYCLE_INVALID")
        void signWithoutSeed() throws Exception {
            // @BeforeEach left the card SEEDED — drive RESET_TO_FACTORY so the rebuilt session
            // can re-run bringToSetupDoneAndVerifyPin from UNINITIALIZED, then stop short of
            // IMPORT_SEED so the sign attempt actually hits the lifecycle guard.
            MeowlFixtures.resetCard(card);
            card.close();
            card = CardClientFactory.create(TestConstants.APPLET_AID_BYTES);
            session = MeowlFixtures.bringToSetupDoneAndVerifyPin(card);
            ResponseAPDU r = signEd25519Resp(new int[] {0x80000000}, SAMPLE_MESSAGE);
            assertEquals(Constants.SW_LIFECYCLE_INVALID & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("SIGN_ED25519 without a verified PIN is rejected (after SC re-handshake)")
        void signWithoutPin() throws Exception {
            session = HostSession.open(card);
            ResponseAPDU r = signEd25519Resp(new int[] {0x80000000}, SAMPLE_MESSAGE);
            assertEquals(Constants.SW_SECURITY_STATUS_NOT_SATISFIED & 0xFFFF, r.getSW());
        }
    }

    @Nested
    @DisplayName("Byte-for-byte cross-check against an independent SLIP-10 + JDK Ed25519 stack")
    class ByteForByte {

        @Test
        @DisplayName("Card sig at m equals JDK sig over the same SLIP-10 leaf key")
        void byteEqualAtMaster() throws Exception {
            int[] path = {};
            byte[] cardSig = signEd25519(path, SAMPLE_MESSAGE);
            byte[] sk = slip10DeriveLeafKey(SLIP10_VECTOR_1_SEED, path);
            byte[] hostSig = jdkSign(sk, SAMPLE_MESSAGE);
            assertArrayEquals(hostSig, cardSig, "Ed25519 RFC 8032 determinism must be byte-equal");
        }

        @Test
        @DisplayName("Card sig at m/0H equals JDK sig over the same SLIP-10 leaf key")
        void byteEqualAtHardenedChild() throws Exception {
            int[] path = {0x80000000};
            byte[] cardSig = signEd25519(path, SAMPLE_MESSAGE);
            byte[] sk = slip10DeriveLeafKey(SLIP10_VECTOR_1_SEED, path);
            byte[] hostSig = jdkSign(sk, SAMPLE_MESSAGE);
            assertArrayEquals(hostSig, cardSig);
        }

        @Test
        @DisplayName("Card sig over empty message equals JDK sig (RFC 8032 |M| = 0 path)")
        void byteEqualEmptyMessage() throws Exception {
            int[] path = {0x80000000};
            byte[] cardSig = signEd25519(path, new byte[0]);
            byte[] sk = slip10DeriveLeafKey(SLIP10_VECTOR_1_SEED, path);
            byte[] hostSig = jdkSign(sk, new byte[0]);
            assertArrayEquals(hostSig, cardSig);
        }

        @Test
        @DisplayName("Card sig at deep hardened path equals JDK sig (5-level)")
        void byteEqualAtDeepPath() throws Exception {
            int[] path = {0x80000000, 0x80000001, 0x80000002, 0x80000003, 0x80000004};
            byte[] cardSig = signEd25519(path, SAMPLE_MESSAGE);
            byte[] sk = slip10DeriveLeafKey(SLIP10_VECTOR_1_SEED, path);
            byte[] hostSig = jdkSign(sk, SAMPLE_MESSAGE);
            assertArrayEquals(hostSig, cardSig);
        }
    }

    @Nested
    @DisplayName("Capability advertisement")
    class Capabilities {

        @Test
        @DisplayName("CAP_ED25519 bit is advertised in GET_INFO")
        void capEd25519IsAdvertised() throws Exception {
            byte[] tlv = transmitOuter(Constants.INS_GET_INFO & 0xFF, 0, 0, null).getData();
            short caps = readCapabilities(tlv);
            assertNotEquals(
                    (short) 0,
                    (short) (caps & Constants.CAP_ED25519),
                    "CAP_ED25519 must be advertised");
        }
    }

    /*  Ed25519-specific helpers.  */

    private byte[] ed25519Pubkey(int[] path) {
        byte[] req = encodeXpubRequest(Constants.CURVE_ED25519, path);
        byte[] resp = session.sendInnerExpectOk(Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, req);
        // Response: pubkey(32) || chain_code(32). We only need the pubkey for verification.
        return Arrays.copyOfRange(resp, 0, Ed25519.PUBLIC_KEY_LEN);
    }

    private byte[] signEd25519(int[] path, byte[] msg) {
        byte[] req = encodeSignRequest(path, msg);
        return session.sendInnerExpectOk(Constants.INS_SIGN_ED25519, (byte) 0, (byte) 0, req);
    }

    private ResponseAPDU signEd25519Resp(int[] path, byte[] msg) {
        byte[] req = encodeSignRequest(path, msg);
        return session.sendInner(Constants.INS_SIGN_ED25519, (byte) 0, (byte) 0, req);
    }

    private static byte[] encodeSignRequest(int[] path, byte[] msg) {
        byte[] out = new byte[1 + 4 * path.length + msg.length];
        out[0] = (byte) path.length;
        for (int i = 0; i < path.length; i++) {
            int idx = path[i];
            out[1 + i * 4] = (byte) (idx >>> 24);
            out[1 + i * 4 + 1] = (byte) (idx >>> 16);
            out[1 + i * 4 + 2] = (byte) (idx >>> 8);
            out[1 + i * 4 + 3] = (byte) idx;
        }
        System.arraycopy(msg, 0, out, 1 + 4 * path.length, msg.length);
        return out;
    }

    private static byte[] encodeXpubRequest(byte curve, int[] path) {
        byte[] out = new byte[2 + 4 * path.length];
        out[0] = curve;
        out[1] = (byte) path.length;
        for (int i = 0; i < path.length; i++) {
            int idx = path[i];
            out[2 + i * 4] = (byte) (idx >>> 24);
            out[2 + i * 4 + 1] = (byte) (idx >>> 16);
            out[2 + i * 4 + 2] = (byte) (idx >>> 8);
            out[2 + i * 4 + 3] = (byte) idx;
        }
        return out;
    }

    /**
     * Independent SLIP-10 Ed25519 leaf-key derivation in the test process — used by {@link
     * ByteForByte} to compute the same 32-byte private key the card materialises internally, so
     * that JDK-side signatures can be compared byte-for-byte against card output. Mirrors {@link
     * Slip10} verbatim: HMAC-SHA-512 of the seed under the {@code "ed25519 seed"} key,
     * hardened-only descent.
     */
    private static byte[] slip10DeriveLeafKey(byte[] seed, int[] path) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA512");
        hmac.init(new SecretKeySpec("ed25519 seed".getBytes(), "HmacSHA512"));
        byte[] iLR = hmac.doFinal(seed);
        byte[] k = Arrays.copyOfRange(iLR, 0, 32);
        byte[] c = Arrays.copyOfRange(iLR, 32, 64);
        for (int idx : path) {
            byte[] data = new byte[1 + 32 + 4];
            data[0] = 0x00;
            System.arraycopy(k, 0, data, 1, 32);
            data[33] = (byte) (idx >>> 24);
            data[34] = (byte) (idx >>> 16);
            data[35] = (byte) (idx >>> 8);
            data[36] = (byte) idx;
            hmac.init(new SecretKeySpec(c, "HmacSHA512"));
            byte[] I = hmac.doFinal(data);
            k = Arrays.copyOfRange(I, 0, 32);
            c = Arrays.copyOfRange(I, 32, 64);
        }
        return k;
    }

    /**
     * Independent JDK-side Ed25519 signer. Wraps the 32-byte RFC 8032 raw private key in a PKCS8
     * {@code PrivateKeyInfo} envelope, then runs the JDK's {@code Signature.getInstance("Ed25519")}
     * signer (Java 15+, no provider required). Used to cross-check the card's deterministic
     * signature output against an independent reference implementation.
     */
    private static byte[] jdkSign(byte[] sk32, byte[] msg) throws Exception {
        byte[] pkcs8 = new byte[ED25519_PKCS8_PREFIX.length + 32];
        System.arraycopy(ED25519_PKCS8_PREFIX, 0, pkcs8, 0, ED25519_PKCS8_PREFIX.length);
        System.arraycopy(sk32, 0, pkcs8, ED25519_PKCS8_PREFIX.length, 32);
        PrivateKey priv =
                KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(priv);
        s.update(msg);
        return s.sign();
    }

    /**
     * JDK-side Ed25519 verifier. Wraps the 32-byte RFC 8032 pubkey in an X.509 {@code
     * SubjectPublicKeyInfo} envelope so the standard {@link KeyFactory} accepts it, then runs the
     * JDK's {@code Signature.getInstance("Ed25519")} verifier (Java 15+, no provider required).
     * Returns {@code false} on any exception so that tamper tests cleanly fail.
     */
    private static boolean jdkVerify(byte[] pk32, byte[] msg, byte[] sig64) {
        try {
            byte[] x509 = new byte[ED25519_X509_PREFIX.length + 32];
            System.arraycopy(ED25519_X509_PREFIX, 0, x509, 0, ED25519_X509_PREFIX.length);
            System.arraycopy(pk32, 0, x509, ED25519_X509_PREFIX.length, 32);
            PublicKey pub =
                    KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(x509));
            Signature v = Signature.getInstance("Ed25519");
            v.initVerify(pub);
            v.update(msg);
            return v.verify(sig64);
        } catch (Exception e) {
            return false;
        }
    }

    private static short readCapabilities(byte[] tlv) {
        int i = 0;
        while (i < tlv.length) {
            int tag = tlv[i++] & 0xFF;
            int len = tlv[i++] & 0xFF;
            if (tag == (Constants.TAG_CAPABILITIES & 0xFF)) {
                return (short) (((tlv[i] & 0xFF) << 8) | (tlv[i + 1] & 0xFF));
            }
            i += len;
        }
        throw new IllegalStateException("capabilities TLV not found");
    }

    private ResponseAPDU transmitOuter(int ins, int p1, int p2, byte[] data) {
        CommandAPDU cmd =
                data == null
                        ? new CommandAPDU(TestConstants.CLA, ins, p1, p2)
                        : new CommandAPDU(TestConstants.CLA, ins, p1, p2, data);
        return card.transmit(cmd);
    }
}
