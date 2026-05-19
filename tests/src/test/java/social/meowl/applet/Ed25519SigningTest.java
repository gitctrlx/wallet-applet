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

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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
class Ed25519SigningTest {

    private static final byte[] APPLET_AID_BYTES = {
        (byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x01
    };

    private static final int CLA = Constants.CLA_MEOWL & 0xFF;
    private static final int INS_INIT_SC = Constants.INS_INIT_SECURE_CHANNEL & 0xFF;
    private static final int INS_OPEN_SC = Constants.INS_OPEN_SECURE_CHANNEL & 0xFF;

    private static final X9ECParameters SECP256K1 = CustomNamedCurves.getByName("secp256k1");
    private static final byte[] HKDF_INFO = "meowl-sc-v1".getBytes();
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final byte[] DEFAULT_PIN = "123456".getBytes();
    private static final byte[] DEFAULT_PUK = "ABCDEFGH".getBytes();

    /**
     * SLIP-10 Vector 1 seed — identical to BIP-32 Vector 1, reused from {@link HdDerivationTest}.
     */
    private static final byte[] SLIP10_VECTOR_1_SEED = hex("000102030405060708090a0b0c0d0e0f");

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

    private CardSimulator simulator;
    private Session session;

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        simulator = new CardSimulator();
        AID aid = AIDUtil.create(APPLET_AID_BYTES);
        simulator.installApplet(aid, MeowlApplet.class);
        simulator.selectApplet(aid);
        session = openSession();
        bringToSetupDoneAndVerifyPin();
        sendInnerExpectOk(
                Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(SLIP10_VECTOR_1_SEED));
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
            RANDOM.nextBytes(msg);
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
                RANDOM.nextBytes(msg);
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
                    hex("a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"), pk);
            byte[] sig = signEd25519(path, SAMPLE_MESSAGE);
            assertTrue(jdkVerify(pk, SAMPLE_MESSAGE, sig));
        }

        @Test
        @DisplayName("Vector 1 / m/0H — pubkey is 8c8a13…350c and the matching signature verifies")
        void vector1ZeroHardened() throws Exception {
            int[] path = {0x80000000};
            byte[] pk = ed25519Pubkey(path);
            assertArrayEquals(
                    hex("8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"), pk);
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
            ResponseAPDU r = sendInner(Constants.INS_SIGN_ED25519, (byte) 0, (byte) 0, new byte[0]);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("Declared depth exceeds available bytes — SW_WRONG_LENGTH")
        void truncatedPath() {
            // depth byte claims 2 levels but we only supply a 4-byte path slice.
            byte[] req = new byte[1 + 4];
            req[0] = 2;
            ResponseAPDU r = sendInner(Constants.INS_SIGN_ED25519, (byte) 0, (byte) 0, req);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("SLIP-10 non-hardened index in the path is rejected with SW_INCORRECT_P1P2")
        void nonHardenedRejected() {
            ResponseAPDU r = signEd25519Resp(new int[] {0}, SAMPLE_MESSAGE);
            assertEquals(Constants.SW_INCORRECT_P1P2 & 0xFFFF, r.getSW());
        }
    }

    @Nested
    @DisplayName("Lifecycle and PIN gating — same contract as the other sign primitives")
    class Lifecycle {

        @Test
        @DisplayName("SIGN_ED25519 before seed is loaded → SW_LIFECYCLE_INVALID")
        void signWithoutSeed() throws Exception {
            // Restart from a clean simulator without importing a seed.
            simulator = new CardSimulator();
            AID aid = AIDUtil.create(APPLET_AID_BYTES);
            simulator.installApplet(aid, MeowlApplet.class);
            simulator.selectApplet(aid);
            session = openSession();
            bringToSetupDoneAndVerifyPin();
            ResponseAPDU r = signEd25519Resp(new int[] {0x80000000}, SAMPLE_MESSAGE);
            assertEquals(Constants.SW_LIFECYCLE_INVALID & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("SIGN_ED25519 without a verified PIN is rejected (after SC re-handshake)")
        void signWithoutPin() throws Exception {
            session = openSession();
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
            byte[] tlv = transmit(Constants.INS_GET_INFO & 0xFF, 0, 0, null).getData();
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
        byte[] resp = sendInnerExpectOk(Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, req);
        // Response: pubkey(32) || chain_code(32). We only need the pubkey for verification.
        return Arrays.copyOfRange(resp, 0, Ed25519.PUBLIC_KEY_LEN);
    }

    private byte[] signEd25519(int[] path, byte[] msg) {
        byte[] req = encodeSignRequest(path, msg);
        return sendInnerExpectOk(Constants.INS_SIGN_ED25519, (byte) 0, (byte) 0, req);
    }

    private ResponseAPDU signEd25519Resp(int[] path, byte[] msg) {
        byte[] req = encodeSignRequest(path, msg);
        return sendInner(Constants.INS_SIGN_ED25519, (byte) 0, (byte) 0, req);
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

    /*  Boilerplate Secure-Channel + lifecycle helpers — same as SchnorrK1Test. Kept inline
     *  rather than extracted to a shared base so each end-to-end test file stays
     *  self-contained.  */

    private void bringToSetupDoneAndVerifyPin() throws Exception {
        byte[] cert = new byte[64];
        for (int i = 0; i < cert.length; i++) cert[i] = (byte) i;
        sendInnerExpectOk(
                Constants.INS_IMPORT_PKI_CERT,
                Constants.PKI_IMPORT_P1_INIT,
                (byte) 0,
                shortBE((short) cert.length));
        byte[] writePayload = new byte[2 + cert.length];
        System.arraycopy(cert, 0, writePayload, 2, cert.length);
        sendInnerExpectOk(
                Constants.INS_IMPORT_PKI_CERT,
                Constants.PKI_IMPORT_P1_WRITE,
                (byte) 0,
                writePayload);
        sendInnerExpectOk(
                Constants.INS_IMPORT_PKI_CERT,
                Constants.PKI_IMPORT_P1_FINALIZE,
                (byte) 0,
                new byte[0]);
        sendInnerExpectOk(Constants.INS_LOCK_PKI, (byte) 0, (byte) 0, new byte[0]);
        session = openSession();
        sendInnerExpectOk(
                Constants.INS_SETUP, (byte) 0, (byte) 0, encodeSetup(DEFAULT_PIN, DEFAULT_PUK));
        assertEquals(
                0x9000,
                sendInner(Constants.INS_VERIFY_PIN, (byte) 0, (byte) 0, DEFAULT_PIN).getSW());
    }

    private byte[] sendInnerExpectOk(byte ins, byte p1, byte p2, byte[] data) {
        ResponseAPDU r = sendInner(ins, p1, p2, data);
        assertEquals(0x9000, r.getSW(), "inner INS 0x" + Integer.toHexString(ins & 0xFF));
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
        out[0] = Constants.CLA_MEOWL;
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

    private static byte[] prefixLen(byte[] data) {
        byte[] out = new byte[1 + data.length];
        out[0] = (byte) data.length;
        System.arraycopy(data, 0, out, 1, data.length);
        return out;
    }

    private static byte[] shortBE(short v) {
        return new byte[] {(byte) (v >> 8), (byte) (v & 0xFF)};
    }

    private static byte[] hex(String h) {
        h = h.replace(" ", "");
        byte[] out = new byte[h.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
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
        byte[] cardEphPub = Arrays.copyOfRange(body, 0, Constants.EC_POINT_UNCOMPRESSED_LEN);

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
            byte[] iv = new byte[Constants.SC_BLOCK_LEN];
            for (int i = 0; i < 8; i++) {
                iv[Constants.SC_BLOCK_LEN - 1 - i] = (byte) ((counter >>> (8 * i)) & 0xFF);
            }
            byte[] padded = pkcs5Pad(plaintext);
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kEnc, "AES"), new IvParameterSpec(iv));
            byte[] ct = c.doFinal(padded);

            int lc = iv.length + ct.length + Constants.SC_MAC_LEN;
            byte[] header = {(byte) CLA, (byte) INS_OPEN_SC, 0x00, 0x00, (byte) lc};
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(kMac, "HmacSHA256"));
            m.update(header);
            m.update(iv);
            m.update(ct);
            byte[] tag = Arrays.copyOf(m.doFinal(), Constants.SC_MAC_LEN);

            byte[] out = new byte[lc];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            System.arraycopy(tag, 0, out, iv.length + ct.length, tag.length);
            return out;
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
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(kMac, "HmacSHA256"));
            m.update((byte) 0xFF);
            m.update(iv);
            m.update(ct);
            byte[] expected = Arrays.copyOf(m.doFinal(), Constants.SC_MAC_LEN);
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
            int rem = in.length % Constants.SC_BLOCK_LEN;
            int pad = Constants.SC_BLOCK_LEN - rem;
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
