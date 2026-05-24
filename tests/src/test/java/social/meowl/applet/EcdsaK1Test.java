/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

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
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * End-to-end tests for the {@code SIGN_ECDSA_K1} primitive — secp256k1 ECDSA signing under a
 * BIP-32-derived key.
 *
 * <p>The card draws a fresh random nonce per ECDSA signature (JC 3.0.5 does not expose an RFC 6979
 * hook), so the tests cannot pin {@code r,s} to a fixed expected pair. Instead each test verifies
 * the structural and cryptographic invariants: per call:
 *
 * <ol>
 *   <li>The signature verifies against the BIP-32-derived pubkey that {@code EXPORT_XPUB} would
 *       return for the same path (proving the card signs with the right scalar).
 *   <li>{@code s ≤ ⌊n/2⌋} (proving the on-card low-{@code s} normalisation per BIP-62 / EIP-2).
 * </ol>
 */
class EcdsaK1Test {

    private static final byte[] APPLET_AID_BYTES = {
        (byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x01
    };

    private static final int CLA = Constants.Wire.CLA & 0xFF;
    private static final int INS_INIT_SC = Constants.Wire.INS_INIT_SECURE_CHANNEL & 0xFF;
    private static final int INS_OPEN_SC = Constants.Wire.INS_OPEN_SECURE_CHANNEL & 0xFF;

    private static final X9ECParameters SECP256K1 = CustomNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters DOMAIN =
            new ECDomainParameters(
                    SECP256K1.getCurve(), SECP256K1.getG(), SECP256K1.getN(), SECP256K1.getH());
    private static final BigInteger HALF_N = SECP256K1.getN().shiftRight(1);
    private static final byte[] HKDF_INFO = "meowl-sc-v1".getBytes();
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final byte[] DEFAULT_PIN = "123456".getBytes();
    private static final byte[] DEFAULT_PUK = "ABCDEFGH".getBytes();

    /** BIP-32 test vector 1 seed (16 bytes). */
    private static final byte[] BIP32_VECTOR_1_SEED = hex("000102030405060708090a0b0c0d0e0f");

    private static final byte[] SAMPLE_DIGEST =
            hex("a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e");

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
        // SIGN_ECDSA_K1 needs a seeded card; install vector 1 seed before each test.
        sendInnerExpectOk(
                Constants.Wire.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(BIP32_VECTOR_1_SEED));
    }

    @Nested
    @DisplayName("ECDSA signing — happy path, verified against the derived pubkey")
    class HappyPath {

        @Test
        @DisplayName("m — sign at the master, verify with the master pubkey")
        void signAtMaster() {
            int[] path = new int[] {};
            byte[] pubkey = derivePubkey(path);
            byte[] sig = signEcdsa(path, SAMPLE_DIGEST);
            assertEquals(Constants.Ec.SIG_LEN_R_S, sig.length);
            assertTrue(
                    verifyEcdsa(pubkey, SAMPLE_DIGEST, sig),
                    "sig must verify under derived pubkey");
            assertLowS(sig);
        }

        @Test
        @DisplayName("m/0H — sign at a hardened child")
        void signAtHardenedChild() {
            int[] path = {0x80000000};
            byte[] pubkey = derivePubkey(path);
            byte[] sig = signEcdsa(path, SAMPLE_DIGEST);
            assertTrue(verifyEcdsa(pubkey, SAMPLE_DIGEST, sig));
            assertLowS(sig);
        }

        @Test
        @DisplayName("m/0H/1 — sign at a non-hardened grandchild")
        void signAtNonHardenedGrandchild() {
            int[] path = {0x80000000, 1};
            byte[] pubkey = derivePubkey(path);
            byte[] sig = signEcdsa(path, SAMPLE_DIGEST);
            assertTrue(verifyEcdsa(pubkey, SAMPLE_DIGEST, sig));
            assertLowS(sig);
        }

        @Test
        @DisplayName("m/0H/1/2H/2/1000000000 — sign at the deepest BIP-32 vector 1 path")
        void signAtDeepPath() {
            int[] path = {0x80000000, 1, 0x80000002, 2, 1000000000};
            byte[] pubkey = derivePubkey(path);
            byte[] sig = signEcdsa(path, SAMPLE_DIGEST);
            assertTrue(verifyEcdsa(pubkey, SAMPLE_DIGEST, sig));
            assertLowS(sig);
        }

        @Test
        @DisplayName("All-zero digest — degenerate but valid input must still sign and verify")
        void signAllZeroDigest() {
            int[] path = {0};
            byte[] pubkey = derivePubkey(path);
            byte[] sig = signEcdsa(path, new byte[Constants.Ec.DIGEST_LEN]);
            assertTrue(verifyEcdsa(pubkey, new byte[Constants.Ec.DIGEST_LEN], sig));
            assertLowS(sig);
        }

        @Test
        @DisplayName("Five different digests at the same path all verify and are all low-s")
        void multipleDigestsSamePath() {
            int[] path = {0x80000001};
            byte[] pubkey = derivePubkey(path);
            for (int i = 0; i < 5; i++) {
                byte[] digest = new byte[Constants.Ec.DIGEST_LEN];
                RANDOM.nextBytes(digest);
                byte[] sig = signEcdsa(path, digest);
                assertTrue(verifyEcdsa(pubkey, digest, sig), "iteration " + i);
                assertLowS(sig);
            }
        }

        @Test
        @DisplayName(
                "Two signatures over the same (path, digest) are both valid (nonce policy is"
                        + " environment-dependent)")
        void repeatedSignAtSamePathValid() {
            // Whether the bytes are identical or differ depends on the underlying ECDSA
            // implementation: real JCOP silicon draws a random k per signature (so sig1 ≠ sig2
            // with overwhelming probability), whereas JCardSim's BouncyCastle backend uses RFC
            // 6979 deterministic nonces (so sig1 == sig2). MEAP-6 documents both as acceptable
            // for v1.0; this test asserts only the property we actually rely on — that both
            // signatures verify under the derived pubkey.
            int[] path = {0};
            byte[] sig1 = signEcdsa(path, SAMPLE_DIGEST);
            byte[] sig2 = signEcdsa(path, SAMPLE_DIGEST);
            byte[] pubkey = derivePubkey(path);
            assertTrue(verifyEcdsa(pubkey, SAMPLE_DIGEST, sig1));
            assertTrue(verifyEcdsa(pubkey, SAMPLE_DIGEST, sig2));
            assertLowS(sig1);
            assertLowS(sig2);
        }
    }

    @Nested
    @DisplayName("ECDSA signing — host-side recovery byte computation works")
    class RecoveryByte {

        @Test
        @DisplayName("Host can recover v ∈ {0, 1} from (r, s, digest, pubkey)")
        void recoveryByteIsComputable() {
            int[] path = {0x80000000, 1};
            byte[] pubkey = derivePubkey(path);
            for (int i = 0; i < 5; i++) {
                byte[] digest = new byte[Constants.Ec.DIGEST_LEN];
                RANDOM.nextBytes(digest);
                byte[] sig = signEcdsa(path, digest);
                int v = recoverV(pubkey, digest, sig);
                assertTrue(v == 0 || v == 1, "v must be 0 or 1; got " + v);
            }
        }
    }

    @Nested
    @DisplayName("SIGN_ECDSA_K1 — negative / gating cases")
    class Negative {

        @Test
        @DisplayName("depth > HD_MAX_DEPTH is rejected with SW_WRONG_LENGTH")
        void depthTooDeep() {
            int[] tooDeep = new int[Constants.Hd.MAX_DEPTH + 1];
            for (int i = 0; i < tooDeep.length; i++) tooDeep[i] = 0x80000000 | i;
            ResponseAPDU r = signEcdsaResp(tooDeep, SAMPLE_DIGEST);
            assertEquals(Constants.Sw.WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("digest shorter than 32 bytes is rejected with SW_WRONG_LENGTH")
        void digestTooShort() {
            byte[] req = encodeSignRequest(new int[] {0}, new byte[16]);
            ResponseAPDU r = sendInner(Constants.Wire.INS_SIGN_ECDSA_K1, (byte) 0, (byte) 0, req);
            assertEquals(Constants.Sw.WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("Empty request is rejected with SW_WRONG_LENGTH")
        void emptyRequest() {
            ResponseAPDU r =
                    sendInner(Constants.Wire.INS_SIGN_ECDSA_K1, (byte) 0, (byte) 0, new byte[0]);
            assertEquals(Constants.Sw.WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("Truncated path (declared depth ≠ supplied bytes) is rejected")
        void truncatedPath() {
            // Claim depth=2 but only supply 4 bytes of path (one index) + 32-byte digest.
            byte[] req = new byte[1 + 4 + Constants.Ec.DIGEST_LEN];
            req[0] = 2; // depth = 2
            ResponseAPDU r = sendInner(Constants.Wire.INS_SIGN_ECDSA_K1, (byte) 0, (byte) 0, req);
            assertEquals(Constants.Sw.WRONG_LENGTH & 0xFFFF, r.getSW());
        }
    }

    @Nested
    @DisplayName("SIGN_ECDSA_K1 — lifecycle / PIN gating")
    class Gating {

        @Test
        @DisplayName("SIGN_ECDSA_K1 before SEEDED is rejected with SW_LIFECYCLE_INVALID")
        void signBeforeSeeded() throws Exception {
            // Re-build a fresh simulator that has not been seeded.
            simulator = new CardSimulator();
            AID aid = AIDUtil.create(APPLET_AID_BYTES);
            simulator.installApplet(aid, MeowlApplet.class);
            simulator.selectApplet(aid);
            session = openSession();
            bringToSetupDoneAndVerifyPin();
            // Do NOT import a seed: lifecycle is SETUP_DONE, not SEEDED.
            ResponseAPDU r = signEcdsaResp(new int[] {0}, SAMPLE_DIGEST);
            assertEquals(Constants.Sw.LIFECYCLE_INVALID & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("SIGN_ECDSA_K1 without a verified PIN is rejected (after SC re-handshake)")
        void signWithoutPinIsRejected() throws Exception {
            // Re-handshake clears the session-scoped PIN-verified flag.
            session = openSession();
            ResponseAPDU r = signEcdsaResp(new int[] {0}, SAMPLE_DIGEST);
            assertEquals(Constants.Sw.SECURITY_STATUS_NOT_SATISFIED & 0xFFFF, r.getSW());
        }
    }

    @Nested
    @DisplayName("Capability advertisement")
    class Capabilities {

        @Test
        @DisplayName("CAP_K1_ECDSA bit is now advertised in GET_INFO")
        void capK1EcdsaIsAdvertised() throws Exception {
            byte[] tlv = transmit(Constants.Wire.INS_GET_INFO & 0xFF, 0, 0, null).getData();
            short caps = readCapabilities(tlv);
            assertNotEquals(
                    (short) 0,
                    (short) (caps & Constants.Wire.CAP_K1_ECDSA),
                    "CAP_K1_ECDSA must be advertised");
        }
    }

    /*  ECDSA-specific helpers.  */

    private byte[] derivePubkey(int[] path) {
        byte[] req = encodeXpubRequest(Constants.Hd.CURVE_SECP256K1, path);
        byte[] resp = sendInnerExpectOk(Constants.Wire.INS_EXPORT_XPUB, (byte) 0, (byte) 0, req);
        return Arrays.copyOfRange(resp, 0, Constants.Ec.POINT_COMPRESSED_LEN);
    }

    private byte[] signEcdsa(int[] path, byte[] digest) {
        byte[] req = encodeSignRequest(path, digest);
        return sendInnerExpectOk(Constants.Wire.INS_SIGN_ECDSA_K1, (byte) 0, (byte) 0, req);
    }

    private ResponseAPDU signEcdsaResp(int[] path, byte[] digest) {
        byte[] req = encodeSignRequest(path, digest);
        return sendInner(Constants.Wire.INS_SIGN_ECDSA_K1, (byte) 0, (byte) 0, req);
    }

    private static byte[] encodeSignRequest(int[] path, byte[] digest) {
        byte[] out = new byte[1 + 4 * path.length + digest.length];
        out[0] = (byte) path.length;
        for (int i = 0; i < path.length; i++) {
            int idx = path[i];
            out[1 + i * 4] = (byte) (idx >>> 24);
            out[1 + i * 4 + 1] = (byte) (idx >>> 16);
            out[1 + i * 4 + 2] = (byte) (idx >>> 8);
            out[1 + i * 4 + 3] = (byte) idx;
        }
        System.arraycopy(digest, 0, out, 1 + 4 * path.length, digest.length);
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

    private static boolean verifyEcdsa(byte[] compressedPub, byte[] digest, byte[] sig64) {
        ECPoint pub = SECP256K1.getCurve().decodePoint(compressedPub).normalize();
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig64, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig64, 32, 64));
        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, new ECPublicKeyParameters(pub, DOMAIN));
        return verifier.verifySignature(digest, r, s);
    }

    private static void assertLowS(byte[] sig64) {
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig64, 32, 64));
        assertTrue(
                s.compareTo(HALF_N) <= 0,
                "s must be ≤ n/2 (low-s canonical form); got " + s.toString(16));
    }

    /**
     * Recovers the public-key recovery byte {@code v ∈ {0, 1}} from a low-{@code s} signature by
     * trying both candidates and comparing against the expected pubkey. This mirrors the host-side
     * recovery work that {@code docs/specs/meap-6.md} delegates off-card.
     */
    private static int recoverV(byte[] expectedCompressedPub, byte[] digest, byte[] sig64) {
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig64, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig64, 32, 64));
        BigInteger e = new BigInteger(1, digest);
        BigInteger n = SECP256K1.getN();
        for (int v = 0; v < 2; v++) {
            try {
                BigInteger x = r;
                if (x.compareTo(SECP256K1.getCurve().getField().getCharacteristic()) >= 0) continue;
                // Compress: 0x02 (even y) or 0x03 (odd y) per v.
                byte[] enc = new byte[33];
                enc[0] = (v == 0) ? (byte) 0x02 : (byte) 0x03;
                byte[] xBytes = bigIntToFixed(x, 32);
                System.arraycopy(xBytes, 0, enc, 1, 32);
                ECPoint R = SECP256K1.getCurve().decodePoint(enc).normalize();
                if (R == null || R.isInfinity()) continue;
                // Q = r⁻¹ (sR - eG)
                BigInteger rInv = r.modInverse(n);
                ECPoint Q =
                        R.multiply(s)
                                .subtract(SECP256K1.getG().multiply(e))
                                .multiply(rInv)
                                .normalize();
                if (Q.isInfinity()) continue;
                byte[] qEnc = Q.getEncoded(true);
                if (Arrays.equals(qEnc, expectedCompressedPub)) return v;
            } catch (Exception ignored) {
                // try next v
            }
        }
        return -1;
    }

    private static short readCapabilities(byte[] tlv) {
        int i = 0;
        while (i < tlv.length) {
            int tag = tlv[i++] & 0xFF;
            int len = tlv[i++] & 0xFF;
            if (tag == (Constants.Wire.TAG_CAPABILITIES & 0xFF)) {
                return (short) (((tlv[i] & 0xFF) << 8) | (tlv[i + 1] & 0xFF));
            }
            i += len;
        }
        throw new IllegalStateException("capabilities TLV not found");
    }

    /*  Generic helpers — identical in spirit to those in HdDerivationTest. Kept duplicated
     *  rather than extracted to a shared base class so each end-to-end test file remains
     *  self-contained (the same precedent PersonalisationTest and HdDerivationTest follow).  */

    private void bringToSetupDoneAndVerifyPin() throws Exception {
        byte[] cert = new byte[64];
        for (int i = 0; i < cert.length; i++) cert[i] = (byte) i;
        sendInnerExpectOk(
                Constants.Wire.INS_IMPORT_PKI_CERT,
                Constants.Pki.IMPORT_P1_INIT,
                (byte) 0,
                shortBE((short) cert.length));
        byte[] writePayload = new byte[2 + cert.length];
        System.arraycopy(cert, 0, writePayload, 2, cert.length);
        sendInnerExpectOk(
                Constants.Wire.INS_IMPORT_PKI_CERT,
                Constants.Pki.IMPORT_P1_WRITE,
                (byte) 0,
                writePayload);
        sendInnerExpectOk(
                Constants.Wire.INS_IMPORT_PKI_CERT,
                Constants.Pki.IMPORT_P1_FINALIZE,
                (byte) 0,
                new byte[0]);
        sendInnerExpectOk(Constants.Wire.INS_LOCK_PKI, (byte) 0, (byte) 0, new byte[0]);
        session = openSession();
        sendInnerExpectOk(
                Constants.Wire.INS_SETUP,
                (byte) 0,
                (byte) 0,
                encodeSetup(DEFAULT_PIN, DEFAULT_PUK));
        assertEquals(
                0x9000,
                sendInner(Constants.Wire.INS_VERIFY_PIN, (byte) 0, (byte) 0, DEFAULT_PIN).getSW());
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
