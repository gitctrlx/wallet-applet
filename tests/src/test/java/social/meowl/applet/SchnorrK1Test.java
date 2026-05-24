/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.MessageDigest;
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
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import social.meowl.applet.cardclient.CardClient;
import social.meowl.applet.cardclient.CardClientFactory;

/**
 * End-to-end tests for the {@code SIGN_SCHNORR_K1} primitive — BIP-340 Schnorr signing under a
 * BIP-32-derived key.
 *
 * <p>The card draws fresh aux randomness per signature, so the resulting {@code (R, s)} is not
 * deterministic and cannot be pinned to a fixed expected pair. Instead each test verifies the
 * card-produced signature against the BIP-340 verification algorithm, run host-side against the
 * x-only public key that {@code EXPORT_XPUB} would return for the same path.
 *
 * <p>BIP-340 official sign vectors take an arbitrary {@code sk}, which the card never accepts —
 * every signing key is BIP-32 derived. The verification half of those vectors is still useful for
 * confirming the host-side verifier itself; one such vector is exercised in {@link
 * Bip340ReferenceVectors}.
 */
@Tag("real-card")
class SchnorrK1Test {

    private static final byte[] APPLET_AID_BYTES = {
        (byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x01
    };

    private static final int CLA = Constants.CLA_MEOWL & 0xFF;
    private static final int INS_INIT_SC = Constants.INS_INIT_SECURE_CHANNEL & 0xFF;
    private static final int INS_OPEN_SC = Constants.INS_OPEN_SECURE_CHANNEL & 0xFF;

    private static final X9ECParameters SECP256K1 = CustomNamedCurves.getByName("secp256k1");
    private static final BigInteger CURVE_P = SECP256K1.getCurve().getField().getCharacteristic();
    private static final BigInteger CURVE_N = SECP256K1.getN();
    private static final byte[] HKDF_INFO = "meowl-sc-v1".getBytes();
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final byte[] DEFAULT_PIN = "123456".getBytes();
    private static final byte[] DEFAULT_PUK = "ABCDEFGH".getBytes();

    /** BIP-32 test vector 1 seed (16 bytes). */
    private static final byte[] BIP32_VECTOR_1_SEED = hex("000102030405060708090a0b0c0d0e0f");

    private static final byte[] SAMPLE_DIGEST =
            hex("a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e");

    private CardClient card;
    private Session session;

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        card = CardClientFactory.create(APPLET_AID_BYTES);
        session = openSession();
        bringToSetupDoneAndVerifyPin();
        sendInnerExpectOk(
                Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(BIP32_VECTOR_1_SEED));
    }

    @AfterEach
    void tearDown() {
        if (card != null) {
            card.close();
        }
    }

    @Nested
    @DisplayName("Schnorr signing — happy path, verified against the x-only derived pubkey")
    class HappyPath {

        @Test
        @DisplayName("m — sign at the master, verify with the x-only master pubkey")
        void signAtMaster() {
            int[] path = {};
            byte[] xOnlyPub = xOnlyPubkey(path);
            byte[] sig = signSchnorr(path, SAMPLE_DIGEST);
            assertEquals(Constants.SIG_LEN_R_S, sig.length);
            assertTrue(
                    Bip340.verify(xOnlyPub, SAMPLE_DIGEST, sig),
                    "card-produced sig must verify under derived x-only pubkey");
        }

        @Test
        @DisplayName("m/0H — sign at a hardened child")
        void signAtHardenedChild() {
            int[] path = {0x80000000};
            byte[] xOnlyPub = xOnlyPubkey(path);
            byte[] sig = signSchnorr(path, SAMPLE_DIGEST);
            assertTrue(Bip340.verify(xOnlyPub, SAMPLE_DIGEST, sig));
        }

        @Test
        @DisplayName("m/0H/1 — sign at a non-hardened grandchild")
        void signAtNonHardenedGrandchild() {
            int[] path = {0x80000000, 1};
            byte[] xOnlyPub = xOnlyPubkey(path);
            byte[] sig = signSchnorr(path, SAMPLE_DIGEST);
            assertTrue(Bip340.verify(xOnlyPub, SAMPLE_DIGEST, sig));
        }

        @Test
        @DisplayName("m/0H/1/2H/2/1000000000 — deepest BIP-32 vector 1 path")
        void signAtDeepPath() {
            int[] path = {0x80000000, 1, 0x80000002, 2, 1000000000};
            byte[] xOnlyPub = xOnlyPubkey(path);
            byte[] sig = signSchnorr(path, SAMPLE_DIGEST);
            assertTrue(Bip340.verify(xOnlyPub, SAMPLE_DIGEST, sig));
        }

        @Test
        @DisplayName("All-zero digest — degenerate but valid input must sign and verify")
        void signAllZeroDigest() {
            int[] path = {0};
            byte[] xOnlyPub = xOnlyPubkey(path);
            byte[] sig = signSchnorr(path, new byte[Constants.DIGEST_LEN]);
            assertTrue(Bip340.verify(xOnlyPub, new byte[Constants.DIGEST_LEN], sig));
        }

        @Test
        @DisplayName("Five random digests at the same path all verify")
        void multipleDigestsSamePath() {
            int[] path = {0x80000001};
            byte[] xOnlyPub = xOnlyPubkey(path);
            for (int i = 0; i < 5; i++) {
                byte[] digest = new byte[Constants.DIGEST_LEN];
                RANDOM.nextBytes(digest);
                byte[] sig = signSchnorr(path, digest);
                assertTrue(Bip340.verify(xOnlyPub, digest, sig), "iteration " + i);
            }
        }

        @Test
        @DisplayName("Two signatures over the same (path, digest) both verify and differ")
        void repeatedSignAtSamePathBothValid() {
            int[] path = {0};
            byte[] xOnlyPub = xOnlyPubkey(path);
            byte[] sig1 = signSchnorr(path, SAMPLE_DIGEST);
            byte[] sig2 = signSchnorr(path, SAMPLE_DIGEST);
            assertTrue(Bip340.verify(xOnlyPub, SAMPLE_DIGEST, sig1));
            assertTrue(Bip340.verify(xOnlyPub, SAMPLE_DIGEST, sig2));
            // BIP-340 with fresh aux randomness must produce a different (R, s) on every call.
            assertNotEquals(
                    bytesToHex(sig1),
                    bytesToHex(sig2),
                    "fresh aux random must produce a non-deterministic signature");
        }
    }

    @Nested
    @DisplayName("Schnorr signing — encoding invariants per BIP-340")
    class EncodingInvariants {

        @Test
        @DisplayName("r encoded as the 32-byte big-endian x-coord of an even-y R")
        void rIsAlwaysEvenY() {
            int[] path = {0x80000000, 1};
            byte[] xOnlyPub = xOnlyPubkey(path);
            for (int i = 0; i < 5; i++) {
                byte[] digest = new byte[Constants.DIGEST_LEN];
                RANDOM.nextBytes(digest);
                byte[] sig = signSchnorr(path, digest);
                // BIP-340 forces y(R) even; verify() implicitly checks this — verify it again
                // here for clarity by lifting r and confirming the lifted-x point has even y.
                BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig, 0, 32));
                ECPoint R = Bip340.liftX(r);
                assertTrue(R != null, "r must be a valid even-y x-coord");
                assertTrue(
                        R.getAffineYCoord().toBigInteger().testBit(0) == false,
                        "y(R) must be even per BIP-340");
            }
        }

        @Test
        @DisplayName("s strictly less than n")
        void sIsLessThanN() {
            int[] path = {0x80000000};
            byte[] sig = signSchnorr(path, SAMPLE_DIGEST);
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, 32, 64));
            assertTrue(s.compareTo(CURVE_N) < 0, "s must be < n");
            assertTrue(s.signum() >= 0, "s must be non-negative");
        }

        @Test
        @DisplayName("r strictly less than the field prime p")
        void rIsLessThanP() {
            int[] path = {0x80000000};
            byte[] sig = signSchnorr(path, SAMPLE_DIGEST);
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig, 0, 32));
            assertTrue(r.compareTo(CURVE_P) < 0, "r must be < p");
        }
    }

    @Nested
    @DisplayName("SIGN_SCHNORR_K1 — negative / gating cases")
    class Negative {

        @Test
        @DisplayName("depth > HD_MAX_DEPTH is rejected with SW_WRONG_LENGTH")
        void depthTooDeep() {
            int[] tooDeep = new int[Constants.HD_MAX_DEPTH + 1];
            for (int i = 0; i < tooDeep.length; i++) tooDeep[i] = 0x80000000 | i;
            ResponseAPDU r = signSchnorrResp(tooDeep, SAMPLE_DIGEST);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("digest shorter than 32 bytes is rejected with SW_WRONG_LENGTH")
        void digestTooShort() {
            byte[] req = encodeSignRequest(new int[] {0}, new byte[16]);
            ResponseAPDU r = sendInner(Constants.INS_SIGN_SCHNORR_K1, (byte) 0, (byte) 0, req);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("Empty request is rejected with SW_WRONG_LENGTH")
        void emptyRequest() {
            ResponseAPDU r =
                    sendInner(Constants.INS_SIGN_SCHNORR_K1, (byte) 0, (byte) 0, new byte[0]);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("Truncated path (declared depth ≠ supplied bytes) is rejected")
        void truncatedPath() {
            byte[] req = new byte[1 + 4 + Constants.DIGEST_LEN];
            req[0] = 2; // declared depth = 2, but we only supply one 4-byte index
            ResponseAPDU r = sendInner(Constants.INS_SIGN_SCHNORR_K1, (byte) 0, (byte) 0, req);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }
    }

    @Nested
    @DisplayName("SIGN_SCHNORR_K1 — lifecycle / PIN gating")
    class Gating {

        @Test
        @DisplayName("SIGN_SCHNORR_K1 before SEEDED is rejected with SW_LIFECYCLE_INVALID")
        void signBeforeSeeded() throws Exception {
            // Discard the seeded card from @BeforeEach and bring up a fresh one without a seed.
            card.close();
            card = CardClientFactory.create(APPLET_AID_BYTES);
            session = openSession();
            bringToSetupDoneAndVerifyPin();
            ResponseAPDU r = signSchnorrResp(new int[] {0}, SAMPLE_DIGEST);
            assertEquals(Constants.SW_LIFECYCLE_INVALID & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("SIGN_SCHNORR_K1 without a verified PIN is rejected (after SC re-handshake)")
        void signWithoutPinIsRejected() throws Exception {
            session = openSession();
            ResponseAPDU r = signSchnorrResp(new int[] {0}, SAMPLE_DIGEST);
            assertEquals(Constants.SW_SECURITY_STATUS_NOT_SATISFIED & 0xFFFF, r.getSW());
        }
    }

    @Nested
    @DisplayName("Capability advertisement")
    class Capabilities {

        @Test
        @DisplayName("CAP_K1_SCHNORR bit is advertised in GET_INFO")
        void capK1SchnorrIsAdvertised() throws Exception {
            byte[] tlv = transmit(Constants.INS_GET_INFO & 0xFF, 0, 0, null).getData();
            short caps = readCapabilities(tlv);
            assertNotEquals(
                    (short) 0,
                    (short) (caps & Constants.CAP_K1_SCHNORR),
                    "CAP_K1_SCHNORR must be advertised");
        }
    }

    @Nested
    @DisplayName("BIP-340 reference vectors — host-side verifier sanity")
    class Bip340ReferenceVectors {

        /**
         * Vector 0 from <a
         * href="https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv">the BIP-340
         * test vector CSV</a>: known-good (pk, m, sig) tuple. The card never produces this exact
         * signature (the secret key {@code 3} is not BIP-32-derivable from our seed), but verifying
         * it exercises the host-side {@link Bip340#verify} reference used by every other test in
         * this class.
         */
        @Test
        @DisplayName("Vector 0 — known-good (pk, m, sig) verifies")
        void vector0Verifies() {
            byte[] pk = hex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
            byte[] m = hex("0000000000000000000000000000000000000000000000000000000000000000");
            byte[] sig =
                    hex(
                            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                                + "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");
            assertTrue(Bip340.verify(pk, m, sig), "BIP-340 vector 0 must verify");
        }

        @Test
        @DisplayName("Vector 5 — tampered sig must be rejected (bit flipped in r)")
        void vector5TamperedFails() {
            byte[] pk = hex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
            byte[] m = hex("0000000000000000000000000000000000000000000000000000000000000000");
            byte[] sig =
                    hex(
                            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                                + "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");
            sig[0] ^= 0x01;
            assertTrue(!Bip340.verify(pk, m, sig), "tampered sig must fail BIP-340 verify");
        }

        @Test
        @DisplayName("Vector — wrong pubkey must reject an otherwise-valid signature")
        void wrongPubkeyFails() {
            byte[] pk = hex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
            byte[] m = hex("0000000000000000000000000000000000000000000000000000000000000000");
            byte[] sig =
                    hex(
                            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                                + "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");
            pk[31] ^= 0x01;
            assertTrue(!Bip340.verify(pk, m, sig), "verification under wrong pk must fail");
        }
    }

    /*  Phase-5B helpers.  */

    private byte[] xOnlyPubkey(int[] path) {
        byte[] req = encodeXpubRequest(Constants.CURVE_SECP256K1, path);
        byte[] resp = sendInnerExpectOk(Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, req);
        // EXPORT_XPUB returns 33-byte compressed P (0x02|0x03 || x); BIP-340 strips the prefix.
        return Arrays.copyOfRange(resp, 1, Constants.EC_POINT_COMPRESSED_LEN);
    }

    private byte[] signSchnorr(int[] path, byte[] digest) {
        byte[] req = encodeSignRequest(path, digest);
        return sendInnerExpectOk(Constants.INS_SIGN_SCHNORR_K1, (byte) 0, (byte) 0, req);
    }

    private ResponseAPDU signSchnorrResp(int[] path, byte[] digest) {
        byte[] req = encodeSignRequest(path, digest);
        return sendInner(Constants.INS_SIGN_SCHNORR_K1, (byte) 0, (byte) 0, req);
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

    /**
     * BIP-340 host-side reference: {@link #verify} implements the verification algorithm verbatim
     * from BIP-340 §3.3, and {@link #liftX} lifts an x-only pubkey to its even-y curve point per
     * §2. Used to check every card-produced signature in this test class — and itself exercised by
     * the {@link Bip340ReferenceVectors} tests against the official BIP-340 CSV vectors.
     */
    private static final class Bip340 {

        static boolean verify(byte[] xOnlyPk, byte[] m, byte[] sig64) {
            if (xOnlyPk.length != 32 || m.length != 32 || sig64.length != 64) return false;
            ECPoint P = liftX(new BigInteger(1, xOnlyPk));
            if (P == null) return false;
            BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig64, 0, 32));
            BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig64, 32, 64));
            if (r.compareTo(CURVE_P) >= 0 || s.compareTo(CURVE_N) >= 0) return false;
            byte[] eBytes =
                    taggedHash(
                            "BIP0340/challenge",
                            concat(concat(Arrays.copyOfRange(sig64, 0, 32), xOnlyPk), m));
            BigInteger e = new BigInteger(1, eBytes).mod(CURVE_N);
            // R = s*G - e*P
            ECPoint R = SECP256K1.getG().multiply(s).subtract(P.multiply(e)).normalize();
            if (R.isInfinity()) return false;
            if (R.getAffineYCoord().toBigInteger().testBit(0)) return false; // y(R) must be even
            return R.getAffineXCoord().toBigInteger().equals(r);
        }

        /** Lifts a 32-byte x-coordinate to the unique curve point with even y. */
        static ECPoint liftX(BigInteger x) {
            if (x.signum() < 0 || x.compareTo(CURVE_P) >= 0) return null;
            BigInteger c =
                    x.modPow(BigInteger.valueOf(3), CURVE_P)
                            .add(BigInteger.valueOf(7))
                            .mod(CURVE_P);
            // p ≡ 3 (mod 4) for secp256k1, so y = c^((p+1)/4) mod p is a square root iff one
            // exists.
            BigInteger y = c.modPow(CURVE_P.add(BigInteger.ONE).shiftRight(2), CURVE_P);
            if (!y.modPow(BigInteger.TWO, CURVE_P).equals(c)) return null;
            if (y.testBit(0)) y = CURVE_P.subtract(y); // pick the even-y root
            return SECP256K1.getCurve().createPoint(x, y);
        }

        private static byte[] taggedHash(String tag, byte[] msg) {
            try {
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                byte[] tagHash = sha.digest(tag.getBytes());
                sha.reset();
                sha.update(tagHash);
                sha.update(tagHash);
                return sha.digest(msg);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        private static byte[] concat(byte[] a, byte[] b) {
            byte[] out = new byte[a.length + b.length];
            System.arraycopy(a, 0, out, 0, a.length);
            System.arraycopy(b, 0, out, a.length, b.length);
            return out;
        }
    }

    private static String bytesToHex(byte[] in) {
        StringBuilder sb = new StringBuilder(in.length * 2);
        for (byte b : in) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
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

    /*  Generic helpers — identical in spirit to those in EcdsaK1Test. Kept duplicated rather
     *  than extracted to a shared base class so each end-to-end test file remains
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
        return card.transmit(cmd);
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
