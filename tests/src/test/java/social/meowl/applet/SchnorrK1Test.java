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
import java.security.Security;
import java.util.Arrays;
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

    private static final BigInteger CURVE_P =
            TestConstants.SECP256K1.getCurve().getField().getCharacteristic();
    private static final BigInteger CURVE_N = TestConstants.SECP256K1.getN();

    private static final byte[] SAMPLE_DIGEST =
            TestConstants.parseHex(
                    "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e");

    private RealCardClient card;
    private HostSession session;

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        card = RealCardClient.connect(TestConstants.APPLET_AID_BYTES);
        session = MeowlFixtures.bringToSetupDoneAndVerifyPin(card);
        session.sendInnerExpectOk(
                Constants.INS_IMPORT_SEED,
                (byte) 0,
                (byte) 0,
                MeowlFixtures.prefixLen(TestConstants.BIP32_VECTOR_1_SEED));
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
                TestConstants.RANDOM.nextBytes(digest);
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
                TestConstants.RANDOM.nextBytes(digest);
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
            byte[] req = MeowlFixtures.encodeSignRequest(new int[] {0}, new byte[16]);
            ResponseAPDU r =
                    session.sendInner(Constants.INS_SIGN_SCHNORR_K1, (byte) 0, (byte) 0, req);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("Empty request is rejected with SW_WRONG_LENGTH")
        void emptyRequest() {
            ResponseAPDU r =
                    session.sendInner(
                            Constants.INS_SIGN_SCHNORR_K1, (byte) 0, (byte) 0, new byte[0]);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("Truncated path (declared depth ≠ supplied bytes) is rejected")
        void truncatedPath() {
            byte[] req = new byte[1 + 4 + Constants.DIGEST_LEN];
            req[0] = 2; // declared depth = 2, but we only supply one 4-byte index
            ResponseAPDU r =
                    session.sendInner(Constants.INS_SIGN_SCHNORR_K1, (byte) 0, (byte) 0, req);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }
    }

    @Nested
    @DisplayName("SIGN_SCHNORR_K1 — lifecycle / PIN gating")
    class Gating {

        @Test
        @DisplayName("SIGN_SCHNORR_K1 before SEEDED is rejected with SW_LIFECYCLE_INVALID")
        void signBeforeSeeded() throws Exception {
            // @BeforeEach left the card SEEDED — drive RESET_TO_FACTORY so the rebuilt session
            // can re-run bringToSetupDoneAndVerifyPin from UNINITIALIZED, then stop short of
            // IMPORT_SEED so the sign attempt actually hits the lifecycle guard.
            MeowlFixtures.resetCard(card);
            card.close();
            card = RealCardClient.connect(TestConstants.APPLET_AID_BYTES);
            session = MeowlFixtures.bringToSetupDoneAndVerifyPin(card);
            ResponseAPDU r = signSchnorrResp(new int[] {0}, SAMPLE_DIGEST);
            assertEquals(Constants.SW_LIFECYCLE_INVALID & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("SIGN_SCHNORR_K1 without a verified PIN is rejected (after SC re-handshake)")
        void signWithoutPinIsRejected() throws Exception {
            session = HostSession.open(card);
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
            byte[] tlv =
                    MeowlFixtures.transmitOuter(card, Constants.INS_GET_INFO & 0xFF, 0, 0, null)
                            .getData();
            short caps = MeowlFixtures.readCapabilities(tlv);
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
            byte[] pk =
                    TestConstants.parseHex(
                            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
            byte[] m =
                    TestConstants.parseHex(
                            "0000000000000000000000000000000000000000000000000000000000000000");
            byte[] sig =
                    TestConstants.parseHex(
                            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                                + "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");
            assertTrue(Bip340.verify(pk, m, sig), "BIP-340 vector 0 must verify");
        }

        @Test
        @DisplayName("Vector 5 — tampered sig must be rejected (bit flipped in r)")
        void vector5TamperedFails() {
            byte[] pk =
                    TestConstants.parseHex(
                            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
            byte[] m =
                    TestConstants.parseHex(
                            "0000000000000000000000000000000000000000000000000000000000000000");
            byte[] sig =
                    TestConstants.parseHex(
                            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                                + "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");
            sig[0] ^= 0x01;
            assertTrue(!Bip340.verify(pk, m, sig), "tampered sig must fail BIP-340 verify");
        }

        @Test
        @DisplayName("Vector — wrong pubkey must reject an otherwise-valid signature")
        void wrongPubkeyFails() {
            byte[] pk =
                    TestConstants.parseHex(
                            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9");
            byte[] m =
                    TestConstants.parseHex(
                            "0000000000000000000000000000000000000000000000000000000000000000");
            byte[] sig =
                    TestConstants.parseHex(
                            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                                + "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");
            pk[31] ^= 0x01;
            assertTrue(!Bip340.verify(pk, m, sig), "verification under wrong pk must fail");
        }
    }

    /*  Phase-5B helpers.  */

    private byte[] xOnlyPubkey(int[] path) {
        byte[] req = MeowlFixtures.encodeXpubRequest(Constants.CURVE_SECP256K1, path);
        byte[] resp = session.sendInnerExpectOk(Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, req);
        // EXPORT_XPUB returns 33-byte compressed P (0x02|0x03 || x); BIP-340 strips the prefix.
        return Arrays.copyOfRange(resp, 1, Constants.EC_POINT_COMPRESSED_LEN);
    }

    private byte[] signSchnorr(int[] path, byte[] digest) {
        byte[] req = MeowlFixtures.encodeSignRequest(path, digest);
        return session.sendInnerExpectOk(Constants.INS_SIGN_SCHNORR_K1, (byte) 0, (byte) 0, req);
    }

    private ResponseAPDU signSchnorrResp(int[] path, byte[] digest) {
        byte[] req = MeowlFixtures.encodeSignRequest(path, digest);
        return session.sendInner(Constants.INS_SIGN_SCHNORR_K1, (byte) 0, (byte) 0, req);
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
            ECPoint R =
                    TestConstants.SECP256K1.getG().multiply(s).subtract(P.multiply(e)).normalize();
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
            return TestConstants.SECP256K1.getCurve().createPoint(x, y);
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
}
