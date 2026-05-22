/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

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
 * End-to-end HD derivation tests — master seed import, card-generated seed, BIP-32 secp256k1
 * derivation verified against the official BIP-32 vectors, and SLIP-10 Ed25519 derivation verified
 * against the official SLIP-10 vectors.
 */
class HdDerivationTest {

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

    /** BIP-32 test vector 1 seed (16 bytes hex 000102030405060708090a0b0c0d0e0f). */
    private static final byte[] BIP32_VECTOR_1_SEED = hex("000102030405060708090a0b0c0d0e0f");

    /** BIP-32 test vector 2 seed (64 bytes — exercises the upper bound of {@code SEED_MAX_LEN}). */
    private static final byte[] BIP32_VECTOR_2_SEED =
            hex(
                    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f"
                            + "9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");

    /**
     * BIP-32 test vector 3 seed — chosen by the spec authors to exercise the case where {@code I_L}
     * from the first hardened child has a leading zero byte, which any naïve implementation that
     * prefix-trims would mishandle.
     */
    private static final byte[] BIP32_VECTOR_3_SEED =
            hex(
                    "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4ac"
                            + "ba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be");

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
        // Walk the card to SETUP_DONE: install a tiny PKI cert, lock, run SETUP, verify PIN.
        bringToSetupDoneAndVerifyPin();
    }

    @Nested
    @DisplayName("IMPORT_SEED / GENERATE_SEED")
    class SeedInstall {

        @Test
        @DisplayName("IMPORT_SEED with a 16-byte seed advances lifecycle to SEEDED")
        void importAdvancesLifecycle() throws Exception {
            sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(BIP32_VECTOR_1_SEED));
            byte[] info = transmit(Constants.INS_GET_INFO & 0xFF, 0, 0, null).getData();
            assertEquals(LifecycleState.SEEDED, readLifecycleFromInfoTlv(info));
        }

        @Test
        @DisplayName("IMPORT_SEED twice fails")
        void importTwiceFails() throws Exception {
            sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(BIP32_VECTOR_1_SEED));
            ResponseAPDU r =
                    sendInner(
                            Constants.INS_IMPORT_SEED,
                            (byte) 0,
                            (byte) 0,
                            prefixLen(BIP32_VECTOR_1_SEED));
            // Lifecycle FSM rejects this because state == SEEDED, not SETUP_DONE.
            assertEquals(Constants.SW_LIFECYCLE_INVALID & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("IMPORT_SEED with seed length outside policy fails with SW_WRONG_LENGTH")
        void importBadLengthFails() {
            byte[] tooShort = new byte[10];
            ResponseAPDU r =
                    sendInner(Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(tooShort));
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("GENERATE_SEED returns a 64-byte seed and advances lifecycle to SEEDED")
        void generateAdvancesLifecycle() throws Exception {
            byte[] resp =
                    sendInnerExpectOk(Constants.INS_GENERATE_SEED, (byte) 0, (byte) 0, new byte[0]);
            assertEquals(Constants.SEED_GENERATED_LEN, resp.length);
            // Sanity: not all zero.
            byte acc = 0;
            for (byte b : resp) {
                acc |= b;
            }
            assertNotEquals(0, acc, "generated seed must contain entropy");

            byte[] info = transmit(Constants.INS_GET_INFO & 0xFF, 0, 0, null).getData();
            assertEquals(LifecycleState.SEEDED, readLifecycleFromInfoTlv(info));
        }
    }

    @Nested
    @DisplayName("BIP-32 secp256k1 derivation vs the official vectors")
    class Bip32Vectors {

        @BeforeEach
        void importVector1Seed() throws Exception {
            sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(BIP32_VECTOR_1_SEED));
        }

        @Test
        @DisplayName("Vector 1 / m — master xpub matches the reference")
        void masterXpub() throws Exception {
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, new int[] {});
            // BIP-32 v1 master pubkey + chain code, hex from the spec.
            byte[] expectedPub =
                    hex("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2");
            byte[] expectedChain =
                    hex("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
            byte[] gotPub = Arrays.copyOfRange(resp, 0, 33);
            byte[] gotChain = Arrays.copyOfRange(resp, 33, 65);
            assertArrayEquals(expectedPub, gotPub, "master pubkey mismatch");
            assertArrayEquals(expectedChain, gotChain, "master chain code mismatch");
        }

        @Test
        @DisplayName("Vector 1 / m/0H — hardened child matches reference")
        void mZeroHardened() throws Exception {
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, new int[] {0x80000000});
            byte[] expectedPub =
                    hex("035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56");
            byte[] expectedChain =
                    hex("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141");
            assertArrayEquals(expectedPub, Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(expectedChain, Arrays.copyOfRange(resp, 33, 65));
        }

        @Test
        @DisplayName("Vector 1 / m/0H/1 — non-hardened child of hardened parent matches reference")
        void mZeroHardenedOne() throws Exception {
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, new int[] {0x80000000, 1});
            byte[] expectedPub =
                    hex("03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c");
            byte[] expectedChain =
                    hex("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19");
            assertArrayEquals(expectedPub, Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(expectedChain, Arrays.copyOfRange(resp, 33, 65));
        }

        @Test
        @DisplayName(
                "Vector 1 / m/0H/1/2H/2/1000000000 — full 5-level path matches reference (deepest"
                        + " case)")
        void fullPath() throws Exception {
            byte[] resp =
                    exportXpub(
                            Constants.CURVE_SECP256K1,
                            new int[] {0x80000000, 1, 0x80000002, 2, 1000000000});
            byte[] expectedPub =
                    hex("022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011");
            byte[] expectedChain =
                    hex("c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e");
            assertArrayEquals(expectedPub, Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(expectedChain, Arrays.copyOfRange(resp, 33, 65));
        }
    }

    @Nested
    @DisplayName("SLIP-10 Ed25519 derivation vs the official vectors")
    class Slip10Vectors {

        @BeforeEach
        void importVector1Seed() throws Exception {
            sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(BIP32_VECTOR_1_SEED));
        }

        @Test
        @DisplayName("SLIP-10 Vector 1 / m — master pubkey + chain code match")
        void masterChainCode() throws Exception {
            byte[] resp = exportXpub(Constants.CURVE_ED25519, new int[] {});
            assertEquals(Ed25519.PUBLIC_KEY_LEN + Constants.CHAIN_CODE_LEN, resp.length);
            assertArrayEquals(
                    hex("a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"),
                    Arrays.copyOfRange(resp, 0, 32));
            assertArrayEquals(
                    hex("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"),
                    Arrays.copyOfRange(resp, 32, 64));
        }

        @Test
        @DisplayName("SLIP-10 Vector 1 / m/0H — hardened child pubkey + chain code match")
        void zeroHardenedChainCode() throws Exception {
            byte[] resp = exportXpub(Constants.CURVE_ED25519, new int[] {0x80000000});
            assertEquals(Ed25519.PUBLIC_KEY_LEN + Constants.CHAIN_CODE_LEN, resp.length);
            assertArrayEquals(
                    hex("8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"),
                    Arrays.copyOfRange(resp, 0, 32));
            assertArrayEquals(
                    hex("8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"),
                    Arrays.copyOfRange(resp, 32, 64));
        }

        @Test
        @DisplayName(
                "SLIP-10 non-hardened index is rejected for Ed25519 with"
                        + " SW_CONDITIONS_NOT_SATISFIED")
        void nonHardenedRejected() {
            // Index 0 (top bit clear) is illegal for ed25519 under SLIP-10. Per audit F-14 the
            // applet returns 6985 (not 6A86): the offending bit lives in the inner data field, not
            // in the APDU header where ISO 7816-4's 6A86 is meaningful.
            ResponseAPDU r = exportXpubResp(Constants.CURVE_ED25519, new int[] {0});
            assertEquals(Constants.SW_CONDITIONS_NOT_SATISFIED & 0xFFFF, r.getSW());
        }
    }

    @Nested
    @DisplayName("BIP-32 Vector 2 — 64-byte seed, deepest hardened-mixed path")
    class Bip32Vector2 {

        @BeforeEach
        void importVector2Seed() {
            sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(BIP32_VECTOR_2_SEED));
        }

        @Test
        @DisplayName("Vector 2 / m — master xpub matches reference")
        void masterXpub() {
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, new int[] {});
            assertArrayEquals(
                    hex("03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7"),
                    Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(
                    hex("60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"),
                    Arrays.copyOfRange(resp, 33, 65));
        }

        @Test
        @DisplayName("Vector 2 / m/0 — non-hardened first child")
        void mZero() {
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, new int[] {0});
            assertArrayEquals(
                    hex("02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"),
                    Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(
                    hex("f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"),
                    Arrays.copyOfRange(resp, 33, 65));
        }

        @Test
        @DisplayName("Vector 2 / m/0/2147483647H/1/2147483646H/2 — full 5-level mixed path")
        void deepMixed() {
            // Indices: 0, 0xFFFFFFFF (=2^32-1, hardened 2^31+0x7FFFFFFF), 1, 0xFFFFFFFE
            // (=hardened 2^31+0x7FFFFFFE), 2.
            int[] path = {0, 0xFFFFFFFF, 1, 0xFFFFFFFE, 2};
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, path);
            assertArrayEquals(
                    hex("024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"),
                    Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(
                    hex("9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271"),
                    Arrays.copyOfRange(resp, 33, 65));
        }
    }

    @Nested
    @DisplayName("BIP-32 Vector 3 — leading-zero I_L edge case")
    class Bip32Vector3 {

        @BeforeEach
        void importVector3Seed() {
            sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(BIP32_VECTOR_3_SEED));
        }

        @Test
        @DisplayName("Vector 3 / m — master xpub matches reference")
        void masterXpub() {
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, new int[] {});
            assertArrayEquals(
                    hex("03683af1ba5743bdfc798cf814efeeab2735ec52d95eced528e692b8e34c4e5669"),
                    Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(
                    hex("01d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f"),
                    Arrays.copyOfRange(resp, 33, 65));
        }

        @Test
        @DisplayName("Vector 3 / m/0H — first hardened child has a leading-zero I_L byte")
        void mZeroHardened() {
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, new int[] {0x80000000});
            assertArrayEquals(
                    hex("026557fdda1d5d43d79611f784780471f086d58e8126b8c40acb82272a7712e7f2"),
                    Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(
                    hex("e5fea12a97b927fc9dc3d2cb0d1ea1cf50aa5a1fdc1f933e8906bb38df3377bd"),
                    Arrays.copyOfRange(resp, 33, 65));
        }
    }

    @Nested
    @DisplayName("SLIP-10 Vector 2 — second seed, deeper hardened path")
    class Slip10Vector2 {

        @BeforeEach
        void importVector2Seed() {
            sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(BIP32_VECTOR_2_SEED));
        }

        @Test
        @DisplayName("SLIP-10 Vector 2 / m — master pubkey + chain code match")
        void masterChainCode() {
            byte[] resp = exportXpub(Constants.CURVE_ED25519, new int[] {});
            assertEquals(Ed25519.PUBLIC_KEY_LEN + Constants.CHAIN_CODE_LEN, resp.length);
            assertArrayEquals(
                    hex("8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a"),
                    Arrays.copyOfRange(resp, 0, 32));
            assertArrayEquals(
                    hex("ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b"),
                    Arrays.copyOfRange(resp, 32, 64));
        }

        @Test
        @DisplayName("SLIP-10 Vector 2 / m/0H — first hardened pubkey + chain code match")
        void zeroHardenedChainCode() {
            byte[] resp = exportXpub(Constants.CURVE_ED25519, new int[] {0x80000000});
            assertEquals(Ed25519.PUBLIC_KEY_LEN + Constants.CHAIN_CODE_LEN, resp.length);
            assertArrayEquals(
                    hex("86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037"),
                    Arrays.copyOfRange(resp, 0, 32));
            assertArrayEquals(
                    hex("0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d"),
                    Arrays.copyOfRange(resp, 32, 64));
        }
    }

    @Nested
    @DisplayName("Multi-derivation + cross-curve — same seed, repeated calls in one session")
    class MultiDerivation {

        @BeforeEach
        void importVector1Seed() {
            sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(BIP32_VECTOR_1_SEED));
        }

        @Test
        @DisplayName("Two consecutive secp256k1 derivations — second still produces correct output")
        void backToBackBip32() {
            // First derivation: m/0H. Triggers Bip32.scalarKey.clearKey() at the end.
            byte[] first = exportXpub(Constants.CURVE_SECP256K1, new int[] {0x80000000});
            // Second derivation on the same simulator instance must work despite the post-clear
            // state of scalarKey — the EC scalar mult inside ckdPriv re-initialises the key.
            byte[] second = exportXpub(Constants.CURVE_SECP256K1, new int[] {0x80000000, 1});
            assertArrayEquals(
                    hex("035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"),
                    Arrays.copyOfRange(first, 0, 33));
            assertArrayEquals(
                    hex("03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"),
                    Arrays.copyOfRange(second, 0, 33));
        }

        @Test
        @DisplayName("Same seed feeds both secp256k1 and Ed25519 trees in one session")
        void crossCurveSameSeed() {
            byte[] k1 = exportXpub(Constants.CURVE_SECP256K1, new int[] {});
            byte[] ed = exportXpub(Constants.CURVE_ED25519, new int[] {});
            assertArrayEquals(
                    hex("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"),
                    Arrays.copyOfRange(k1, 33, 65));
            assertArrayEquals(
                    hex("a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"),
                    Arrays.copyOfRange(ed, 0, 32));
            assertArrayEquals(
                    hex("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"),
                    Arrays.copyOfRange(ed, 32, 64));
        }

        @Test
        @DisplayName("Determinism — same path yields the same output across calls")
        void deterministicRepeatedPath() {
            int[] path = {0x80000000, 1, 0x80000002, 2, 1000000000};
            byte[] first = exportXpub(Constants.CURVE_SECP256K1, path);
            byte[] second = exportXpub(Constants.CURVE_SECP256K1, path);
            assertArrayEquals(first, second);
        }
    }

    @Nested
    @DisplayName("EXPORT_XPUB — negative cases")
    class ExportXpubNegative {

        @BeforeEach
        void importVector1Seed() {
            sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(BIP32_VECTOR_1_SEED));
        }

        @Test
        @DisplayName("depth > HD_MAX_DEPTH (=8) is rejected with SW_WRONG_LENGTH")
        void depthTooDeep() {
            int[] tooDeep = new int[Constants.HD_MAX_DEPTH + 1];
            for (int i = 0; i < tooDeep.length; i++) tooDeep[i] = 0x80000000 | i;
            ResponseAPDU r = exportXpubResp(Constants.CURVE_SECP256K1, tooDeep);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("Unknown curve byte (0x02) is rejected with SW_INCORRECT_P1P2")
        void unknownCurve() {
            ResponseAPDU r = exportXpubResp((byte) 0x02, new int[] {});
            assertEquals(Constants.SW_INCORRECT_P1P2 & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("Truncated path (declared depth > supplied path bytes) is rejected")
        void truncatedPath() {
            // Encode path with depth=2 but only one index of payload.
            byte[] req = new byte[2 + 4];
            req[0] = Constants.CURVE_SECP256K1;
            req[1] = 2; // claims depth = 2
            // remaining 4 bytes = a single index, so total dataLen = 6 ≠ 2 + 4*2 = 10
            ResponseAPDU r = sendInner(Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, req);
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }
    }

    @Nested
    @DisplayName("Lifecycle / PIN gating — HD derivation INS commands")
    class HdGating {

        @Test
        @DisplayName("EXPORT_XPUB before SEEDED is rejected with SW_LIFECYCLE_INVALID")
        void exportBeforeSeeded() {
            // setUp() leaves the card in SETUP_DONE. EXPORT_XPUB requires SEEDED.
            ResponseAPDU r = exportXpubResp(Constants.CURVE_SECP256K1, new int[] {});
            assertEquals(Constants.SW_LIFECYCLE_INVALID & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("IMPORT_SEED without a verified PIN is rejected with SW_SECURITY_STATUS")
        void importWithoutPinIsRejected() throws Exception {
            // Re-handshake the SC: this clears the session-scoped PIN-verified flag.
            session = openSession();
            ResponseAPDU r =
                    sendInner(
                            Constants.INS_IMPORT_SEED,
                            (byte) 0,
                            (byte) 0,
                            prefixLen(BIP32_VECTOR_1_SEED));
            assertEquals(Constants.SW_SECURITY_STATUS_NOT_SATISFIED & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("EXPORT_XPUB without a verified PIN is rejected (after SC re-handshake)")
        void exportWithoutPinIsRejected() throws Exception {
            sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED, (byte) 0, (byte) 0, prefixLen(BIP32_VECTOR_1_SEED));
            // SC re-handshake invalidates the PIN session.
            session = openSession();
            ResponseAPDU r = exportXpubResp(Constants.CURVE_SECP256K1, new int[] {});
            assertEquals(Constants.SW_SECURITY_STATUS_NOT_SATISFIED & 0xFFFF, r.getSW());
        }
    }

    /*  Helpers shared across nested test classes.  */

    private byte[] exportXpub(byte curve, int[] path) {
        byte[] req = encodePath(curve, path);
        return sendInnerExpectOk(Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, req);
    }

    private ResponseAPDU exportXpubResp(byte curve, int[] path) {
        byte[] req = encodePath(curve, path);
        return sendInner(Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, req);
    }

    private static byte[] encodePath(byte curve, int[] path) {
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

    private void bringToSetupDoneAndVerifyPin() throws Exception {
        // Install a tiny PKI cert + lock so lifecycle reaches PERSONALIZED.
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
        // PKI lock invalidates the SC and PIN; re-open a session before the user flow.
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
