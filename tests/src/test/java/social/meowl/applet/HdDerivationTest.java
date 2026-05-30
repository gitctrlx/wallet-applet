/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.security.Security;
import java.util.Arrays;
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
import social.meowl.applet.cardclient.RealCardClient;
import social.meowl.applet.testkit.HostSession;
import social.meowl.applet.testkit.MeowlFixtures;
import social.meowl.applet.testkit.TestConstants;

/**
 * End-to-end HD derivation tests — master seed import, card-generated seed, BIP-32 secp256k1
 * derivation verified against the official BIP-32 vectors, and SLIP-10 Ed25519 derivation verified
 * against the official SLIP-10 vectors.
 */
@Tag("real-card")
class HdDerivationTest {

    /** BIP-32 test vector 1 seed (16 bytes). */
    private static final byte[] BIP32_VECTOR_1_SEED = TestConstants.BIP32_VECTOR_1_SEED;

    /** BIP-32 test vector 2 seed (64 bytes — exercises the upper bound of {@code SEED_MAX_LEN}). */
    private static final byte[] BIP32_VECTOR_2_SEED =
            TestConstants.parseHex(
                    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f"
                            + "9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");

    /**
     * BIP-32 test vector 3 seed — chosen by the spec authors to exercise the case where {@code I_L}
     * from the first hardened child has a leading zero byte, which any naïve implementation that
     * prefix-trims would mishandle.
     */
    private static final byte[] BIP32_VECTOR_3_SEED =
            TestConstants.parseHex(
                    "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4ac"
                            + "ba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be");

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
        // Walk the card to SETUP_DONE: install a tiny PKI cert, lock, run SETUP, verify PIN.
        session = MeowlFixtures.bringToSetupDoneAndVerifyPin(card);
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
    @DisplayName("IMPORT_SEED / GENERATE_SEED")
    class SeedInstall {

        @Test
        @DisplayName("IMPORT_SEED with a 16-byte seed advances lifecycle to SEEDED")
        void importAdvancesLifecycle() throws Exception {
            session.sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.prefixLen(BIP32_VECTOR_1_SEED));
            byte[] info = transmitOuter(Constants.INS_GET_INFO & 0xFF, 0, 0, null).getData();
            assertEquals(LifecycleState.SEEDED, readLifecycleFromInfoTlv(info));
        }

        @Test
        @DisplayName("IMPORT_SEED twice fails")
        void importTwiceFails() throws Exception {
            session.sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.prefixLen(BIP32_VECTOR_1_SEED));
            ResponseAPDU r =
                    session.sendInner(
                            Constants.INS_IMPORT_SEED,
                            (byte) 0,
                            (byte) 0,
                            MeowlFixtures.prefixLen(BIP32_VECTOR_1_SEED));
            // Lifecycle FSM rejects this because state == SEEDED, not SETUP_DONE.
            assertEquals(Constants.SW_LIFECYCLE_INVALID & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("IMPORT_SEED with seed length outside policy fails with SW_WRONG_LENGTH")
        void importBadLengthFails() {
            byte[] tooShort = new byte[10];
            ResponseAPDU r =
                    session.sendInner(
                            Constants.INS_IMPORT_SEED,
                            (byte) 0,
                            (byte) 0,
                            MeowlFixtures.prefixLen(tooShort));
            assertEquals(Constants.SW_WRONG_LENGTH & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("GENERATE_SEED returns a 64-byte seed and advances lifecycle to SEEDED")
        void generateAdvancesLifecycle() throws Exception {
            byte[] resp =
                    session.sendInnerExpectOk(
                            Constants.INS_GENERATE_SEED, (byte) 0, (byte) 0, new byte[0]);
            assertEquals(Constants.SEED_GENERATED_LEN, resp.length);
            // Sanity: not all zero.
            byte acc = 0;
            for (byte b : resp) {
                acc |= b;
            }
            assertNotEquals(0, acc, "generated seed must contain entropy");

            byte[] info = transmitOuter(Constants.INS_GET_INFO & 0xFF, 0, 0, null).getData();
            assertEquals(LifecycleState.SEEDED, readLifecycleFromInfoTlv(info));
        }
    }

    @Nested
    @DisplayName("BIP-32 secp256k1 derivation vs the official vectors")
    class Bip32Vectors {

        @BeforeEach
        void importVector1Seed() throws Exception {
            session.sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.prefixLen(BIP32_VECTOR_1_SEED));
        }

        @Test
        @DisplayName("Vector 1 / m — master xpub matches the reference")
        void masterXpub() throws Exception {
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, new int[] {});
            // BIP-32 v1 master pubkey + chain code, hex from the spec.
            byte[] expectedPub =
                    TestConstants.parseHex(
                            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2");
            byte[] expectedChain =
                    TestConstants.parseHex(
                            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
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
                    TestConstants.parseHex(
                            "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56");
            byte[] expectedChain =
                    TestConstants.parseHex(
                            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141");
            assertArrayEquals(expectedPub, Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(expectedChain, Arrays.copyOfRange(resp, 33, 65));
        }

        @Test
        @DisplayName("Vector 1 / m/0H/1 — non-hardened child of hardened parent matches reference")
        void mZeroHardenedOne() throws Exception {
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, new int[] {0x80000000, 1});
            byte[] expectedPub =
                    TestConstants.parseHex(
                            "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c");
            byte[] expectedChain =
                    TestConstants.parseHex(
                            "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19");
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
                    TestConstants.parseHex(
                            "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011");
            byte[] expectedChain =
                    TestConstants.parseHex(
                            "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e");
            assertArrayEquals(expectedPub, Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(expectedChain, Arrays.copyOfRange(resp, 33, 65));
        }
    }

    @Nested
    @DisplayName("SLIP-10 Ed25519 derivation vs the official vectors")
    class Slip10Vectors {

        @BeforeEach
        void importVector1Seed() throws Exception {
            session.sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.prefixLen(BIP32_VECTOR_1_SEED));
        }

        @Test
        @DisplayName("SLIP-10 Vector 1 / m — master pubkey + chain code match")
        void masterChainCode() throws Exception {
            byte[] resp = exportXpub(Constants.CURVE_ED25519, new int[] {});
            assertEquals(Ed25519.PUBLIC_KEY_LEN + Constants.CHAIN_CODE_LEN, resp.length);
            assertArrayEquals(
                    TestConstants.parseHex(
                            "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"),
                    Arrays.copyOfRange(resp, 0, 32));
            assertArrayEquals(
                    TestConstants.parseHex(
                            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"),
                    Arrays.copyOfRange(resp, 32, 64));
        }

        @Test
        @DisplayName("SLIP-10 Vector 1 / m/0H — hardened child pubkey + chain code match")
        void zeroHardenedChainCode() throws Exception {
            byte[] resp = exportXpub(Constants.CURVE_ED25519, new int[] {0x80000000});
            assertEquals(Ed25519.PUBLIC_KEY_LEN + Constants.CHAIN_CODE_LEN, resp.length);
            assertArrayEquals(
                    TestConstants.parseHex(
                            "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"),
                    Arrays.copyOfRange(resp, 0, 32));
            assertArrayEquals(
                    TestConstants.parseHex(
                            "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"),
                    Arrays.copyOfRange(resp, 32, 64));
        }

        @Test
        @DisplayName(
                "SLIP-10 non-hardened index is rejected for Ed25519 with"
                        + " SW_CONDITIONS_NOT_SATISFIED")
        void nonHardenedRejected() {
            // Index 0 (top bit clear) is illegal for ed25519 under SLIP-10. The applet returns
            // 6985 (not 6A86): the offending bit lives in the inner data field, not in the APDU
            // header where ISO 7816-4's 6A86 is meaningful.
            ResponseAPDU r = exportXpubResp(Constants.CURVE_ED25519, new int[] {0});
            assertEquals(Constants.SW_CONDITIONS_NOT_SATISFIED & 0xFFFF, r.getSW());
        }
    }

    @Nested
    @DisplayName("BIP-32 Vector 2 — 64-byte seed, deepest hardened-mixed path")
    class Bip32Vector2 {

        @BeforeEach
        void importVector2Seed() {
            session.sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.prefixLen(BIP32_VECTOR_2_SEED));
        }

        @Test
        @DisplayName("Vector 2 / m — master xpub matches reference")
        void masterXpub() {
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, new int[] {});
            assertArrayEquals(
                    TestConstants.parseHex(
                            "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7"),
                    Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(
                    TestConstants.parseHex(
                            "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"),
                    Arrays.copyOfRange(resp, 33, 65));
        }

        @Test
        @DisplayName("Vector 2 / m/0 — non-hardened first child")
        void mZero() {
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, new int[] {0});
            assertArrayEquals(
                    TestConstants.parseHex(
                            "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"),
                    Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(
                    TestConstants.parseHex(
                            "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"),
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
                    TestConstants.parseHex(
                            "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"),
                    Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(
                    TestConstants.parseHex(
                            "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271"),
                    Arrays.copyOfRange(resp, 33, 65));
        }
    }

    @Nested
    @DisplayName("BIP-32 Vector 3 — leading-zero I_L edge case")
    class Bip32Vector3 {

        @BeforeEach
        void importVector3Seed() {
            session.sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.prefixLen(BIP32_VECTOR_3_SEED));
        }

        @Test
        @DisplayName("Vector 3 / m — master xpub matches reference")
        void masterXpub() {
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, new int[] {});
            assertArrayEquals(
                    TestConstants.parseHex(
                            "03683af1ba5743bdfc798cf814efeeab2735ec52d95eced528e692b8e34c4e5669"),
                    Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(
                    TestConstants.parseHex(
                            "01d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f"),
                    Arrays.copyOfRange(resp, 33, 65));
        }

        @Test
        @DisplayName("Vector 3 / m/0H — first hardened child has a leading-zero I_L byte")
        void mZeroHardened() {
            byte[] resp = exportXpub(Constants.CURVE_SECP256K1, new int[] {0x80000000});
            assertArrayEquals(
                    TestConstants.parseHex(
                            "026557fdda1d5d43d79611f784780471f086d58e8126b8c40acb82272a7712e7f2"),
                    Arrays.copyOfRange(resp, 0, 33));
            assertArrayEquals(
                    TestConstants.parseHex(
                            "e5fea12a97b927fc9dc3d2cb0d1ea1cf50aa5a1fdc1f933e8906bb38df3377bd"),
                    Arrays.copyOfRange(resp, 33, 65));
        }
    }

    @Nested
    @DisplayName("SLIP-10 Vector 2 — second seed, deeper hardened path")
    class Slip10Vector2 {

        @BeforeEach
        void importVector2Seed() {
            session.sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.prefixLen(BIP32_VECTOR_2_SEED));
        }

        @Test
        @DisplayName("SLIP-10 Vector 2 / m — master pubkey + chain code match")
        void masterChainCode() {
            byte[] resp = exportXpub(Constants.CURVE_ED25519, new int[] {});
            assertEquals(Ed25519.PUBLIC_KEY_LEN + Constants.CHAIN_CODE_LEN, resp.length);
            assertArrayEquals(
                    TestConstants.parseHex(
                            "8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a"),
                    Arrays.copyOfRange(resp, 0, 32));
            assertArrayEquals(
                    TestConstants.parseHex(
                            "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b"),
                    Arrays.copyOfRange(resp, 32, 64));
        }

        @Test
        @DisplayName("SLIP-10 Vector 2 / m/0H — first hardened pubkey + chain code match")
        void zeroHardenedChainCode() {
            byte[] resp = exportXpub(Constants.CURVE_ED25519, new int[] {0x80000000});
            assertEquals(Ed25519.PUBLIC_KEY_LEN + Constants.CHAIN_CODE_LEN, resp.length);
            assertArrayEquals(
                    TestConstants.parseHex(
                            "86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037"),
                    Arrays.copyOfRange(resp, 0, 32));
            assertArrayEquals(
                    TestConstants.parseHex(
                            "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d"),
                    Arrays.copyOfRange(resp, 32, 64));
        }
    }

    @Nested
    @DisplayName("Multi-derivation + cross-curve — same seed, repeated calls in one session")
    class MultiDerivation {

        @BeforeEach
        void importVector1Seed() {
            session.sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.prefixLen(BIP32_VECTOR_1_SEED));
        }

        @Test
        @DisplayName("Two consecutive secp256k1 derivations — second still produces correct output")
        void backToBackBip32() {
            // First derivation: m/0H. Triggers Bip32.scalarKey.clearKey() at the end.
            byte[] first = exportXpub(Constants.CURVE_SECP256K1, new int[] {0x80000000});
            // Second derivation on the same card instance must work despite the post-clear
            // state of scalarKey — the EC scalar mult inside ckdPriv re-initialises the key.
            byte[] second = exportXpub(Constants.CURVE_SECP256K1, new int[] {0x80000000, 1});
            assertArrayEquals(
                    TestConstants.parseHex(
                            "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"),
                    Arrays.copyOfRange(first, 0, 33));
            assertArrayEquals(
                    TestConstants.parseHex(
                            "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"),
                    Arrays.copyOfRange(second, 0, 33));
        }

        @Test
        @DisplayName("Same seed feeds both secp256k1 and Ed25519 trees in one session")
        void crossCurveSameSeed() {
            byte[] k1 = exportXpub(Constants.CURVE_SECP256K1, new int[] {});
            byte[] ed = exportXpub(Constants.CURVE_ED25519, new int[] {});
            assertArrayEquals(
                    TestConstants.parseHex(
                            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"),
                    Arrays.copyOfRange(k1, 33, 65));
            assertArrayEquals(
                    TestConstants.parseHex(
                            "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"),
                    Arrays.copyOfRange(ed, 0, 32));
            assertArrayEquals(
                    TestConstants.parseHex(
                            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"),
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
            session.sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.prefixLen(BIP32_VECTOR_1_SEED));
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
            ResponseAPDU r = session.sendInner(Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, req);
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
            session = HostSession.open(card);
            ResponseAPDU r =
                    session.sendInner(
                            Constants.INS_IMPORT_SEED,
                            (byte) 0,
                            (byte) 0,
                            MeowlFixtures.prefixLen(BIP32_VECTOR_1_SEED));
            assertEquals(Constants.SW_SECURITY_STATUS_NOT_SATISFIED & 0xFFFF, r.getSW());
        }

        @Test
        @DisplayName("EXPORT_XPUB without a verified PIN is rejected (after SC re-handshake)")
        void exportWithoutPinIsRejected() throws Exception {
            session.sendInnerExpectOk(
                    Constants.INS_IMPORT_SEED,
                    (byte) 0,
                    (byte) 0,
                    MeowlFixtures.prefixLen(BIP32_VECTOR_1_SEED));
            // SC re-handshake invalidates the PIN session.
            session = HostSession.open(card);
            ResponseAPDU r = exportXpubResp(Constants.CURVE_SECP256K1, new int[] {});
            assertEquals(Constants.SW_SECURITY_STATUS_NOT_SATISFIED & 0xFFFF, r.getSW());
        }
    }

    /*  Helpers shared across nested test classes.  */

    private byte[] exportXpub(byte curve, int[] path) {
        byte[] req = encodePath(curve, path);
        return session.sendInnerExpectOk(Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, req);
    }

    private ResponseAPDU exportXpubResp(byte curve, int[] path) {
        byte[] req = encodePath(curve, path);
        return session.sendInner(Constants.INS_EXPORT_XPUB, (byte) 0, (byte) 0, req);
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

    private ResponseAPDU transmitOuter(int ins, int p1, int p2, byte[] data) {
        CommandAPDU cmd =
                data == null
                        ? new CommandAPDU(TestConstants.CLA, ins, p1, p2)
                        : new CommandAPDU(TestConstants.CLA, ins, p1, p2, data);
        return card.transmit(cmd);
    }
}
