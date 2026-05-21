/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.proto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import social.meowl.tools.core.Hex;

/**
 * RFC 5869 test vectors for HKDF-SHA-256.
 *
 * <p>The three published vectors with SHA-256 (Test Case 1, 2, 3) are pinned exactly. Any deviation
 * in {@link HkdfSha256} therefore fails one of these tests rather than appearing later as a Secure
 * Channel handshake mismatch.
 */
class HkdfSha256Test {

    @Nested
    @DisplayName("RFC 5869 published test vectors")
    class Vectors {

        @Test
        @DisplayName("Test Case 1 — basic test case with SHA-256")
        void testCase1() {
            byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            byte[] salt = Hex.decode("000102030405060708090a0b0c");
            byte[] info = Hex.decode("f0f1f2f3f4f5f6f7f8f9");
            int L = 42;

            byte[] expectedPrk =
                    Hex.decode(
                            "077709362c2e32df0ddc3f0dc47bba63"
                                    + "90b6c73bb50f9c3122ec844ad7c2b3e5");
            byte[] expectedOkm =
                    Hex.decode(
                            "3cb25f25faacd57a90434f64d0362f2a"
                                    + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                                    + "34007208d5b887185865");

            byte[] prk = HkdfSha256.extract(salt, ikm);
            assertArrayEquals(expectedPrk, prk, "PRK");

            byte[] okm = HkdfSha256.expand(prk, info, L);
            assertEquals(L, okm.length);
            assertArrayEquals(expectedOkm, okm, "OKM");
        }

        @Test
        @DisplayName("Test Case 2 — longer inputs/outputs with SHA-256")
        void testCase2() {
            byte[] ikm =
                    Hex.decode(
                            "000102030405060708090a0b0c0d0e0f"
                                    + "101112131415161718191a1b1c1d1e1f"
                                    + "202122232425262728292a2b2c2d2e2f"
                                    + "303132333435363738393a3b3c3d3e3f"
                                    + "404142434445464748494a4b4c4d4e4f");
            byte[] salt =
                    Hex.decode(
                            "606162636465666768696a6b6c6d6e6f"
                                    + "707172737475767778797a7b7c7d7e7f"
                                    + "808182838485868788898a8b8c8d8e8f"
                                    + "909192939495969798999a9b9c9d9e9f"
                                    + "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
            byte[] info =
                    Hex.decode(
                            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                                    + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                                    + "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                                    + "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                                    + "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
            int L = 82;

            byte[] expectedPrk =
                    Hex.decode(
                            "06a6b88c5853361a06104c9ceb35b45c"
                                    + "ef760014904671014a193f40c15fc244");
            byte[] expectedOkm =
                    Hex.decode(
                            "b11e398dc80327a1c8e7f78c596a4934"
                                    + "4f012eda2d4efad8a050cc4c19afa97c"
                                    + "59045a99cac7827271cb41c65e590e09"
                                    + "da3275600c2f09b8367793a9aca3db71"
                                    + "cc30c58179ec3e87c14c01d5c1f3434f"
                                    + "1d87");

            byte[] prk = HkdfSha256.extract(salt, ikm);
            assertArrayEquals(expectedPrk, prk, "PRK");
            byte[] okm = HkdfSha256.expand(prk, info, L);
            assertEquals(L, okm.length);
            assertArrayEquals(expectedOkm, okm, "OKM");
        }

        @Test
        @DisplayName("Test Case 3 — zero-length salt and info")
        void testCase3() {
            byte[] ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            byte[] salt = new byte[0];
            byte[] info = new byte[0];
            int L = 42;

            byte[] expectedPrk =
                    Hex.decode(
                            "19ef24a32c717b167f33a91d6f648bdf"
                                    + "96596776afdb6377ac434c1c293ccb04");
            byte[] expectedOkm =
                    Hex.decode(
                            "8da4e775a563c18f715f802a063c5a31"
                                    + "b8a11f5c5ee1879ec3454e5f3c738d2d"
                                    + "9d201395faa4b61a96c8");

            byte[] prk = HkdfSha256.extract(salt, ikm);
            assertArrayEquals(expectedPrk, prk, "PRK");
            byte[] okm = HkdfSha256.expand(prk, info, L);
            assertEquals(L, okm.length);
            assertArrayEquals(expectedOkm, okm, "OKM");
        }
    }

    @Nested
    @DisplayName("argument validation")
    class Validation {

        @Test
        @DisplayName("expand rejects negative length")
        void negativeLengthRejected() {
            byte[] prk = new byte[32];
            assertThrows(IllegalArgumentException.class, () -> HkdfSha256.expand(prk, null, -1));
        }

        @Test
        @DisplayName("expand rejects length above 255 × HashLen")
        void overlongLengthRejected() {
            byte[] prk = new byte[32];
            assertThrows(
                    IllegalArgumentException.class,
                    () -> HkdfSha256.expand(prk, null, HkdfSha256.MAX_LEN + 1));
        }

        @Test
        @DisplayName("expand allows length exactly 255 × HashLen")
        void maximumLengthAllowed() {
            byte[] prk = new byte[32];
            byte[] okm = HkdfSha256.expand(prk, null, HkdfSha256.MAX_LEN);
            assertEquals(HkdfSha256.MAX_LEN, okm.length);
        }

        @Test
        @DisplayName("null salt is treated as a HashLen-byte zero string")
        void nullSaltActsAsZero() {
            byte[] ikm = new byte[8];
            byte[] explicitZero = HkdfSha256.extract(new byte[32], ikm);
            byte[] nullSalt = HkdfSha256.extract(null, ikm);
            assertArrayEquals(explicitZero, nullSalt);
        }
    }

    @Test
    @DisplayName("MEAP-2 schedule: 80-byte expand splits into K_enc / K_mac / IV_base")
    void meap2Schedule() {
        // Synthetic but stable inputs: schedule just needs to be deterministic and partitionable.
        byte[] sharedX = new byte[32];
        for (int i = 0; i < sharedX.length; i++) sharedX[i] = (byte) i;
        byte[] salt = new byte[64];
        byte[] info = "meowl-sc-v1".getBytes();

        byte[] prk = HkdfSha256.extract(salt, sharedX);
        byte[] okm = HkdfSha256.expand(prk, info, 80);
        assertEquals(80, okm.length);

        // The three sub-keys must be non-zero and pairwise distinct (negligible chance of
        // collision with random PRK / info, so this catches partition-bug regressions).
        byte[] kEnc = java.util.Arrays.copyOfRange(okm, 0, 32);
        byte[] kMac = java.util.Arrays.copyOfRange(okm, 32, 64);
        byte[] ivBase = java.util.Arrays.copyOfRange(okm, 64, 80);
        org.junit.jupiter.api.Assertions.assertFalse(java.util.Arrays.equals(kEnc, kMac));
        org.junit.jupiter.api.Assertions.assertFalse(java.util.Arrays.equals(kEnc, new byte[32]));
        org.junit.jupiter.api.Assertions.assertFalse(java.util.Arrays.equals(kMac, new byte[32]));
        org.junit.jupiter.api.Assertions.assertFalse(java.util.Arrays.equals(ivBase, new byte[16]));
    }
}
