/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.proto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

/** Tests for {@link HostCrypto}. */
class HostCryptoTest {

    @Nested
    @DisplayName("generateEphKeyPair()")
    class EphKey {

        @RepeatedTest(50)
        @DisplayName("produces a uncompressed point on secp256k1 with d in [1, n-1]")
        void wellFormed() {
            HostCrypto.EphKeyPair kp = HostCrypto.generateEphKeyPair();
            assertNotNull(kp);
            assertEquals(HostCrypto.EC_POINT_UNCOMPRESSED_LEN, kp.publicEncoded().length);
            assertEquals(0x04, kp.publicEncoded()[0] & 0xFF);
            assertTrue(kp.privateScalar().signum() > 0);
            assertTrue(kp.privateScalar().compareTo(HostCrypto.SECP256K1.getN()) < 0);

            // The public key must round-trip through the curve as a valid point.
            org.bouncycastle.math.ec.ECPoint decoded =
                    HostCrypto.SECP256K1.getCurve().decodePoint(kp.publicEncoded()).normalize();
            assertTrue(decoded.isValid());
        }
    }

    @Nested
    @DisplayName("ecdhSharedX()")
    class Ecdh {

        @Test
        @DisplayName("two parties derive the same shared X from their handshake")
        void mutualDerive() {
            HostCrypto.EphKeyPair alice = HostCrypto.generateEphKeyPair();
            HostCrypto.EphKeyPair bob = HostCrypto.generateEphKeyPair();
            byte[] aliceSharedX =
                    HostCrypto.ecdhSharedX(alice.privateScalar(), bob.publicEncoded());
            byte[] bobSharedX = HostCrypto.ecdhSharedX(bob.privateScalar(), alice.publicEncoded());
            assertArrayEquals(aliceSharedX, bobSharedX);
            assertEquals(HostCrypto.EC_SCALAR_LEN, aliceSharedX.length);
        }

        @Test
        @DisplayName("rejects a peer point that is not 65 SEC1-uncompressed bytes")
        void wrongLengthRejected() {
            HostCrypto.EphKeyPair kp = HostCrypto.generateEphKeyPair();
            assertThrows(
                    IllegalArgumentException.class,
                    () -> HostCrypto.ecdhSharedX(kp.privateScalar(), new byte[33]));
        }

        @Test
        @DisplayName("rejects an off-curve peer point")
        void offCurveRejected() {
            HostCrypto.EphKeyPair kp = HostCrypto.generateEphKeyPair();
            byte[] bogus = new byte[HostCrypto.EC_POINT_UNCOMPRESSED_LEN];
            bogus[0] = 0x04;
            // x = 1, y = 1 → not on secp256k1 (y² ≢ x³ + 7 (mod p))
            bogus[32] = 0x01;
            bogus[64] = 0x01;
            assertThrows(
                    IllegalArgumentException.class,
                    () -> HostCrypto.ecdhSharedX(kp.privateScalar(), bogus));
        }
    }

    @Nested
    @DisplayName("aesCbcEncrypt() / aesCbcDecrypt()")
    class AesCbc {

        @RepeatedTest(20)
        @DisplayName("round-trip with random plaintext and key")
        void roundTrip() {
            byte[] key = randomBytes(HostCrypto.AES_KEY_LEN);
            byte[] iv = randomBytes(HostCrypto.AES_BLOCK_LEN);
            byte[] plaintext = randomBytes(1 + (int) (Math.random() * 64));

            byte[] ciphertext = HostCrypto.aesCbcEncrypt(key, iv, plaintext);
            assertEquals(0, ciphertext.length % HostCrypto.AES_BLOCK_LEN);
            assertEquals(
                    HostCrypto.AES_BLOCK_LEN * (1 + plaintext.length / HostCrypto.AES_BLOCK_LEN),
                    ciphertext.length);

            byte[] decoded = HostCrypto.aesCbcDecrypt(key, iv, ciphertext);
            assertArrayEquals(plaintext, decoded);
        }

        @Test
        @DisplayName("rejects an AES key that is not 32 bytes")
        void wrongKeyLength() {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> HostCrypto.aesCbcEncrypt(new byte[16], new byte[16], new byte[8]));
        }

        @Test
        @DisplayName("rejects an IV that is not 16 bytes")
        void wrongIvLength() {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> HostCrypto.aesCbcEncrypt(new byte[32], new byte[15], new byte[8]));
        }

        @Test
        @DisplayName("decrypt rejects malformed PKCS#5 padding")
        void malformedPaddingRejected() {
            byte[] key = new byte[HostCrypto.AES_KEY_LEN];
            byte[] iv = new byte[HostCrypto.AES_BLOCK_LEN];
            byte[] ciphertext = HostCrypto.aesCbcEncrypt(key, iv, "hello".getBytes());
            // Tamper with the last block to break the pad.
            byte[] tampered = ciphertext.clone();
            tampered[tampered.length - 1] ^= (byte) 0xFF;
            assertThrows(
                    IllegalArgumentException.class,
                    () -> HostCrypto.aesCbcDecrypt(key, iv, tampered));
        }
    }

    @Test
    @DisplayName("hmacSha256Truncated returns 16 bytes and matches concatenated input")
    void hmacTruncated() {
        byte[] key = randomBytes(32);
        byte[] a = randomBytes(13);
        byte[] b = randomBytes(7);
        byte[] tag = HostCrypto.hmacSha256Truncated(key, a, b);
        assertEquals(HostCrypto.MAC_LEN, tag.length);

        byte[] concat = HostCrypto.concat(a, b);
        byte[] sameTag = HostCrypto.hmacSha256Truncated(key, concat);
        assertArrayEquals(tag, sameTag);
    }

    @Test
    @DisplayName("verifyEcdsaSecp256k1 returns false on a mutated signature")
    void verifyEcdsaSurvivesTamper() throws Exception {
        // Use BouncyCastle to sign a synthetic message, then tamper the signature.
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider());
        org.bouncycastle.jce.spec.ECParameterSpec spec =
                org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");
        java.security.KeyPairGenerator gen = java.security.KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(spec);
        java.security.KeyPair kp = gen.generateKeyPair();
        java.security.Signature signer =
                java.security.Signature.getInstance("SHA256withECDSA", "BC");
        signer.initSign(kp.getPrivate());
        byte[] message = "MEAP-2 handshake".getBytes();
        signer.update(message);
        byte[] sig = signer.sign();

        org.bouncycastle.jce.interfaces.ECPublicKey ecPub =
                (org.bouncycastle.jce.interfaces.ECPublicKey) kp.getPublic();
        byte[] compressed = ecPub.getQ().getEncoded(true); // 33 bytes

        assertTrue(HostCrypto.verifyEcdsaSecp256k1(compressed, message, sig));

        byte[] tampered = sig.clone();
        tampered[tampered.length - 1] ^= 0x01;
        assertFalse(HostCrypto.verifyEcdsaSecp256k1(compressed, message, tampered));
    }

    @Nested
    @DisplayName("bigIntToFixed()")
    class BigIntPad {

        @Test
        @DisplayName("pads on the left for short values")
        void padsShort() {
            BigInteger v = BigInteger.valueOf(0xDEAD_BEEFL);
            byte[] padded = HostCrypto.bigIntToFixed(v, 8);
            assertArrayEquals(
                    new byte[] {0, 0, 0, 0, (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF},
                    padded);
        }

        @Test
        @DisplayName("strips a leading zero sign byte")
        void stripsSignByte() {
            BigInteger v = new BigInteger(1, new byte[] {(byte) 0xFF, 0x00});
            byte[] padded = HostCrypto.bigIntToFixed(v, 2);
            assertArrayEquals(new byte[] {(byte) 0xFF, 0x00}, padded);
        }

        @Test
        @DisplayName("rejects values that genuinely overflow")
        void rejectsOverflow() {
            BigInteger v = new BigInteger("1" + "00".repeat(33), 16); // 33+ bytes magnitude
            assertThrows(IllegalArgumentException.class, () -> HostCrypto.bigIntToFixed(v, 32));
        }
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new java.security.SecureRandom().nextBytes(b);
        return Arrays.copyOf(b, n);
    }
}
