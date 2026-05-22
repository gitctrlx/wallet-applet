/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Pinned boundary cases for {@link HmacSha}. Complements {@link HmacShaTest} (RFC 4231 + 200
 * random differentials) by exercising the explicit message-length and key-length edges that the
 * software fallback walks per RFC 2104:
 *
 * <ul>
 *   <li>empty message ({@code msgLen == 0});
 *   <li>1-byte message;
 *   <li>{@code msgLen == B - 1}, {@code msgLen == B}, {@code msgLen == B + 1} for both SHA-256
 *       (block size {@code B = 64}) and SHA-512 ({@code B = 128});
 *   <li>{@code keyLen} below the block size, equal to the block size, and longer than the block
 *       size (which triggers the {@code K' = H(K)} pre-hash branch in RFC 2104 §2).
 * </ul>
 *
 * <p>Every case is verified against {@link javax.crypto.Mac} on both the native HMAC path that
 * jcardsim always supports and the {@link HmacSha#forceSoftware} path the runtime J3R180 takes.
 */
class HmacShaEdgeTest {

    static java.util.stream.Stream<Arguments> edgeCases() {
        java.util.List<Arguments> args = new java.util.ArrayList<>();
        // (algName, jdkAlg, blockSize)
        Object[][] algs = {
            {"SHA-256", "HmacSHA256", 64},
            {"SHA-512", "HmacSHA512", 128},
        };
        // (keyLen description, keyLen value relative to block size). Negative values mean
        // "block - |value|"; positive values are absolute.
        // We expand them per algorithm at expansion time below.
        int[][] msgLens = {
            {0, 0}, // explicit empty
            {1, 0}, // 1 byte
            {-1, 0}, // block - 1
            {0, 1}, // exactly block
            {1, 1}, // block + 1
            {0, 2}, // 2 * block
        };
        for (Object[] alg : algs) {
            String algName = (String) alg[0];
            String jdkAlg = (String) alg[1];
            int block = (int) alg[2];
            int[] keyLens = {1, 16, block - 1, block, block + 1, 2 * block, 4 * block};
            for (int keyLen : keyLens) {
                for (int[] m : msgLens) {
                    int msgLen = (m[0] >= 0 ? m[0] : block + m[0]) + m[1] * block;
                    if (msgLen < 0) continue;
                    args.add(Arguments.of(algName, jdkAlg, keyLen, msgLen));
                }
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "{0}: key={2} bytes, msg={3} bytes — native vs JDK")
    @MethodSource("edgeCases")
    @DisplayName("native HMAC matches JDK on every (keyLen, msgLen) boundary case")
    void nativeMatchesJdk(String algName, String jdkAlg, int keyLen, int msgLen) throws Exception {
        byte alg = "SHA-256".equals(algName) ? HmacSha.ALG_SHA_256 : HmacSha.ALG_SHA_512;
        byte[] key = deterministicBytes(0x11, keyLen);
        byte[] msg = deterministicBytes(0x22, msgLen);

        Mac jdkMac = Mac.getInstance(jdkAlg);
        jdkMac.init(new SecretKeySpec(key, jdkAlg));
        byte[] expected = jdkMac.doFinal(msg);

        HmacSha h = new HmacSha(alg);
        byte[] got = new byte[expected.length];
        short n =
                h.sign(
                        key,
                        (short) 0,
                        (short) key.length,
                        msg,
                        (short) 0,
                        (short) msg.length,
                        got,
                        (short) 0);
        assertEquals(expected.length, n);
        assertArrayEquals(
                expected,
                got,
                "native HMAC-" + algName + " disagrees with JDK at keyLen=" + keyLen + ", msgLen=" + msgLen);
    }

    @ParameterizedTest(name = "{0}: key={2} bytes, msg={3} bytes — software vs JDK")
    @MethodSource("edgeCases")
    @DisplayName("software HMAC fallback matches JDK on every (keyLen, msgLen) boundary case")
    void softwareMatchesJdk(String algName, String jdkAlg, int keyLen, int msgLen) throws Exception {
        byte alg = "SHA-256".equals(algName) ? HmacSha.ALG_SHA_256 : HmacSha.ALG_SHA_512;
        byte[] key = deterministicBytes(0x11, keyLen);
        byte[] msg = deterministicBytes(0x22, msgLen);

        Mac jdkMac = Mac.getInstance(jdkAlg);
        jdkMac.init(new SecretKeySpec(key, jdkAlg));
        byte[] expected = jdkMac.doFinal(msg);

        HmacSha h = HmacSha.forceSoftware(alg);
        byte[] got = new byte[expected.length];
        short n =
                h.sign(
                        key,
                        (short) 0,
                        (short) key.length,
                        msg,
                        (short) 0,
                        (short) msg.length,
                        got,
                        (short) 0);
        assertEquals(expected.length, n);
        assertArrayEquals(
                expected,
                got,
                "software HMAC-" + algName + " disagrees with JDK at keyLen=" + keyLen + ", msgLen=" + msgLen);
    }

    /** Deterministic non-zero payload, so a regression that drops the message entirely shows up. */
    private static byte[] deterministicBytes(int seed, int length) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) (seed + i);
        }
        return out;
    }
}
