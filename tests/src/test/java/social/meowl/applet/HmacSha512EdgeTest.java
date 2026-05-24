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
 * Pinned boundary cases for {@link HmacSha512}. Complements {@link HmacSha512Test} (RFC 4231 + 200
 * random differentials) by exercising the explicit message-length and key-length edges that the
 * software fallback walks per RFC 2104:
 *
 * <ul>
 *   <li>empty message ({@code msgLen == 0});
 *   <li>1-byte message;
 *   <li>{@code msgLen == B - 1}, {@code msgLen == B}, {@code msgLen == B + 1} ({@code B = 128} for
 *       SHA-512);
 *   <li>{@code keyLen} below the block size, equal to the block size, and longer than the block
 *       size (which triggers the {@code K' = H(K)} pre-hash branch in RFC 2104 §2).
 * </ul>
 *
 * <p>Every case is verified against {@link javax.crypto.Mac}. {@link HmacSha512} is the RFC 2104
 * software implementation the runtime J3R180 takes (the chip exposes no {@code ALG_HMAC_SHA_512}
 * primitive).
 */
class HmacSha512EdgeTest {

    private static final int BLOCK_SIZE = 128;

    static java.util.stream.Stream<Arguments> edgeCases() {
        java.util.List<Arguments> args = new java.util.ArrayList<>();
        // (msgLen offset relative to block, msgLen multiple of block).
        int[][] msgLens = {
            {0, 0}, // explicit empty
            {1, 0}, // 1 byte
            {-1, 0}, // block - 1
            {0, 1}, // exactly block
            {1, 1}, // block + 1
            {0, 2}, // 2 * block
        };
        int[] keyLens = {
            1, 16, BLOCK_SIZE - 1, BLOCK_SIZE, BLOCK_SIZE + 1, 2 * BLOCK_SIZE, 4 * BLOCK_SIZE
        };
        for (int keyLen : keyLens) {
            for (int[] m : msgLens) {
                int msgLen = (m[0] >= 0 ? m[0] : BLOCK_SIZE + m[0]) + m[1] * BLOCK_SIZE;
                if (msgLen < 0) continue;
                args.add(Arguments.of(keyLen, msgLen));
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "key={0} bytes, msg={1} bytes")
    @MethodSource("edgeCases")
    @DisplayName("HMAC-SHA-512 matches JDK on every (keyLen, msgLen) boundary case")
    void matchesJdk(int keyLen, int msgLen) throws Exception {
        byte[] key = deterministicBytes(0x11, keyLen);
        byte[] msg = deterministicBytes(0x22, msgLen);

        Mac jdkMac = Mac.getInstance("HmacSHA512");
        jdkMac.init(new SecretKeySpec(key, "HmacSHA512"));
        byte[] expected = jdkMac.doFinal(msg);

        HmacSha512 h = new HmacSha512();
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
                "HMAC-SHA-512 disagrees with JDK at keyLen=" + keyLen + ", msgLen=" + msgLen);
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
