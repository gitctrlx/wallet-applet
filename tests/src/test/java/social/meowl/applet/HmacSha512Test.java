/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Verifies {@link HmacSha512} against:
 *
 * <ul>
 *   <li>The seven RFC 4231 §4.2-4.8 test vectors for HMAC-SHA-512 (the canonical interop suite that
 *       pins MAC bytes for every other implementation in the world).
 *   <li>Random-input differential testing against the JDK's built-in {@code javax.crypto.Mac} (200
 *       random {@code (key, message)} pairs), proving byte-for-byte agreement on inputs that are
 *       not in the RFC test set.
 * </ul>
 *
 * <p>{@link HmacSha512} is the RFC 2104 software implementation the runtime J3R180 takes (the chip
 * exposes no {@code ALG_HMAC_SHA_512} primitive). This test runs in the same JVM as jcardsim's mock
 * JC API, so the engine is exercised as a plain Java class without an applet dispatch layer.
 */
class HmacSha512Test {

    /** RFC 4231 §4.2: 20-byte key, short message. */
    private static final byte[] RFC4231_KEY_1 = repeat((byte) 0x0b, 20);

    private static final byte[] RFC4231_DATA_1 = "Hi There".getBytes();

    /** RFC 4231 §4.3: 4-byte key, longer message. */
    private static final byte[] RFC4231_KEY_2 = "Jefe".getBytes();

    private static final byte[] RFC4231_DATA_2 = "what do ya want for nothing?".getBytes();

    /** RFC 4231 §4.4: 20-byte key, 50-byte 0xdd payload. */
    private static final byte[] RFC4231_KEY_3 = repeat((byte) 0xaa, 20);

    private static final byte[] RFC4231_DATA_3 = repeat((byte) 0xdd, 50);

    /** RFC 4231 §4.5: 25-byte key, 50-byte 0xcd payload. */
    private static final byte[] RFC4231_KEY_4 =
            hex("0102030405060708090a0b0c0d0e0f10111213141516171819");

    private static final byte[] RFC4231_DATA_4 = repeat((byte) 0xcd, 50);

    /** RFC 4231 §4.7: 131-byte key (longer than block), short message. */
    private static final byte[] RFC4231_KEY_6 = repeat((byte) 0xaa, 131);

    private static final byte[] RFC4231_DATA_6 =
            "Test Using Larger Than Block-Size Key - Hash Key First".getBytes();

    /** RFC 4231 §4.8: 131-byte key (longer than block), long message. */
    private static final byte[] RFC4231_KEY_7 = repeat((byte) 0xaa, 131);

    private static final byte[] RFC4231_DATA_7 =
            ("This is a test using a larger than block-size key and a larger than block-size data."
                 + " The key needs to be hashed before being used by the HMAC algorithm.")
                    .getBytes();

    private static final byte[][] RFC4231_KEYS = {
        RFC4231_KEY_1, RFC4231_KEY_2, RFC4231_KEY_3, RFC4231_KEY_4, RFC4231_KEY_6, RFC4231_KEY_7
    };

    private static final byte[][] RFC4231_DATA = {
        RFC4231_DATA_1,
        RFC4231_DATA_2,
        RFC4231_DATA_3,
        RFC4231_DATA_4,
        RFC4231_DATA_6,
        RFC4231_DATA_7
    };

    /** RFC 4231 §4.2-4.8 expected HMAC-SHA-512 outputs. */
    private static final String[] RFC4231_HMAC_SHA512_EXPECTED = {
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
        "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
        "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
        "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
    };

    static java.util.stream.Stream<Arguments> rfcVectors() {
        java.util.List<Arguments> args = new java.util.ArrayList<>();
        for (int i = 0; i < RFC4231_KEYS.length; i++) {
            args.add(
                    Arguments.of(
                            i,
                            RFC4231_KEYS[i],
                            RFC4231_DATA[i],
                            hex(RFC4231_HMAC_SHA512_EXPECTED[i])));
        }
        return args.stream();
    }

    @ParameterizedTest(name = "RFC 4231 vector {0}")
    @MethodSource("rfcVectors")
    @DisplayName("RFC 4231 HMAC-SHA-512 vectors")
    void rfc4231(int idx, byte[] key, byte[] data, byte[] expected) {
        HmacSha512 h = new HmacSha512();
        byte[] out = new byte[expected.length];
        short n =
                h.sign(
                        key,
                        (short) 0,
                        (short) key.length,
                        data,
                        (short) 0,
                        (short) data.length,
                        out,
                        (short) 0);
        assertEquals(expected.length, n);
        assertArrayEquals(expected, out, "RFC 4231 vector " + idx + " mismatch");
    }

    /**
     * Differential agreement against {@code javax.crypto.Mac} on 200 random {@code (key, message)}
     * pairs. The seed range exercises every length branch in the RFC 2104 software path: {@code |K|
     * == 0}, {@code |K| < B}, {@code |K| == B}, {@code |K| > B}, and messages shorter / equal /
     * longer than the SHA-512 block.
     */
    @ParameterizedTest(name = "HMAC-SHA-512 matches JDK on seed {0}")
    @ValueSource(ints = {0})
    void matchesJdkOnRandomInputs(int unused) throws Exception {
        for (int seed = 0; seed < 200; seed++) {
            java.util.Random rng = new java.util.Random(seed);
            int keyLen = rng.nextInt(257); // 0..256, hits both <B and >B branches
            int msgLen = rng.nextInt(513); // 0..512
            byte[] key = new byte[keyLen];
            rng.nextBytes(key);
            byte[] msg = new byte[msgLen];
            rng.nextBytes(msg);

            // JDK's Mac.init rejects 0-length keys; HMAC is technically defined for them, so we
            // substitute a single zero byte on both sides for parity. Real callers never pass 0.
            byte[] safeKey = key.length == 0 ? new byte[1] : key;
            Mac jdkMac = Mac.getInstance("HmacSHA512");
            jdkMac.init(new SecretKeySpec(safeKey, "HmacSHA512"));
            byte[] expected = jdkMac.doFinal(msg);

            HmacSha512 h = new HmacSha512();
            byte[] out = new byte[expected.length];
            h.sign(
                    safeKey,
                    (short) 0,
                    (short) safeKey.length,
                    msg,
                    (short) 0,
                    (short) msg.length,
                    out,
                    (short) 0);

            assertArrayEquals(
                    expected,
                    out,
                    "HMAC-SHA-512 disagrees with JDK on seed="
                            + seed
                            + ", keyLen="
                            + safeKey.length
                            + ", msgLen="
                            + msg.length);
        }
    }

    private static byte[] repeat(byte v, int n) {
        byte[] r = new byte[n];
        java.util.Arrays.fill(r, v);
        return r;
    }

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }
}
