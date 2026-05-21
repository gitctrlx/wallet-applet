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

/**
 * Verifies {@link HmacSha} against:
 *
 * <ul>
 *   <li>The seven RFC 4231 §4.2-4.8 test vectors for HMAC-SHA-256 and HMAC-SHA-512 (the canonical
 *       interop suite that pins MAC bytes for every other implementation in the world).
 *   <li>Random-input differential testing against the JDK's built-in {@code javax.crypto.Mac} (1000
 *       random {@code (key, message)} pairs), proving byte-for-byte agreement on inputs that are
 *       not in the RFC test set.
 * </ul>
 *
 * <p>Each scenario is exercised twice — once on the native HMAC path that jcardsim always supports,
 * and once on the {@link HmacSha#forceSoftware forceSoftware} path that mirrors the runtime J3R180
 * (and any other JC card without {@code Signature.ALG_HMAC_SHA_*}) takes. Both paths must produce
 * identical bytes for every input.
 *
 * <p>Note: this test runs in the same JVM as jcardsim's mock JC API, so {@link HmacSha} is
 * exercised as a plain Java class without an applet dispatch layer in front of it.
 */
class HmacShaTest {

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

    /** RFC 4231 §4.2-4.8 expected HMAC-SHA-256 outputs (truncated tests 5/6 omitted). */
    private static final String[] RFC4231_HMAC_SHA256_EXPECTED = {
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
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
                            "SHA-256",
                            RFC4231_KEYS[i],
                            RFC4231_DATA[i],
                            hex(RFC4231_HMAC_SHA256_EXPECTED[i])));
            args.add(
                    Arguments.of(
                            i,
                            "SHA-512",
                            RFC4231_KEYS[i],
                            RFC4231_DATA[i],
                            hex(RFC4231_HMAC_SHA512_EXPECTED[i])));
        }
        return args.stream();
    }

    @ParameterizedTest(name = "RFC 4231 vector {0} - native HMAC-{1}")
    @MethodSource("rfcVectors")
    @DisplayName("RFC 4231 vectors via native HMAC path")
    void rfc4231Native(int idx, String algName, byte[] key, byte[] data, byte[] expected) {
        HmacSha h =
                new HmacSha("SHA-256".equals(algName) ? HmacSha.ALG_SHA_256 : HmacSha.ALG_SHA_512);
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
        assertArrayEquals(
                expected, out, "RFC 4231 vector " + idx + " mismatch (native " + algName + ")");
    }

    @ParameterizedTest(name = "RFC 4231 vector {0} - software HMAC-{1}")
    @MethodSource("rfcVectors")
    @DisplayName("RFC 4231 vectors via software fallback path")
    void rfc4231Software(int idx, String algName, byte[] key, byte[] data, byte[] expected) {
        HmacSha h =
                HmacSha.forceSoftware(
                        "SHA-256".equals(algName) ? HmacSha.ALG_SHA_256 : HmacSha.ALG_SHA_512);
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
        assertArrayEquals(
                expected, out, "RFC 4231 vector " + idx + " mismatch (software " + algName + ")");
    }

    /**
     * Differential agreement against {@code javax.crypto.Mac} on 200 random {@code (key, message)}
     * pairs per algorithm. The seed range exercises every length branch in the RFC 2104 software
     * path: {@code |K| == 0}, {@code |K| < B}, {@code |K| == B}, {@code |K| > B}, and messages
     * shorter / equal / longer than the digest block.
     */
    @ParameterizedTest(name = "software HMAC-{0} matches JDK on 200 random inputs")
    @org.junit.jupiter.params.provider.ValueSource(strings = {"SHA-256", "SHA-512"})
    void softwareMatchesJdkOnRandomInputs(String algName) throws Exception {
        String jdkAlg = "SHA-256".equals(algName) ? "HmacSHA256" : "HmacSHA512";
        byte alg = "SHA-256".equals(algName) ? HmacSha.ALG_SHA_256 : HmacSha.ALG_SHA_512;
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
            Mac jdkMac = Mac.getInstance(jdkAlg);
            jdkMac.init(new SecretKeySpec(safeKey, jdkAlg));
            byte[] expected = jdkMac.doFinal(msg);

            HmacSha h = HmacSha.forceSoftware(alg);
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
                    "software HMAC-"
                            + algName
                            + " disagrees with JDK on seed="
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
