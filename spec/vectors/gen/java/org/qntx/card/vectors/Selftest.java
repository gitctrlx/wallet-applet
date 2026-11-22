// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Agreement self-test of the two generators: the canonical encoding and the primitives every later
 * vector file builds on (SHA-256, SHA-512, HMAC-SHA512, secp256k1 public keys). Inputs mirror
 * gen/ts/selftest.ts.
 */
final class Selftest {
    private static final HexFormat HEX = HexFormat.of();
    private static final X9ECParameters K1 = CustomNamedCurves.getByName("secp256k1");

    private Selftest() {}

    static Object document() {
        List<byte[]> messages = List.of(ascii(""), ascii("abc"), new byte[200]);
        List<Object> hashes =
                messages.stream()
                        .<Object>map(
                                m ->
                                        object(
                                                "input", hex(m),
                                                "sha256", hex(digest(new SHA256Digest(), m)),
                                                "sha512", hex(digest(new SHA512Digest(), m))))
                        .toList();
        byte[] key = ascii("Jefe");
        byte[] data = ascii("what do ya want for nothing?");
        BigInteger n = K1.getN();
        List<BigInteger> scalars =
                List.of(
                        BigInteger.ONE,
                        BigInteger.TWO,
                        n.subtract(BigInteger.ONE),
                        new BigInteger(1, digest(new SHA256Digest(), ascii("qntx-card/selftest"))));
        List<Object> points =
                scalars.stream()
                        .<Object>map(
                                d -> {
                                    ECPoint p = K1.getG().multiply(d).normalize();
                                    return object(
                                            "d", HEX.formatHex(fixed(d)),
                                            "compressed", hex(p.getEncoded(true)),
                                            "uncompressed", hex(p.getEncoded(false)));
                                })
                        .toList();
        return object(
                "description",
                "Agreement self-test of the vector generators; not a protocol vector file",
                "count",
                hashes.size() + 1 + points.size(),
                "hashes",
                hashes,
                "hmacSha512",
                List.of(object("key", hex(key), "data", hex(data), "mac", hex(hmac(key, data)))),
                "secp256k1",
                points,
                "flags",
                List.of(true, false));
    }

    private static Map<String, Object> object(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private static String hex(byte[] b) {
        return HEX.formatHex(b);
    }

    private static byte[] fixed(BigInteger d) {
        byte[] b = d.toByteArray();
        byte[] out = new byte[32];
        int len = Math.min(b.length, 32);
        System.arraycopy(b, b.length - len, out, 32 - len, len);
        return out;
    }

    private static byte[] digest(Digest d, byte[] m) {
        d.update(m, 0, m.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        HMac mac = new HMac(new SHA512Digest());
        mac.init(new KeyParameter(key));
        mac.update(data, 0, data.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }
}
