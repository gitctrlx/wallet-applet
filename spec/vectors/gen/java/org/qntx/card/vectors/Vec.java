// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import org.bouncycastle.crypto.digests.SHA256Digest;

/** Shared helpers of the vector documents: hex, ordered objects, ASCII and synthetic bytes. */
final class Vec {
    private static final HexFormat HEX = HexFormat.of();

    private Vec() {}

    /**
     * {@code det(name) = SHA-256(ASCII("qntx-card/vectors/" + name))} — the deterministic input of
     * every generated value; 16-byte values take the first 16 bytes.
     */
    static byte[] det(String name) {
        SHA256Digest d = new SHA256Digest();
        byte[] in = ascii("qntx-card/vectors/" + name);
        d.update(in, 0, in.length);
        byte[] out = new byte[32];
        d.doFinal(out, 0);
        return out;
    }

    /**
     * The first {@code len} bytes of {@code det(name) ‖ det(name + "/1") ‖ det(name + "/2") ‖ …};
     * for {@code len <= 32} this is just the prefix of {@code det(name)}.
     */
    static byte[] det(String name, int len) {
        byte[] out = new byte[len];
        for (int i = 0, done = 0; done < len; i++) {
            byte[] block = i == 0 ? det(name) : det(name + "/" + i);
            int take = Math.min(32, len - done);
            System.arraycopy(block, 0, out, done, take);
            done += take;
        }
        return out;
    }

    /** Ordered JSON object literal: alternating keys and values. */
    static Map<String, Object> object(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    static String hex(byte[] b) {
        return HEX.formatHex(b);
    }

    static byte[] unhex(String s) {
        return HEX.parseHex(s);
    }

    static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    /** {@code len} synthetic bytes starting at {@code first}, wrapping mod 256. */
    static byte[] seq(int first, int len) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) (first + i);
        }
        return out;
    }

    /** The 32-byte big-endian encoding of {@code v}. */
    static byte[] scalar(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        int len = Math.min(b.length, 32);
        System.arraycopy(b, b.length - len, out, 32 - len, len);
        return out;
    }

    /** Small test scalar: {@code 0^(31) ‖ n}. */
    static byte[] scalar(int n) {
        byte[] out = new byte[32];
        out[31] = (byte) n;
        return out;
    }
}
