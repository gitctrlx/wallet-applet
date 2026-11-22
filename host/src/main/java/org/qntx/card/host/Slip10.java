// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.bouncycastle.math.ec.ECPoint;

/**
 * SLIP-10 for ed25519 (spec/protocol.md §10.2, §10.4): the master node is {@code
 * HMAC-SHA512("ed25519 seed", seed)}, every child is hardened ({@code I = HMAC-SHA512(c_par, 0x00 ‖
 * k_par ‖ u32(i'))}), and the leaf key is an RFC 8032 private key whose public point the card
 * outputs as the Wei25519 point {@code W(A) = X(32) ‖ Y(32)}.
 */
public final class Slip10 {
    private static final byte[] SEED_KEY = "ed25519 seed".getBytes(StandardCharsets.US_ASCII);

    /** A SLIP-10 node: the 32-byte key and its 32-byte chain code. */
    public record Node(byte[] privateKey, byte[] chainCode) {}

    private Slip10() {}

    /**
     * The node at {@code path}; every index MUST be hardened (§9.2, §10.4).
     *
     * @throws IllegalArgumentException on a malformed path or a non-hardened index
     */
    public static Node derive(byte[] seed, String path) {
        byte[] i = Crypto.hmacSha512(SEED_KEY, seed);
        Node node = new Node(Arrays.copyOf(i, 32), Arrays.copyOfRange(i, 32, 64));
        for (long index : Paths.indices(path)) {
            if (index < Paths.HARDENED || index > 0xFFFFFFFFL) {
                throw new IllegalArgumentException("ed25519 paths are hardened: " + path);
            }
            byte[] data = new byte[37];
            System.arraycopy(node.privateKey(), 0, data, 1, 32);
            data[33] = (byte) (index >>> 24);
            data[34] = (byte) (index >>> 16);
            data[35] = (byte) (index >>> 8);
            data[36] = (byte) index;
            i = Crypto.hmacSha512(node.chainCode(), data);
            node = new Node(Arrays.copyOf(i, 32), Arrays.copyOfRange(i, 32, 64));
        }
        return node;
    }

    /**
     * {@code W(A)} of the leaf private key {@code privateKey} (§10.4): with {@code a =
     * clamp(SHA-512(sk)[0..32))} read little-endian (RFC 8032 §5.1.5), the 64-byte {@code X ‖ Y} of
     * {@code (a mod ℓ)·G_W}.
     */
    public static byte[] wei(byte[] privateKey) {
        if (privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("ed25519 private key must be 32 bytes");
        }
        byte[] a = Arrays.copyOf(Crypto.sha512(privateKey), 32);
        a[0] &= 0xf8;
        a[31] &= 0x7f;
        a[31] |= 0x40;
        for (int i = 0, j = 31; i < j; i++, j--) {
            byte t = a[i];
            a[i] = a[j];
            a[j] = t;
        }
        BigInteger scalar = new BigInteger(1, a).mod(Wei25519.ORDER);
        ECPoint p = Wei25519.G.multiply(scalar).normalize();
        byte[] out = new byte[64];
        write(p.getAffineXCoord().toBigInteger(), out, 0);
        write(p.getAffineYCoord().toBigInteger(), out, 32);
        return out;
    }

    private static void write(BigInteger v, byte[] out, int off) {
        byte[] b = v.toByteArray();
        int len = Math.min(b.length, 32);
        System.arraycopy(b, b.length - len, out, off + 32 - len, len);
    }
}
