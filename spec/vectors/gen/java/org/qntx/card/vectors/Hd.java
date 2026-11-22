// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * The private derivations of spec/protocol.md §10.2–10.4: BIP-32 {@code CKDpriv} over secp256k1
 * from {@code HMAC-SHA512("Bitcoin seed", seed)} and SLIP-10 for ed25519 from {@code
 * HMAC-SHA512("ed25519 seed", seed)}.
 */
final class Hd {
    private static final byte[] BITCOIN_SEED = Vec.ascii("Bitcoin seed");
    private static final byte[] ED25519_SEED = Vec.ascii("ed25519 seed");
    static final long HARDENED = 0x80000000L;

    /** An extended private node: 32-byte key and 32-byte chain code. */
    record Node(byte[] privateKey, byte[] chainCode) {}

    private Hd() {}

    /**
     * The BIP-32 master node of {@code seed} (§10.2). Throws {@link IllegalStateException} when
     * {@code kM} is outside {@code [1, n−1]}.
     */
    static Node bip32Master(byte[] seed) {
        byte[] i = Crypto.hmacSha512(BITCOIN_SEED, seed);
        BigInteger k = new BigInteger(1, Arrays.copyOf(i, 32));
        if (k.signum() <= 0 || k.compareTo(Crypto.N) >= 0) {
            throw new IllegalStateException("invalid BIP-32 master key");
        }
        return new Node(Arrays.copyOf(i, 32), Arrays.copyOfRange(i, 32, 64));
    }

    /**
     * BIP-32 {@code CKDpriv} (§10.3): hardened {@code I = HMAC-SHA512(c, 0x00 ‖ k ‖ u32(i))},
     * non-hardened {@code I = HMAC-SHA512(c, compressed(k·G) ‖ u32(i))}. Returns {@code null} for
     * an invalid child ({@code int(I_L) ≥ n} or {@code k = 0}).
     */
    static Node bip32Child(Node parent, long index) {
        byte[] i =
                Crypto.hmacSha512(parent.chainCode(), childData(parent, index, true), u32(index));
        byte[] k = childStep(parent.privateKey(), Arrays.copyOf(i, 32));
        if (k == null) {
            return null;
        }
        return new Node(k, Arrays.copyOfRange(i, 32, 64));
    }

    /**
     * The child step {@code k = (int(IL) + k_par) mod n} shared by {@link #bip32Child} and the
     * {@code invalidChild} cases: {@code null} when {@code int(IL) ≥ n} or the sum is zero.
     */
    static byte[] childStep(byte[] parentKey, byte[] il) {
        BigInteger left = new BigInteger(1, il);
        if (left.compareTo(Crypto.N) >= 0) {
            return null;
        }
        BigInteger k = left.add(new BigInteger(1, parentKey)).mod(Crypto.N);
        if (k.signum() == 0) {
            return null;
        }
        return Vec.scalar(k);
    }

    /** The SLIP-10 ed25519 master node of {@code seed} (§10.2); always valid. */
    static Node slip10Master(byte[] seed) {
        byte[] i = Crypto.hmacSha512(ED25519_SEED, seed);
        return new Node(Arrays.copyOf(i, 32), Arrays.copyOfRange(i, 32, 64));
    }

    /** The BIP-32 node at {@code path} derived from {@code seed}; throws on an invalid child. */
    static Node bip32Derive(byte[] seed, String path) {
        Node node = bip32Master(seed);
        for (long index : indices(path)) {
            node = bip32Child(node, index);
            if (node == null) {
                throw new IllegalStateException("invalid child on path " + path);
            }
        }
        return node;
    }

    /** The SLIP-10 ed25519 node at {@code path} derived from {@code seed}. */
    static Node slip10Derive(byte[] seed, String path) {
        Node node = slip10Master(seed);
        for (long index : indices(path)) {
            node = slip10Child(node, index);
        }
        return node;
    }

    /** SLIP-10 ed25519 child (§10.4): only hardened indices exist; every index is {@code i'}. */
    static Node slip10Child(Node parent, long index) {
        if (index < HARDENED || index > 0xFFFFFFFFL) {
            throw new IllegalArgumentException("ed25519 paths are hardened: " + index);
        }
        byte[] i =
                Crypto.hmacSha512(parent.chainCode(), childData(parent, index, false), u32(index));
        return new Node(Arrays.copyOf(i, 32), Arrays.copyOfRange(i, 32, 64));
    }

    /**
     * The data argument of {@code I}: {@code 0x00 ‖ k(32)} hardened, {@code compressed(k·G)}
     * non-hardened (bip32 only).
     */
    private static byte[] childData(Node parent, long index, boolean bip32) {
        byte[] prefix;
        if (index >= HARDENED || !bip32) {
            prefix = new byte[33];
            System.arraycopy(parent.privateKey(), 0, prefix, 1, 32);
        } else {
            prefix = Crypto.compress(Crypto.publicKey(new BigInteger(1, parent.privateKey())));
        }
        return prefix;
    }

    private static byte[] u32(long v) {
        return new byte[] {
            (byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v,
        };
    }

    /**
     * The {@code "m/…"} string form to the wire indices: {@code '44''} is {@code 44 + 2³¹}; each
     * index is an unsigned 32-bit value.
     */
    static long[] indices(String path) {
        if (path.equals("m")) {
            return new long[0];
        }
        if (!path.startsWith("m/")) {
            throw new IllegalArgumentException("path must start with m/: " + path);
        }
        String[] parts = path.substring(2).split("/");
        if (parts.length < 1 || parts.length > 10) {
            throw new IllegalArgumentException("path depth must be in [1, 10]: " + path);
        }
        long[] out = new long[parts.length];
        for (int i = 0; i < parts.length; i++) {
            String p = parts[i];
            long index = 0;
            if (p.endsWith("'")) {
                index = HARDENED;
                p = p.substring(0, p.length() - 1);
            }
            if (p.isEmpty() || p.length() > 10 || !p.chars().allMatch(Character::isDigit)) {
                throw new IllegalArgumentException("bad path index: " + path);
            }
            long v = Long.parseLong(p);
            if (v >= HARDENED) {
                throw new IllegalArgumentException("path index too large: " + path);
            }
            out[i] = index + v;
        }
        return out;
    }

    /** The §9.2 wire form of a non-master path: {@code depth(1) ‖ u32(index)…}. */
    static byte[] wire(String path) {
        long[] idx = indices(path);
        if (idx.length == 0) {
            throw new IllegalArgumentException("the master path has no wire form");
        }
        byte[] out = new byte[1 + 4 * idx.length];
        out[0] = (byte) idx.length;
        for (int i = 0; i < idx.length; i++) {
            System.arraycopy(u32(idx[i]), 0, out, 1 + 4 * i, 4);
        }
        return out;
    }
}
