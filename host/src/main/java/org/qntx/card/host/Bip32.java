// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * BIP-32 {@code CKDpriv} over secp256k1 (spec/protocol.md §10.2–10.3): the master node is {@code
 * HMAC-SHA512("Bitcoin seed", seed)} and is valid when {@code 1 ≤ kM ≤ n − 1}; a child is invalid
 * when {@code int(I_L) ≥ n} or the derived key is zero.
 */
public final class Bip32 {
    private static final byte[] SEED_KEY = "Bitcoin seed".getBytes(StandardCharsets.US_ASCII);

    /** An extended private node: the 32-byte key and its 32-byte chain code. */
    public record Node(byte[] privateKey, byte[] chainCode) {
        /** The SEC 1 compressed public key {@code k·G} (33 bytes). */
        public byte[] publicKey() {
            return Crypto.compress(Crypto.publicKey(new BigInteger(1, privateKey)));
        }
    }

    private Bip32() {}

    /**
     * The master node of {@code seed} (§10.2).
     *
     * @throws IllegalArgumentException when the master key is outside {@code [1, n−1]}
     */
    public static Node master(byte[] seed) {
        byte[] i = Crypto.hmacSha512(SEED_KEY, seed);
        BigInteger k = new BigInteger(1, Arrays.copyOf(i, 32));
        if (k.signum() <= 0 || k.compareTo(Crypto.N) >= 0) {
            throw new IllegalArgumentException("invalid BIP-32 master key");
        }
        return new Node(Arrays.copyOf(i, 32), Arrays.copyOfRange(i, 32, 64));
    }

    /** The compressed master public key {@code compressed(kM·G)} of §9.2's WalletInfo. */
    public static byte[] masterPublicKey(byte[] seed) {
        return master(seed).publicKey();
    }

    /**
     * The node at {@code path} ({@code "m"}, {@code "m/44'/60'/0'/0/0"}, …) by repeated {@code
     * CKDpriv} (§10.3).
     *
     * @throws IllegalArgumentException on a malformed path or an invalid child
     */
    public static Node derive(byte[] seed, String path) {
        Node node = master(seed);
        for (long index : Paths.indices(path)) {
            node = child(node, index);
        }
        return node;
    }

    /**
     * One {@code CKDpriv} step: hardened {@code I = HMAC-SHA512(c, 0x00 ‖ k ‖ u32(i))},
     * non-hardened {@code I = HMAC-SHA512(c, compressed(k·G) ‖ u32(i))}, {@code k = (int(I_L) +
     * k_par) mod n}, {@code c = I_R} (§10.3).
     *
     * @throws IllegalArgumentException when {@code int(I_L) ≥ n} or the child key is zero
     */
    public static Node child(Node parent, long index) {
        byte[] prefix;
        if (index >= Paths.HARDENED) {
            prefix = new byte[33];
            System.arraycopy(parent.privateKey(), 0, prefix, 1, 32);
        } else {
            prefix = Crypto.compress(Crypto.publicKey(new BigInteger(1, parent.privateKey())));
        }
        byte[] i =
                Crypto.hmacSha512(
                        parent.chainCode(),
                        prefix,
                        new byte[] {
                            (byte) (index >>> 24),
                            (byte) (index >>> 16),
                            (byte) (index >>> 8),
                            (byte) index
                        });
        BigInteger left = new BigInteger(1, Arrays.copyOf(i, 32));
        if (left.compareTo(Crypto.N) >= 0) {
            throw new IllegalArgumentException("invalid BIP-32 child: I_L ≥ n");
        }
        BigInteger k = left.add(new BigInteger(1, parent.privateKey())).mod(Crypto.N);
        if (k.signum() == 0) {
            throw new IllegalArgumentException("invalid BIP-32 child: zero key");
        }
        byte[] key = new byte[32];
        byte[] kb = k.toByteArray();
        int len = Math.min(kb.length, 32);
        System.arraycopy(kb, kb.length - len, key, 32 - len, len);
        return new Node(key, Arrays.copyOfRange(i, 32, 64));
    }
}
