// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.math.ec.ECPoint;

/**
 * {@code ecdsa.json}: secp256k1 ECDSA signing vectors of spec/protocol.md §12.1 over the secp256k1
 * templates of {@code derivation.json}. Signatures are RFC 6979 deterministic (no low-s
 * normalisation); each case also carries the low-s and high-s variants with the SEC 1 §4.1.6
 * recovery id of every variant, recovered independently with point arithmetic. The {@code invalid}
 * entries are asserted to fail §1 verification ({@code r}, {@code s} outside {@code [1, n−1]},
 * wrong digest, wrong key).
 */
final class EcdsaDoc {
    private static final BigInteger N = Crypto.N;
    private static final BigInteger P = Crypto.DOMAIN.getCurve().getField().getCharacteristic();

    private static final String[][] TEMPLATES = {
        {"evm", "m/44'/60'/0'/0/0"},
        {"tron", "m/44'/195'/0'/0/0"},
        {"btc-bip84-account", "m/84'/0'/0'"},
        {"btc-bip84", "m/84'/0'/0'/0/0"},
        {"depth-10", "m/0/1'/2/3'/4/5'/6/7'/8/9'"},
    };

    private EcdsaDoc() {}

    static Object document() {
        List<Object> cases = new ArrayList<>();
        List<byte[]> keys33 = new ArrayList<>();
        List<byte[]> digests = new ArrayList<>();
        List<byte[]> signatures = new ArrayList<>();
        for (String[] t : TEMPLATES) {
            cases.add(signCase(t[0], t[1], keys33, digests, signatures));
        }
        return Vec.object("cases", cases, "invalid", invalid(keys33, digests, signatures));
    }

    private static Object signCase(
            String name,
            String path,
            List<byte[]> keys33,
            List<byte[]> digests,
            List<byte[]> signatures) {
        Hd.Node node = Hd.bip32Derive(DerivationDoc.TEMPLATE_SEED, path);
        BigInteger d = new BigInteger(1, node.privateKey());
        byte[] pub65 = Crypto.publicKey(d);
        byte[] pub33 = Crypto.compress(pub65);
        byte[] digest = Vec.det("ecdsa/" + name + "/digest");
        byte[] sig = Crypto.sign(d, digest);
        byte[] lowS = flipS(sig, false);
        byte[] highS = flipS(sig, true);
        assertVerify(pub65, digest, sig, name + " signature");
        assertVerify(pub65, digest, lowS, name + " lowS");
        assertVerify(pub65, digest, highS, name + " highS");
        keys33.add(pub33);
        digests.add(digest);
        signatures.add(lowS);
        return Vec.object(
                "name", name,
                "path", path,
                "wire", Vec.hex(Hd.wire(path)),
                "privateKey", Vec.hex(node.privateKey()),
                "publicKey", Vec.hex(pub33),
                "publicKeyUncompressed", Vec.hex(pub65),
                "digest", Vec.hex(digest),
                "signature", Vec.hex(sig),
                "recoveryId", recoveryId(pub65, digest, sig),
                "lowS", Vec.hex(lowS),
                "lowSRecoveryId", recoveryId(pub65, digest, lowS),
                "highS", Vec.hex(highS),
                "highSRecoveryId", recoveryId(pub65, digest, highS));
    }

    /** {@code r ‖ min(s, n−s)} or {@code r ‖ max(s, n−s)} of the {@code r ‖ s} signature. */
    private static byte[] flipS(byte[] rs, boolean high) {
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(rs, 32, 64));
        BigInteger complement = N.subtract(s);
        BigInteger v = high == (s.compareTo(complement) >= 0) ? s : complement;
        byte[] out = rs.clone();
        System.arraycopy(Vec.scalar(v), 0, out, 32, 32);
        return out;
    }

    /**
     * The SEC 1 §4.1.6 recovery id (0–3) of {@code r ‖ s} for {@code publicKey65}: candidate {@code
     * R} points are {@code x = r + (i ≫ 1)·n} with {@code y} parity {@code i & 1}, the key is
     * {@code r⁻¹·(s·R − e·G)}.
     */
    private static int recoveryId(byte[] publicKey65, byte[] digest, byte[] rs) {
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(rs, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(rs, 32, 64));
        BigInteger e = new BigInteger(1, digest);
        ECPoint q = Crypto.DOMAIN.getCurve().decodePoint(publicKey65);
        BigInteger rInv = r.modInverse(N);
        for (int i = 0; i < 4; i++) {
            BigInteger x = i < 2 ? r : r.add(N);
            if (x.compareTo(P) >= 0) {
                continue;
            }
            byte[] enc = new byte[33];
            enc[0] = (byte) (0x02 | (i & 1));
            System.arraycopy(Vec.scalar(x), 0, enc, 1, 32);
            ECPoint pointR;
            try {
                pointR = Crypto.DOMAIN.getCurve().decodePoint(enc);
            } catch (RuntimeException bad) {
                continue;
            }
            if (!pointR.multiply(N).isInfinity()) {
                continue;
            }
            ECPoint candidate =
                    pointR.multiply(s)
                            .subtract(Crypto.DOMAIN.getG().multiply(e))
                            .multiply(rInv)
                            .normalize();
            if (candidate.equals(q)) {
                return i;
            }
        }
        throw new IllegalStateException("no recovery id for " + Vec.hex(rs));
    }

    private static List<Object> invalid(
            List<byte[]> keys33, List<byte[]> digests, List<byte[]> signatures) {
        byte[] evmKey = keys33.get(0);
        byte[] evmDigest = digests.get(0);
        byte[] evmSig = signatures.get(0);
        byte[] wrongDigest = evmDigest.clone();
        wrongDigest[31] ^= 0x01;
        List<Object> out = new ArrayList<>();
        out.add(
                invalid(
                        "r-zero",
                        evmKey,
                        evmDigest,
                        withComponent(evmSig, 0, new byte[32]),
                        "r is outside [1, n-1]"));
        out.add(
                invalid(
                        "s-zero",
                        evmKey,
                        evmDigest,
                        withComponent(evmSig, 1, new byte[32]),
                        "s is outside [1, n-1]"));
        out.add(
                invalid(
                        "r-is-n",
                        evmKey,
                        evmDigest,
                        withComponent(evmSig, 0, Vec.scalar(N)),
                        "r is outside [1, n-1]"));
        out.add(
                invalid(
                        "s-is-n",
                        evmKey,
                        evmDigest,
                        withComponent(evmSig, 1, Vec.scalar(N)),
                        "s is outside [1, n-1]"));
        out.add(
                invalid(
                        "wrong-digest",
                        evmKey,
                        wrongDigest,
                        evmSig,
                        "the signature was made over a different digest"));
        out.add(
                invalid(
                        "wrong-key",
                        keys33.get(1),
                        evmDigest,
                        evmSig,
                        "the signature was made under a different key"));
        return out;
    }

    private static byte[] withComponent(byte[] rs, int half, byte[] component) {
        byte[] out = rs.clone();
        System.arraycopy(component, 0, out, 32 * half, 32);
        return out;
    }

    private static Object invalid(
            String name, byte[] publicKey33, byte[] digest, byte[] signature, String reason) {
        byte[] pub65 = Crypto.DOMAIN.getCurve().decodePoint(publicKey33).getEncoded(false);
        if (Crypto.verify(pub65, digest, signature)) {
            throw new IllegalStateException("invalid case verifies: " + name);
        }
        return Vec.object(
                "name", name,
                "publicKey", Vec.hex(publicKey33),
                "digest", Vec.hex(digest),
                "signature", Vec.hex(signature),
                "reason", reason);
    }

    private static void assertVerify(byte[] pub65, byte[] digest, byte[] sig, String what) {
        if (!Crypto.verify(pub65, digest, sig)) {
            throw new IllegalStateException("signature does not verify: " + what);
        }
    }
}
