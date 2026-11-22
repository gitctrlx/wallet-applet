// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CBCModeCipher;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;

/**
 * The cryptographic primitives of spec/protocol.md §1, §8 for the host side: SHA-256, AES-CBC and
 * AES-CMAC, the one-step KDF and KDF108, M2 padding and secp256k1 ECDSA (RFC 6979, no low-s
 * normalisation). Written from the spec only; nothing is taken from applet output.
 */
public final class Crypto {
    private static final X9ECParameters K1 = CustomNamedCurves.getByName("secp256k1");

    /** The secp256k1 domain parameters (SEC 2 §2.4.1). */
    public static final ECDomainParameters DOMAIN =
            new ECDomainParameters(K1.getCurve(), K1.getG(), K1.getN(), K1.getH());

    /** The group order {@code n}. */
    public static final BigInteger N = K1.getN();

    /** The generator {@code G}. */
    public static final ECPoint G = K1.getG();

    private Crypto() {}

    /** {@code SHA-256} of the concatenated parts. */
    public static byte[] sha256(byte[]... parts) {
        SHA256Digest d = new SHA256Digest();
        for (byte[] p : parts) {
            d.update(p, 0, p.length);
        }
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    /** Full 16-byte AES-CMAC of the concatenated parts under {@code key}. */
    public static byte[] cmac(byte[] key, byte[]... parts) {
        CMac mac = new CMac(AESEngine.newInstance());
        mac.init(new KeyParameter(key));
        for (byte[] p : parts) {
            mac.update(p, 0, p.length);
        }
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    /** One AES-128 block encrypt under {@code key}. */
    public static byte[] aesBlock(byte[] key, byte[] block) {
        if (block.length != 16) {
            throw new IllegalArgumentException("AES block must be 16 bytes");
        }
        BlockCipher engine = AESEngine.newInstance();
        engine.init(true, new KeyParameter(key));
        byte[] out = new byte[16];
        engine.processBlock(block, 0, out, 0);
        return out;
    }

    /** AES-128-CBC with a fixed IV; {@code data} must be a whole number of blocks. */
    public static byte[] aesCbc(byte[] key, byte[] iv, byte[] data, boolean encrypt) {
        if (data.length % 16 != 0) {
            throw new IllegalArgumentException("CBC input must be a multiple of 16");
        }
        CBCModeCipher engine = CBCBlockCipher.newInstance(AESEngine.newInstance());
        engine.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] out = new byte[data.length];
        for (int off = 0; off < data.length; off += 16) {
            engine.processBlock(data, off, out, off);
        }
        return out;
    }

    /**
     * One-step KDF of NIST SP 800-56C Rev. 2 §4.1 option 1 (§1): the first {@code len} bytes of
     * {@code SHA-256(u32(1) ‖ Z ‖ label ‖ ctx) ‖ SHA-256(u32(2) ‖ …)}, {@code len ≤ 64}.
     */
    public static byte[] kdf(byte[] z, byte[] label, byte[] ctx, int len) {
        if (len < 0 || len > 64) {
            throw new IllegalArgumentException("KDF length must be in [0, 64]");
        }
        byte[] out = new byte[len];
        for (int i = 1, done = 0; done < len; i++) {
            byte[] block = sha256(u32(i), z, label, ctx);
            int take = Math.min(32, len - done);
            System.arraycopy(block, 0, out, done, take);
            done += take;
        }
        return out;
    }

    /**
     * Counter-mode KDF of NIST SP 800-108r1 §4.1 with PRF = CMAC, r = 8, 256-bit output (§1):
     * {@code CMAC(K, i ‖ label ‖ 0x00 ‖ ctx ‖ 0x0100)} for {@code i = 1, 2}. Returns 32 bytes.
     */
    public static byte[] kdf108(byte[] key, byte[] label, byte[] ctx) {
        byte[] out = new byte[32];
        for (int i = 1; i <= 2; i++) {
            byte[] block =
                    cmac(key, new byte[] {(byte) i}, label, new byte[] {0}, ctx, new byte[] {1, 0});
            System.arraycopy(block, 0, out, (i - 1) * 16, 16);
        }
        return out;
    }

    /** ISO/IEC 9797-1 padding method 2: {@code X ‖ 0x80 ‖ 0ᵏ} to a multiple of 16. */
    public static byte[] m2pad(byte[] plain) {
        int padded = (plain.length / 16 + 1) * 16;
        byte[] out = new byte[padded];
        System.arraycopy(plain, 0, out, 0, plain.length);
        out[plain.length] = (byte) 0x80;
        return out;
    }

    /**
     * Removes M2 padding; {@code null} when the input is empty, not a multiple of 16, its last
     * non-zero byte is not {@code 0x80} or more than 15 zero bytes follow it.
     */
    public static byte[] m2unpad(byte[] padded) {
        if (padded.length == 0 || padded.length % 16 != 0) {
            return null;
        }
        int marker = -1;
        for (int i = 0; i < padded.length; i++) {
            if (padded[i] != 0) {
                marker = i;
            }
        }
        if (marker < 0 || padded[marker] != (byte) 0x80 || padded.length - marker > 16) {
            return null;
        }
        return Arrays.copyOf(padded, marker);
    }

    /** Big-endian two-byte encoding of {@code v & 0xFFFF}. */
    public static byte[] u16(int v) {
        return new byte[] {(byte) (v >>> 8), (byte) v};
    }

    /** Constant-time equality; used for every tag/MAC/signature comparison. */
    public static boolean equalConstantTime(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    /** {@code scalar · point} as a 65-byte uncompressed encoding, {@code null} on infinity. */
    public static byte[] multiply(BigInteger scalar, byte[] point65) {
        ECPoint p = DOMAIN.getCurve().decodePoint(point65).multiply(scalar);
        if (p.isInfinity()) {
            return null;
        }
        return p.normalize().getEncoded(false);
    }

    /** {@code scalar · G} uncompressed (65 bytes). */
    public static byte[] publicKey(BigInteger scalar) {
        return DOMAIN.getG().multiply(scalar).normalize().getEncoded(false);
    }

    /** SEC 1 §2.3.3 compression of a point (33 bytes). */
    public static byte[] compress(byte[] point65) {
        return DOMAIN.getCurve().decodePoint(point65).getEncoded(true);
    }

    /** SEC 1 §2.3.4 decompression of a compressed point (65 bytes). */
    public static byte[] decompress(byte[] compressed33) {
        return DOMAIN.getCurve().decodePoint(compressed33).getEncoded(false);
    }

    /**
     * ECDSA over the 32-byte message hash with RFC 6979 nonces (SHA-256) and no low-s normalisation
     * (§1, spec/vectors README); wire form {@code r(32) ‖ s(32)}.
     */
    public static byte[] sign(BigInteger privateKey, byte[] hash32) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(privateKey, DOMAIN));
        BigInteger[] rs = signer.generateSignature(hash32);
        byte[] out = new byte[64];
        writeFixed(rs[0], out, 0);
        writeFixed(rs[1], out, 32);
        return out;
    }

    /**
     * ECDSA verification of {@code r ‖ s} under the uncompressed public key; fails when {@code r}
     * or {@code s} is outside {@code [1, n−1]} (§1) or the point does not decode.
     */
    public static boolean verify(byte[] publicKey65, byte[] hash32, byte[] rs) {
        if (rs.length != 64) {
            return false;
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(rs, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(rs, 32, 64));
        if (!inRange(r) || !inRange(s)) {
            return false;
        }
        ECPoint q;
        try {
            q = DOMAIN.getCurve().decodePoint(publicKey65);
        } catch (IllegalArgumentException e) {
            return false;
        }
        ECDSASigner signer = new ECDSASigner();
        signer.init(false, new ECPublicKeyParameters(q, DOMAIN));
        return signer.verifySignature(hash32, r, s);
    }

    private static boolean inRange(BigInteger v) {
        return v.signum() > 0 && v.compareTo(N) < 0;
    }

    private static void writeFixed(BigInteger v, byte[] out, int off) {
        byte[] b = v.toByteArray();
        int len = Math.min(b.length, 32);
        System.arraycopy(b, b.length - len, out, off + 32 - len, len);
    }

    private static byte[] u32(int v) {
        return new byte[] {(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v};
    }
}
