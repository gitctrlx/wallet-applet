// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

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
 * The spec/protocol.md §1 primitives the vector documents need: SHA-256, AES-CBC/CMAC, the one-step
 * KDF and KDF108, M2 padding and secp256k1 ECDSA with RFC 6979 nonces. Implemented from the spec
 * here so the Java generator does not depend on the host library.
 */
final class Crypto {
    private static final X9ECParameters K1 = CustomNamedCurves.getByName("secp256k1");

    static final ECDomainParameters DOMAIN =
            new ECDomainParameters(K1.getCurve(), K1.getG(), K1.getN(), K1.getH());

    static final BigInteger N = K1.getN();

    private Crypto() {}

    static byte[] sha256(byte[]... parts) {
        SHA256Digest d = new SHA256Digest();
        for (byte[] p : parts) {
            d.update(p, 0, p.length);
        }
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    static byte[] cmac(byte[] key, byte[]... parts) {
        CMac mac = new CMac(AESEngine.newInstance());
        mac.init(new KeyParameter(key));
        for (byte[] p : parts) {
            mac.update(p, 0, p.length);
        }
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    static byte[] aesBlock(byte[] key, byte[] block) {
        BlockCipher engine = AESEngine.newInstance();
        engine.init(true, new KeyParameter(key));
        byte[] out = new byte[16];
        engine.processBlock(block, 0, out, 0);
        return out;
    }

    static byte[] aesCbc(byte[] key, byte[] iv, byte[] data, boolean encrypt) {
        CBCModeCipher engine = CBCBlockCipher.newInstance(AESEngine.newInstance());
        engine.init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] out = new byte[data.length];
        for (int off = 0; off < data.length; off += 16) {
            engine.processBlock(data, off, out, off);
        }
        return out;
    }

    /** SP 800-56C Rev. 2 §4.1 option 1: {@code SHA-256(u32(i) ‖ Z ‖ label ‖ ctx)} blocks. */
    static byte[] kdf(byte[] z, byte[] label, byte[] ctx, int len) {
        byte[] out = new byte[len];
        for (int i = 1, done = 0; done < len; i++) {
            byte[] block = sha256(u32(i), z, label, ctx);
            int take = Math.min(32, len - done);
            System.arraycopy(block, 0, out, done, take);
            done += take;
        }
        return out;
    }

    /** SP 800-108r1 §4.1 counter KDF, PRF = CMAC, r = 8, 256-bit output. */
    static byte[] kdf108(byte[] key, byte[] label, byte[] ctx) {
        byte[] out = new byte[32];
        for (int i = 1; i <= 2; i++) {
            byte[] block =
                    cmac(key, new byte[] {(byte) i}, label, new byte[] {0}, ctx, new byte[] {1, 0});
            System.arraycopy(block, 0, out, (i - 1) * 16, 16);
        }
        return out;
    }

    /** ISO/IEC 9797-1 padding method 2: {@code X ‖ 0x80 ‖ 0ᵏ} to a multiple of 16. */
    static byte[] m2pad(byte[] plain) {
        int padded = (plain.length / 16 + 1) * 16;
        byte[] out = new byte[padded];
        System.arraycopy(plain, 0, out, 0, plain.length);
        out[plain.length] = (byte) 0x80;
        return out;
    }

    static byte[] u16(int v) {
        return new byte[] {(byte) (v >>> 8), (byte) v};
    }

    static byte[] multiply(BigInteger scalar, byte[] point65) {
        ECPoint p = DOMAIN.getCurve().decodePoint(point65).multiply(scalar);
        if (p.isInfinity()) {
            return null;
        }
        return p.normalize().getEncoded(false);
    }

    static byte[] publicKey(BigInteger scalar) {
        return DOMAIN.getG().multiply(scalar).normalize().getEncoded(false);
    }

    static byte[] compress(byte[] point65) {
        return DOMAIN.getCurve().decodePoint(point65).getEncoded(true);
    }

    /** ECDSA {@code r(32) ‖ s(32)} over a 32-byte hash, RFC 6979 nonces, no low-s normalisation. */
    static byte[] sign(BigInteger privateKey, byte[] hash32) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(privateKey, DOMAIN));
        BigInteger[] rs = signer.generateSignature(hash32);
        byte[] out = new byte[64];
        writeFixed(rs[0], out, 0);
        writeFixed(rs[1], out, 32);
        return out;
    }

    /** ECDSA verification of {@code r ‖ s}; false on out-of-range scalars or a bad point. */
    static boolean verify(byte[] publicKey65, byte[] hash32, byte[] rs) {
        if (rs.length != 64) {
            return false;
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(rs, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(rs, 32, 64));
        if (r.signum() <= 0 || r.compareTo(N) >= 0 || s.signum() <= 0 || s.compareTo(N) >= 0) {
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

    private static void writeFixed(BigInteger v, byte[] out, int off) {
        byte[] b = v.toByteArray();
        int len = Math.min(b.length, 32);
        System.arraycopy(b, b.length - len, out, off + 32 - len, len);
    }

    private static byte[] u32(int v) {
        return new byte[] {(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v};
    }
}
