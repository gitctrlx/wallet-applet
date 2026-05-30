/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.proto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Host-side cryptographic primitives for the meowl Secure Channel client:
 *
 * <ul>
 *   <li>secp256k1 ephemeral key generation + ECDH x-coordinate
 *   <li>AES-256-CBC encrypt / decrypt with PKCS#5 padding
 *   <li>AES-CMAC-128 (the channel MAC; matches the J3R180 native primitive)
 *   <li>SHA-256 with optional 16-byte truncation (the KDF salt compressor)
 *   <li>SHA-256-with-ECDSA verification on secp256k1 (handshake authentication)
 * </ul>
 *
 * <p>JDK JCE handles AES / message-digest; BouncyCastle provides the AES-CMAC-128 PRF and the curve
 * arithmetic.
 */
public final class HostCrypto {

    /** secp256k1 curve parameters, sourced from BouncyCastle's named-curve registry. */
    public static final X9ECParameters SECP256K1 = CustomNamedCurves.getByName("secp256k1");

    /** Length of the AES-256 K_enc key, in bytes. */
    public static final int AES_KEY_LEN = 32;

    /** Length of the AES-128 K_mac key, in bytes (matches the AES-CMAC-128 key width). */
    public static final int MAC_KEY_LEN = 16;

    /** AES-CBC block size and IV length, in bytes. */
    public static final int AES_BLOCK_LEN = 16;

    /** AES-CMAC-128 tag length used for the channel MAC. */
    public static final int MAC_LEN = 16;

    /** Length of an EC scalar (private key, x-coordinate, hash output). */
    public static final int EC_SCALAR_LEN = 32;

    /** Length of an uncompressed secp256k1 point: {@code 0x04 || x(32) || y(32)}. */
    public static final int EC_POINT_UNCOMPRESSED_LEN = 65;

    /** Length of a compressed secp256k1 point: {@code 0x02|0x03 || x(32)}. */
    public static final int EC_POINT_COMPRESSED_LEN = 33;

    private static final SecureRandom RNG = new SecureRandom();

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private HostCrypto() {}

    /** Ephemeral secp256k1 keypair returned to the caller after {@link #generateEphKeyPair()}. */
    public record EphKeyPair(BigInteger privateScalar, byte[] publicEncoded) {

        public EphKeyPair {
            Objects.requireNonNull(privateScalar, "privateScalar");
            Objects.requireNonNull(publicEncoded, "publicEncoded");
            if (publicEncoded.length != EC_POINT_UNCOMPRESSED_LEN) {
                throw new IllegalArgumentException(
                        "publicEncoded must be %d bytes, got %d"
                                .formatted(EC_POINT_UNCOMPRESSED_LEN, publicEncoded.length));
            }
        }

        /** The 32-byte affine x-coordinate of the public key. */
        public byte[] xCoordinate() {
            return Arrays.copyOfRange(publicEncoded, 1, 1 + EC_SCALAR_LEN);
        }
    }

    /**
     * Generates a fresh secp256k1 ephemeral keypair. Private scalar is drawn from {@code [1, n-1]}
     * via rejection sampling; public key is SEC1 uncompressed.
     */
    public static EphKeyPair generateEphKeyPair() {
        BigInteger n = SECP256K1.getN();
        BigInteger d;
        byte[] candidate = new byte[EC_SCALAR_LEN];
        do {
            RNG.nextBytes(candidate);
            d = new BigInteger(1, candidate);
        } while (d.signum() == 0 || d.compareTo(n) >= 0);

        org.bouncycastle.math.ec.ECPoint pub = SECP256K1.getG().multiply(d).normalize();
        byte[] encoded = pub.getEncoded(false); // false = uncompressed
        // Defensive copy — getEncoded() returns a fresh array per call already, but make this
        // intent obvious to readers.
        return new EphKeyPair(d, encoded.clone());
    }

    /**
     * Computes the secp256k1 ECDH shared {@code x}-coordinate between {@code clientPriv} and the
     * SEC1-uncompressed peer {@code peerPubEncoded}.
     *
     * @return the 32-byte big-endian shared {@code x}
     * @throws IllegalArgumentException if {@code peerPubEncoded} is not on the curve
     */
    public static byte[] ecdhSharedX(BigInteger clientPriv, byte[] peerPubEncoded) {
        Objects.requireNonNull(clientPriv, "clientPriv");
        Objects.requireNonNull(peerPubEncoded, "peerPubEncoded");
        if (peerPubEncoded.length != EC_POINT_UNCOMPRESSED_LEN
                || (peerPubEncoded[0] & 0xFF) != 0x04) {
            throw new IllegalArgumentException(
                    "peer public key must be 65-byte SEC1-uncompressed (0x04 || x || y)");
        }
        org.bouncycastle.math.ec.ECPoint peerPoint;
        try {
            peerPoint = SECP256K1.getCurve().decodePoint(peerPubEncoded).normalize();
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("peer public key is not on the secp256k1 curve", e);
        }
        org.bouncycastle.math.ec.ECPoint shared = peerPoint.multiply(clientPriv).normalize();
        return bigIntToFixed(shared.getAffineXCoord().toBigInteger(), EC_SCALAR_LEN);
    }

    /** Verifies a DER-encoded SHA-256-with-ECDSA signature on secp256k1. */
    public static boolean verifyEcdsaSecp256k1(
            byte[] compressedPubkey, byte[] message, byte[] derSignature) {
        Objects.requireNonNull(compressedPubkey, "compressedPubkey");
        Objects.requireNonNull(message, "message");
        Objects.requireNonNull(derSignature, "derSignature");
        if (compressedPubkey.length != EC_POINT_COMPRESSED_LEN) {
            throw new IllegalArgumentException(
                    "compressed pubkey must be %d bytes".formatted(EC_POINT_COMPRESSED_LEN));
        }
        try {
            org.bouncycastle.math.ec.ECPoint point =
                    SECP256K1.getCurve().decodePoint(compressedPubkey).normalize();
            EllipticCurve curve =
                    new EllipticCurve(
                            new ECFieldFp(SECP256K1.getCurve().getField().getCharacteristic()),
                            SECP256K1.getCurve().getA().toBigInteger(),
                            SECP256K1.getCurve().getB().toBigInteger());
            ECParameterSpec params =
                    new ECParameterSpec(
                            curve,
                            new ECPoint(
                                    SECP256K1.getG().getAffineXCoord().toBigInteger(),
                                    SECP256K1.getG().getAffineYCoord().toBigInteger()),
                            SECP256K1.getN(),
                            SECP256K1.getH().intValue());
            ECPublicKeySpec spec =
                    new ECPublicKeySpec(
                            new ECPoint(
                                    point.getAffineXCoord().toBigInteger(),
                                    point.getAffineYCoord().toBigInteger()),
                            params);
            KeyFactory kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
            Signature verifier =
                    Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME);
            verifier.initVerify(kf.generatePublic(spec));
            verifier.update(message);
            return verifier.verify(derSignature);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA256withECDSA / secp256k1 unavailable", e);
        }
    }

    /** Encrypts plaintext with AES-256-CBC, padding to the AES block size with PKCS#5. */
    public static byte[] aesCbcEncrypt(byte[] key, byte[] iv, byte[] plaintext) {
        return aesCbc(Cipher.ENCRYPT_MODE, key, iv, pkcs5Pad(plaintext));
    }

    /**
     * Decrypts AES-256-CBC ciphertext and strips PKCS#5 padding. Raises {@link
     * SecureChannelException} on a malformed pad (treated as a MAC-equivalent failure per
     * protocol.md §6.3).
     */
    public static byte[] aesCbcDecrypt(byte[] key, byte[] iv, byte[] ciphertext) {
        byte[] padded = aesCbc(Cipher.DECRYPT_MODE, key, iv, ciphertext);
        return pkcs5Unpad(padded);
    }

    /**
     * Computes the Secure Channel envelope MAC: AES-CMAC-128 over the concatenation of {@code
     * parts} keyed by the 16-byte {@code key}. Matches the applet-side {@code
     * Signature.ALG_AES_CMAC_128} primitive exactly.
     */
    public static byte[] aesCmac128(byte[] key, byte[]... parts) {
        Objects.requireNonNull(key, "key");
        if (key.length != MAC_KEY_LEN) {
            throw new IllegalArgumentException(
                    "AES-CMAC-128 key must be %d bytes, got %d".formatted(MAC_KEY_LEN, key.length));
        }
        try {
            Mac mac = Mac.getInstance("AESCMAC", BouncyCastleProvider.PROVIDER_NAME);
            mac.init(new SecretKeySpec(key, "AES"));
            for (byte[] part : parts) {
                Objects.requireNonNull(part, "part");
                mac.update(part);
            }
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-CMAC-128 unavailable", e);
        }
    }

    /** SHA-256 over a single message; used by tests that compare against the applet's digest. */
    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * Encodes a non-negative {@link BigInteger} as a big-endian fixed-length byte array,
     * left-padding with zeros (or stripping a leading zero sign byte) as needed.
     */
    public static byte[] bigIntToFixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        if (raw.length == length) return raw;
        byte[] out = new byte[length];
        if (raw.length > length) {
            // BigInteger#toByteArray prepends a sign byte for positive values whose high bit is
            // 1; strip it but reject genuine overflows. The diagnostic deliberately omits the
            // value itself because this helper may handle secret scalar material.
            int excess = raw.length - length;
            for (int i = 0; i < excess; i++) {
                if (raw[i] != 0) {
                    throw new IllegalArgumentException(
                            "value does not fit in "
                                    + length
                                    + " bytes (encoded width "
                                    + raw.length
                                    + " bytes)");
                }
            }
            System.arraycopy(raw, excess, out, 0, length);
        } else {
            System.arraycopy(raw, 0, out, length - raw.length, raw.length);
        }
        return out;
    }

    /** Concatenates an arbitrary number of byte arrays. */
    public static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) total += part.length;
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, pos, part.length);
            pos += part.length;
        }
        return out;
    }

    private static byte[] aesCbc(int mode, byte[] key, byte[] iv, byte[] input) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(iv, "iv");
        if (key.length != AES_KEY_LEN) {
            throw new IllegalArgumentException(
                    "AES key must be %d bytes, got %d".formatted(AES_KEY_LEN, key.length));
        }
        if (iv.length != AES_BLOCK_LEN) {
            throw new IllegalArgumentException(
                    "AES-CBC IV must be %d bytes, got %d".formatted(AES_BLOCK_LEN, iv.length));
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-256-CBC unavailable", e);
        }
    }

    private static byte[] pkcs5Pad(byte[] in) {
        int padLen = AES_BLOCK_LEN - (in.length % AES_BLOCK_LEN);
        byte[] out = new byte[in.length + padLen];
        System.arraycopy(in, 0, out, 0, in.length);
        Arrays.fill(out, in.length, out.length, (byte) padLen);
        return out;
    }

    /**
     * Strips PKCS#5 padding from a decrypted block. Every padding failure raises {@link
     * SecureChannelException} so the Secure Channel stack speaks one exception family. {@code sw =
     * 0} because the failure is detected entirely in host code after AES decrypt.
     */
    private static byte[] pkcs5Unpad(byte[] padded) {
        if (padded.length == 0 || padded.length % AES_BLOCK_LEN != 0) {
            throw new SecureChannelException(
                    0, "PKCS#5 input must be a non-empty multiple of the block size");
        }
        int padLen = padded[padded.length - 1] & 0xFF;
        if (padLen == 0 || padLen > AES_BLOCK_LEN) {
            throw new SecureChannelException(0, "Invalid PKCS#5 pad length: " + padLen);
        }
        for (int i = padded.length - padLen; i < padded.length; i++) {
            if ((padded[i] & 0xFF) != padLen) {
                throw new SecureChannelException(0, "PKCS#5 padding bytes are inconsistent");
            }
        }
        return Arrays.copyOf(padded, padded.length - padLen);
    }
}
