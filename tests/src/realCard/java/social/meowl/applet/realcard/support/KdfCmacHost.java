/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet.realcard.support;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Host-side mirror of the applet's {@code Kdf} class — AES-CMAC-128 PRF + SHA-256 salt compression,
 * used by every test-suite Session helper to derive {@code K_enc} / {@code K_mac} / {@code IV_base}
 * from the ECDH-X coordinate. Mirrors the on-card algorithm byte-for-byte so test envelopes encrypt
 * and authenticate exactly the way real cards do.
 */
public final class KdfCmacHost {

    /** AES-CMAC-128 output (and PRK) length, in bytes. */
    public static final int BLOCK_LEN = 16;

    private KdfCmacHost() {}

    /** Derives the 16-byte PRK from {@code salt ‖ ikm}. */
    public static byte[] extract(byte[] salt, byte[] ikm) {
        Objects.requireNonNull(ikm, "ikm");
        byte[] extractKey = compressSaltToKey(salt);
        try {
            Mac mac = Mac.getInstance("AESCMAC", BouncyCastleProvider.PROVIDER_NAME);
            mac.init(new SecretKeySpec(extractKey, "AES"));
            return mac.doFinal(ikm);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-CMAC-128 unavailable", e);
        } finally {
            Arrays.fill(extractKey, (byte) 0);
        }
    }

    /**
     * Compresses an arbitrary-length salt to a 16-byte AES-CMAC-128 key:
     *
     * <ul>
     *   <li>{@code null} or empty: 16-byte zero buffer
     *   <li>1..16 bytes: zero-padded to 16 bytes
     *   <li>{@code > 16} bytes: {@code SHA-256(salt)[0..16]}
     * </ul>
     */
    private static byte[] compressSaltToKey(byte[] salt) {
        byte[] key = new byte[BLOCK_LEN];
        if (salt == null || salt.length == 0) {
            return key;
        }
        if (salt.length <= BLOCK_LEN) {
            System.arraycopy(salt, 0, key, 0, salt.length);
            return key;
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(salt);
            System.arraycopy(digest, 0, key, 0, BLOCK_LEN);
            Arrays.fill(digest, (byte) 0);
            return key;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * Derives {@code length} bytes of OKM. {@code T(i) = AES-CMAC(PRK, T(i-1) ‖ info ‖
     * counter_byte_i)}.
     */
    public static byte[] expand(byte[] prk, byte[] info, int length) {
        Objects.requireNonNull(prk, "prk");
        if (prk.length != BLOCK_LEN) {
            throw new IllegalArgumentException(
                    "PRK must be %d bytes, got %d".formatted(BLOCK_LEN, prk.length));
        }
        if (length < 0) {
            throw new IllegalArgumentException("length must be non-negative");
        }
        byte[] effectiveInfo = info == null ? new byte[0] : info;
        Mac mac;
        try {
            mac = Mac.getInstance("AESCMAC", BouncyCastleProvider.PROVIDER_NAME);
            mac.init(new SecretKeySpec(prk, "AES"));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-CMAC-128 unavailable", e);
        }
        byte[] out = new byte[length];
        byte[] previous = new byte[0];
        int blocks = (length + BLOCK_LEN - 1) / BLOCK_LEN;
        int written = 0;
        for (int i = 1; i <= blocks; i++) {
            mac.update(previous);
            mac.update(effectiveInfo);
            mac.update((byte) i);
            byte[] next = mac.doFinal();
            Arrays.fill(previous, (byte) 0);
            previous = next;
            int copyLen = Math.min(BLOCK_LEN, length - written);
            System.arraycopy(previous, 0, out, written, copyLen);
            written += copyLen;
        }
        Arrays.fill(previous, (byte) 0);
        return out;
    }

    /** AES-CMAC-128 over a sequence of byte-array fragments. */
    public static byte[] aesCmac128(byte[] key, byte[]... parts) {
        Objects.requireNonNull(key, "key");
        if (key.length != BLOCK_LEN) {
            throw new IllegalArgumentException(
                    "AES-CMAC-128 key must be %d bytes".formatted(BLOCK_LEN));
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
}
