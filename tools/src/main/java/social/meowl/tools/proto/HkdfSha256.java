/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.proto;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * RFC 5869 HKDF-SHA-256, the key-derivation function used by MEAP-2's Secure Channel.
 *
 * <p>The implementation is intentionally tiny — just {@code Extract} and {@code Expand} on top of
 * the JDK's {@link Mac} — because the MEAP-2 spec only ever calls Extract once and Expand once
 * (with {@code L = 80} bytes). We do not depend on BouncyCastle's HKDF here so this class can be
 * reused inside the JCardSim test path without dragging the BC provider into every classpath.
 *
 * <p>For the security and correctness rationale see {@code docs/specs/meap-2.md} §"Key derivation".
 */
public final class HkdfSha256 {

    /** SHA-256 output length, in bytes — also the HMAC-SHA-256 output length. */
    public static final int HASH_LEN = 32;

    /** Maximum {@code L} per RFC 5869 §2.3: {@code 255 × HashLen}. */
    public static final int MAX_LEN = 255 * HASH_LEN;

    private HkdfSha256() {}

    /**
     * RFC 5869 §2.2 — {@code HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)}.
     *
     * @param salt the optional salt; if {@code null} or empty, a zero-filled {@code HashLen}-byte
     *     string is used (per RFC)
     * @param ikm input keying material
     * @return the 32-byte pseudorandom key
     */
    public static byte[] extract(byte[] salt, byte[] ikm) {
        Objects.requireNonNull(ikm, "ikm");
        byte[] effectiveSalt = (salt == null || salt.length == 0) ? new byte[HASH_LEN] : salt;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(effectiveSalt, "HmacSHA256"));
            return mac.doFinal(ikm);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA-256 unavailable", e);
        }
    }

    /**
     * RFC 5869 §2.3 — {@code HKDF-Expand(PRK, info, L)}.
     *
     * @param prk the pseudorandom key, typically the output of {@link #extract}
     * @param info optional context-and-application-specific info; may be {@code null}
     * @param length desired output length in bytes; MUST be {@code 0 ≤ length ≤ 255 × HashLen}
     * @return {@code length} bytes of output keying material
     */
    public static byte[] expand(byte[] prk, byte[] info, int length) {
        Objects.requireNonNull(prk, "prk");
        if (length < 0 || length > MAX_LEN) {
            throw new IllegalArgumentException(
                    "HKDF-Expand length out of range: %d (max %d)".formatted(length, MAX_LEN));
        }
        byte[] effectiveInfo = info == null ? new byte[0] : info;

        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA-256 unavailable", e);
        }

        byte[] out = new byte[length];
        byte[] previous = new byte[0];
        int blocks = (length + HASH_LEN - 1) / HASH_LEN;
        int written = 0;
        for (int i = 1; i <= blocks; i++) {
            mac.update(previous);
            mac.update(effectiveInfo);
            mac.update((byte) i);
            previous = mac.doFinal();
            int copyLen = Math.min(HASH_LEN, length - written);
            System.arraycopy(previous, 0, out, written, copyLen);
            written += copyLen;
        }
        // Defensive: scrub the last T(N) buffer we no longer need.
        Arrays.fill(previous, (byte) 0);
        return out;
    }
}
