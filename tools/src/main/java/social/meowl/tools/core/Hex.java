/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import java.util.HexFormat;
import java.util.Objects;

/**
 * Strict hexadecimal codec used wherever the CLI accepts user-supplied hex (APDU bytes, AIDs,
 * digests, …). A thin wrapper around {@link HexFormat} that
 *
 * <ul>
 *   <li>strips an optional {@code 0x} / {@code 0X} prefix so paste-from-debugger workflows work;
 *   <li>surfaces the offending value in error messages instead of {@link HexFormat}'s generic one;
 *   <li>normalises encode output to uppercase so JSON dumps diff cleanly across runs.
 * </ul>
 */
public final class Hex {

    private static final HexFormat UPPER = HexFormat.of().withUpperCase();

    private Hex() {}

    /**
     * Decodes a hexadecimal string into its raw bytes.
     *
     * <p>An optional {@code 0x} / {@code 0X} prefix is accepted and stripped. The input must be a
     * plain hex string with no separators or whitespace; pre-process it with {@link String#strip()}
     * before calling if your source might contain padding.
     *
     * @param hex hex string, with or without a {@code 0x} prefix; must not be {@code null}
     * @return the decoded bytes (length = hex length / 2)
     * @throws IllegalArgumentException if the input has odd length or contains non-hex characters
     */
    public static byte[] decode(String hex) {
        Objects.requireNonNull(hex, "hex");
        String body = stripPrefix(hex);
        if ((body.length() & 1) != 0) {
            throw new IllegalArgumentException(
                    "Hex string has odd length (%d): %s".formatted(body.length(), preview(body)));
        }
        try {
            return HexFormat.of().parseHex(body);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException(
                    "Hex string contains non-hex characters: " + preview(body), ex);
        }
    }

    /** Encodes a byte array as an uppercase hex string with no separators. */
    public static String encode(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        return UPPER.formatHex(bytes);
    }

    /**
     * Encodes a byte array as an uppercase hex string with a single-character separator between
     * bytes — useful for human-readable APDU dumps and debug logs.
     */
    public static String encodeWithSeparator(byte[] bytes, char separator) {
        Objects.requireNonNull(bytes, "bytes");
        return HexFormat.ofDelimiter(String.valueOf(separator)).withUpperCase().formatHex(bytes);
    }

    /** Encodes a single byte as a 2-character uppercase hex string. */
    public static String encodeByte(byte b) {
        return UPPER.toHexDigits(b);
    }

    /** Encodes a 16-bit value as a 4-character uppercase hex string (big-endian). */
    public static String encodeShort(short s) {
        return UPPER.toHexDigits(s);
    }

    private static String stripPrefix(String hex) {
        if (hex.length() >= 2) {
            char c0 = hex.charAt(0);
            char c1 = hex.charAt(1);
            if (c0 == '0' && (c1 == 'x' || c1 == 'X')) {
                return hex.substring(2);
            }
        }
        return hex;
    }

    /** Truncates over-long inputs in error messages so logs stay readable. */
    private static String preview(String hex) {
        if (hex.length() <= 32) return hex;
        return hex.substring(0, 32) + "…(" + hex.length() + " chars)";
    }
}
