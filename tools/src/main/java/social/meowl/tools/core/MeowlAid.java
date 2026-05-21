/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import java.util.Arrays;
import java.util.Objects;

/**
 * Default Application Identifier for the meowl applet.
 *
 * <p>The default AID lives in the ISO/IEC 7816-5 proprietary {@code F0} prefix range, suitable for
 * development and self-deployed cards. Production deployments must register their own RID; see the
 * {@code README.md} for rationale.
 *
 * <p>Encoding (7 bytes): {@code F0 6D 65 6F 77 6C 01} — that is, the ASCII bytes for {@code
 * "meowl"} prefixed with the proprietary tag {@code 0xF0} and suffixed with an instance byte {@code
 * 0x01}.
 */
public final class MeowlAid {

    /** Hex form of {@link #defaultBytes()}, suitable for CLI usage messages. */
    public static final String DEFAULT_HEX = "F06D656F776C01";

    /** Minimum AID length per ISO/IEC 7816-5 §8.2.1.2 (5 bytes). */
    public static final int MIN_LEN = 5;

    /** Maximum AID length per ISO/IEC 7816-5 §8.2.1.2 (16 bytes). */
    public static final int MAX_LEN = 16;

    private static final byte[] DEFAULT_BYTES = Hex.decode(DEFAULT_HEX);

    private MeowlAid() {}

    /** Returns a defensive copy of the default AID bytes. */
    public static byte[] defaultBytes() {
        return DEFAULT_BYTES.clone();
    }

    /**
     * Parses an AID from a hex string and validates its length is within the ISO/IEC 7816-5 bounds.
     */
    public static byte[] parse(String hex) {
        Objects.requireNonNull(hex, "hex");
        byte[] bytes = Hex.decode(hex);
        if (bytes.length < MIN_LEN || bytes.length > MAX_LEN) {
            throw new IllegalArgumentException(
                    "AID length must be between %d and %d bytes (got %d): %s"
                            .formatted(MIN_LEN, MAX_LEN, bytes.length, Hex.encode(bytes)));
        }
        return bytes;
    }

    /**
     * Returns {@code true} iff the supplied AID equals the default meowl AID. Used by safety
     * heuristics that warn before reusing default keys against a non-meowl applet.
     */
    public static boolean isDefault(byte[] aid) {
        Objects.requireNonNull(aid, "aid");
        return Arrays.equals(aid, DEFAULT_BYTES);
    }
}
