/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Status word table mirrored from {@code social.meowl.wallet.Constants}.
 *
 * <p>This is the host-side decoder used by the CLI and shell to translate a returned {@link
 * apdu4j.core.ResponseAPDU#getSW()} into a human-readable label. The applet emits status words from
 * three families:
 *
 * <ul>
 *   <li><strong>Standard</strong> — fixed ISO/IEC 7816-4 codes ({@code 9000}, {@code 6700} …)
 *   <li><strong>Counted</strong> — {@code 6FAn} reset countdown and {@code 63Cn} PIN retries; the
 *       low nibble is a counter that {@link #describe(int)} extracts.
 *   <li><strong>Applet-private</strong> — {@code 6FB0} … {@code 6FE1}
 * </ul>
 *
 * <p>{@link #describe(int)} is the canonical pretty-print entry-point: it covers all three families
 * and falls back to {@code "Unknown SW: 0xXXXX"} for anything we have not catalogued so the user
 * always sees the raw hex value.
 */
public enum MeowlSw {
    NO_ERROR((short) 0x9000, "Success"),
    WRONG_LENGTH((short) 0x6700, "Wrong length"),
    SECURITY_STATUS_NOT_SATISFIED(
            (short) 0x6982, "Security status not satisfied (PIN / Secure Channel)"),
    AUTH_BLOCKED((short) 0x6983, "Authentication method blocked (PIN/PUK exhausted)"),
    CONDITIONS_NOT_SATISFIED(
            (short) 0x6985, "Condition of use not satisfied (e.g. wrong lifecycle state)"),
    INCORRECT_P1P2((short) 0x6A86, "Incorrect P1 or P2"),
    INS_NOT_SUPPORTED((short) 0x6D00, "INS not supported"),
    CLA_NOT_SUPPORTED((short) 0x6E00, "CLA not supported"),
    LIFECYCLE_INVALID((short) 0x6FB0, "Lifecycle state forbids this command"),
    SECURE_CHANNEL_REQUIRED((short) 0x6FB1, "Secure Channel required"),
    SECURE_CHANNEL_FAILED((short) 0x6FB2, "Secure Channel cryptographic check failed"),
    UNSUPPORTED_FEATURE((short) 0x6FE0, "Required JavaCard feature not available on this card"),
    INTERNAL_ERROR((short) 0x6FE1, "Internal sentinel: retry with fresh randomness");

    /**
     * Base for the {@code 6FAn} reset-countdown family — see {@code
     * Constants.SW_RESET_COUNTDOWN_BASE}.
     */
    public static final int RESET_COUNTDOWN_BASE = 0x6FA0;

    /** Base for the {@code 63Cn} PIN retries family — see {@code Constants.SW_PIN_RETRIES_BASE}. */
    public static final int PIN_RETRIES_BASE = 0x63C0;

    private static final Map<Short, MeowlSw> BY_VALUE =
            Arrays.stream(values())
                    .collect(Collectors.toUnmodifiableMap(MeowlSw::value, Function.identity()));

    private final short value;
    private final String description;

    MeowlSw(short value, String description) {
        this.value = value;
        this.description = description;
    }

    public short value() {
        return value;
    }

    /** The 4-character uppercase hex form, e.g. {@code "9000"}. */
    public String hex() {
        return Hex.encodeShort(value);
    }

    public String description() {
        return description;
    }

    /** Looks up a status word by its 16-bit wire value. */
    public static Optional<MeowlSw> ofValue(short value) {
        return Optional.ofNullable(BY_VALUE.get(value));
    }

    /**
     * Renders any 16-bit status word as a {@code "<hex> — <description>"} string, recognising the
     * {@code 6FAn} reset-countdown and {@code 63Cn} PIN-retry families and falling back to {@code
     * "Unknown SW: 0xXXXX"} for unknowns.
     */
    public static String describe(int sw) {
        int code = sw & 0xFFFF;
        String hex = "0x%04X".formatted(code);

        // Counted families take precedence over the table because they carry a useful low nibble.
        if ((code & 0xFFF0) == RESET_COUNTDOWN_BASE) {
            int remaining = code & 0x000F;
            return remaining == 0
                    ? "%s — RESET_TO_FACTORY wipe complete".formatted(hex)
                    : "%s — RESET_TO_FACTORY: %d invocation(s) remaining".formatted(hex, remaining);
        }
        if ((code & 0xFFF0) == PIN_RETRIES_BASE) {
            int remaining = code & 0x000F;
            return "%s — PIN verification failed; %d attempt(s) remaining"
                    .formatted(hex, remaining);
        }

        return ofValue((short) code)
                .map(s -> "%s — %s".formatted(hex, s.description))
                .orElseGet(() -> "%s — Unknown SW".formatted(hex));
    }

    /** {@code true} iff the SW indicates ISO success (i.e. {@code 9000}). */
    public static boolean isSuccess(int sw) {
        return (sw & 0xFFFF) == (NO_ERROR.value & 0xFFFF);
    }
}
