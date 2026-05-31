/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

/**
 * Raised when the card returns a non-success status word in a context where the caller asserted
 * success (e.g. {@code meowl info} expects {@code 9000} from {@code GET_INFO}).
 *
 * <p>Lives in {@code core} so every layer above it — {@code card}, {@code shell}, {@code cli} — can
 * raise and catch it without an upward package dependency. The associated SW value is preserved so
 * the CLI's execution-exception handler can render a descriptive error line and map a stable exit
 * code.
 */
public final class ProtocolException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final int sw;

    public ProtocolException(int sw, String context) {
        super(context + ": " + MeowlSw.describe(sw));
        this.sw = sw;
    }

    /** The 16-bit status word that triggered this exception. */
    public int sw() {
        return sw;
    }
}
