/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import social.meowl.tools.core.MeowlSw;

/**
 * Raised by a subcommand when the card returned a non-success status word in a context where the
 * caller asserted success (e.g. {@code meowl info} expects {@code 9000} from {@code GET_INFO}).
 *
 * <p>The associated SW value is preserved so {@link MeowlExecutionExceptionHandler} can render a
 * descriptive error line.
 */
public final class ProtocolException extends RuntimeException {

    private final int sw;

    public ProtocolException(int sw, String context) {
        super(context + ": " + MeowlSw.describe(sw));
        this.sw = sw;
    }

    public int sw() {
        return sw;
    }
}
