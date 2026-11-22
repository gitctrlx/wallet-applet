// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

/**
 * A response record failed a §8.4 check (outer status, length, tag, padding or plaintext length) or
 * the session ended. The host abandons the session.
 */
public final class SessionBrokenException extends Exception {
    public SessionBrokenException(String message) {
        super(message);
    }
}
