// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

/**
 * OPEN failed (§8.1): bad status, wrong response length, a certificate under no trusted anchor or
 * an invalid session signature. The card is abandoned with no option to continue.
 */
public final class CardNotGenuineException extends Exception {
    public CardNotGenuineException(String message) {
        super(message);
    }
}
