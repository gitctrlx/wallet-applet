// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

/**
 * Thrown by {@link Card#transmit(byte[])} when the armed tear point fired and the card lost power
 * mid-command. The command produced no response; {@link Card#powerCycle()} plus a fresh SELECT
 * restore the card.
 */
public final class TornException extends RuntimeException {

    TornException() {}
}
