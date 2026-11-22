// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

/**
 * Uncatchable power-loss signal (architecture spec section 8, patch 5). An {@link Error} so no
 * applet {@code catch}/{@code finally} of {@code Exception} or {@code Throwable} can stop it; the
 * agent still steers it around every handler so no handler body runs at all.
 */
public final class PowerLoss extends Error {

    PowerLoss() {}
}
