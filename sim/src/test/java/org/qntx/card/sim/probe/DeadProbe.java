// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim.probe;

/**
 * Probe whose {@code if}-guard can be turned unconditional to leave a dead tail, mimicking the
 * bytecode {@code RemoveConditionalMutator} produces for an early-return guard.
 */
public final class DeadProbe {

    private DeadProbe() {}

    public static short dead(short v) {
        if (v == 0) {
            return 0;
        }
        short tail = 7;
        return tail;
    }
}
