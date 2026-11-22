// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim.probe;

/**
 * Probe for the {@code Fault} weaving: {@link #chain} calls {@link #value} so the call site sits
 * inside an instrumented package and {@code Fault.ret} sees the {@code "FaultProbe.value"} result.
 */
public final class FaultProbe {

    private FaultProbe() {}

    public static short chain(short v) {
        return value(v);
    }

    static short value(short v) {
        return v;
    }
}
