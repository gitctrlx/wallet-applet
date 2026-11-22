// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javacard.security.CryptoException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.probe.FaultProbe;

/** {@link Fault} injection over the agent's woven call sites (architecture spec section 9). */
final class FaultTest {

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    @Test
    void unarmedCallsPassThrough() {
        assertEquals(7, FaultProbe.chain((short) 7));
        assertEquals(0, Fault.calls("FaultProbe.value"));
    }

    @Test
    void armReplacesOnlyTheNthResult() {
        Fault.arm("FaultProbe.value", 2, (short) 0x1234);
        assertEquals(7, FaultProbe.chain((short) 7));
        assertEquals(0x1234, FaultProbe.chain((short) 7));
        assertEquals(9, FaultProbe.chain((short) 9));
        assertEquals(3, Fault.calls("FaultProbe.value"));
    }

    @Test
    void armThrowThrowsCryptoException() {
        Fault.armThrow("FaultProbe.value", 1);
        CryptoException e = assertThrows(CryptoException.class, () -> FaultProbe.chain((short) 7));
        assertEquals(CryptoException.ILLEGAL_VALUE, e.getReason());
    }

    @Test
    void resetDisarmsAndClearsCounts() {
        Fault.arm("FaultProbe.value", 1, (short) 0x1234);
        Fault.reset();
        assertEquals(7, FaultProbe.chain((short) 7));
        // counting only runs while a fault is armed
        assertEquals(0, Fault.calls("FaultProbe.value"));
    }
}
