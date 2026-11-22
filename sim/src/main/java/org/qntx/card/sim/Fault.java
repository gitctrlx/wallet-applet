// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import java.util.HashMap;
import java.util.Map;
import javacard.security.CryptoException;

/**
 * Fault injection over the agent's woven call sites (architecture spec section 9): every call made
 * by instrumented code to an instrumented method returning {@code short} is routed through {@link
 * #ret}, so a test can arm the n-th call of a method to return a chosen value or to throw. This is
 * the hand-written-fault infrastructure the §16.2 item 4 double checks are tested against.
 *
 * <p>Method keys are {@code "SimpleClass.method"} — e.g. {@code "State.life"}, {@code
 * "Bytes.equal"}, {@code "Identity.verify"} — regardless of the caller. Counting runs only while a
 * fault is armed so the unwoven fast path is a single flag check.
 */
public final class Fault {

    private static final class Slot {
        int calls;
        int nth;
        short value;
        boolean throwing;
    }

    private static final Map<String, Slot> armed = new HashMap<>();
    private static final Map<String, Integer> counts = new HashMap<>();
    private static volatile boolean active;

    private Fault() {}

    /**
     * Makes the {@code nth} call (1-based, counted since arming or the last {@link #reset}) of
     * {@code method} return {@code value} instead of its real result.
     */
    public static void arm(String method, int nth, short value) {
        Slot s = armed.computeIfAbsent(method, k -> new Slot());
        s.calls = 0;
        s.nth = nth;
        s.value = value;
        s.throwing = false;
        active = true;
    }

    /**
     * Makes the {@code nth} call of {@code method} throw {@link CryptoException} ({@code
     * ILLEGAL_VALUE}) instead of returning.
     */
    public static void armThrow(String method, int nth) {
        Slot s = armed.computeIfAbsent(method, k -> new Slot());
        s.calls = 0;
        s.nth = nth;
        s.throwing = true;
        active = true;
    }

    /** Calls of {@code method} since {@link #reset}; counting is on only while a fault is armed. */
    public static int calls(String method) {
        return counts.getOrDefault(method, 0);
    }

    /** Disarms every method and clears the call counters. */
    public static void reset() {
        armed.clear();
        counts.clear();
        active = false;
    }

    /** The woven entry point: the untouched result normally, the armed fault on the n-th call. */
    public static short ret(short value, String method) {
        if (!active) {
            return value;
        }
        counts.merge(method, 1, Integer::sum);
        Slot s = armed.get(method);
        if (s == null || ++s.calls != s.nth) {
            return value;
        }
        if (s.throwing) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        return s.value;
    }
}
