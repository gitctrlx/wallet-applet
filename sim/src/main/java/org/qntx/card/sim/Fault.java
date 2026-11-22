// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
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
 *
 * <p>Void methods are covered by {@link #armSkip} over the agent's woven guard: the n-th call is
 * skipped entirely. {@link #armStore} faults the value a persistent {@code Util.setShort} writes.
 */
public final class Fault {

    private static final class Slot {
        int calls;
        final Set<Integer> nth = new HashSet<>();
        short value;
        boolean throwing;
        boolean skipping;
    }

    private static final Map<String, Slot> armed = new HashMap<>();
    private static final Map<String, Integer> counts = new HashMap<>();
    private static volatile boolean active;
    private static int storeArmed;
    private static int storeSeen;
    private static short storeValue;

    private Fault() {}

    /**
     * Makes the {@code nth} call (1-based, counted since arming or the last {@link #reset}) of
     * {@code method} return {@code value} instead of its real result. Repeated calls accumulate
     * positions, so several evaluations of one method can be forced in a single command.
     */
    public static void arm(String method, int nth, short value) {
        Slot s = armed.computeIfAbsent(method, k -> new Slot());
        s.calls = 0;
        s.nth.add(nth);
        s.value = value;
        s.throwing = false;
        s.skipping = false;
        active = true;
    }

    /**
     * Makes the {@code nth} call of {@code method} throw {@link CryptoException} ({@code
     * ILLEGAL_VALUE}) instead of returning.
     */
    public static void armThrow(String method, int nth) {
        Slot s = armed.computeIfAbsent(method, k -> new Slot());
        s.calls = 0;
        s.nth.add(nth);
        s.throwing = true;
        s.skipping = false;
        active = true;
    }

    /**
     * Makes the {@code nth} call (counted since arming) of the <em>void</em> method {@code method}
     * return without running its body — the agent's woven guard pops the arguments and continues.
     * {@code JCSystem.beginTransaction}/{@code commitTransaction}/{@code abortTransaction} are also
     * woven, so a skipped commit leaves the transaction open.
     */
    public static void armSkip(String method, int nth) {
        Slot s = armed.computeIfAbsent(method, k -> new Slot());
        s.calls = 0;
        s.nth.add(nth);
        s.throwing = false;
        s.skipping = true;
        active = true;
    }

    /**
     * Makes the {@code nth} persistent {@code Util.setShort} (counted since arming; only writes to
     * applet persistent arrays count) store {@code value} instead of its argument.
     */
    public static void armStore(int nth, short value) {
        storeArmed = nth;
        storeSeen = 0;
        storeValue = value;
        active = true;
    }

    /**
     * Turns call counting on ({@link #calls}) without arming a fault; {@link #reset} turns it off.
     */
    public static void countCalls() {
        armed.clear();
        counts.clear();
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
        storeArmed = 0;
    }

    /**
     * The woven guard of void calls: {@code true} means skip the call. Counts on the same counters
     * as {@link #ret}, returns {@code false} fast when nothing is armed.
     */
    public static boolean skip(String method) {
        if (!active) {
            return false;
        }
        counts.merge(method, 1, Integer::sum);
        Slot s = armed.get(method);
        return s != null && s.skipping && s.nth.contains(++s.calls);
    }

    /**
     * Called by {@link Nvm#setShort} before a persistent store: returns the argument, or the armed
     * fault value on the n-th persistent store since arming.
     */
    public static short storeValue(short value) {
        if (storeArmed != 0 && ++storeSeen == storeArmed) {
            return storeValue;
        }
        return value;
    }

    /** The woven entry point: the untouched result normally, the armed fault on the n-th call. */
    public static short ret(short value, String method) {
        if (!active) {
            return value;
        }
        counts.merge(method, 1, Integer::sum);
        Slot s = armed.get(method);
        if (s == null || !s.nth.contains(++s.calls)) {
            return value;
        }
        if (s.throwing) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        return s.value;
    }
}
