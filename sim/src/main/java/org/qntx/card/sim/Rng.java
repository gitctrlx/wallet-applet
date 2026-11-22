// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

/**
 * Deterministic randomness for the applet under test (architecture spec section 9): {@link
 * #fix(byte[])} makes every {@code RandomData} engine instrumented code holds — engines are created
 * once at install, so the hook must act on engines that already exist — serve {@code bytes} from
 * index 0 on every {@code generateData}/{@code nextBytes} call until {@link #reset}, cycling only
 * inside one call when it asks for more than the block holds.
 *
 * <p>{@link Memory#randomData} therefore wraps every engine it hands to instrumented code in the
 * {@link FixedRandom} delegate, armed or not; an unarmed delegate is a pure pass-through. Only
 * applet-created engines are wrapped — the hook lives on the {@code Memory.randomData} path the
 * agent weaves into instrumented code — and the engine's transient charge is identical with or
 * without the delegate.
 */
public final class Rng {

    private static volatile byte[] block;

    private Rng() {}

    /**
     * From this call on, every {@code generateData}/{@code nextBytes} call of every applet-created
     * {@code RandomData} engine writes {@code bytes[0], bytes[1], …} — index 0 of the block for
     * every call, cycling inside the call when it is longer than the block — until {@link #reset}.
     * {@code setSeed} and {@code getAlgorithm} always delegate to the real engine.
     *
     * @throws IllegalArgumentException when {@code bytes} is empty — a zero-length block cannot
     *     fill anything
     */
    public static void fix(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            throw new IllegalArgumentException("Rng.fix needs a non-empty block");
        }
        block = bytes;
    }

    /** Every call from now on draws from the real generator again. */
    public static void reset() {
        block = null;
    }

    /** The armed block, or {@code null} while nothing is fixed. */
    static byte[] block() {
        return block;
    }
}
