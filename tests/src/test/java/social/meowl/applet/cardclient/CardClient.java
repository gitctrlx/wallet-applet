/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet.cardclient;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Backend-agnostic card I/O surface for integration tests. Lets a single test class drive either
 * jcardsim's in-JVM {@code CardSimulator} or a physical card via PCSC without changing the test
 * code.
 *
 * <p>Two implementations:
 *
 * <ul>
 *   <li>{@link SimulatorCardClient} wraps {@code com.licel.jcardsim.smartcardio.CardSimulator}.
 *       Cheap, in-JVM, but cannot run anything that exercises the J3R180-only key types or the
 *       prime-modulus RSA primitive (post-Phase-1, that is most integration suites).
 *   <li>{@link RealCardClient} wraps {@code javax.smartcardio.CardChannel} against a PCSC reader.
 *       The only backend that actually models J3R180 silicon behaviour, and therefore the only
 *       backend the post-Phase-1 integration suites can use.
 * </ul>
 *
 * <p>Backend selection is driven by the {@code cardBackend} system property — see {@link
 * CardClientFactory}. Tests obtain a client through the factory and never reference an
 * implementation directly.
 *
 * <p>The interface intentionally exposes no install/select primitives: each backend brings the card
 * up to a freshly-selected applet inside its own constructor (simulator: {@code installApplet} +
 * {@code selectApplet}; real card: ISO 7816 SELECT against an already-installed applet).
 *
 * <p>{@link AutoCloseable#close} is called from the test's {@code @AfterEach} to release the
 * underlying handle (no-op for the simulator; {@code Card.disconnect(false)} for PCSC).
 */
public interface CardClient extends AutoCloseable {

    /**
     * Sends a single APDU and returns the response. Backend-specific I/O failures (PCSC errors,
     * simulator IllegalState, …) are wrapped as unchecked {@link RuntimeException} so test code can
     * stay APDU-shaped and not pollute every method signature with {@code throws CardException}.
     */
    ResponseAPDU transmit(CommandAPDU cmd);

    @Override
    void close();
}
