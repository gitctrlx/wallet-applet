/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet.cardclient;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Card I/O surface for integration tests. The {@code @Tag("real-card")} suites all run against a
 * physical J3R180 over PCSC — jcardsim cannot install the post-Phase-1 applet (no {@code
 * TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT}, no prime-modulus RSA), so a single {@link RealCardClient}
 * backend is all this interface ships.
 *
 * <p>The interface stays as a thin indirection so a future J3R180-faithful simulator (or a
 * card-emulator transport) can slot in without rewriting the test source files. Tests obtain a
 * client through {@link CardClientFactory} and never reference {@link RealCardClient} directly.
 *
 * <p>{@link AutoCloseable#close} is called from the test's {@code @AfterEach} to release the
 * underlying PCSC handle.
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
