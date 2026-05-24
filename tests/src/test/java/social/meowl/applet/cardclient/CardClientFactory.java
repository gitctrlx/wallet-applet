/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet.cardclient;

import javacard.framework.Applet;
import social.meowl.applet.MeowlApplet;

/**
 * Resolves the active {@link CardClient} backend from system properties.
 *
 * <p>Selection rules:
 *
 * <ul>
 *   <li>{@code -DcardBackend=real} → {@link RealCardClient} against the PCSC reader named by {@code
 *       -DcardReader=...} (or the first available terminal if unset).
 *   <li>Anything else (including the default empty value) → {@link SimulatorCardClient} with a
 *       fresh in-JVM jcardsim instance hosting {@link MeowlApplet}.
 * </ul>
 *
 * <p>Tests call {@link #create(byte[])} from their {@code @BeforeEach}; the same test source file
 * therefore runs unchanged on either backend, with {@code @Tag("real-card")} controlling which
 * Gradle task ({@code :tests:test} or {@code :tests:realCardTest}) actually picks it up.
 */
public final class CardClientFactory {

    private CardClientFactory() {}

    /**
     * Backend constants exposed for tests that want to assert which backend they are running on.
     */
    public static final String BACKEND_REAL = "real";

    public static final String BACKEND_SIMULATOR = "simulator";

    /** Convenience overload that hosts {@link MeowlApplet} on the simulator backend. */
    public static CardClient create(byte[] aidBytes) {
        return create(aidBytes, MeowlApplet.class);
    }

    /** Backend-agnostic factory: bring up the active backend with {@code aidBytes} selected. */
    public static CardClient create(byte[] aidBytes, Class<? extends Applet> appletClass) {
        if (BACKEND_REAL.equalsIgnoreCase(activeBackend())) {
            return RealCardClient.connect(aidBytes, System.getProperty("cardReader"));
        }
        return SimulatorCardClient.installFresh(aidBytes, appletClass);
    }

    /** Returns the active backend name, defaulting to {@link #BACKEND_SIMULATOR}. */
    public static String activeBackend() {
        return System.getProperty("cardBackend", BACKEND_SIMULATOR);
    }
}
