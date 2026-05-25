/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet.cardclient;

/**
 * Connects integration tests to a {@link RealCardClient} backed by PCSC. The PCSC reader name comes
 * from the {@code cardReader} system property; if unset the first available terminal is used. The
 * factory is a thin indirection so tests stay decoupled from {@code javax.smartcardio} directly.
 */
public final class CardClientFactory {

    private CardClientFactory() {}

    /** Connects to the configured PCSC reader and SELECTs the applet at {@code aidBytes}. */
    public static CardClient create(byte[] aidBytes) {
        return RealCardClient.connect(aidBytes, System.getProperty("cardReader"));
    }
}
