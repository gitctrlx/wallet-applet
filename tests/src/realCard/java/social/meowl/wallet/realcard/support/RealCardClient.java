/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.wallet.realcard.support;

import java.util.List;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

/**
 * Card I/O surface for the integration suites, backed by a PCSC-attached physical card. The applet
 * under test must already be installed on the card; this client only opens a channel and runs ISO
 * 7816 SELECT.
 *
 * <p>The reader is selected by name via {@code -DcardReader=...}; if unset, the first terminal
 * reporting a card present is used (so dual-interface readers such as the ACR1552 1S, which expose
 * an always-empty SAM slot alongside the PICC slot, pick the slot the J3R180 actually sits on).
 *
 * <p>Each {@link #connect} call performs:
 *
 * <ol>
 *   <li>{@code Card card = terminal.connect("*")} — pick whichever protocol the reader negotiates.
 *   <li>{@code SELECT aid} — must return {@code 0x9000}, otherwise the constructor throws.
 * </ol>
 *
 * <p>Persistent-state isolation between tests is the test's responsibility — see {@code
 * CardLifecycle.resetCard()}, which the suites invoke from {@code @AfterEach}.
 */
public final class RealCardClient implements AutoCloseable {

    private final Card card;
    private final CardChannel channel;

    /** Connects using the reader named by {@code -DcardReader=...} (first available when unset). */
    public static RealCardClient connect(byte[] aidBytes) {
        return connect(aidBytes, System.getProperty("cardReader"));
    }

    /**
     * Connects to a PCSC reader, opens a channel, and SELECTs {@code aidBytes}. Persistent state
     * isolation between tests is delegated to the test's {@code @AfterEach} via {@code
     * MeowlFixtures.resetCard()}.
     *
     * @param aidBytes target applet AID
     * @param terminalName reader name (e.g. {@code "ACR1552U-MF"}); {@code null} = first available
     */
    public static RealCardClient connect(byte[] aidBytes, String terminalName) {
        try {
            CardTerminal terminal = pickTerminal(terminalName);
            Card card = terminal.connect("*");
            CardChannel channel = card.getBasicChannel();
            ResponseAPDU select =
                    channel.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aidBytes));
            if (select.getSW() != 0x9000) {
                card.disconnect(false);
                throw new IllegalStateException(
                        "SELECT failed: SW=0x" + Integer.toHexString(select.getSW()));
            }
            return new RealCardClient(card, channel);
        } catch (CardException e) {
            throw new RuntimeException("real card connect failed", e);
        }
    }

    private static CardTerminal pickTerminal(String terminalName) throws CardException {
        TerminalFactory factory = TerminalFactory.getDefault();
        if (terminalName == null || terminalName.isEmpty()) {
            List<CardTerminal> terminals = factory.terminals().list();
            if (terminals.isEmpty()) {
                throw new IllegalStateException(
                        "no PCSC terminals; specify one with -DcardReader=...");
            }
            // Prefer a terminal that reports a card; on dual-interface readers (e.g. ACR1552 1S
            // exposes a SAM slot + a PICC slot) the SAM slot is always empty, so blindly taking
            // terminals.get(0) yields SCARD_W_REMOVED_CARD even though the J3R180 is sitting on
            // PICC. Fall back to the first terminal when none reports a card so the original
            // diagnostics ("No card present") still surface naturally.
            for (CardTerminal t : terminals) {
                if (t.isCardPresent()) {
                    return t;
                }
            }
            return terminals.get(0);
        }
        CardTerminal terminal = factory.terminals().getTerminal(terminalName);
        if (terminal == null) {
            throw new IllegalStateException("PCSC terminal not found: " + terminalName);
        }
        return terminal;
    }

    private RealCardClient(Card card, CardChannel channel) {
        this.card = card;
        this.channel = channel;
    }

    public ResponseAPDU transmit(CommandAPDU cmd) {
        try {
            return channel.transmit(cmd);
        } catch (CardException e) {
            throw new RuntimeException("transmit failed", e);
        }
    }

    /**
     * Disconnects with {@code reset = true} so the ICC reset propagates a {@code CLEAR_ON_RESET}
     * wipe — the per-deselect counter that {@code RESET_TO_FACTORY} relies on returns to its
     * install-time value. Tests that need persistent state cleared must drive {@code
     * RESET_TO_FACTORY} explicitly via {@code CardLifecycle.resetCard()} before close.
     */
    @Override
    public void close() {
        try {
            card.disconnect(true);
        } catch (CardException ignored) {
            // best-effort teardown; nothing useful to do on disconnect failure
        }
    }
}
