/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet.cardclient;

import java.util.List;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import social.meowl.applet.Constants;

/**
 * {@link CardClient} backed by a PCSC-attached physical card. The applet under test must already be
 * installed on the card; this client only opens a channel and runs ISO 7816 SELECT.
 *
 * <p>The reader is selected by name via {@code -DcardReader=...}; if unset, the first terminal
 * reported by {@link TerminalFactory#getDefault()} is used.
 *
 * <p>Each {@link #connect} call performs:
 *
 * <ol>
 *   <li>{@code Card card = terminal.connect("*")} — pick whichever protocol the reader negotiates.
 *   <li>{@code SELECT aid} — must return {@code 0x9000}, otherwise the constructor throws.
 * </ol>
 *
 * <p>Test isolation between calls is the test's responsibility (typically {@code RESET_TO_FACTORY}
 * inside an {@code @AfterEach}). The card itself persists state across tests, unlike the simulator
 * which is fresh on every {@link SimulatorCardClient#installFresh} call.
 */
public final class RealCardClient implements CardClient {

    private final Card card;
    private final CardChannel channel;

    /**
     * Connects to a PCSC reader, opens a channel, SELECTs {@code aidBytes}, and drives a complete
     * {@code RESET_TO_FACTORY} sequence so the applet's persistent lifecycle is wiped back to
     * {@code UNINITIALIZED}. The wipe matches the {@link SimulatorCardClient#installFresh}
     * fresh-install semantics: every {@code @BeforeEach} starts on the same lifecycle state, so
     * cross-test EEPROM pollution (which {@link Card#disconnect}{@code (true)} cannot clear) cannot
     * bleed between {@code @Test} methods.
     *
     * <p>The wipe is idempotent — on a card already in {@code UNINITIALIZED} the four invocations
     * still emit the canonical countdown SW progression (0x6FA3 → 0x6FA2 → 0x6FA1 → 0x6FA0) but the
     * terminal wipe touches no live persistent state.
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
            wipePersistentState(channel);
            return new RealCardClient(card, channel);
        } catch (CardException e) {
            throw new RuntimeException("real card connect failed", e);
        }
    }

    /**
     * Drives {@link Constants#RESET_REQUIRED_INVOCATIONS} consecutive {@code RESET_TO_FACTORY}
     * APDUs. The applet's multi-step trigger replies with {@code SW_RESET_COUNTDOWN_BASE +
     * remaining} for the first {@code n − 1} calls and {@code SW_RESET_COUNTDOWN_BASE + 0} on the
     * terminal call (which performs the wipe). We do not assert the SW values here — the lifecycle
     * post-condition (everything back to UNINITIALIZED) is what the per-test {@code @BeforeEach}
     * relies on, and that holds whether or not the wipe actually had work to do.
     */
    private static void wipePersistentState(CardChannel channel) throws CardException {
        CommandAPDU reset =
                new CommandAPDU(
                        Constants.CLA_MEOWL & 0xFF,
                        Constants.INS_RESET_TO_FACTORY & 0xFF,
                        0x00,
                        0x00);
        for (int i = 0; i < Constants.RESET_REQUIRED_INVOCATIONS; i++) {
            channel.transmit(reset);
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

    @Override
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
     * install-time value, matching the {@link SimulatorCardClient#installFresh} fresh-card
     * semantics. Tests that need persistent state to survive across {@code @BeforeEach} cycles must
     * drive {@code RESET_TO_FACTORY} explicitly inside an {@code @AfterEach}.
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
