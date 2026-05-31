/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.card;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBOException;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.util.Objects;
import social.meowl.tools.core.MeowlAid;
import social.meowl.tools.core.MeowlInfo;
import social.meowl.tools.core.MeowlInsn;
import social.meowl.tools.core.MeowlSw;
import social.meowl.tools.core.ProtocolException;
import social.meowl.tools.proto.SecureChannelClient;

/**
 * Stateful facade over an open {@link APDUBIBO} that encapsulates every meowl card operation in one
 * place: SELECT, GET_INFO, GET_AUTHENTIKEY, the Secure Channel handshake bootstrap, the
 * RESET_TO_FACTORY countdown, and raw passthrough.
 *
 * <p>Both the picocli subcommands (one instance per {@code CardTransport.run} visitor) and the
 * interactive shell (one long-lived instance holding the persistent connection) drive the card
 * through this class, so the wire choreography lives in a single, unit-testable home rather than
 * being copied across every caller.
 *
 * <p>The card does <strong>not</strong> own the transport: the caller is responsible for the {@link
 * APDUBIBO} lifecycle. Instances are single-threaded and track whether the applet has been selected
 * on the current connection so callers can rely on lazy {@link #ensureSelected()}.
 */
public final class MeowlCard {

    /** ISO/IEC 7816-4 §6.11 SELECT BY DF NAME. */
    private static final int CLA_ISO = 0x00;

    private static final int INS_SELECT = 0xA4;
    private static final int P1_SELECT_BY_DF = 0x04;

    private static final int CLA_MEOWL = MeowlInsn.CLA_MEOWL & 0xFF;

    /**
     * Consecutive un-interleaved {@code RESET_TO_FACTORY} invocations the applet requires before it
     * performs the wipe; mirrors {@code social.meowl.applet.Constants.RESET_REQUIRED_INVOCATIONS}.
     */
    public static final int RESET_REQUIRED_INVOCATIONS = 4;

    private final APDUBIBO bibo;
    private byte[] aid;
    private boolean selected;

    /** Creates a card bound to the default meowl AID. */
    public MeowlCard(APDUBIBO bibo) {
        this(bibo, MeowlAid.defaultBytes());
    }

    /**
     * @param bibo the open (and typically decorated) transport; not owned by this instance
     * @param aid the applet AID to SELECT
     */
    public MeowlCard(APDUBIBO bibo, byte[] aid) {
        this.bibo = Objects.requireNonNull(bibo, "bibo");
        this.aid = Objects.requireNonNull(aid, "aid").clone();
    }

    /** The AID this card will SELECT, as a defensive copy. */
    public byte[] aid() {
        return aid.clone();
    }

    /** Re-targets a new AID for subsequent {@link #select()} calls and clears selection state. */
    public void aid(byte[] aid) {
        this.aid = Objects.requireNonNull(aid, "aid").clone();
        this.selected = false;
    }

    /** Whether the applet has been successfully selected on this connection. */
    public boolean isSelected() {
        return selected;
    }

    /**
     * Issues a SELECT BY DF NAME for the configured AID and returns the FCI bytes.
     *
     * @throws ProtocolException if the card returns a non-success status word
     */
    public byte[] select() throws BIBOException {
        ResponseAPDU resp =
                bibo.transmit(new CommandAPDU(CLA_ISO, INS_SELECT, P1_SELECT_BY_DF, 0x00, aid));
        if (!MeowlSw.isSuccess(resp.getSW())) {
            selected = false;
            throw new ProtocolException(resp.getSW(), "SELECT meowl applet failed");
        }
        selected = true;
        return resp.getData();
    }

    /** SELECTs the applet only if it has not already been selected on this connection. */
    public void ensureSelected() throws BIBOException {
        if (!selected) {
            select();
        }
    }

    /** Issues {@code GET_INFO} (selecting first if needed) and returns the decoded profile. */
    public MeowlInfo getInfo() throws BIBOException {
        ensureSelected();
        return MeowlInfo.parse(outerNoData(MeowlInsn.GET_INFO, "GET_INFO"));
    }

    /**
     * Issues {@code GET_AUTHENTIKEY} (selecting first if needed) and returns the 33-byte compressed
     * public key.
     */
    public byte[] getAuthentikey() throws BIBOException {
        ensureSelected();
        return outerNoData(MeowlInsn.GET_AUTHENTIKEY, "GET_AUTHENTIKEY");
    }

    /**
     * Fetches the authentikey and opens a verified Secure Channel against it. The returned client
     * has completed its handshake and is ready for {@link SecureChannelClient#sendInner}.
     */
    public SecureChannelClient openSecureChannel() throws BIBOException {
        byte[] authentikey = getAuthentikey();
        return SecureChannelClient.open(bibo, authentikey);
    }

    /**
     * Drives {@code RESET_TO_FACTORY} to completion, returning the per-step status words.
     *
     * @throws ProtocolException if any step deviates from the {@code 6FAx} countdown family, or the
     *     final step does not report wipe-complete (low nibble {@code 0})
     */
    public int[] resetToFactory() throws BIBOException {
        ensureSelected();
        int[] sequence = new int[RESET_REQUIRED_INVOCATIONS];
        for (int i = 0; i < RESET_REQUIRED_INVOCATIONS; i++) {
            ResponseAPDU resp =
                    bibo.transmit(
                            new CommandAPDU(
                                    CLA_MEOWL, MeowlInsn.RESET_TO_FACTORY.value() & 0xFF, 0, 0));
            int sw = resp.getSW();
            sequence[i] = sw;
            // Assert the kind, not just the final value: a non-meowl applet could otherwise return
            // e.g. 6D00 four times and slip past the final-SW check.
            if ((sw & 0xFFF0) != MeowlSw.RESET_COUNTDOWN_BASE) {
                throw new ProtocolException(
                        sw,
                        "RESET_TO_FACTORY step %d returned %04X, expected a 6FAx countdown"
                                .formatted(i + 1, sw));
            }
        }
        int last = sequence[sequence.length - 1];
        if ((last & 0x000F) != 0) {
            throw new ProtocolException(last, "RESET_TO_FACTORY did not complete the wipe");
        }
        return sequence;
    }

    /** Transmits a raw APDU verbatim, with no meowl framing or status-word assertion. */
    public ResponseAPDU transmit(CommandAPDU command) throws BIBOException {
        return bibo.transmit(command);
    }

    /** Sends an outer-channel, no-data meowl INS, asserts {@code 9000}, and returns the body. */
    private byte[] outerNoData(MeowlInsn ins, String label) throws BIBOException {
        ResponseAPDU resp = bibo.transmit(new CommandAPDU(CLA_MEOWL, ins.value() & 0xFF, 0, 0));
        if (!MeowlSw.isSuccess(resp.getSW())) {
            throw new ProtocolException(resp.getSW(), label + " failed");
        }
        return resp.getData();
    }
}
