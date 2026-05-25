/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBOException;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import social.meowl.tools.core.MeowlSw;

/**
 * Helpers shared by every subcommand that needs to talk to the meowl applet.
 *
 * <p>All meowl APDUs require the applet to be selected first. The shared {@link #select(APDUBIBO,
 * byte[])} helper centralises the ISO 7816-4 SELECT command and translates non-success status words
 * into the structured {@link ProtocolException} so {@link MeowlExecutionExceptionHandler} can
 * render them with the appropriate exit code.
 */
public final class MeowlSession {

    private MeowlSession() {}

    /** ISO 7816-4 §6.11 SELECT BY DF NAME, P1=0x04, P2=0x00. */
    public static final int CLA_ISO = 0x00;

    public static final int INS_SELECT = 0xA4;

    public static final int P1_SELECT_BY_DF = 0x04;

    /** SELECTs the meowl applet at the supplied AID, asserting success. */
    public static byte[] select(APDUBIBO bibo, byte[] aid) throws BIBOException {
        ResponseAPDU resp =
                bibo.transmit(new CommandAPDU(CLA_ISO, INS_SELECT, P1_SELECT_BY_DF, 0x00, aid));
        if (!MeowlSw.isSuccess(resp.getSW())) {
            throw new ProtocolException(resp.getSW(), "SELECT meowl applet failed");
        }
        return resp.getData();
    }
}
