/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBOException;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.core.Hex;
import social.meowl.tools.core.MeowlInsn;
import social.meowl.tools.core.MeowlSw;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl authentikey} — fetches the card's compressed authentikey public key.
 *
 * <p>The authentikey is generated once at install time and never rotates; it anchors device
 * identity for the Secure Channel handshake (MEAP-2) and PKI personalisation (MEAP-4). Two
 * consecutive invocations of this command must therefore return identical bytes.
 */
@Command(
        name = "authentikey",
        mixinStandardHelpOptions = true,
        description = "Returns the card's 33-byte compressed authentikey public key.")
public final class AuthentikeyCommand implements Callable<Integer> {

    private static final byte CLA_MEOWL = (byte) 0x80;

    @ParentCommand private MeowlCli parent;

    @Mixin public AidOption aid = new AidOption();

    @Override
    public Integer call() {
        byte[] pubkey =
                CardTransport.run(
                        parent.globalOptions.toReaderPreferences(), this::queryAuthentikey);

        if (parent.globalOptions.json) {
            JsonOutput.writeMap(
                    System.out, "authentikey", "0x" + Hex.encode(pubkey), "length", pubkey.length);
        } else {
            System.out.println("0x" + Hex.encode(pubkey));
        }
        return 0;
    }

    private byte[] queryAuthentikey(APDUBIBO bibo) throws BIBOException {
        MeowlSession.select(bibo, aid.bytes());
        ResponseAPDU resp =
                bibo.transmit(
                        new CommandAPDU(
                                CLA_MEOWL & 0xFF, MeowlInsn.GET_AUTHENTIKEY.value() & 0xFF, 0, 0));
        if (!MeowlSw.isSuccess(resp.getSW())) {
            throw new ProtocolException(resp.getSW(), "GET_AUTHENTIKEY failed");
        }
        return resp.getData();
    }
}
