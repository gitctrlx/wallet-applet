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
import social.meowl.tools.proto.SecureChannelClient;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl sc handshake} — runs only the {@code INIT_SECURE_CHANNEL} half of the MEAP-2
 * protocol against the card, verifies the authentikey signature, and prints the resulting
 * session-state digest. The connection is closed at the end so the session does not persist; follow
 * up with {@code meowl sc send} when you actually need to invoke an inner-band INS.
 */
@Command(
        name = "handshake",
        mixinStandardHelpOptions = true,
        description =
                "Performs an INIT_SECURE_CHANNEL handshake and prints the derived session state.")
public final class ScHandshakeCommand implements Callable<Integer> {

    @ParentCommand private ScCommand parent;

    @Mixin public AidOption aid = new AidOption();

    @Override
    public Integer call() {
        MeowlCli root = (MeowlCli) parent.spec.commandLine().getParent().getCommand();
        SecureChannelClient.Handshake hs =
                CardTransport.run(root.globalOptions.toReaderPreferences(), this::handshake);

        if (root.globalOptions.json) {
            JsonOutput.writeMap(
                    System.out,
                    "card_eph_pub",
                    "0x" + Hex.encode(hs.cardEphPub()),
                    "signature_der",
                    "0x" + Hex.encode(hs.signatureDer()),
                    "iv_base",
                    "0x" + Hex.encode(hs.ivBase()));
        } else {
            System.out.printf("  card_eph_pub  : 0x%s%n", Hex.encode(hs.cardEphPub()));
            System.out.printf(
                    "  signature_der : 0x%s (%d bytes)%n",
                    Hex.encode(hs.signatureDer()), hs.signatureDer().length);
            System.out.printf("  iv_base       : 0x%s%n", Hex.encode(hs.ivBase()));
            System.out.println("OK (handshake verified)");
        }
        return 0;
    }

    private SecureChannelClient.Handshake handshake(APDUBIBO bibo) throws BIBOException {
        MeowlSession.select(bibo, aid.bytes());

        // Fetch the authentikey first so we can verify the handshake signature against it.
        // GET_AUTHENTIKEY uses the meowl CLA (0x80), not ISO 0x00.
        ResponseAPDU resp =
                bibo.transmit(
                        new CommandAPDU(
                                SecureChannelClient.CLA_MEOWL,
                                MeowlInsn.GET_AUTHENTIKEY.value() & 0xFF,
                                0,
                                0));
        if (!MeowlSw.isSuccess(resp.getSW())) {
            throw new ProtocolException(resp.getSW(), "GET_AUTHENTIKEY failed during sc handshake");
        }
        SecureChannelClient sc = new SecureChannelClient(bibo, resp.getData());
        return sc.handshake();
    }
}
