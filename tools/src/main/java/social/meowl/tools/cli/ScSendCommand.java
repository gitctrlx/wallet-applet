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
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.core.Hex;
import social.meowl.tools.core.MeowlInsn;
import social.meowl.tools.core.MeowlSw;
import social.meowl.tools.proto.SecureChannelClient;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl sc send <inner-hex>} — opens a Secure Channel and sends a single inner APDU through
 * the {@code OPEN_SECURE_CHANNEL} envelope, then decrypts and prints the card's response.
 *
 * <p>The {@code <inner-hex>} argument is the plaintext inner APDU bytes — typically constructed as
 * {@code 80 INS P1 P2 LC DATA}. For a quick reference of available INS bytes use {@code meowl
 * --help} or consult {@code MeowlInsn} (CLI names) and the MEAP specifications.
 */
@Command(
        name = "send",
        mixinStandardHelpOptions = true,
        description =
                "Sends a single inner APDU through a fresh Secure Channel envelope and prints"
                        + " the decrypted response.")
public final class ScSendCommand implements Callable<Integer> {

    @ParentCommand private ScCommand parent;

    @Mixin public AidOption aid = new AidOption();

    @Parameters(
            arity = "1",
            paramLabel = "INNER_HEX",
            description =
                    "Plaintext inner APDU encoded as hexadecimal (e.g. \"8021000404123456\""
                            + " for VERIFY_PIN with PIN 0x12 0x34 0x56).")
    public String innerHex;

    @Override
    public Integer call() {
        MeowlCli root = (MeowlCli) parent.spec.commandLine().getParent().getCommand();
        byte[] innerApdu = Hex.decode(innerHex);

        byte[] response =
                CardTransport.run(
                        root.globalOptions.toReaderPreferences(),
                        bibo -> handshakeAndSend(bibo, innerApdu));

        if (root.globalOptions.json) {
            JsonOutput.writeMap(System.out, "data", "0x" + Hex.encode(response));
        } else {
            System.out.printf("<-- %s%n", Hex.encode(response));
        }
        return 0;
    }

    private byte[] handshakeAndSend(APDUBIBO bibo, byte[] innerApdu) throws BIBOException {
        MeowlSession.select(bibo, aid.bytes());

        ResponseAPDU akResp =
                bibo.transmit(
                        new CommandAPDU(
                                SecureChannelClient.CLA_MEOWL,
                                MeowlInsn.GET_AUTHENTIKEY.value() & 0xFF,
                                0,
                                0));
        if (!MeowlSw.isSuccess(akResp.getSW())) {
            throw new ProtocolException(akResp.getSW(), "GET_AUTHENTIKEY failed during sc send");
        }

        SecureChannelClient sc = new SecureChannelClient(bibo, akResp.getData());
        sc.handshake();
        return sc.sendInner(innerApdu);
    }
}
