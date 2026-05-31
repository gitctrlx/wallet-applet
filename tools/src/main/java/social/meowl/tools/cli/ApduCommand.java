/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.card.MeowlCard;
import social.meowl.tools.core.Hex;
import social.meowl.tools.core.MeowlSw;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl apdu <hex>} — sends a raw hex-encoded APDU and prints the response.
 *
 * <p>The command optionally selects the meowl applet first (suppress with {@code --no-select} when
 * targeting a different applet, the GP card manager, or an unselected card). The output format
 * mirrors {@code apdu4j-tool}'s shorthand: {@code <-- <data> SW=<sw> — <description>}.
 */
@Command(
        name = "apdu",
        mixinStandardHelpOptions = true,
        description = "Transmits a raw hex APDU to the card and prints the response.")
public final class ApduCommand implements Callable<Integer> {

    @ParentCommand private MeowlCli parent;

    @Mixin public AidOption aid = new AidOption();

    @Option(
            names = "--no-select",
            description =
                    "Skip the SELECT meowl applet step before transmitting (use when talking to"
                            + " the GP card manager or another applet).")
    public boolean noSelect = false;

    @Parameters(
            arity = "1",
            paramLabel = "HEX",
            description =
                    "The raw command APDU encoded as hexadecimal (e.g. \"80010000\" for"
                            + " GET_INFO).")
    public String hex;

    @Override
    public Integer call() {
        CommandAPDU command = new CommandAPDU(Hex.decode(hex));
        ResponseAPDU resp =
                CardTransport.run(
                        parent.globalOptions.toReaderPreferences(),
                        bibo -> {
                            MeowlCard card = new MeowlCard(bibo, aid.bytes());
                            if (!noSelect) {
                                card.select();
                            }
                            return card.transmit(command);
                        });

        if (parent.globalOptions.json) {
            JsonOutput.writeMap(
                    System.out,
                    "data",
                    "0x" + Hex.encode(resp.getData()),
                    "sw",
                    "0x%04X".formatted(resp.getSW()),
                    "sw_description",
                    MeowlSw.describe(resp.getSW()));
        } else {
            System.out.printf(
                    "<-- %s SW=%04X (%s)%n",
                    Hex.encode(resp.getData()), resp.getSW(), MeowlSw.describe(resp.getSW()));
        }
        return MeowlSw.isSuccess(resp.getSW()) ? 0 : MeowlExecutionExceptionHandler.EXIT_PROTOCOL;
    }
}
