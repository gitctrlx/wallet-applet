/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import apdu4j.core.CommandAPDU;
import apdu4j.core.GetResponseWrapper;
import apdu4j.core.MockBIBO;
import apdu4j.core.ResponseAPDU;
import apdu4j.core.RetryWithRightLengthWrapper;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.core.Hex;
import social.meowl.tools.core.MeowlSw;

/**
 * {@code meowl replay <dump-file> <hex-apdu>} — replays an APDU exchange from a previously captured
 * dump file, without touching a real card.
 *
 * <p>This is the offline counterpart to {@code meowl --dump} sessions: a developer captures a real
 * exchange against the card, then iterates against the dump to test host-side behaviour (parsers,
 * error-handling) at zero cost and without needing a card at hand. The dump format is apdu4j's
 * {@link MockBIBO#fromDump(java.io.InputStream) MockBIBO replay format}, which the dump file
 * produced by {@code DumpingBIBO} writes directly.
 */
@Command(
        name = "replay",
        mixinStandardHelpOptions = true,
        description =
                "Replays a previously captured APDU dump file against MockBIBO and prints the"
                        + " response — no card required.")
public final class ReplayCommand implements Callable<Integer> {

    @ParentCommand private MeowlCli parent;

    @Parameters(
            index = "0",
            paramLabel = "DUMP",
            description = "The dump file produced by `meowl --dump FILE`.")
    public Path dumpFile;

    @Parameters(
            index = "1",
            paramLabel = "HEX",
            description = "The command APDU to issue against the replayed session, hexadecimal.")
    public String hex;

    @Override
    public Integer call() {
        CommandAPDU command = new CommandAPDU(Hex.decode(hex));

        try (FileInputStream in = new FileInputStream(dumpFile.toFile())) {
            BIBO replay =
                    MockBIBO.fromDump(in)
                            .then(GetResponseWrapper::wrap)
                            .then(RetryWithRightLengthWrapper::wrap);
            APDUBIBO apdu = new APDUBIBO(replay);
            ResponseAPDU resp;
            try {
                resp = apdu.transmit(command);
            } catch (BIBOException e) {
                throw new UncheckedIOException(
                        "Dump did not contain an entry for " + Hex.encode(command.getBytes()),
                        new IOException(e.getMessage(), e));
            }

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
            return MeowlSw.isSuccess(resp.getSW())
                    ? 0
                    : MeowlExecutionExceptionHandler.EXIT_PROTOCOL;
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read dump file " + dumpFile, e);
        }
    }
}
