/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import apdu4j.pcsc.NoMatchingReaderException;
import picocli.CommandLine;
import picocli.CommandLine.IExecutionExceptionHandler;
import picocli.CommandLine.ParseResult;
import social.meowl.tools.core.ProtocolException;
import social.meowl.tools.gp.GpFacade.GpException;
import social.meowl.tools.proto.SecureChannelException;
import social.meowl.tools.transport.CardTransport.CardIoException;

/**
 * Translates the various exception families emitted by the CLI into picocli exit codes.
 *
 * <p>Per POSIX convention, exit codes are 8-bit unsigned. We use:
 *
 * <ul>
 *   <li>{@code 0} — success
 *   <li>{@code 1} — generic / unexpected error
 *   <li>{@code 2} — usage error (caught upstream by picocli; mirrored here for consistency)
 *   <li>{@code 3} — card-layer I/O failure ({@link CardIoException}, no reader, card removed)
 *   <li>{@code 4} — protocol / status-word failure (the card returned non-9000 in a context where
 *       the subcommand asserted success)
 *   <li>{@code 5} — Secure Channel failure ({@link SecureChannelException}: host/card crypto or MAC
 *       mismatch)
 *   <li>{@code 6} — GlobalPlatform card-management failure ({@link GpException})
 * </ul>
 *
 * <p>Verbose mode ({@code -v} / {@code --verbose}) prints the full stack trace; otherwise a single
 * human-readable line is shown so terminal output stays clean during typical use. (APDU-level
 * tracing is a separate concern, toggled by {@code --trace}.)
 */
public final class MeowlExecutionExceptionHandler implements IExecutionExceptionHandler {

    public static final int EXIT_CARD_IO = 3;
    public static final int EXIT_PROTOCOL = 4;
    public static final int EXIT_SECURE_CHANNEL = 5;
    public static final int EXIT_GP = 6;

    public static final MeowlExecutionExceptionHandler INSTANCE =
            new MeowlExecutionExceptionHandler();

    private MeowlExecutionExceptionHandler() {}

    @Override
    public int handleExecutionException(
            Exception ex, CommandLine commandLine, ParseResult parseResult) {
        boolean verbose = isVerbose(commandLine);

        if (ex instanceof ProtocolException pe) {
            commandLine.getErr().println("error: " + pe.getMessage());
            if (verbose) ex.printStackTrace(commandLine.getErr());
            return EXIT_PROTOCOL;
        }

        if (ex instanceof SecureChannelException sce) {
            commandLine.getErr().println("secure-channel: " + sce.getMessage());
            if (verbose) ex.printStackTrace(commandLine.getErr());
            return EXIT_SECURE_CHANNEL;
        }

        if (ex instanceof GpException) {
            commandLine.getErr().println("gp: " + ex.getMessage());
            if (verbose) ex.printStackTrace(commandLine.getErr());
            return EXIT_GP;
        }

        if (ex instanceof CardIoException || ex instanceof NoMatchingReaderException) {
            commandLine.getErr().println("card: " + ex.getMessage());
            if (verbose) ex.printStackTrace(commandLine.getErr());
            return EXIT_CARD_IO;
        }

        if (ex instanceof IllegalArgumentException) {
            commandLine.getErr().println("error: " + ex.getMessage());
            return CommandLine.ExitCode.USAGE;
        }

        commandLine
                .getErr()
                .println("error: " + ex.getClass().getSimpleName() + ": " + ex.getMessage());
        if (verbose) {
            ex.printStackTrace(commandLine.getErr());
        } else {
            commandLine.getErr().println("(re-run with -v for a stack trace)");
        }
        return CommandLine.ExitCode.SOFTWARE;
    }

    /** Walks the command tree to find the {@code -v} / {@code --verbose} flag, if present. */
    private static boolean isVerbose(CommandLine commandLine) {
        for (CommandLine cl = commandLine; cl != null; cl = cl.getParent()) {
            Object userObject = cl.getCommand();
            if (userObject instanceof MeowlCli root) {
                return root.globalOptions.verbose;
            }
        }
        return false;
    }
}
