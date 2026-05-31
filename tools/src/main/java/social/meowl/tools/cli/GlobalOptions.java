/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import java.nio.file.Path;
import java.util.Optional;
import picocli.CommandLine.Option;
import social.meowl.tools.transport.ReaderPreferences;

/**
 * Mixin holding the picocli options that every {@code meowl} subcommand inherits. Subcommands
 * receive an instance via {@code @Mixin} and forward it to {@link #toReaderPreferences()} when they
 * need to talk to a card.
 */
public final class GlobalOptions {

    @Option(
            names = {"-r", "--reader"},
            paramLabel = "NAME",
            description =
                    "PC/SC reader name (substring match). Falls back to the $MEOWL_READER"
                            + " environment variable.")
    public String reader = "";

    @Option(
            names = "--reader-ignore",
            paramLabel = "NAME",
            description =
                    "Skip readers whose name contains this substring. Falls back to"
                            + " $MEOWL_READER_IGNORE.")
    public String readerIgnore = "";

    @Option(
            names = "--protocol",
            paramLabel = "PROTO",
            description =
                    "PC/SC protocol — \"T=0\", \"T=1\", or \"*\" for any (default:"
                            + " ${DEFAULT-VALUE}).",
            defaultValue = "T=1")
    public String protocol = "T=1";

    @Option(
            names = "--exclusive",
            description = "Acquire the reader exclusively; fail if another process holds the card.")
    public boolean exclusive = false;

    @Option(names = "--trace", description = "Log every APDU exchange at TRACE level via SLF4J.")
    public boolean trace = false;

    @Option(
            names = {"-v", "--verbose"},
            description = "Print full stack traces on error instead of a single-line message.")
    public boolean verbose = false;

    @Option(
            names = "--dump",
            paramLabel = "FILE",
            description =
                    "Append each APDU exchange to FILE in apdu4j MockBIBO replay format. The"
                            + " session can later be replayed offline with `meowl replay FILE`.")
    public Path dumpFile;

    @Option(
            names = "--json",
            description = "Emit machine-readable JSON output (where the subcommand supports it).")
    public boolean json = false;

    /**
     * Resolves these CLI inputs against the environment to produce the immutable {@link
     * ReaderPreferences} consumed by {@code transport.CardTransport}.
     */
    public ReaderPreferences toReaderPreferences() {
        return ReaderPreferences.fromEnvironment(
                reader,
                readerIgnore,
                Optional.ofNullable(protocol),
                Optional.ofNullable(dumpFile),
                Optional.of(trace),
                Optional.of(exclusive));
    }
}
