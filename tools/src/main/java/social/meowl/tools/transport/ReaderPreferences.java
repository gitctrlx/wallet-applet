/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.transport;

import java.nio.file.Path;
import java.util.Optional;

/**
 * Immutable bundle of reader-selection and tracing preferences resolved from CLI options and the
 * environment. Lives in {@code transport} (which cannot depend on the {@code cli} package) so the
 * dependency graph stays {@code core ⇐ transport ⇐ cli}.
 *
 * @param readerName substring match for the PC/SC reader name; empty means "the unique reader"
 * @param readerIgnore substring match for readers to skip; empty disables filtering
 * @param protocol PC/SC protocol; defaults to {@code "T=1"}
 * @param dumpFile optional MockBIBO replay-format dump file
 * @param trace whether to log every APDU at TRACE level via SLF4J
 * @param requireExclusive whether to acquire the reader exclusively
 */
public record ReaderPreferences(
        String readerName,
        String readerIgnore,
        String protocol,
        Optional<Path> dumpFile,
        boolean trace,
        boolean requireExclusive) {

    /** Environment variable consulted when the CLI does not specify {@code --reader}. */
    public static final String ENV_READER = "MEOWL_READER";

    /** Environment variable consulted when the CLI does not specify {@code --reader-ignore}. */
    public static final String ENV_READER_IGNORE = "MEOWL_READER_IGNORE";

    /** Default PC/SC transport protocol; {@code "T=1"} is universally supported. */
    public static final String DEFAULT_PROTOCOL = "T=1";

    public ReaderPreferences {
        if (protocol == null || protocol.isBlank()) {
            throw new IllegalArgumentException("protocol must be non-blank (use \"*\" for any)");
        }
    }

    /** Default preferences: any reader, T=1, no tracing, no exclusivity, no dump. */
    public static ReaderPreferences defaults() {
        return new ReaderPreferences("", "", DEFAULT_PROTOCOL, Optional.empty(), false, false);
    }

    /**
     * Resolves preferences from CLI inputs, falling back to environment variables for any input the
     * user left empty. Empty CLI strings ({@code ""}) and {@code null} both mean "fall back".
     */
    public static ReaderPreferences fromEnvironment(
            String readerCli,
            String readerIgnoreCli,
            Optional<String> protocolCli,
            Optional<Path> dumpFileCli,
            Optional<Boolean> traceCli,
            Optional<Boolean> exclusiveCli) {
        String reader = nonEmpty(readerCli).orElseGet(() -> envOrEmpty(ENV_READER));
        String ignore = nonEmpty(readerIgnoreCli).orElseGet(() -> envOrEmpty(ENV_READER_IGNORE));
        String protocol = protocolCli.filter(s -> !s.isBlank()).orElse(DEFAULT_PROTOCOL);
        return new ReaderPreferences(
                reader,
                ignore,
                protocol,
                dumpFileCli,
                traceCli.orElse(false),
                exclusiveCli.orElse(false));
    }

    /** Returns whether the user constrained reader selection by name. */
    public boolean hasReaderConstraint() {
        return !readerName.isBlank();
    }

    /** Returns whether reader-ignore filtering is active. */
    public boolean hasIgnoreFilter() {
        return !readerIgnore.isBlank();
    }

    private static Optional<String> nonEmpty(String s) {
        return s == null || s.isBlank() ? Optional.empty() : Optional.of(s);
    }

    private static String envOrEmpty(String key) {
        String v = System.getenv(key);
        return v == null ? "" : v;
    }
}
