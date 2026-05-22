/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.transport;

import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import apdu4j.core.DumpingBIBO;
import apdu4j.core.GetResponseWrapper;
import apdu4j.core.LoggingBIBO;
import apdu4j.core.RetryWithRightLengthWrapper;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Composes the apdu4j {@link BIBO} decorator stack used by the {@code meowl} CLI. Bottom-up:
 *
 * <ol>
 *   <li>raw transport (PC/SC, MockBIBO replay, JCardSim, …)
 *   <li>{@link RetryWithRightLengthWrapper} — auto-retries {@code 6CXX} length mismatches
 *   <li>{@link GetResponseWrapper} — coalesces {@code 61XX} GET-RESPONSE chains
 *   <li>{@link DumpingBIBO} (optional) — appends every APDU pair to a MockBIBO-replay file
 *   <li>{@link LoggingBIBO} (optional) — emits one TRACE SLF4J line per exchange
 * </ol>
 *
 * <p>Logging and dumping sit on top so they observe the logical exchange after retry / GET-RESPONSE
 * coalescing; dumping is below logging so a single trace line covers each command.
 */
public final class BiboStack {

    private static final Logger LOG = LoggerFactory.getLogger("meowl.apdu");

    private BiboStack() {}

    /**
     * Decorates a raw transport with the configured tracing, dumping and protocol-quirk wrappers.
     *
     * @param raw the underlying BIBO transport (must not be {@code null})
     * @param prefs reader-and-tracing preferences resolved from the CLI / environment
     * @return a new BIBO that wraps {@code raw}; the caller still owns lifecycle of {@code raw}
     */
    public static BIBO decorate(BIBO raw, ReaderPreferences prefs) {
        BIBO bibo = raw.then(GetResponseWrapper::wrap).then(RetryWithRightLengthWrapper::wrap);

        FileOutputStream dumpStream = null;
        if (prefs.dumpFile().isPresent()) {
            dumpStream = openDumpFile(prefs);
            final FileOutputStream finalStream = dumpStream;
            bibo = bibo.then(b -> DumpingBIBO.wrap(b, finalStream));
        }
        if (prefs.trace()) {
            bibo = bibo.then(b -> LoggingBIBO.wrap(b, LOG::trace));
        }
        if (dumpStream != null) {
            // Outermost wrapper so close() flushes the dump file; DumpingBIBO does not own its
            // stream's lifecycle by design.
            bibo = new ClosingBibo(bibo, dumpStream);
        }
        return bibo;
    }

    private static FileOutputStream openDumpFile(ReaderPreferences prefs) {
        try {
            // Append-mode so consecutive subcommand invocations build a single replayable session.
            return new FileOutputStream(prefs.dumpFile().orElseThrow().toFile(), true);
        } catch (IOException e) {
            throw new UncheckedIOException(
                    "Cannot open APDU dump file " + prefs.dumpFile().orElseThrow(), e);
        }
    }

    /** BIBO decorator that closes an external {@link FileOutputStream} when the chain is closed. */
    private static final class ClosingBibo implements BIBO {
        private final BIBO delegate;
        private final FileOutputStream owned;

        ClosingBibo(BIBO delegate, FileOutputStream owned) {
            this.delegate = delegate;
            this.owned = owned;
        }

        @Override
        public byte[] transceive(byte[] cmd) throws BIBOException {
            return delegate.transceive(cmd);
        }

        @Override
        public void close() {
            try {
                delegate.close();
            } finally {
                try {
                    owned.close();
                } catch (IOException ignored) {
                    // Swallow: BIBO.close() must be exception-free.
                }
            }
        }
    }
}
