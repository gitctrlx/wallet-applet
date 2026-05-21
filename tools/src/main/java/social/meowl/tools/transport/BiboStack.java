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
 * Composes the apdu4j {@link BIBO} decorator stack used by the {@code meowl} CLI.
 *
 * <p>The stack is built bottom-up so the wire-side end of the chain is the raw transport, and the
 * application-side end is what subcommands {@code transmit()} against. From bottom to top:
 *
 * <ol>
 *   <li>raw transport (PC/SC channel, MockBIBO replay, JCardSim, …)
 *   <li>{@link RetryWithRightLengthWrapper} — re-issues commands automatically when the card
 *       answers {@code 6CXX} indicating the host underestimated the response length
 *   <li>{@link GetResponseWrapper} — turns the multi-APDU {@code GET RESPONSE} dance for {@code
 *       61XX} into a single logical exchange
 *   <li>{@link DumpingBIBO} (optional) — records every APDU pair to a text file in {@link
 *       apdu4j.core.MockBIBO}'s replay format so a debug session can be re-run offline
 *   <li>{@link LoggingBIBO} (optional) — emits one TRACE-level SLF4J line per APDU exchange
 * </ol>
 *
 * <p>Layering matters: logging and dumping must observe the <em>logical</em> exchange (after retry
 * + GET-RESPONSE coalescing), so they sit on top. Dumping is below logging so the log can include a
 * single tracer line per command even when dumping is also active.
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
            // Outermost wrapper so a `close()` call on the returned BIBO is guaranteed to flush
            // and release the dump file's OutputStream, even if the inner apdu4j decorators do
            // not propagate close() to their delegate (DumpingBIBO does not own the stream's
            // lifecycle by design — see its javadoc).
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

    /**
     * BIBO decorator whose only responsibility is to close an external resource (the dump file's
     * {@link FileOutputStream}) when the chain is closed. Transceives are forwarded verbatim.
     */
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
                    // We are already on the close path; deliberately swallow so the close() of the
                    // outer transport chain remains exception-free, matching the BIBO contract.
                }
            }
        }
    }
}
