/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.transport;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import apdu4j.pcsc.ReaderSelector;
import apdu4j.pcsc.Readers;

/**
 * Bridges picocli subcommands to the apdu4j {@link ReaderSelector} visitor: configures the selector
 * from {@link ReaderPreferences}, installs the {@link BiboStack} decorators (retry, GET-RESPONSE,
 * dump, trace), and propagates {@link BIBOException} as an unchecked {@link CardIoException} for
 * picocli's exit-code mapping.
 *
 * <p>No long-lived {@code AutoCloseable} — the visitor model gives one PC/SC connection per logical
 * operation, matching how {@code meowl shell} re-acquires the card per command.
 */
public final class CardTransport {

    private CardTransport() {}

    /** Action executed against an open card; may throw {@link BIBOException} unmodified. */
    @FunctionalInterface
    public interface CardAction<T> {
        T run(APDUBIBO bibo) throws BIBOException;
    }

    /** Consumer-shaped variant for {@link #runVoid(ReaderPreferences, ConsumerAction)}. */
    @FunctionalInterface
    public interface ConsumerAction {
        void run(APDUBIBO bibo) throws BIBOException;
    }

    /**
     * Opens a card per {@code prefs}, decorates the transport, and runs {@code action}.
     *
     * @throws CardIoException if the card layer raises a {@link BIBOException}
     */
    public static <T> T run(ReaderPreferences prefs, CardAction<T> action) {
        ReaderSelector selector = configureReader(prefs);
        return selector.run(
                (APDUBIBO raw) -> {
                    BIBO stacked = BiboStack.decorate(raw, prefs);
                    APDUBIBO bibo = new APDUBIBO(stacked);
                    try {
                        return action.run(bibo);
                    } catch (BIBOException e) {
                        throw new CardIoException(e);
                    }
                });
    }

    /** Convenience overload for actions that produce no result. */
    public static void runVoid(ReaderPreferences prefs, ConsumerAction action) {
        run(
                prefs,
                bibo -> {
                    action.run(bibo);
                    return null;
                });
    }

    /**
     * Opens a long-lived card connection per {@code prefs}, returning a decorated {@link APDUBIBO}
     * the caller is responsible for {@code close()}-ing. Unlike {@link #run}, the connection
     * survives across many operations — used by {@code meowl shell} to hold a single PC/SC session
     * for the REPL lifetime. The same {@link BiboStack} decorators (retry, GET-RESPONSE, dump,
     * trace) are applied, so tracing and dumping behave identically in the shell and the one-shot
     * subcommands.
     */
    public static APDUBIBO connect(ReaderPreferences prefs) {
        APDUBIBO raw = configureReader(prefs).connect();
        return new APDUBIBO(BiboStack.decorate(raw, prefs));
    }

    private static ReaderSelector configureReader(ReaderPreferences prefs) {
        ReaderSelector selector = Readers.select();
        if (prefs.hasReaderConstraint()) {
            selector = selector.select(prefs.readerName());
        }
        if (prefs.hasIgnoreFilter()) {
            selector = selector.ignore(prefs.readerIgnore());
        }
        selector = selector.protocol(prefs.protocol());
        if (prefs.requireExclusive()) {
            selector = selector.exclusive();
        }
        return selector.withCard();
    }

    /** Wraps a checked {@link BIBOException} so subcommand bodies can stay {@code throws}-free. */
    public static final class CardIoException extends RuntimeException {
        public CardIoException(BIBOException cause) {
            super(cause.getMessage(), cause);
        }
    }
}
