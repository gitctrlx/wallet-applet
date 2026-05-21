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
 * Bridges picocli subcommands to the apdu4j {@link ReaderSelector} visitor without forcing each
 * command to re-implement the connect → execute → close lifecycle.
 *
 * <p>{@link ReaderSelector#run(java.util.function.Function)} is the canonical apdu4j 26.x entry
 * point: it acquires a PC/SC channel, hands it to the supplied function as an {@link APDUBIBO}, and
 * guarantees the channel is released even if the function throws. {@link #run(ReaderPreferences,
 * CardAction)} is a thin wrapper that
 *
 * <ol>
 *   <li>configures a {@link ReaderSelector} from {@link ReaderPreferences},
 *   <li>installs the {@link BiboStack} of decorators (retry, GET-RESPONSE, dump, trace),
 *   <li>re-exposes the result as an {@link APDUBIBO} so subcommands keep using the typed {@code
 *       transmit(CommandAPDU)} API,
 *   <li>and propagates {@link BIBOException} as an unchecked {@link CardIoException} so picocli's
 *       exception handler can format it.
 * </ol>
 *
 * <p>The transport intentionally does not expose a long-lived {@code AutoCloseable} handle. The
 * visitor model is the safer default — one PC/SC connection per logical operation — and matches how
 * the {@code meowl shell} REPL is implemented (each shell command re-acquires the card so that
 * physically removing the card between two commands surfaces immediately).
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
     * Opens a card per {@code prefs}, decorates the transport with {@link BiboStack#decorate}, and
     * runs {@code action} against the resulting APDU-typed BIBO.
     *
     * @return whatever {@code action} returned
     * @throws CardIoException if the card layer raised a {@link BIBOException} (wrapped to keep the
     *     exit-code mapping in {@code MeowlCli} simple)
     * @throws RuntimeException any unchecked exception thrown by the action is rethrown unchanged
     *     so picocli's {@code IExecutionExceptionHandler} can format it
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
