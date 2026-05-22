/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import apdu4j.core.APDUBIBO;
import apdu4j.pcsc.ReaderSelector;
import apdu4j.pcsc.Readers;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;
import org.jline.reader.EndOfFileException;
import org.jline.reader.LineReader;
import org.jline.reader.LineReaderBuilder;
import org.jline.reader.UserInterruptException;
import org.jline.reader.impl.completer.AggregateCompleter;
import org.jline.reader.impl.completer.ArgumentCompleter;
import org.jline.reader.impl.completer.NullCompleter;
import org.jline.reader.impl.completer.StringsCompleter;
import org.jline.reader.impl.history.DefaultHistory;
import org.jline.terminal.Terminal;
import org.jline.terminal.TerminalBuilder;
import picocli.CommandLine.Command;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.shell.ShellSession;
import social.meowl.tools.transport.ReaderPreferences;

/**
 * {@code meowl shell} — interactive REPL with persistent PC/SC connection and Secure Channel
 * session, JLine line editing, persistent history at {@code ~/.meowl/history}, and tab-completion
 * of the verb set. Prompt reflects session state. {@code Ctrl-D} / {@code exit} / {@code quit} tear
 * it down.
 */
@Command(
        name = "shell",
        mixinStandardHelpOptions = true,
        description =
                "Interactive REPL with a persistent PC/SC connection and Secure Channel session.")
public final class ShellCommand implements Callable<Integer> {

    @ParentCommand private MeowlCli parent;

    @Override
    public Integer call() throws IOException {
        ReaderPreferences prefs = parent.globalOptions.toReaderPreferences();
        APDUBIBO bibo = openCard(prefs);

        try (Terminal terminal = TerminalBuilder.builder().system(true).build()) {
            Path historyFile = ensureHistoryFile();
            LineReader reader =
                    LineReaderBuilder.builder()
                            .terminal(terminal)
                            .completer(buildCompleter())
                            .history(new DefaultHistory())
                            .variable(LineReader.HISTORY_FILE, historyFile)
                            .variable(LineReader.HISTORY_FILE_SIZE, 1000)
                            .build();

            PrintWriter out = terminal.writer();
            ShellSession session = new ShellSession(bibo, out, out);
            terminal.writer().println("meowl shell — type 'help' for commands, 'exit' to quit.");

            while (true) {
                String line;
                try {
                    line = reader.readLine(session.prompt());
                } catch (UserInterruptException e) {
                    // Ctrl-C: discard the current line, re-prompt.
                    continue;
                } catch (EndOfFileException e) {
                    // Ctrl-D: clean exit.
                    break;
                }
                if (line == null) break;
                String trimmed = line.trim();
                if (trimmed.equalsIgnoreCase("exit") || trimmed.equalsIgnoreCase("quit")) {
                    break;
                }
                try {
                    session.execute(trimmed);
                } catch (ShellSession.ShellException ex) {
                    out.println("error: " + ex.getMessage());
                } catch (Exception ex) {
                    out.println("error: " + ex.getClass().getSimpleName() + ": " + ex.getMessage());
                    if (parent.globalOptions.trace) {
                        ex.printStackTrace(out);
                    }
                }
            }
            session.shutdown();
        } finally {
            bibo.close();
        }
        return 0;
    }

    private static APDUBIBO openCard(ReaderPreferences prefs) {
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
        return selector.withCard().connect();
    }

    private static AggregateCompleter buildCompleter() {
        return new AggregateCompleter(
                new ArgumentCompleter(
                        new StringsCompleter(
                                "select",
                                "info",
                                "authentikey",
                                "apdu",
                                "sc",
                                "reset",
                                "help",
                                "exit",
                                "quit"),
                        NullCompleter.INSTANCE),
                new ArgumentCompleter(
                        new StringsCompleter("sc"),
                        new StringsCompleter("handshake", "send", "close"),
                        NullCompleter.INSTANCE));
    }

    private static Path ensureHistoryFile() {
        Path home = Path.of(System.getProperty("user.home", "."));
        Path dir = home.resolve(".meowl");
        Path file = dir.resolve("history");
        try {
            if (!Files.exists(dir)) {
                Files.createDirectories(dir);
            }
            if (!Files.exists(file)) {
                Files.createFile(file);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot prepare shell history at " + file, e);
        }
        return file;
    }

    /** Documented for tests — list of completer keywords kept in one place. */
    public static List<String> verbs() {
        return List.of(
                "select", "info", "authentikey", "apdu", "sc", "reset", "help", "exit", "quit");
    }
}
