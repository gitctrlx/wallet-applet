/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;
import social.meowl.tools.core.ProtocolException;
import social.meowl.tools.proto.SecureChannelException;

/** Tests the CLI's exception-to-exit-code policy. */
class MeowlExecutionExceptionHandlerTest {

    private final ByteArrayOutputStream err = new ByteArrayOutputStream();

    private int handle(Exception ex) {
        CommandLine cl = MeowlCli.commandLine();
        cl.setErr(new PrintWriter(new OutputStreamWriter(err, StandardCharsets.UTF_8), true));
        return MeowlExecutionExceptionHandler.INSTANCE.handleExecutionException(ex, cl, null);
    }

    private String stderr() {
        return err.toString(StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("a status-word failure maps to EXIT_PROTOCOL (4)")
    void protocolException() {
        assertEquals(
                MeowlExecutionExceptionHandler.EXIT_PROTOCOL,
                handle(new ProtocolException(0x6A82, "GET_INFO")));
        assertTrue(stderr().startsWith("error:"), stderr());
    }

    @Test
    @DisplayName("a Secure Channel failure maps to EXIT_SECURE_CHANNEL (5)")
    void secureChannelException() {
        assertEquals(
                MeowlExecutionExceptionHandler.EXIT_SECURE_CHANNEL,
                handle(new SecureChannelException(0, "outbound envelope MAC mismatch")));
        assertTrue(stderr().startsWith("secure-channel:"), stderr());
    }

    @Test
    @DisplayName("a malformed-argument failure maps to the USAGE exit code")
    void illegalArgument() {
        assertEquals(CommandLine.ExitCode.USAGE, handle(new IllegalArgumentException("bad hex")));
    }

    @Test
    @DisplayName("an unmapped exception maps to the generic SOFTWARE exit code")
    void unmappedException() {
        assertEquals(CommandLine.ExitCode.SOFTWARE, handle(new IllegalStateException("boom")));
    }
}
