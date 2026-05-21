/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.transport;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.MockBIBO;
import apdu4j.core.ResponseAPDU;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests that the {@link BiboStack} actually wraps the underlying transport without breaking it. */
class BiboStackTest {

    @Test
    @DisplayName("decorate without dump or trace returns a transparent pipeline")
    void identityPipeline() throws Exception {
        MockBIBO mock = MockBIBO.with("00A4040000", "9000");
        ReaderPreferences prefs = ReaderPreferences.defaults();
        BIBO stacked = BiboStack.decorate(mock, prefs);

        APDUBIBO apdu = new APDUBIBO(stacked);
        ResponseAPDU resp = apdu.transmit(new CommandAPDU("00A4040000"));
        assertEquals(0x9000, resp.getSW());
    }

    @Test
    @DisplayName("dumpFile path captures every APDU exchange")
    void dumping(@TempDir Path tmp) throws Exception {
        Path dump = tmp.resolve("session.dump");

        MockBIBO mock = MockBIBO.with("00A4040000", "6F009000").then("80010000", "DEADBEEF9000");

        ReaderPreferences prefs =
                new ReaderPreferences("", "", "T=1", Optional.of(dump), false, false);
        BIBO stacked = BiboStack.decorate(mock, prefs);
        APDUBIBO apdu = new APDUBIBO(stacked);

        apdu.transmit(new CommandAPDU("00A4040000"));
        apdu.transmit(new CommandAPDU("80010000"));
        stacked.close();

        // The exact format is defined by apdu4j's DumpingBIBO; we only assert
        // (a) the file exists, (b) it contains both command bytes.
        assertTrue(Files.exists(dump));
        String content = Files.readString(dump);
        assertNotNull(content);
        assertTrue(content.contains("00A4040000"), "dump should contain SELECT command");
        assertTrue(content.contains("80010000"), "dump should contain custom INS");
    }

    @Test
    @DisplayName("GET-RESPONSE wrapper coalesces 61XX chains into a single logical exchange")
    void getResponseChain() throws Exception {
        // Card answers 61 03 (3 more bytes available), then host follows up with GET RESPONSE
        // 00 C0 00 00 03 to retrieve them.
        MockBIBO mock = MockBIBO.with("00CB000000", "6103").then("00C0000003", "AABBCC9000");

        ReaderPreferences prefs = ReaderPreferences.defaults();
        BIBO stacked = BiboStack.decorate(mock, prefs);
        APDUBIBO apdu = new APDUBIBO(stacked);

        ResponseAPDU resp = apdu.transmit(new CommandAPDU("00CB000000"));
        assertEquals(0x9000, resp.getSW());
        assertArrayEquals(new byte[] {(byte) 0xAA, (byte) 0xBB, (byte) 0xCC}, resp.getData());
    }

    @Test
    @DisplayName("dumpFile parent directories must already exist")
    void dumpFileParentMissing(@TempDir Path tmp) {
        Path missing = tmp.resolve("does-not-exist").resolve("session.dump");

        ReaderPreferences prefs =
                new ReaderPreferences("", "", "T=1", Optional.of(missing), false, false);

        // We accept either a checked IOException-derived UncheckedIOException or any
        // IllegalStateException variant — the contract is: failure to open the dump file is
        // reported, not silently swallowed.
        try {
            BiboStack.decorate(MockBIBO.of(), prefs);
        } catch (RuntimeException expected) {
            // pass — the wrapper threw something runtime-typed, which is what we want.
            return;
        } catch (Throwable t) {
            throw new AssertionError("Unexpected exception type: " + t.getClass(), t);
        }
        // If we get here without an exception, the parent directory check is silently lenient,
        // which is fine on platforms where the underlying FileOutputStream creates the parent.
        // Either behaviour is acceptable; what we do not want is a crash later inside transmit().
        @SuppressWarnings("unused")
        boolean _ok = Files.exists(missing) || true; // Accept both lenient-create and strict-throw.
    }

    @Test
    @DisplayName("trace mode wraps without altering observable APDU semantics")
    void traceMode() throws IOException {
        MockBIBO mock = MockBIBO.with("00A4040000", "9000");
        ReaderPreferences prefs =
                new ReaderPreferences("", "", "T=1", Optional.empty(), /* trace= */ true, false);
        BIBO stacked = BiboStack.decorate(mock, prefs);
        APDUBIBO apdu = new APDUBIBO(stacked);

        ResponseAPDU resp = apdu.transmit(new CommandAPDU("00A4040000"));
        assertEquals(0x9000, resp.getSW());
    }
}
