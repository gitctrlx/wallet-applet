/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Tests for {@link JsonOutput}. */
class JsonOutputTest {

    @Nested
    @DisplayName("write()")
    class Write {

        @Test
        @DisplayName("serialises a flat map with stable key order")
        void flatMap() {
            Map<String, Object> obj = new LinkedHashMap<>();
            obj.put("name", "meowl");
            obj.put("answer", 42);
            obj.put("ok", true);

            String out = capture(o -> JsonOutput.write(o, obj));
            // jackson-jr pretty-printing uses 2-space indent.
            assertTrue(out.contains("\"name\""), out);
            assertTrue(out.contains("\"meowl\""), out);
            assertTrue(out.contains("\"answer\""), out);
            assertTrue(out.contains("42"), out);
            // Keys must appear in insertion order.
            int nameIdx = out.indexOf("\"name\"");
            int answerIdx = out.indexOf("\"answer\"");
            int okIdx = out.indexOf("\"ok\"");
            assertTrue(nameIdx < answerIdx && answerIdx < okIdx, out);
        }

        @Test
        @DisplayName("serialises nested structures")
        void nested() {
            Map<String, Object> outer = new LinkedHashMap<>();
            outer.put(
                    "items",
                    List.of(
                            Map.of("aid", "F0...", "kind", "Application"),
                            Map.of("aid", "A0...", "kind", "Package")));

            String out = capture(o -> JsonOutput.write(o, outer));
            assertTrue(out.contains("\"items\""));
            assertTrue(out.contains("\"aid\""));
            assertTrue(out.contains("\"kind\""));
            assertTrue(out.contains("Application"));
            assertTrue(out.contains("Package"));
        }

        @Test
        @DisplayName("output ends with a newline")
        void trailingNewline() {
            String out = capture(o -> JsonOutput.write(o, Map.of("k", "v")));
            assertTrue(out.endsWith(System.lineSeparator()) || out.endsWith("\n"));
        }
    }

    @Nested
    @DisplayName("writeMap()")
    class WriteMap {

        @Test
        @DisplayName("builds a JSON object from alternating key/value pairs")
        void happyPath() {
            String out = capture(o -> JsonOutput.writeMap(o, "k1", "v1", "k2", 42));
            assertTrue(out.contains("\"k1\""), out);
            assertTrue(out.contains("\"v1\""), out);
            assertTrue(out.contains("\"k2\""), out);
            assertTrue(out.contains("42"), out);
        }

        @Test
        @DisplayName("rejects an odd number of arguments")
        void oddArgsRejected() {
            ByteArrayOutputStream sink = new ByteArrayOutputStream();
            PrintStream out = new PrintStream(sink);
            assertThrows(
                    IllegalArgumentException.class,
                    () -> JsonOutput.writeMap(out, "k1", "v1", "k2"));
        }

        @Test
        @DisplayName("preserves insertion order of pairs")
        void orderPreserved() {
            String out = capture(o -> JsonOutput.writeMap(o, "z", 1, "a", 2));
            int zIdx = out.indexOf("\"z\"");
            int aIdx = out.indexOf("\"a\"");
            assertTrue(zIdx < aIdx, "z must appear before a in: " + out);
        }
    }

    private static String capture(java.util.function.Consumer<PrintStream> action) {
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        try (PrintStream ps = new PrintStream(sink, true, StandardCharsets.UTF_8)) {
            action.accept(ps);
        }
        return sink.toString(StandardCharsets.UTF_8);
    }

    @Test
    @DisplayName("captures the well-known 'meowl info' JSON shape end-to-end")
    void wellKnownInfoShape() {
        // A representative payload that matches what InfoCommand would produce, verified to
        // serialise without surprises (no escaping issues, no NaN, etc.).
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("protocol_version", "1.0");
        info.put("applet_version", "0.1");
        info.put("lifecycle", Map.of("code", 0, "name", "UNINITIALIZED"));
        info.put("authentikey", "0x02ab3f12...");

        String out = capture(o -> JsonOutput.write(o, info));
        assertEquals(true, out.contains("\"protocol_version\""));
        assertEquals(true, out.contains("\"UNINITIALIZED\""));
        assertEquals(true, out.contains("\"0x02ab3f12...\""));
    }
}
