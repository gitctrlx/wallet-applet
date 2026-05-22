/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import com.fasterxml.jackson.jr.ob.JSON;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UncheckedIOException;

/**
 * Tiny output formatter shared by every subcommand that supports {@code --json}. Backed by {@link
 * JSON jackson-jr} (smallest reasonable JVM JSON binding) — we deliberately avoid the 2 MB Jackson
 * Databind footprint. Output is always pretty-printed.
 */
public final class JsonOutput {

    private static final JSON CODEC = JSON.std.with(JSON.Feature.PRETTY_PRINT_OUTPUT);

    private JsonOutput() {}

    /** Serialises the given object graph and writes it (with a trailing newline) to {@code out}. */
    public static void write(PrintStream out, Object value) {
        try {
            out.println(CODEC.asString(value));
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot serialise value to JSON", e);
        }
    }

    /**
     * Convenience: build a JSON map from alternating {@code (key, value)} pairs and write it.
     * Insertion order is preserved via {@link java.util.LinkedHashMap}.
     */
    public static void writeMap(PrintStream out, Object... keyValuePairs) {
        if ((keyValuePairs.length & 1) != 0) {
            throw new IllegalArgumentException("Odd number of arguments to writeMap");
        }
        var map = new java.util.LinkedHashMap<String, Object>();
        for (int i = 0; i < keyValuePairs.length; i += 2) {
            map.put((String) keyValuePairs[i], keyValuePairs[i + 1]);
        }
        write(out, map);
    }
}
