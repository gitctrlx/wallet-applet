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
 * Tiny output formatter shared by every subcommand that supports {@code --json}.
 *
 * <p>Backed by {@link JSON jackson-jr}, which is the smallest reasonable JSON binding on the JVM
 * (~150 KB, no annotations, no reflection beyond bean introspection). We deliberately do not pull
 * in Jackson Databind — its 2 MB transitive footprint dwarfs every other dependency in the CLI and
 * its features (custom serialisers, type info, JSON Schema) are not used here.
 *
 * <p>Output is always pretty-printed (2-space indent, trailing newline) so the {@code meowl info
 * --json} response is human-readable without piping through {@code jq}.
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
     * Convenience: build a JSON map from alternating {@code (key, value)} pairs and write it to
     * {@code out}. Strongly typed callers should prefer constructing a record + {@link
     * #write(PrintStream, Object)}; this overload is for ad-hoc inline outputs.
     *
     * <p>Insertion order is preserved (the underlying serialiser walks a {@link
     * java.util.LinkedHashMap LinkedHashMap}), so callers can deliberately order keys to keep the
     * output stable across runs and easy to read.
     */
    public static void writeMap(PrintStream out, Object... keyValuePairs) {
        if ((keyValuePairs.length & 1) != 0) {
            throw new IllegalArgumentException("Odd number of arguments to writeMap");
        }
        var map = new java.util.LinkedHashMap<String, Object>();
        for (int i = 0; i < keyValuePairs.length; i += 2) {
            map.put((String) keyValuePairs[i], keyValuePairs[i + 1]);
        }
        // Map.copyOf() does NOT preserve insertion order, so we hand the LinkedHashMap directly
        // to jackson-jr; the map is constructed locally and never mutated after this point.
        write(out, map);
    }
}
