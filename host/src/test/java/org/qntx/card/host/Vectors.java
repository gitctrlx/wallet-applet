// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import com.fasterxml.jackson.jr.ob.JSON;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** Loads the committed spec/vectors files the host tests consume. */
final class Vectors {
    private static final Path DIR = Path.of(System.getProperty("qntx.vectors", "spec/vectors"));

    private Vectors() {}

    static Map<String, Object> load(String name) {
        try {
            return JSON.std.mapFrom(Files.readAllBytes(DIR.resolve(name)));
        } catch (IOException e) {
            throw new IllegalStateException("cannot read vector file " + name, e);
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Map<String, Object> doc, String key) {
        return (Map<String, Object>) doc.get(key);
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> list(Map<String, Object> doc, String key) {
        return (List<Map<String, Object>>) doc.get(key);
    }

    static byte[] hex(Map<String, Object> obj, String key) {
        return HexFormat.of().parseHex((String) obj.get(key));
    }

    static byte[] unhex(String s) {
        return HexFormat.of().parseHex(s);
    }
}
