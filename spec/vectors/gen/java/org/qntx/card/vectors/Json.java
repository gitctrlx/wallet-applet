// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.util.List;
import java.util.Map;

/**
 * The canonical vector encoding of spec/vectors/README.md: byte-identical to {@code
 * JSON.stringify(value, null, 2) + "\n"} for objects (insertion order), lists, strings, integers
 * and booleans, so the Java and TypeScript generators can be compared byte for byte.
 */
final class Json {
    private Json() {}

    static String encode(Object value) {
        StringBuilder out = new StringBuilder();
        write(out, value, "");
        return out.append('\n').toString();
    }

    private static void write(StringBuilder out, Object value, String indent) {
        switch (value) {
            case Map<?, ?> map -> {
                if (map.isEmpty()) {
                    out.append("{}");
                    return;
                }
                String inner = indent + "  ";
                out.append("{\n");
                int i = 0;
                for (Map.Entry<?, ?> e : map.entrySet()) {
                    out.append(inner);
                    string(out, (String) e.getKey());
                    out.append(": ");
                    write(out, e.getValue(), inner);
                    out.append(++i < map.size() ? ",\n" : "\n");
                }
                out.append(indent).append('}');
            }
            case List<?> list -> {
                if (list.isEmpty()) {
                    out.append("[]");
                    return;
                }
                String inner = indent + "  ";
                out.append("[\n");
                for (int i = 0; i < list.size(); i++) {
                    out.append(inner);
                    write(out, list.get(i), inner);
                    out.append(i + 1 < list.size() ? ",\n" : "\n");
                }
                out.append(indent).append(']');
            }
            case String s -> string(out, s);
            case Integer n -> out.append(n);
            case Long n -> {
                if (Math.abs(n) > (1L << 53) - 1) {
                    throw new IllegalArgumentException("integer outside the safe range: " + n);
                }
                out.append(n);
            }
            case Boolean b -> out.append(b);
            default -> throw new IllegalArgumentException("not a vector value: " + value);
        }
    }

    private static void string(StringBuilder out, String s) {
        out.append('"');
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20 || c > 0x7E) {
                        throw new IllegalArgumentException("vector strings are printable ASCII");
                    }
                    out.append(c);
                }
            }
        }
        out.append('"');
    }
}
