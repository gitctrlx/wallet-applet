/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for {@link CapBreakdown}. Each test builds a synthetic CAP-shaped ZIP on disk and
 * verifies the byte-category accounting + descending sort of the on-card components.
 */
class CapBreakdownTest {

    @Test
    @DisplayName("classifies real CAP-shaped paths into components / classes / other")
    void classification(@TempDir Path tmp) throws IOException {
        Path cap = tmp.resolve("test.cap");
        Map<String, Integer> entries = new LinkedHashMap<>();
        // On-card components.
        entries.put("social/meowl/wallet/javacard/Method.cap", 12000);
        entries.put("social/meowl/wallet/javacard/ConstantPool.cap", 1400);
        entries.put("social/meowl/wallet/javacard/Header.cap", 19);
        // JVM bytecode (not on-card).
        entries.put("APPLET-INF/classes/social/meowl/wallet/WalletApplet.class", 12000);
        entries.put("APPLET-INF/classes/social/meowl/wallet/Bip32.class", 3700);
        // Workshop metadata.
        entries.put("META-INF/MANIFEST.MF", 1100);
        entries.put("social/meowl/wallet/javacard/meowl.exp", 800);
        writeZip(cap, entries);

        CapBreakdown b = CapBreakdown.read(cap);

        assertEquals(13_419L, b.componentsBytes());
        assertEquals(15_700L, b.classBytes());
        assertEquals(1_900L, b.otherBytes());
        assertTrue(b.zipBytes() > 0);

        // Components are sorted by size descending.
        assertEquals(3, b.components().size());
        assertEquals("Method", b.components().get(0).name());
        assertEquals(12_000L, b.components().get(0).bytes());
        assertEquals("ConstantPool", b.components().get(1).name());
        assertEquals(1_400L, b.components().get(1).bytes());
        assertEquals("Header", b.components().get(2).name());
        assertEquals(19L, b.components().get(2).bytes());
    }

    @Test
    @DisplayName("ignores .cap entries that are not under a javacard/ subdirectory")
    void capOutsideJavacardDir(@TempDir Path tmp) throws IOException {
        Path cap = tmp.resolve("test.cap");
        Map<String, Integer> entries = new LinkedHashMap<>();
        entries.put("docs/manual.cap", 500); // looks like a component but isn't one
        entries.put("APPLET-INF/classes/X.class", 100);
        writeZip(cap, entries);

        CapBreakdown b = CapBreakdown.read(cap);

        assertEquals(0L, b.componentsBytes());
        assertEquals(100L, b.classBytes());
        assertEquals(500L, b.otherBytes());
        assertTrue(b.components().isEmpty());
    }

    @Test
    @DisplayName("returns zero counters and empty components for an empty ZIP")
    void emptyZip(@TempDir Path tmp) throws IOException {
        Path cap = tmp.resolve("empty.cap");
        writeZip(cap, new LinkedHashMap<>());

        CapBreakdown b = CapBreakdown.read(cap);

        assertEquals(0L, b.componentsBytes());
        assertEquals(0L, b.classBytes());
        assertEquals(0L, b.otherBytes());
        assertTrue(b.components().isEmpty());
        assertTrue(b.zipBytes() > 0);
    }

    @Test
    @DisplayName("returned components list is unmodifiable")
    void componentsListIsUnmodifiable(@TempDir Path tmp) throws IOException {
        Path cap = tmp.resolve("test.cap");
        writeZip(cap, Map.of("social/meowl/wallet/javacard/Method.cap", 100));

        CapBreakdown b = CapBreakdown.read(cap);
        List<CapBreakdown.Component> components = b.components();

        try {
            components.add(new CapBreakdown.Component("X", 1));
            throw new AssertionError("expected unmodifiable list");
        } catch (UnsupportedOperationException expected) {
            // ok
        }
    }

    private static void writeZip(Path path, Map<String, Integer> entries) throws IOException {
        try (OutputStream raw = Files.newOutputStream(path);
                ZipOutputStream zos = new ZipOutputStream(raw)) {
            for (Map.Entry<String, Integer> e : entries.entrySet()) {
                ZipEntry zipEntry = new ZipEntry(e.getKey());
                zos.putNextEntry(zipEntry);
                zos.write(new byte[e.getValue()]);
                zos.closeEntry();
            }
        }
    }
}
