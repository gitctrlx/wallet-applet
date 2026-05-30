/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Decomposes a JavaCard CAP file (a vanilla ZIP container) into the three byte categories the
 * developer cares about when sizing the on-card footprint:
 *
 * <ol>
 *   <li>{@code *.cap} components under {@code .../javacard/} — the Load File payload that the GP
 *       {@code LOAD} INS uploads to the card after subtracting the optional {@code Descriptor.cap}
 *       debug component.
 *   <li>{@code *.class} JVM bytecode — emitted by {@code javac} and kept inside the CAP for IDE /
 *       cap-converter round-trips. The card VM cannot execute these; they never reach the chip.
 *   <li>Anything else — {@code MANIFEST.MF}, {@code .exp} export files, {@code APPLET-INF/} loader
 *       hints. Workshop metadata; also doesn't ship to the card.
 * </ol>
 *
 * <p>Entries with unknown sizes (the ZIP central directory uses {@code -1} for entries written with
 * no advance size declaration) are skipped silently.
 */
public record CapBreakdown(
        long zipBytes,
        long componentsBytes,
        long classBytes,
        long otherBytes,
        List<Component> components) {

    /** A single {@code *.cap} Load File component with its uncompressed size. */
    public record Component(String name, long bytes) {}

    private static final String COMPONENT_DIR_MARKER = "/javacard/";
    private static final String COMPONENT_SUFFIX = ".cap";
    private static final String CLASS_SUFFIX = ".class";

    /**
     * Reads {@code capPath} as a ZIP and computes the byte breakdown. Throws {@link
     * UncheckedIOException} if the file cannot be opened — callers may surface a friendlier message
     * but should not silently swallow it.
     */
    public static CapBreakdown read(Path capPath) {
        long zipBytes;
        try {
            zipBytes = Files.size(capPath);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot stat CAP file " + capPath, e);
        }

        long components = 0;
        long classes = 0;
        long other = 0;
        List<Component> componentList = new ArrayList<>();

        try (ZipFile zf = new ZipFile(capPath.toFile())) {
            Enumeration<? extends ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory()) continue;
                long size = entry.getSize();
                if (size < 0) continue;
                String name = entry.getName().replace('\\', '/');
                if (isLoadFileComponent(name)) {
                    components += size;
                    componentList.add(new Component(stripComponentName(name), size));
                } else if (name.endsWith(CLASS_SUFFIX)) {
                    classes += size;
                } else {
                    other += size;
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read CAP file as ZIP " + capPath, e);
        }

        componentList.sort(Comparator.comparingLong(Component::bytes).reversed());
        return new CapBreakdown(zipBytes, components, classes, other, List.copyOf(componentList));
    }

    private static boolean isLoadFileComponent(String name) {
        return name.endsWith(COMPONENT_SUFFIX) && name.contains(COMPONENT_DIR_MARKER);
    }

    private static String stripComponentName(String fullPath) {
        int slash = fullPath.lastIndexOf('/');
        String fileName = slash >= 0 ? fullPath.substring(slash + 1) : fullPath;
        return fileName.endsWith(COMPONENT_SUFFIX)
                ? fileName.substring(0, fileName.length() - COMPONENT_SUFFIX.length())
                : fileName;
    }
}
