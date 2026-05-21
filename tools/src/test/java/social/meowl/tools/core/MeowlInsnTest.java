/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Tests for the host-side mirror of the applet INS table. */
class MeowlInsnTest {

    @Test
    @DisplayName("every INS has a unique CLI name and a unique wire byte")
    void uniqueness() {
        Set<String> cliNames = new HashSet<>();
        Set<Byte> values = new HashSet<>();
        for (MeowlInsn insn : MeowlInsn.values()) {
            assertTrue(cliNames.add(insn.cliName()), "duplicate cliName: " + insn.cliName());
            assertTrue(values.add(insn.value()), "duplicate value: " + insn.hex());
        }
    }

    @Test
    @DisplayName("CLI names are kebab-case and non-empty")
    void cliNamesAreKebabCase() {
        for (MeowlInsn insn : MeowlInsn.values()) {
            String name = insn.cliName();
            assertNotNull(name);
            assertFalse(name.isBlank(), insn::name);
            assertEquals(name.toLowerCase(), name, insn::name);
            assertFalse(name.contains("_"), insn::name);
        }
    }

    @Test
    @DisplayName("descriptions are non-empty single-line strings")
    void descriptionsArePopulated() {
        for (MeowlInsn insn : MeowlInsn.values()) {
            String desc = insn.description();
            assertNotNull(desc);
            assertFalse(desc.isBlank(), insn::name);
            assertFalse(desc.contains("\n"), insn::name);
        }
    }

    @ParameterizedTest
    @EnumSource(MeowlInsn.class)
    @DisplayName("ofCliName / ofValue round-trip every entry")
    void roundTrip(MeowlInsn insn) {
        assertEquals(insn, MeowlInsn.ofCliName(insn.cliName()).orElseThrow());
        assertEquals(insn, MeowlInsn.ofValue(insn.value()).orElseThrow());
    }

    @Test
    @DisplayName("ofCliName / ofValue return Optional.empty for unknown inputs")
    void unknownLookupReturnsEmpty() {
        assertTrue(MeowlInsn.ofCliName("not-a-real-instruction").isEmpty());
        assertTrue(MeowlInsn.ofValue((byte) 0x7F).isEmpty());
    }

    @Test
    @DisplayName("the OUTER INS surface matches the applet's spec banding (0x00–0x1F)")
    void outerInsBanding() {
        for (MeowlInsn insn : MeowlInsn.values()) {
            int v = insn.value() & 0xFF;
            boolean inOuterBand = v <= 0x1F;
            assertEquals(
                    inOuterBand,
                    insn.channel() == MeowlInsn.Channel.OUTER,
                    () ->
                            "INS %s (0x%02X) is in outer band: %b but channel is %s"
                                    .formatted(insn.name(), v, inOuterBand, insn.channel()));
        }
    }

    @Test
    @DisplayName("requiresSecureChannel agrees with channel()")
    void requiresSecureChannelConsistent() {
        for (MeowlInsn insn : MeowlInsn.values()) {
            assertEquals(insn.channel() == MeowlInsn.Channel.INNER, insn.requiresSecureChannel());
        }
    }

    @Test
    @DisplayName("hex() returns 2-character uppercase hex of the wire byte")
    void hex() {
        assertEquals("01", MeowlInsn.GET_INFO.hex());
        assertEquals("52", MeowlInsn.SIGN_ED25519.hex());
    }

    @Test
    @DisplayName("a representative subset of CLI names matches the documented spec")
    void cliNamesMatchSpec() {
        // Spot-check a few ensure renaming an INS does not silently break shell completion.
        assertEquals("get-info", MeowlInsn.GET_INFO.cliName());
        assertEquals("init-sc", MeowlInsn.INIT_SECURE_CHANNEL.cliName());
        assertEquals("sign-schnorr-k1", MeowlInsn.SIGN_SCHNORR_K1.cliName());
        assertEquals("import-pki-cert", MeowlInsn.IMPORT_PKI_CERT.cliName());
    }

    @Test
    @DisplayName("the enum size is in sync with the applet's documented INS surface")
    void enumSizeMatchesSpec() {
        // 21 INS bytes are documented in `social.meowl.applet.Constants` at the time of writing.
        // Any change to that surface MUST be reflected here; the corresponding test in the applet
        // module (MeowlInsTableTest, Phase 2) will keep us honest reflectively.
        assertEquals(21, MeowlInsn.values().length);
    }

    @Test
    @DisplayName("cliName never reuses the enum's screaming-snake-case name verbatim")
    void cliNameDifferentFromName() {
        // Guard against a forgotten override that would leave the CLI surface populated with
        // ALL_CAPS names like `IMPORT_PKI_CERT` instead of the documented `import-pki-cert`.
        for (MeowlInsn insn : MeowlInsn.values()) {
            assertFalse(
                    insn.cliName().equals(insn.name()),
                    () -> "cliName collides with enum name: " + insn.name());
        }
    }
}
