/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;
import pro.javacard.gp.GPCardKeys;
import pro.javacard.gp.keys.PlaintextKeys;

/**
 * Verifies the resolution rules of {@link GpKeysOption}: defaults, master-key mode, ENC/MAC/KEK
 * triple mode, and the mutually-exclusive validation paths.
 */
class GpKeysOptionTest {

    private static final String SAMPLE_MASTER = "404142434445464748494A4B4C4D4E4F";
    private static final String SAMPLE_ENC = "5A9E63D03BADBC2A240FE8F534709EDF";
    private static final String SAMPLE_MAC = "7CCC1E79D64FC5FA263B8F2955282998";
    private static final String SAMPLE_KEK = "B040703EC3DE23EE8AE4CFB6D632AA80";

    @Test
    @DisplayName("no options → returns the GP development default key set")
    void defaultWhenNoOptions() {
        GpKeysOption opt = parse();
        GPCardKeys keys = opt.toCardKeys();
        assertNotNull(keys);
        // Sanity: PlaintextKeys.defaultKey() exposes the well-known 4040..4F bytes through
        // its master-key accessor. Compare to assert we are on the default branch and nothing
        // sneaks past.
        PlaintextKeys plaintext = (PlaintextKeys) keys;
        assertTrue(plaintext.getMasterKey().isPresent(), "default key set must expose master key");
        assertArrayEquals(
                hex(SAMPLE_MASTER),
                plaintext.getMasterKey().get(),
                "default key must equal the GP development static set");
    }

    @Test
    @DisplayName("--key-master decodes to a master-key PlaintextKeys")
    void masterKeyMode() {
        GpKeysOption opt = parse("--key-master", SAMPLE_MASTER);
        PlaintextKeys keys = (PlaintextKeys) opt.toCardKeys();
        assertTrue(keys.getMasterKey().isPresent());
        assertArrayEquals(hex(SAMPLE_MASTER), keys.getMasterKey().get());
    }

    @Test
    @DisplayName("--key-enc/--key-mac/--key-kek decode into a static-keys PlaintextKeys")
    void tripleMode() {
        GpKeysOption opt =
                parse(
                        "--key-enc", SAMPLE_ENC,
                        "--key-mac", SAMPLE_MAC,
                        "--key-kek", SAMPLE_KEK);
        // We do not have direct access to the three components from PlaintextKeys' public surface
        // (they live in a private map), but a successful resolution that does NOT throw is the
        // contract we care about — and the result is not the default-key instance.
        PlaintextKeys keys = (PlaintextKeys) opt.toCardKeys();
        assertNotNull(keys);
        // PlaintextKeys.fromKeys does not expose the master-key shortcut, so getMasterKey() is
        // empty — this lets us tell the two factory methods apart.
        assertTrue(
                keys.getMasterKey().isEmpty(),
                "fromKeys() construction must NOT expose a master key");
    }

    @Test
    @DisplayName("--key-master is mutually exclusive with --key-enc")
    void masterAndTripleAreMutuallyExclusive() {
        GpKeysOption opt =
                parse(
                        "--key-master", SAMPLE_MASTER,
                        "--key-enc", SAMPLE_ENC,
                        "--key-mac", SAMPLE_MAC,
                        "--key-kek", SAMPLE_KEK);
        // The diagnostic surfaces as a picocli ParameterException once a CommandLine context is
        // attached (which @Mixin parsing always provides) and as a plain IllegalArgumentException
        // when the option is constructed standalone — both are RuntimeException subclasses, so
        // we test on the common base and assert the message text instead of the concrete class.
        RuntimeException ex = assertThrows(RuntimeException.class, opt::toCardKeys);
        assertTrue(
                ex.getMessage().toLowerCase().contains("mutually exclusive"),
                "diagnostic should call out the exclusivity, got: " + ex.getMessage());
    }

    @Test
    @DisplayName("partial triple (e.g. only --key-enc + --key-mac) is rejected")
    void partialTripleIsRejected() {
        GpKeysOption opt =
                parse(
                        "--key-enc", SAMPLE_ENC,
                        "--key-mac", SAMPLE_MAC);
        RuntimeException ex = assertThrows(RuntimeException.class, opt::toCardKeys);
        assertTrue(
                ex.getMessage().contains("must all be supplied"),
                "diagnostic should explain the all-three rule, got: " + ex.getMessage());
    }

    @Test
    @DisplayName("non-hex key value is rejected with a clear message")
    void invalidHexIsRejected() {
        GpKeysOption opt = parse("--key-master", "ZZNOPE");
        RuntimeException ex = assertThrows(RuntimeException.class, opt::toCardKeys);
        assertTrue(ex.getMessage().contains("--key-master"));
        assertTrue(ex.getMessage().toLowerCase().contains("hex"));
    }

    @Test
    @DisplayName("wrong-length key (8 bytes instead of 16) is rejected")
    void wrongLengthIsRejected() {
        GpKeysOption opt = parse("--key-master", "0102030405060708");
        RuntimeException ex = assertThrows(RuntimeException.class, opt::toCardKeys);
        assertTrue(ex.getMessage().contains("16 bytes"));
        assertTrue(ex.getMessage().contains("8 bytes"));
    }

    /**
     * Parses the given args into a fresh {@link GpKeysOption} via picocli, exactly as it would be
     * populated when the CLI runs. We host the option on a throwaway top-level command because
     * picocli requires an actual {@code @Command} to drive {@code @Mixin} resolution.
     */
    private static GpKeysOption parse(String... args) {
        Holder holder = new Holder();
        new CommandLine(holder).parseArgs(args);
        return holder.keys;
    }

    @CommandLine.Command(name = "test")
    private static final class Holder {
        @CommandLine.Mixin GpKeysOption keys = new GpKeysOption();
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
