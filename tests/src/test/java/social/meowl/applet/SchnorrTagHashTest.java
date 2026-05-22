/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Audit F-12 sanity check: every {@code SHA256(tag)} constant baked into {@link Schnorr} must match
 * the runtime {@code SHA-256} of the literal tag bytes specified by BIP-340 §3.2. A typo in any of
 * the three constants would silently produce signatures that fail BIP-340 verification on every
 * wallet on the planet, so we pin the expectation here so the build trips on the first compile.
 *
 * <p>The constants themselves are package-private to keep the public API of {@link Schnorr}
 * minimal; this test lives in the same Java package so it can read them directly.
 */
class SchnorrTagHashTest {

    @Test
    @DisplayName("HASH_OF_TAG_AUX matches SHA-256(\"BIP0340/aux\")")
    void auxConstantMatches() throws NoSuchAlgorithmException {
        assertArrayEquals(sha256("BIP0340/aux"), Schnorr.HASH_OF_TAG_AUX);
    }

    @Test
    @DisplayName("HASH_OF_TAG_NONCE matches SHA-256(\"BIP0340/nonce\")")
    void nonceConstantMatches() throws NoSuchAlgorithmException {
        assertArrayEquals(sha256("BIP0340/nonce"), Schnorr.HASH_OF_TAG_NONCE);
    }

    @Test
    @DisplayName("HASH_OF_TAG_CHALLENGE matches SHA-256(\"BIP0340/challenge\")")
    void challengeConstantMatches() throws NoSuchAlgorithmException {
        assertArrayEquals(sha256("BIP0340/challenge"), Schnorr.HASH_OF_TAG_CHALLENGE);
    }

    private static byte[] sha256(String tag) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(tag.getBytes(StandardCharsets.US_ASCII));
    }
}
