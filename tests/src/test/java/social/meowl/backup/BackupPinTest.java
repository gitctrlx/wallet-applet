/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.backup;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link BackupPin} as a plain class under jcardsim's mock JC API.
 *
 * <p>Pins the no-PUK, wipe-on-exhaustion contract: a wrong PIN consumes a try, an out-of-policy
 * length never does, and the counter blocks once exhausted (the applet turns that block into a seed
 * wipe — that orchestration is covered by the real-card {@code BackupAppletIT}).
 */
class BackupPinTest {

    private static final byte[] PIN = "123456".getBytes();
    private static final byte[] NEW_PIN = "654321".getBytes();
    private static final byte[] WRONG_PIN = "999999".getBytes();

    @Test
    @DisplayName("setup provisions the PIN; the session is not verified until a correct check")
    void setupProvisions() {
        BackupPin pin = provisioned();
        assertTrue(pin.isProvisioned());
        assertFalse(pin.isVerified());
        assertEquals(Constants.BACKUP_PIN_RETRY_LIMIT, pin.triesRemaining());
    }

    @Test
    @DisplayName("a correct PIN verifies, marks the session and leaves the counter full")
    void correctPinVerifies() {
        BackupPin pin = provisioned();
        assertTrue(pin.check(PIN, (short) 0, (short) PIN.length));
        assertTrue(pin.isVerified());
        assertEquals(Constants.BACKUP_PIN_RETRY_LIMIT, pin.triesRemaining());
    }

    @Test
    @DisplayName("a wrong PIN fails and consumes one try")
    void wrongPinConsumesTry() {
        BackupPin pin = provisioned();
        assertFalse(pin.check(WRONG_PIN, (short) 0, (short) WRONG_PIN.length));
        assertFalse(pin.isVerified());
        assertEquals((byte) (Constants.BACKUP_PIN_RETRY_LIMIT - 1), pin.triesRemaining());
    }

    @Test
    @DisplayName("an out-of-policy length returns 6700 without consuming a try")
    void lengthPolicyDoesNotConsumeTry() {
        BackupPin pin = provisioned();

        byte[] tooShort = "123".getBytes(); // below PIN_MIN_LEN
        ISOException shortEx =
                assertThrows(
                        ISOException.class,
                        () -> pin.check(tooShort, (short) 0, (short) tooShort.length));
        assertEquals(Constants.SW_WRONG_LENGTH, shortEx.getReason());

        byte[] tooLong = "123456789".getBytes(); // above BACKUP_PIN_MAX_LEN
        ISOException longEx =
                assertThrows(
                        ISOException.class,
                        () -> pin.check(tooLong, (short) 0, (short) tooLong.length));
        assertEquals(Constants.SW_WRONG_LENGTH, longEx.getReason());

        assertEquals(Constants.BACKUP_PIN_RETRY_LIMIT, pin.triesRemaining());
    }

    @Test
    @DisplayName("exhausting the counter blocks further checks with 6983 (no PUK)")
    void exhaustionBlocks() {
        BackupPin pin = provisioned();
        for (int i = 0; i < Constants.BACKUP_PIN_RETRY_LIMIT; i++) {
            assertFalse(pin.check(WRONG_PIN, (short) 0, (short) WRONG_PIN.length));
        }
        assertEquals((byte) 0, pin.triesRemaining());

        ISOException ex =
                assertThrows(
                        ISOException.class, () -> pin.check(PIN, (short) 0, (short) PIN.length));
        assertEquals(Constants.SW_AUTH_BLOCKED, ex.getReason());
    }

    @Test
    @DisplayName("a second setup is rejected with 6985")
    void setupTwiceRejected() {
        BackupPin pin = provisioned();
        ISOException ex =
                assertThrows(
                        ISOException.class,
                        () -> pin.setupInTx(PIN, (short) 0, (short) PIN.length));
        assertEquals(Constants.SW_CONDITIONS_NOT_SATISFIED, ex.getReason());
    }

    @Test
    @DisplayName("change rotates the PIN; the new one verifies and the old one no longer does")
    void changeRotatesPin() {
        BackupPin pin = provisioned();
        assertTrue(pin.check(PIN, (short) 0, (short) PIN.length));

        JCSystem.beginTransaction();
        pin.changeInTx(NEW_PIN, (short) 0, (short) NEW_PIN.length);
        JCSystem.commitTransaction();

        pin.clearSession();
        assertTrue(pin.check(NEW_PIN, (short) 0, (short) NEW_PIN.length));
        pin.clearSession();
        assertFalse(pin.check(PIN, (short) 0, (short) PIN.length));
    }

    @Test
    @DisplayName("clearSession drops the in-session verified flag")
    void clearSessionDropsVerified() {
        BackupPin pin = provisioned();
        assertTrue(pin.check(PIN, (short) 0, (short) PIN.length));
        assertTrue(pin.isVerified());
        pin.clearSession();
        assertFalse(pin.isVerified());
    }

    private static BackupPin provisioned() {
        BackupPin pin = new BackupPin();
        JCSystem.beginTransaction();
        pin.setupInTx(PIN, (short) 0, (short) PIN.length);
        JCSystem.commitTransaction();
        return pin;
    }
}
