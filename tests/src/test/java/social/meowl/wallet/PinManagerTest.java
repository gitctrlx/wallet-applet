/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.wallet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link PinManager#unblockPin} as a plain Java class under jcardsim's mock JC API.
 *
 * <p>The key regression these tests pin is the ordering fix: {@code unblockPin} validates the
 * new-PIN length policy <em>before</em> it verifies the PUK, so a malformed new PIN (a host-side
 * protocol error) cannot burn one of the scarce PUK attempts. A wrong PUK still consumes one. This
 * mirrors {@link PinManager#changePin} and supersedes the earlier "consume a PUK regardless of the
 * new-PIN policy" behaviour.
 */
class PinManagerTest {

    private static final byte[] PIN = "123456".getBytes();
    private static final byte[] PUK = "ABCDEFGH".getBytes();
    private static final byte[] NEW_PIN = "654321".getBytes();
    private static final byte[] WRONG_PIN = "999999".getBytes();

    @Test
    @DisplayName("unblockPin: malformed new PIN returns 6700 and does NOT consume a PUK retry")
    void malformedNewPinDoesNotConsumePuk() throws Exception {
        PinManager pm = provisionedAndBlocked();
        assertEquals(Constants.PUK_RETRY_LIMIT, pukTriesRemaining(pm));

        byte[] tooShort = "12".getBytes(); // below PIN_MIN_LEN
        ISOException ex =
                assertThrows(
                        ISOException.class,
                        () ->
                                pm.unblockPin(
                                        PUK,
                                        (short) 0,
                                        (short) PUK.length,
                                        tooShort,
                                        (short) 0,
                                        (short) tooShort.length));

        assertEquals(Constants.SW_WRONG_LENGTH, ex.getReason());
        assertEquals(
                Constants.PUK_RETRY_LIMIT,
                pukTriesRemaining(pm),
                "a malformed new PIN must not burn a PUK attempt");
    }

    @Test
    @DisplayName("unblockPin: wrong PUK (valid new PIN) consumes a PUK retry")
    void wrongPukConsumesRetry() throws Exception {
        PinManager pm = provisionedAndBlocked();
        byte[] wrongPuk = "ZZZZZZZZ".getBytes(); // valid length, wrong value

        ISOException ex =
                assertThrows(
                        ISOException.class,
                        () ->
                                pm.unblockPin(
                                        wrongPuk,
                                        (short) 0,
                                        (short) wrongPuk.length,
                                        NEW_PIN,
                                        (short) 0,
                                        (short) NEW_PIN.length));

        assertEquals(Constants.SW_PIN_RETRIES_BASE & 0xFFF0, ex.getReason() & 0xFFF0);
        assertEquals((short) (Constants.PUK_RETRY_LIMIT - 1), pukTriesRemaining(pm));
    }

    @Test
    @DisplayName("unblockPin: correct PUK + valid new PIN unblocks and installs the new PIN")
    void correctPukUnblocks() throws Exception {
        PinManager pm = provisionedAndBlocked();

        pm.unblockPin(
                PUK, (short) 0, (short) PUK.length, NEW_PIN, (short) 0, (short) NEW_PIN.length);

        // The new PIN now verifies (no throw) and the session flag is set.
        pm.verifyPin(NEW_PIN, (short) 0, (short) NEW_PIN.length);
        assertTrue(pm.isPinVerified());
    }

    /** Provisions a manager then exhausts the PIN counter so {@code unblockPin} is reachable. */
    private static PinManager provisionedAndBlocked() {
        PinManager pm = new PinManager();
        JCSystem.beginTransaction();
        pm.setupInTx(PIN, (short) 0, (short) PIN.length, PUK, (short) 0, (short) PUK.length);
        JCSystem.commitTransaction();
        for (int i = 0; i < Constants.PIN_RETRY_LIMIT; i++) {
            try {
                pm.verifyPin(WRONG_PIN, (short) 0, (short) WRONG_PIN.length);
            } catch (ISOException expected) {
                // wrong PIN consumes a retry; the throw is the documented contract
            }
        }
        return pm;
    }

    private static short pukTriesRemaining(PinManager pm) throws Exception {
        Field field = PinManager.class.getDeclaredField("puk");
        field.setAccessible(true);
        return ((OwnerPIN) field.get(pm)).getTriesRemaining();
    }
}
