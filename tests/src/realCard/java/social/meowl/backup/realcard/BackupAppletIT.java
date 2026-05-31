/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.backup.realcard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import social.meowl.backup.Constants;
import social.meowl.wallet.realcard.support.CardLifecycle;
import social.meowl.wallet.realcard.support.HostSession;
import social.meowl.wallet.realcard.support.RealCardClient;
import social.meowl.wallet.realcard.support.TestConstants;

/**
 * End-to-end tests for the backup applet driven over PCSC. The backup CAP must already be installed
 * under instance AID {@code F06D656F776C0201} (e.g. {@code make install-backup}). Every
 * secret-touching command runs inside the meowl Secure Channel, so each test opens a {@link
 * HostSession} (the same host SC reference client the wallet suites use — the protocol is
 * identical) and dispatches inner APDUs via {@code OPEN_SECURE_CHANNEL}.
 *
 * <p>Backup needs no PKI personalisation: a fresh card goes straight from {@code SETUP_PIN} to
 * {@code BACKUP_SEED}. {@link #tearDown()} drives the {@code RESET_TO_FACTORY} countdown so each
 * test starts on a wiped card.
 */
class BackupAppletIT {

    private static final byte[] BACKUP_AID = {
        (byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x02, 0x01
    };

    private static final byte[] PIN = "123456".getBytes(StandardCharsets.UTF_8);

    /** Lifecycle bytes as the backup applet reports them (shared FSM ordinals). */
    private static final byte LC_FRESH = 0x00;

    private static final byte LC_PIN_SET = 0x01;
    private static final byte LC_SEEDED = 0x02;

    private RealCardClient card;
    private HostSession session;

    @BeforeAll
    static void registerProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() {
        card = RealCardClient.connect(BACKUP_AID);
        session = HostSession.open(card);
    }

    @AfterEach
    void tearDown() {
        if (card != null) {
            try {
                CardLifecycle.resetCard(card);
            } catch (Exception ignored) {
                // best-effort reset; the next test's @BeforeEach surfaces real problems
            }
            card.close();
        }
    }

    @Test
    @DisplayName("SETUP_PIN advances the lifecycle to PIN_SET and reports an empty seed slot")
    void setupReportsPinSet() {
        setupPin();
        byte[] status = status();
        assertEquals(LC_PIN_SET, tlvByte(status, Constants.TAG_LIFECYCLE_STATE));
        assertEquals((byte) 0, tlvByte(status, Constants.TAG_SEED_PRESENT));
        assertEquals(Constants.BACKUP_PIN_RETRY_LIMIT, tlvByte(status, Constants.TAG_PIN_TRIES));
    }

    @ParameterizedTest(name = "{0}-byte entropy")
    @ValueSource(ints = {16, 24, 32})
    @DisplayName("BACKUP_SEED then RESTORE_SEED round-trips the entropy byte-for-byte")
    void backupRestoreRoundTrip(int entropyLen) {
        setupPin();
        verifyPin();
        byte[] entropy = new byte[entropyLen];
        TestConstants.RANDOM.nextBytes(entropy);

        session.sendInnerExpectOk(
                Constants.INS_BACKUP_SEED, (byte) 0, (byte) 0, lenPrefixed(entropy));

        byte[] status = status();
        assertEquals(LC_SEEDED, tlvByte(status, Constants.TAG_LIFECYCLE_STATE));
        assertEquals((byte) 1, tlvByte(status, Constants.TAG_SEED_PRESENT));
        assertEquals((byte) entropyLen, tlvByte(status, Constants.TAG_SEED_LEN));

        byte[] restored =
                session.sendInnerExpectOk(
                        Constants.INS_RESTORE_SEED, (byte) 0, (byte) 0, new byte[0]);
        assertArrayEquals(entropy, restored);
    }

    @Test
    @DisplayName("VERIFY_SEED succeeds on a freshly stored seed")
    void verifySeedAfterBackup() {
        setupPin();
        verifyPin();
        byte[] entropy = new byte[32];
        TestConstants.RANDOM.nextBytes(entropy);
        session.sendInnerExpectOk(
                Constants.INS_BACKUP_SEED, (byte) 0, (byte) 0, lenPrefixed(entropy));
        assertEquals(
                0x9000,
                session.sendInner(Constants.INS_VERIFY_SEED, (byte) 0, (byte) 0, new byte[0])
                        .getSW());
    }

    @Test
    @DisplayName("A second BACKUP_SEED is rejected — the slot is single-use")
    void backupTwiceRejected() {
        setupPin();
        verifyPin();
        byte[] entropy = new byte[32];
        TestConstants.RANDOM.nextBytes(entropy);
        session.sendInnerExpectOk(
                Constants.INS_BACKUP_SEED, (byte) 0, (byte) 0, lenPrefixed(entropy));
        ResponseAPDU second =
                session.sendInner(
                        Constants.INS_BACKUP_SEED, (byte) 0, (byte) 0, lenPrefixed(entropy));
        assertEquals(Constants.SW_SEED_ALREADY_PRESENT & 0xFFFF, second.getSW());
    }

    @Test
    @DisplayName("RESTORE_SEED requires a PIN verified in the current Secure Channel session")
    void restoreRequiresPin() {
        setupPin();
        verifyPin();
        byte[] entropy = new byte[32];
        TestConstants.RANDOM.nextBytes(entropy);
        session.sendInnerExpectOk(
                Constants.INS_BACKUP_SEED, (byte) 0, (byte) 0, lenPrefixed(entropy));

        // A fresh handshake drops the PIN-verified flag; RESTORE must now be refused.
        session = HostSession.open(card);
        ResponseAPDU r =
                session.sendInner(Constants.INS_RESTORE_SEED, (byte) 0, (byte) 0, new byte[0]);
        assertEquals(Constants.SW_SECURITY_STATUS_NOT_SATISFIED & 0xFFFF, r.getSW());
    }

    @Test
    @DisplayName("CHANGE_PIN rotates the PIN; the new one verifies after a re-handshake")
    void changePinRotates() {
        setupPin();
        verifyPin();
        byte[] newPin = "654321".getBytes(StandardCharsets.UTF_8);
        session.sendInnerExpectOk(
                Constants.INS_CHANGE_PIN, (byte) 0, (byte) 0, lenPrefixedPair(PIN, newPin));

        session = HostSession.open(card);
        assertEquals(
                0x9000,
                session.sendInner(Constants.INS_VERIFY_PIN, (byte) 0, (byte) 0, newPin).getSW());
    }

    @Test
    @DisplayName("SET_NAME stores the card label, surfaced in GET_STATUS")
    void setNameRoundTrips() {
        setupPin();
        verifyPin();
        byte[] name = "meowl-cold".getBytes(StandardCharsets.UTF_8);
        session.sendInnerExpectOk(Constants.INS_SET_NAME, (byte) 0, (byte) 0, name);
        assertArrayEquals(name, tlv(status(), Constants.TAG_CARD_NAME));
    }

    @Test
    @DisplayName("Exhausting the PIN wipes the seed and resets the card to FRESH")
    void pinExhaustionWipesSeed() {
        setupPin();
        verifyPin();
        byte[] entropy = new byte[32];
        TestConstants.RANDOM.nextBytes(entropy);
        session.sendInnerExpectOk(
                Constants.INS_BACKUP_SEED, (byte) 0, (byte) 0, lenPrefixed(entropy));

        // A fresh handshake clears the PIN session, then we burn every try.
        session = HostSession.open(card);
        byte[] wrong = "999999".getBytes(StandardCharsets.UTF_8);
        ResponseAPDU last = null;
        for (int i = 0; i < Constants.BACKUP_PIN_RETRY_LIMIT; i++) {
            last = session.sendInner(Constants.INS_VERIFY_PIN, (byte) 0, (byte) 0, wrong);
        }
        assertEquals(Constants.SW_AUTH_BLOCKED & 0xFFFF, last.getSW());

        byte[] status = status();
        assertEquals(LC_FRESH, tlvByte(status, Constants.TAG_LIFECYCLE_STATE));
        assertEquals((byte) 0, tlvByte(status, Constants.TAG_SEED_PRESENT));
    }

    // ---- helpers ----

    private void setupPin() {
        session.sendInnerExpectOk(Constants.INS_SETUP, (byte) 0, (byte) 0, lenPrefixed(PIN));
    }

    private void verifyPin() {
        assertEquals(
                0x9000,
                session.sendInner(Constants.INS_VERIFY_PIN, (byte) 0, (byte) 0, PIN).getSW());
    }

    private byte[] status() {
        return CardLifecycle.transmitOuter(card, Constants.INS_GET_INFO & 0xFF, 0, 0, null)
                .getData();
    }

    private static byte[] lenPrefixed(byte[] data) {
        byte[] out = new byte[1 + data.length];
        out[0] = (byte) data.length;
        System.arraycopy(data, 0, out, 1, data.length);
        return out;
    }

    private static byte[] lenPrefixedPair(byte[] first, byte[] second) {
        byte[] out = new byte[1 + first.length + 1 + second.length];
        out[0] = (byte) first.length;
        System.arraycopy(first, 0, out, 1, first.length);
        out[1 + first.length] = (byte) second.length;
        System.arraycopy(second, 0, out, 2 + first.length, second.length);
        return out;
    }

    /** Returns the value bytes of the first TLV with {@code tag}, or {@code null} if absent. */
    private static byte[] tlv(byte[] data, byte tag) {
        int i = 0;
        while (i + 1 < data.length) {
            int t = data[i++] & 0xFF;
            int len = data[i++] & 0xFF;
            if (t == (tag & 0xFF)) {
                return Arrays.copyOfRange(data, i, i + len);
            }
            i += len;
        }
        return null;
    }

    private static byte tlvByte(byte[] data, byte tag) {
        byte[] value = tlv(data, tag);
        if (value == null || value.length != 1) {
            throw new IllegalStateException(
                    "TLV tag 0x" + Integer.toHexString(tag & 0xFF) + " missing or not 1 byte");
        }
        return value[0];
    }
}
