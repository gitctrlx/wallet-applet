/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBO;
import apdu4j.core.BIBOException;
import apdu4j.core.CommandAPDU;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import social.meowl.tools.core.MeowlAid;
import social.meowl.tools.core.MeowlInfo;
import social.meowl.tools.core.MeowlLifecycle;
import social.meowl.tools.core.ProtocolException;
import social.meowl.tools.core.Tlv;

/** Tests for the {@link MeowlCard} operations facade, driven by an in-memory transport double. */
class MeowlCardTest {

    private static final byte[] OK = sw(0x9000);

    private MeowlCard card(FakeBibo fake) {
        return new MeowlCard(new APDUBIBO(fake), MeowlAid.defaultBytes());
    }

    @Test
    @DisplayName("select returns the FCI, marks selected, and issues SELECT BY DF NAME")
    void selectSuccess() throws BIBOException {
        FakeBibo fake = new FakeBibo().respond(resp(0x9000, new byte[] {0x6F, 0x02, (byte) 0xAA}));
        MeowlCard card = card(fake);

        byte[] fci = card.select();

        assertArrayEquals(new byte[] {0x6F, 0x02, (byte) 0xAA}, fci);
        assertTrue(card.isSelected());
        byte[] cmd = fake.received.get(0);
        assertEquals(0x00, cmd[0] & 0xFF);
        assertEquals(0xA4, cmd[1] & 0xFF);
        assertEquals(0x04, cmd[2] & 0xFF);
    }

    @Test
    @DisplayName("select surfaces a non-success SW as ProtocolException and stays unselected")
    void selectFailure() {
        MeowlCard card = card(new FakeBibo().respond(sw(0x6A82)));
        ProtocolException ex = assertThrows(ProtocolException.class, card::select);
        assertEquals(0x6A82, ex.sw());
        assertFalse(card.isSelected());
    }

    @Test
    @DisplayName("getInfo lazily selects then decodes the GET_INFO profile")
    void getInfoSelectsAndDecodes() throws BIBOException {
        FakeBibo fake = new FakeBibo().respond(OK, resp(0x9000, infoBlob()));
        MeowlCard card = card(fake);

        MeowlInfo info = card.getInfo();

        assertEquals(MeowlLifecycle.SEEDED, info.lifecycle().orElseThrow());
        assertEquals(0x01F7, info.capabilityBits());
        assertEquals(2, fake.received.size(), "should SELECT then GET_INFO");
        assertEquals(0x01, fake.received.get(1)[1] & 0xFF, "second command is GET_INFO (INS 0x01)");
    }

    @Test
    @DisplayName("an explicit select is not repeated by a subsequent operation")
    void selectionIsReused() throws BIBOException {
        FakeBibo fake = new FakeBibo().respond(OK, resp(0x9000, infoBlob()));
        MeowlCard card = card(fake);

        card.select();
        card.getInfo();

        assertEquals(2, fake.received.size(), "ensureSelected must not re-SELECT");
    }

    @Test
    @DisplayName("getAuthentikey returns the compressed key body")
    void getAuthentikey() throws BIBOException {
        byte[] key = new byte[33];
        key[0] = 0x02;
        MeowlCard card = card(new FakeBibo().respond(OK, resp(0x9000, key)));

        assertArrayEquals(key, card.getAuthentikey());
    }

    @Test
    @DisplayName("resetToFactory walks the 6FA3→6FA0 countdown and returns each step")
    void resetSuccess() throws BIBOException {
        FakeBibo fake = new FakeBibo().respond(OK, sw(0x6FA3), sw(0x6FA2), sw(0x6FA1), sw(0x6FA0));
        MeowlCard card = card(fake);

        int[] steps = card.resetToFactory();

        assertArrayEquals(new int[] {0x6FA3, 0x6FA2, 0x6FA1, 0x6FA0}, steps);
    }

    @Test
    @DisplayName("resetToFactory rejects a step that is not a 6FAx countdown")
    void resetDeviation() {
        MeowlCard card = card(new FakeBibo().respond(OK, sw(0x6D00)));
        ProtocolException ex = assertThrows(ProtocolException.class, card::resetToFactory);
        assertEquals(0x6D00, ex.sw());
    }

    @Test
    @DisplayName("resetToFactory rejects a final step that did not complete the wipe")
    void resetIncomplete() {
        FakeBibo fake = new FakeBibo().respond(OK, sw(0x6FA3), sw(0x6FA2), sw(0x6FA1), sw(0x6FA1));
        ProtocolException ex = assertThrows(ProtocolException.class, card(fake)::resetToFactory);
        assertTrue(ex.getMessage().contains("did not complete"), ex::getMessage);
    }

    @Test
    @DisplayName("transmit is a raw passthrough that does not auto-select")
    void transmitRaw() throws BIBOException {
        FakeBibo fake = new FakeBibo().respond(sw(0x9000));
        MeowlCard card = card(fake);

        card.transmit(new CommandAPDU(0x80, 0x42, 0x00, 0x00));

        assertEquals(1, fake.received.size(), "transmit must not issue a SELECT");
        assertFalse(card.isSelected());
        assertEquals(0x42, fake.received.get(0)[1] & 0xFF);
    }

    @Test
    @DisplayName("re-targeting the AID clears selection state")
    void aidResetsSelection() throws BIBOException {
        MeowlCard card = card(new FakeBibo().respond(OK));
        card.select();
        assertTrue(card.isSelected());

        card.aid(MeowlAid.parse("A0000000041010"));

        assertFalse(card.isSelected());
        assertArrayEquals(MeowlAid.parse("A0000000041010"), card.aid());
    }

    private static byte[] infoBlob() {
        byte[] authentikey = new byte[33];
        authentikey[0] = 0x02;
        Map<Byte, byte[]> tags = new LinkedHashMap<>();
        tags.put(MeowlInfo.TAG_PROTOCOL_VERSION, new byte[] {0x01, 0x00});
        tags.put(MeowlInfo.TAG_APPLET_VERSION, new byte[] {0x00, 0x01});
        tags.put(MeowlInfo.TAG_LIFECYCLE, new byte[] {0x03});
        tags.put(MeowlInfo.TAG_CAPABILITIES, new byte[] {0x01, (byte) 0xF7});
        tags.put(MeowlInfo.TAG_AUTHENTIKEY, authentikey);
        return Tlv.encodeAll(tags);
    }

    private static byte[] sw(int sw) {
        return resp(sw, new byte[0]);
    }

    private static byte[] resp(int sw, byte[] data) {
        byte[] out = new byte[data.length + 2];
        System.arraycopy(data, 0, out, 0, data.length);
        out[data.length] = (byte) ((sw >>> 8) & 0xFF);
        out[data.length + 1] = (byte) (sw & 0xFF);
        return out;
    }

    /** In-memory {@link BIBO} that records commands and replays a scripted response queue. */
    private static final class FakeBibo implements BIBO {
        private final Deque<byte[]> responses = new ArrayDeque<>();
        final List<byte[]> received = new ArrayList<>();

        FakeBibo respond(byte[]... resp) {
            for (byte[] r : resp) {
                responses.add(r);
            }
            return this;
        }

        @Override
        public byte[] transceive(byte[] cmd) throws BIBOException {
            received.add(cmd.clone());
            if (responses.isEmpty()) {
                throw new IllegalStateException("FakeBibo: no scripted response for command");
            }
            return responses.poll();
        }

        @Override
        public void close() {}
    }
}
