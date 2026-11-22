// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/**
 * The qntx card wallet applet (protocol.md §2, §6, §9.1). Constructs the object graph once — {@code
 * Mem, State, ModArith, Secp256k1, Identity, Session, Wallet} — and dispatches the outer commands
 * of §9.1 and, inside a session record, the inner commands of §9.2.
 */
public final class WalletApplet extends Applet {
    private final Mem mem;
    private final State state;
    private final Identity identity;
    private final Session session;
    private final Wallet wallet;

    private WalletApplet(byte[] bArray, short bOffset) {
        Const.init();
        mem = new Mem();
        state = new State();
        ModArith modArith = new ModArith(mem);
        Secp256k1 secp = new Secp256k1(mem, modArith);
        identity = new Identity(mem, state, secp);
        session = new Session(mem, state, secp, identity);
        wallet = new Wallet(state);
        register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    /** GlobalPlatform install entry; the instance AID is taken from the install data. */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new WalletApplet(bArray, bOffset);
    }

    /** SELECT of the wallet applet tears down any session (§6, §8.5); it writes nothing. */
    public boolean select() {
        session.teardown();
        return true;
    }

    /**
     * Outer dispatch in the order of protocol.md §9.1. Handlers write their response at buffer
     * offset 0 and return its length; scratch is wiped before every response or error so no command
     * residue leaves the card (§8.1, §16.3 item 3).
     */
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        short len;
        try {
            len = dispatch(apdu);
        } catch (ISOException e) {
            mem.wipeScratch();
            if (e.getReason() == Const.SW_FAULT) {
                session.teardown();
            }
            throw e;
        } catch (Exception e) {
            // §16.3 item 4: unexpected exceptions map to 6F00, reason codes never escape
            mem.wipeScratch();
            session.teardown();
            ISOException.throwIt(Const.SW_FAULT);
            return;
        }
        mem.wipeScratch();
        apdu.setOutgoingAndSend((short) 0, len);
    }

    /** The §9.1 outer table: CLA, reception, then the INS row's own checking order. */
    private short dispatch(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != Const.CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        short lc = receiveAll(apdu);
        short len;
        switch (buf[ISO7816.OFFSET_INS]) {
            case Const.INS_GET_IDENTITY:
                len = identity.getIdentity(apdu, lc);
                break;
            case Const.INS_PERSONALIZE:
                len = identity.personalize(apdu, lc);
                break;
            case Const.INS_OPEN:
                len = session.open(apdu, lc);
                break;
            case Const.INS_SESSION:
                len = session(apdu, lc);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                return 0;
        }
        return len;
    }

    /**
     * The SESSION path (§8.3–8.4): {@code unwrap} throws the outer status on record failures; the
     * inner result (a status word plus optional data at buffer offset 0) is wrapped into a response
     * record with outer {@code 9000}.
     */
    private short session(APDU apdu, short lc) {
        byte[] buf = apdu.getBuffer();
        short plain = session.unwrap(apdu, lc);
        short dataLen = 0;
        short sw = ISO7816.SW_NO_ERROR;
        try {
            if (plain < 3) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            dataLen = inner(buf, plain);
        } catch (ISOException e) {
            sw = e.getReason();
        } catch (Exception e) {
            sw = Const.SW_FAULT;
        }
        short len = session.wrap(apdu, dataLen, sw);
        session.afterResponse(sw);
        return len;
    }

    /**
     * Inner dispatch (§9.2): pending states first, then the §9.2 checking order — INS known, life
     * gate, {@code P1}/{@code P2}, length, verified gate — then the handler, whose response goes to
     * buffer offset 0. Returns the response length.
     */
    private short inner(byte[] buf, short plain) {
        byte ins = buf[ISO7816.OFFSET_CDATA];
        byte p1 = buf[(short) (ISO7816.OFFSET_CDATA + 1)];
        byte p2 = buf[(short) (ISO7816.OFFSET_CDATA + 2)];
        short pending = session.beginDispatch(ins, p1);
        short sw = ISO7816.SW_NO_ERROR;
        try {
            short row = -1;
            for (short i = 0; i < Const.INNER_INS.length; i++) {
                if (Const.INNER_INS[i] == ins) {
                    row = i;
                }
            }
            if (row < 0) {
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
            short life = state.life();
            short bit =
                    life == Const.LIFE_BLANK
                            ? Const.LIFE_BIT_BLANK
                            : life == Const.LIFE_LOADED ? Const.LIFE_BIT_LOADED : (short) 0;
            if ((short) (Const.INNER_LIFE[row] & bit) == 0) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            if (p2 != 0 || (short) (p1 & 0xFF) > Const.INNER_P1_MAX[row]) {
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            }
            if ((short) (plain - 3) != 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            if (Const.INNER_VERIFIED[row] != 0 && session.verified() != Const.VERIFIED_YES) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            return wallet.status(buf, (short) 0);
        } catch (ISOException e) {
            sw = e.getReason();
            throw e;
        } catch (Exception e) {
            sw = Const.SW_FAULT;
            throw e;
        } finally {
            session.endDispatch(pending, ins, p1, sw);
        }
    }

    /** Receives the full command body; returns the declared Lc. Reception has no status word. */
    private static short receiveAll(APDU apdu) {
        short received = apdu.setIncomingAndReceive();
        short lc = apdu.getIncomingLength();
        while (received < lc) {
            received += apdu.receiveBytes((short) (ISO7816.OFFSET_CDATA + received));
        }
        return lc;
    }
}
