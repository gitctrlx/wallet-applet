#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 QuantX
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generates spec/vectors/apdu.json from the protocol tables (spec/protocol.md §18).

Transcribes the checks of §8.1 (OPEN), §8.3 (SESSION, outer only — the record-level cases
live in record.json), §9.2 (checking order and the unknown-INS case), §9.3 (STATUS) and
§14.1–14.2 (GET_IDENTITY, PERSONALIZE). APDUs are templates with {symbol} placeholders;
this script computes each Lc byte from the symbol lengths. In every command, case k violates
check k and every later check that can be violated at the same time, and expects check k's
status word; the last case is the success case. Stdlib only; output is canonical
(json.dumps(obj, indent=2) + "\\n", ASCII).

Usage: python3 apdu.py [out.json]
"""
import json
import sys

# Placeholder byte lengths. {record0} is the ct‖tag part of record.json commands[0].
SYMBOL_LEN = {
    "A": 33,
    "cert": 97,
    "cert.otherA": 97,
    "cert.otherCa": 97,
    "caKey": 65,
    "caKey.prefix03": 65,
    "caKey.xIsP": 65,
    "caKey.yIsP": 65,
    "caKey.offCurve": 65,
    "hostEph": 65,
    "hostEph.prefix02": 65,
    "hostEph.offCurve": 65,
    "openResponse": 226,
    "record0": 24,
}

SYMBOLS = {
    "A": "33 bytes: the compressed identity key of the card under test, cert[0..33) — cert.json's card1",
    "cert": "97 bytes: cert = A ‖ r ‖ s of the card under test under ca1 — cert.json's card1 certificate",
    "cert.otherA": "97 bytes: a certificate under ca1 for a different identity key — cert.json's card2 certificate",
    "cert.otherCa": "97 bytes: the certificate of this card's A issued under ca2 — cert.json identity card1 signed by ca2",
    "caKey": "65 bytes: the uncompressed public key of ca1 — cert.json cas[0].public",
    "caKey.prefix03": "65 bytes: caKey with the first byte changed to 0x03 (not an uncompressed point)",
    "caKey.xIsP": "65 bytes: caKey with x replaced by the field prime p",
    "caKey.yIsP": "65 bytes: caKey with y replaced by the field prime p",
    "caKey.offCurve": "65 bytes: caKey with y flipped so y^2 != x^3 + 7 (mod p)",
    "hostEph": "65 bytes: a valid uncompressed host ephemeral public key — session.json hostEph",
    "hostEph.prefix02": "65 bytes: hostEph with the first byte changed to 0x02",
    "hostEph.offCurve": "65 bytes: hostEph with y flipped so the point is off the curve",
    "openResponse": "226 bytes: cardEph ‖ sig ‖ cert plus SW 9000; verified through Open.response (session.json)",
    "record0": "24 bytes: ct ‖ tag of record.json commands[0].apdu — a well-formed record",
}


def apdu(head, *data, lc=None, le=None):
    """Build the hex-string APDU `head ‖ Lc ‖ data ‖ Le`.

    `head` is the four header bytes; `data` tokens are hex or {symbol} placeholders; `lc`
    overrides the computed Lc (used by the intentional length violations); `le` appends a
    trailing Le byte.
    """
    dl = sum(
        SYMBOL_LEN[t[1:-1]] if t.startswith("{") else len(bytes.fromhex(t)) for t in data
    )
    declared = dl if lc is None else lc
    assert 0 <= declared <= 0xFF
    out = head
    if data or lc is not None:
        out += f"{declared:02x}" + "".join(data)
    if le is not None:
        out += le
    return out


def case(name, life, session, apdu_hex, inner, sw, response=None):
    c = {
        "name": name,
        "life": life,
        "session": session,
        "apdu": apdu_hex,
        "inner": inner,
        "sw": sw,
    }
    if response is not None:
        c["response"] = response
    return c


# life values: FACTORY, BLANK, LOADED (§4.1) or "any". session: "none" or "open".
COMMANDS = [
    {
        "name": "DISPATCH",
        "section": "9.1",
        "cases": [
            case("wrong-cla", "any", "none", apdu("00e00000", le="00"), False, "6e00"),
            case("unknown-ins", "any", "none", apdu("807f0000", le="00"), False, "6d00"),
        ],
    },
    {
        "name": "GET_IDENTITY",
        "section": "14.1",
        "cases": [
            # life checked first: P1/P2 and Lc are also wrong here
            case("life-blank", "BLANK", "none", apdu("80e00100", "00"), False, "6985"),
            # P1/P2 checked before length: Lc is also wrong here
            case("p1p2", "FACTORY", "none", apdu("80e00100", "00"), False, "6a86"),
            case("length", "FACTORY", "none", apdu("80e00000", "00"), False, "6700"),
            case(
                "success",
                "FACTORY",
                "none",
                apdu("80e00000", le="00"),
                False,
                "9000",
                "{A}",
            ),
        ],
    },
    {
        "name": "PERSONALIZE",
        "section": "14.2",
        "cases": [
            case(
                "life-blank",
                "BLANK",
                "none",
                apdu("80e20100", "{cert}", "{caKey}", lc=0xA1),
                False,
                "6985",
            ),
            case(
                "p1p2",
                "FACTORY",
                "none",
                apdu("80e20100", "{cert}", "{caKey}", lc=0xA1),
                False,
                "6a86",
            ),
            # declared Lc = 161, one short of 162; the trailing byte parses as Le
            case(
                "length",
                "FACTORY",
                "none",
                apdu("80e20000", "{cert}", "{caKey}", lc=0xA1),
                False,
                "6700",
            ),
            case(
                "cert-not-this-card",
                "FACTORY",
                "none",
                apdu("80e20000", "{cert.otherA}", "{caKey}"),
                False,
                "6a80",
            ),
            case(
                "cakey-prefix03",
                "FACTORY",
                "none",
                apdu("80e20000", "{cert}", "{caKey.prefix03}"),
                False,
                "6a80",
            ),
            case(
                "cakey-x-is-p",
                "FACTORY",
                "none",
                apdu("80e20000", "{cert}", "{caKey.xIsP}"),
                False,
                "6a80",
            ),
            case(
                "cakey-y-is-p",
                "FACTORY",
                "none",
                apdu("80e20000", "{cert}", "{caKey.yIsP}"),
                False,
                "6a80",
            ),
            case(
                "cakey-off-curve",
                "FACTORY",
                "none",
                apdu("80e20000", "{cert}", "{caKey.offCurve}"),
                False,
                "6a80",
            ),
            case(
                "cert-under-other-ca",
                "FACTORY",
                "none",
                apdu("80e20000", "{cert.otherCa}", "{caKey}"),
                False,
                "6a80",
            ),
            case(
                "success",
                "FACTORY",
                "none",
                apdu("80e20000", "{cert}", "{caKey}"),
                False,
                "9000",
            ),
        ],
    },
    {
        "name": "OPEN",
        "section": "8.1",
        "cases": [
            case("life-factory", "FACTORY", "none", apdu("80100100", "00"), False, "6985"),
            case("p1p2", "BLANK", "none", apdu("80100100", "00"), False, "6a86"),
            # declared Lc = 64: the 65th point byte parses as Le, incoming length 64 != 65
            case(
                "length",
                "BLANK",
                "none",
                apdu("80100000", "{hostEph}", lc=0x40),
                False,
                "6700",
            ),
            case(
                "hosteph-prefix02",
                "BLANK",
                "none",
                apdu("80100000", "{hostEph.prefix02}", le="00"),
                False,
                "6a80",
            ),
            case(
                "hosteph-off-curve",
                "BLANK",
                "none",
                apdu("80100000", "{hostEph.offCurve}", le="00"),
                False,
                "6a80",
            ),
            case(
                "success",
                "BLANK",
                "none",
                apdu("80100000", "{hostEph}", le="00"),
                False,
                "9000",
                "{openResponse}",
            ),
        ],
    },
    {
        "name": "SESSION",
        "section": "8.3",
        "cases": [
            # record-level rejections live in record.json rejectedCommands
            case(
                "no-session",
                "BLANK",
                "none",
                apdu("80120000", "{record0}", le="00"),
                False,
                "6985",
            ),
        ],
    },
    {
        "name": "INNER_DISPATCH",
        "section": "9.2",
        "cases": [
            # INS known is the first inner check; P1/P2 and data are also wrong here
            case("unknown-ins", "BLANK", "open", "7f0102ff", True, "6d00"),
        ],
    },
    {
        "name": "STATUS",
        "section": "9.3",
        "cases": [
            case("p1p2", "BLANK", "open", "20010200", True, "6a86"),
            case("length", "BLANK", "open", "20000001", True, "6700"),
            case("success-blank", "BLANK", "open", "200000", True, "9000", "0100"),
            case("success-loaded", "LOADED", "open", "200000", True, "9000", "020a"),
        ],
    },
]


def main():
    doc = {"symbols": SYMBOLS, "commands": COMMANDS}
    out = json.dumps(doc, indent=2, ensure_ascii=True) + "\n"
    if len(sys.argv) > 1:
        with open(sys.argv[1], "w", encoding="ascii", newline="\n") as f:
            f.write(out)
    else:
        sys.stdout.write(out)


if __name__ == "__main__":
    main()
