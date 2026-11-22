#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 QuantX
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generates spec/vectors/verify-sequence.json from spec/protocol.md §7.3, §9.3, §9.5 and §9.15.

A small model of the access-code rules (life, the failure count f, the session's waited count)
computes the expected inner status word and the STATUS response after every step of each
scripted sequence. Each sequence starts on a LOADED card whose wallet was created with the
"right" access hash, in a fresh session that is not verified. Stdlib only; output is canonical
(json.dumps(obj, indent=2) + "\\n", ASCII).

Usage: python3 sequence.py [out.json]
"""
import json
import sys

L, F, W, I = 10, 3, 15, 400

SETUP = (
    "Each sequence starts on a card that is LOADED by CREATE with the right access hash "
    "(any 32-byte value; the wrong access hash is any other value), followed by a new OPEN: "
    "f = 0, waited = 0, not verified. After every step the replayer sends STATUS in the "
    "current session and compares its response with status (life(1) ‖ tries(1), §9.3); STATUS "
    "has no side effect. A step with repeat n is sent n times, each answered with sw; status "
    "is checked after the last one."
)

TEAR = (
    "after-T-FAIL: power is lost after the T-FAIL transaction of this VERIFY committed and "
    "before any later persistent write (§9.5 steps 5-9). The command has no response "
    "(sw torn); the replayer powers the card up, SELECTs the wallet applet and OPENs a new "
    "session before the STATUS check."
)


class Card:
    """The §9.5 model: one LOADED wallet, its count f and the session's waited count."""

    def __init__(self):
        self.life = "LOADED"
        self.f = 0
        self.waited = 0

    def status(self):
        if self.life == "BLANK":
            return "0100"
        return "02%02x" % max(L - self.f, 0)

    def erase(self):
        self.life = "BLANK"
        self.f = 0

    def verify(self, code, tear):
        if self.life != "LOADED":
            return "6985"
        if self.f >= L:  # step 2: re-entry after a lost T-ERASE
            self.erase()
            return "6983"
        if self.f >= F and self.waited < W:  # step 3: nothing written, waited kept
            return "6985"
        self.waited = 0  # step 4
        self.f += 1  # step 5, T-FAIL
        if tear:
            self.waited = 0  # power loss ends the session
            return "torn"
        if code == "right":  # step 8, T-OK
            self.f = 0
            return "9000"
        if self.f == L:  # step 9
            self.erase()
            return "6983"
        return "63c%x" % (L - self.f)  # step 10

    def wait(self):
        if self.life != "LOADED":
            return "6985"
        self.waited = min(self.waited + 1, W)
        return "9000"

    def open(self):
        self.waited = 0
        return "9000"


class Script:
    def __init__(self, name, description):
        self.card = Card()
        self.seq = {"name": name, "description": description, "steps": []}

    def verify(self, code, tear=None):
        step = {"command": "VERIFY", "code": code}
        if tear:
            step["tear"] = tear
        step["sw"] = self.card.verify(code, tear)
        step["status"] = self.card.status()
        self.seq["steps"].append(step)
        return self

    def wait(self, n=W):
        sws = {self.card.wait() for _ in range(n)}
        assert len(sws) == 1
        self.seq["steps"].append(
            {"command": "WAIT", "repeat": n, "sw": sws.pop(), "status": self.card.status()}
        )
        return self

    def open(self):
        self.seq["steps"].append(
            {"command": "OPEN", "sw": self.card.open(), "status": self.card.status()}
        )
        return self

    def wrong_to(self, f):
        """Wrong codes (with W waits once f >= F) until the count is f."""
        while self.card.f < f:
            if self.card.f >= F:
                self.wait()
            self.verify("wrong")
        return self

    def done(self):
        return self.seq


def sequences():
    out = []

    s = Script(
        "wrong-to-limit",
        "Wrong codes from f = 0 to L: three free attempts, then 6985 until W WAITs complete "
        "in the session (a refused VERIFY keeps waited), then one attempt per W WAITs; the "
        "L-th failure erases. Afterwards VERIFY and WAIT are refused in BLANK.",
    )
    s.verify("wrong").verify("wrong").verify("wrong")
    s.verify("wrong").wait(W - 1).verify("wrong").wait(1).verify("wrong")
    for _ in range(F + 1, L):
        s.wait().verify("wrong")
    s.verify("right").wait(1)
    out.append(s.done())

    for k in range(L):
        s = Script(
            "right-resets-at-f-%d" % k,
            "k = %d wrong codes, then the right code resets f to 0; the free attempts "
            "return." % k,
        )
        s.wrong_to(k)
        if k >= F:
            s.wait()
        s.verify("right").verify("wrong")
        out.append(s.done())

    s = Script(
        "right-needs-wait",
        "Once f >= F the wait applies to the right code too; nothing is written while it is "
        "refused.",
    )
    s.wrong_to(F).verify("right").wait().verify("right")
    out.append(s.done())

    s = Script(
        "waited-lost-on-open",
        "waited is session state: a new OPEN discards completed WAITs.",
    )
    s.wrong_to(F).wait().open().verify("wrong").wait().verify("wrong")
    out.append(s.done())

    s = Script(
        "wait-beyond-W",
        "waited saturates at W; one VERIFY consumes all of it, so the next attempt needs W "
        "new WAITs.",
    )
    s.wrong_to(F).wait(W + 5).verify("wrong").verify("wrong")
    out.append(s.done())

    s = Script(
        "torn-right-code-counts",
        "The right code with power lost after T-FAIL: the attempt stays counted; the next "
        "right code resets.",
    )
    s.verify("right", tear="after-T-FAIL").verify("right")
    out.append(s.done())

    s = Script(
        "tries-zero",
        "Power lost after the L-th T-FAIL, before T-ERASE: STATUS reports tries = 0 and the "
        "next VERIFY erases at step 2 without comparing, even with the right code and no "
        "WAIT.",
    )
    s.wrong_to(L - 1).wait().verify("wrong", tear="after-T-FAIL").verify("right")
    out.append(s.done())

    return out


def main():
    doc = {
        "constants": {"L": L, "F": F, "W": W, "I": I},
        "setup": SETUP,
        "tear": TEAR,
        "sequences": sequences(),
    }
    text = json.dumps(doc, indent=2, ensure_ascii=True) + "\n"
    if len(sys.argv) > 1:
        with open(sys.argv[1], "w", encoding="ascii", newline="\n") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
