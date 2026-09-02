#!/usr/bin/env python3
"""Round-trip test for RGB-packed symbols: three codes stacked one per colour
channel, optionally with every finder pattern erased.

    pip install segno
    python tests/test_packed.py
"""
import os
import random
import sys

import numpy as np
import segno

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import qrrecover as Q


def matrix_of(text, version, ecl):
    """Encode at exactly this version and level, trimming the text if it will
    not fit."""
    while text:
        try:
            qr = segno.make(text, version=version, error=ecl, boost_error=False)
        except segno.DataOverflowError:
            text = text[:-1]
            continue
        return text, np.array([[int(b) for b in row] for row in qr.matrix], np.uint8)
    raise RuntimeError("nothing fits version %s level %s" % (version, ecl))


def pack(mats, invert, scale, quiet):
    """Stack three equal-sized module matrices into one 8-colour image."""
    n = mats[0].shape[0]
    canvas = np.zeros((n + 2 * quiet, n + 2 * quiet, 3), np.uint8)
    for ci, m in enumerate(mats):
        plane = np.zeros(canvas.shape[:2], np.uint8)
        plane[quiet:quiet + n, quiet:quiet + n] = m
        canvas[..., ci] = (plane if invert else 1 - plane) * 255
    return np.kron(canvas, np.ones((scale, scale, 1), np.uint8))


def erase_finders(mats):
    for m in mats:
        n = m.shape[0]
        for r0, c0 in ((0, 0), (0, n - 8), (n - 8, 0)):
            m[r0:r0 + 8, c0:c0 + 8] = 0
    return mats


class Args:
    version = None
    rebuild = None
    quiet = True
    no_split = False


def run():
    rng = random.Random(20260902)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789 -_."
    fails, total = [], 0

    cases = []
    for version in (1, 3, 5, 9, 14):
        for ecl in ("l", "m", "q", "h"):
            for erased in (False, True):
                cases.append((version, ecl, erased))

    for version, ecl, erased in cases:
        cap = {1: 8, 3: 20, 5: 34, 9: 55, 14: 80}[version]
        texts = ["".join(rng.choice(alphabet) for _ in range(rng.randint(4, cap)))
                 for _ in range(3)]
        pairs = [matrix_of(t, version, ecl) for t in texts]
        texts = [t for t, _ in pairs]
        mats = [m for _, m in pairs]
        if erased:
            mats = erase_finders([m.copy() for m in mats])
        invert = bool(rng.getrandbits(1))
        img = pack(mats, invert, scale=rng.choice((3, 5, 8)), quiet=rng.choice((4, 5)))
        total += 1

        if not Q.detect_packed(img):
            fails.append((version, ecl, erased, "not detected as packed"))
            continue
        out = Q.recover_packed(img, Args())
        if out is None:
            fails.append((version, ecl, erased, "recover_packed returned None"))
            continue
        got = [r.text if r else None for _, r, _ in out]
        if got != texts:
            fails.append((version, ecl, erased, "payload mismatch %r != %r" % (got, texts)))
            continue
        wrong_certain = [r.text for _, r, _ in out
                         if r and r.certain and r.text not in texts]
        if wrong_certain:
            fails.append((version, ecl, erased, "CERTAIN but wrong: %r" % wrong_certain))
        print("v%-3d %s  finders %-7s ok" % (version, ecl.upper(),
                                             "erased" if erased else "intact"))

    print("\n==== %d/%d packed round trips passed ====" % (total - len(fails), total))
    for f in fails:
        print("  FAIL", f)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(run())
