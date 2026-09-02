#!/usr/bin/env python3
"""Round-trip test: build QR codes with segno, redact them, recover with qrrecover."""
import random, subprocess, sys, os
import numpy as np

QRR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "qrrecover.py")
from PIL import Image
import segno

SC = 7          # px per module
QZ = 4          # quiet zone modules

def build(msg, version, ecl):
    q = segno.make(msg, version=version, error=ecl, boost_error=False)
    m = np.array([[int(b) for b in row] for row in q.matrix], np.uint8)
    n = m.shape[0]
    img = np.full((n + 2*QZ, n + 2*QZ, 3), 255, np.uint8)
    img[QZ:QZ+n, QZ:QZ+n][m == 1] = (0, 0, 0)
    return np.kron(img, np.ones((SC, SC, 1), np.uint8)), n

def redact(img, n, side, corner=0, colour=(42, 129, 252)):
    """Paint a triangular blob over one corner, `side` modules on the leg."""
    a = img.copy()
    for r in range(side):
        for c in range(side - r):
            rr, cc = r, c
            if corner == 1: rr, cc = r, n - 1 - c
            if corner == 2: rr, cc = n - 1 - r, c
            if corner == 3: rr, cc = n - 1 - r, n - 1 - c
            y = (QZ + rr) * SC; x = (QZ + cc) * SC
            a[y:y+SC, x:x+SC] = colour
    return a

def run(path, extra=()):
    p = subprocess.run([sys.executable, QRR, path, "--rebuild", "",
                        "--json", "/tmp/_r.json"] + list(extra),
                       capture_output=True, text=True)
    info = {}
    if p.returncode == 0 and os.path.exists("/tmp/_r.json"):
        import json as _j
        info = _j.load(open("/tmp/_r.json")); os.remove("/tmp/_r.json")
    return p.returncode, info.get("payload", ""), p.stderr.strip(), info

LIES = []


DAMAGE = float(os.environ.get("DAMAGE", "0.30"))


def main():
    random.seed(1)
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .:/-"
    fails, total = [], 0
    for version in range(1, 41):
        for ecl in "LMQH":
            cap = segno.make("x", version=version, error=ecl, boost_error=False)
            # payload sized to roughly fill the symbol
            nchars = {1: 10, 2: 20}.get(version, min(400, 8 * version))
            msg = "".join(random.choice(alphabet) for _ in range(nchars))
            try:
                img, n = build(msg, version, ecl)
            except Exception:
                continue
            side = max(10, min(n - 2, int(n * DAMAGE)))
            dmg = redact(img, n, side)
            path = "/tmp/t_%d%s.png" % (version, ecl)
            Image.fromarray(dmg).save(path)
            total += 1
            rc, out, err, info = run(path)
            if rc != 0 or out != msg:
                tag = "certain=%s" % info.get("certain") if rc == 0 else ""
                fails.append((version, ecl, side, rc, (tag + " " + (err or out))[:110]))
                if rc == 0 and info.get("certain"):
                    LIES.append((version, ecl, side))
            os.remove(path)
        print("v%-3d done (%d fails so far)" % (version, len(fails)), flush=True)

    print("\n--- rotation / mirror test (v6-Q) ---")
    msg = "ROTATION TEST 12345 abcdef"
    img, n = build(msg, 6, "Q")
    for k in range(4):
        d = redact(img, n, 12)
        d = np.rot90(d, k)
        Image.fromarray(np.ascontiguousarray(d)).save("/tmp/rot.png")
        rc, out, err, _ = run("/tmp/rot.png")
        print("rot %3d deg -> %s" % (k*90, "OK" if out == msg else "FAIL: %s" % (err or out)[:90]))
    d = np.fliplr(redact(img, n, 12))
    Image.fromarray(np.ascontiguousarray(d)).save("/tmp/mir.png")
    rc, out, err, _ = run("/tmp/mir.png")
    print("mirrored    -> %s" % ("OK" if out == msg else "FAIL: %s" % (err or out)[:90]))

    print("\n--- over-capacity test (should refuse, not lie) ---")
    img, n = build("THIS SHOULD FAIL", 2, "L")
    Image.fromarray(redact(img, n, n - 1)).save("/tmp/over.png")
    rc, out, err, _ = run("/tmp/over.png")
    print("rc=%d  %s" % (rc, (err or out)[:150]))

    print("\n==== %d/%d round trips passed ====" % (total - len(fails), total))
    print("SILENT WRONG ANSWERS (reported CERTAIN but wrong): %d %s" % (len(LIES), LIES))
    for f in fails:
        print("FAIL v%d-%s side=%d rc=%d %s" % f)
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
