"""Robustness: noise, JPEG, rescale, missing quiet zone, black redaction."""
import os, subprocess, sys, io
import numpy as np

QRR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "qrrecover.py")
from PIL import Image
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_qrrecover as T

MSG = "Forensics lab: evidence tag 7741-B / hash 9f2c"

def run(path, extra=()):
    p = subprocess.run([sys.executable, QRR, path, "--quiet", "--rebuild", ""] + list(extra),
                       capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

def check(name, arr, extra=(), fmt="png"):
    path = "/tmp/rb.%s" % fmt
    Image.fromarray(arr).save(path, quality=55) if fmt == "jpg" else Image.fromarray(arr).save(path)
    rc, out, err = run(path, extra)
    print("%-28s %s" % (name, "OK" if out == MSG else "FAIL rc=%d %s" % (rc, (err or out)[:80])))

img, n = T.build(MSG, 6, "M")
base = T.redact(img, n, 12)

check("clean", base)

rng = np.random.default_rng(0)
noisy = np.clip(base.astype(int) + rng.normal(0, 18, base.shape), 0, 255).astype(np.uint8)
check("gaussian noise sigma=18", noisy)

noisy2 = np.clip(base.astype(int) + rng.normal(0, 35, base.shape), 0, 255).astype(np.uint8)
check("gaussian noise sigma=35", noisy2)

check("jpeg quality 55", base, fmt="jpg")

im = Image.fromarray(base)
check("rescaled x0.55 (bilinear)", np.array(im.resize((int(im.width*.55), int(im.height*.55)), Image.BILINEAR)))
check("rescaled x2.3", np.array(im.resize((int(im.width*2.3), int(im.height*2.3)), Image.BICUBIC)))

q = T.QZ * T.SC
check("no quiet zone (cropped)", base[q:-q, q:-q])

grey = base.copy()
mask = (grey[..., 2] > 200) & (grey[..., 0] < 120)
grey[mask] = (20, 20, 20)
check("black marker + --no-colour", grey, extra=("--no-colour-occlusion",))

pink = base.copy(); pink[mask] = (255, 105, 180)
check("pink redaction (auto)", pink)

blk = base.copy(); blk[mask] = (0, 0, 0)
rc, out, err = run("/tmp/rb.png") if False else (0, "", "")
Image.fromarray(blk).save("/tmp/rb.png")
rc, out, err = run("/tmp/rb.png")
print("%-28s %s" % ("black redaction, no hint", "recovered" if out == MSG
      else "declined/deviated: %s" % (err or out)[:70]))
