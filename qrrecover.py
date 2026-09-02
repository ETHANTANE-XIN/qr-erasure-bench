#!/usr/bin/env python3
"""
qrrecover.py - recover the payload of a damaged, redacted or partially
               obliterated QR Code from a scanned image.

Ordinary QR readers give up as soon as a finder pattern is covered.  This tool
does not: it locates the symbol from whatever structure survives, rebuilds the
parts of the code that the standard fixes by definition (finder patterns,
separators, timing patterns, alignment patterns, format and version
information), marks every module that was painted over as a Reed-Solomon
*erasure*, and then decodes.

Erasure decoding is the important bit.  A QR block with ``n`` error-correction
codewords can repair ``n/2`` codewords whose position is unknown, but ``n``
codewords whose position IS known.  Because we know exactly which modules were
obscured, we get double the usual correcting power, and the tool can tell you
whether the recovered message is mathematically certain or merely probable.

Usage
-----
    python qrrecover.py secret.png
    python qrrecover.py evidence.png --report report.txt --rebuild fixed.png
    python qrrecover.py scan.png --occlusion "#2a81fc" --tolerance 60
    python qrrecover.py scan.png --grid 759,546,29.15,33      # manual override

Requirements
------------
    pip install pillow numpy

Licence: MIT.  Written for a digital-forensics lab.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field

try:
    import numpy as np
except ImportError:  # pragma: no cover
    sys.exit("numpy is required:  pip install numpy")
try:
    from PIL import Image
except ImportError:  # pragma: no cover
    sys.exit("pillow is required:  pip install pillow")


# --------------------------------------------------------------------------- #
#  Standard tables (ISO/IEC 18004)                                             #
# --------------------------------------------------------------------------- #

ECC_TABLE = {   # version: (L, M, Q, H); each = ((blocks, total_cw, data_cw), ...)
     1: (((1,26,19),), ((1,26,16),), ((1,26,13),), ((1,26,9),)),
     2: (((1,44,34),), ((1,44,28),), ((1,44,22),), ((1,44,16),)),
     3: (((1,70,55),), ((1,70,44),), ((2,35,17),), ((2,35,13),)),
     4: (((1,100,80),), ((2,50,32),), ((2,50,24),), ((4,25,9),)),
     5: (((1,134,108),), ((2,67,43),), ((2,33,15),(2,34,16)), ((2,33,11),(2,34,12))),
     6: (((2,86,68),), ((4,43,27),), ((4,43,19),), ((4,43,15),)),
     7: (((2,98,78),), ((4,49,31),), ((2,32,14),(4,33,15)), ((4,39,13),(1,40,14))),
     8: (((2,121,97),), ((2,60,38),(2,61,39)), ((4,40,18),(2,41,19)), ((4,40,14),(2,41,15))),
     9: (((2,146,116),), ((3,58,36),(2,59,37)), ((4,36,16),(4,37,17)), ((4,36,12),(4,37,13))),
    10: (((2,86,68),(2,87,69)), ((4,69,43),(1,70,44)), ((6,43,19),(2,44,20)), ((6,43,15),(2,44,16))),
    11: (((4,101,81),), ((1,80,50),(4,81,51)), ((4,50,22),(4,51,23)), ((3,36,12),(8,37,13))),
    12: (((2,116,92),(2,117,93)), ((6,58,36),(2,59,37)), ((4,46,20),(6,47,21)), ((7,42,14),(4,43,15))),
    13: (((4,133,107),), ((8,59,37),(1,60,38)), ((8,44,20),(4,45,21)), ((12,33,11),(4,34,12))),
    14: (((3,145,115),(1,146,116)), ((4,64,40),(5,65,41)), ((11,36,16),(5,37,17)), ((11,36,12),(5,37,13))),
    15: (((5,109,87),(1,110,88)), ((5,65,41),(5,66,42)), ((5,54,24),(7,55,25)), ((11,36,12),(7,37,13))),
    16: (((5,122,98),(1,123,99)), ((7,73,45),(3,74,46)), ((15,43,19),(2,44,20)), ((3,45,15),(13,46,16))),
    17: (((1,135,107),(5,136,108)), ((10,74,46),(1,75,47)), ((1,50,22),(15,51,23)), ((2,42,14),(17,43,15))),
    18: (((5,150,120),(1,151,121)), ((9,69,43),(4,70,44)), ((17,50,22),(1,51,23)), ((2,42,14),(19,43,15))),
    19: (((3,141,113),(4,142,114)), ((3,70,44),(11,71,45)), ((17,47,21),(4,48,22)), ((9,39,13),(16,40,14))),
    20: (((3,135,107),(5,136,108)), ((3,67,41),(13,68,42)), ((15,54,24),(5,55,25)), ((15,43,15),(10,44,16))),
    21: (((4,144,116),(4,145,117)), ((17,68,42),), ((17,50,22),(6,51,23)), ((19,46,16),(6,47,17))),
    22: (((2,139,111),(7,140,112)), ((17,74,46),), ((7,54,24),(16,55,25)), ((34,37,13),)),
    23: (((4,151,121),(5,152,122)), ((4,75,47),(14,76,48)), ((11,54,24),(14,55,25)), ((16,45,15),(14,46,16))),
    24: (((6,147,117),(4,148,118)), ((6,73,45),(14,74,46)), ((11,54,24),(16,55,25)), ((30,46,16),(2,47,17))),
    25: (((8,132,106),(4,133,107)), ((8,75,47),(13,76,48)), ((7,54,24),(22,55,25)), ((22,45,15),(13,46,16))),
    26: (((10,142,114),(2,143,115)), ((19,74,46),(4,75,47)), ((28,50,22),(6,51,23)), ((33,46,16),(4,47,17))),
    27: (((8,152,122),(4,153,123)), ((22,73,45),(3,74,46)), ((8,53,23),(26,54,24)), ((12,45,15),(28,46,16))),
    28: (((3,147,117),(10,148,118)), ((3,73,45),(23,74,46)), ((4,54,24),(31,55,25)), ((11,45,15),(31,46,16))),
    29: (((7,146,116),(7,147,117)), ((21,73,45),(7,74,46)), ((1,53,23),(37,54,24)), ((19,45,15),(26,46,16))),
    30: (((5,145,115),(10,146,116)), ((19,75,47),(10,76,48)), ((15,54,24),(25,55,25)), ((23,45,15),(25,46,16))),
    31: (((13,145,115),(3,146,116)), ((2,74,46),(29,75,47)), ((42,54,24),(1,55,25)), ((23,45,15),(28,46,16))),
    32: (((17,145,115),), ((10,74,46),(23,75,47)), ((10,54,24),(35,55,25)), ((19,45,15),(35,46,16))),
    33: (((17,145,115),(1,146,116)), ((14,74,46),(21,75,47)), ((29,54,24),(19,55,25)), ((11,45,15),(46,46,16))),
    34: (((13,145,115),(6,146,116)), ((14,74,46),(23,75,47)), ((44,54,24),(7,55,25)), ((59,46,16),(1,47,17))),
    35: (((12,151,121),(7,152,122)), ((12,75,47),(26,76,48)), ((39,54,24),(14,55,25)), ((22,45,15),(41,46,16))),
    36: (((6,151,121),(14,152,122)), ((6,75,47),(34,76,48)), ((46,54,24),(10,55,25)), ((2,45,15),(64,46,16))),
    37: (((17,152,122),(4,153,123)), ((29,74,46),(14,75,47)), ((49,54,24),(10,55,25)), ((24,45,15),(46,46,16))),
    38: (((4,152,122),(18,153,123)), ((13,74,46),(32,75,47)), ((48,54,24),(14,55,25)), ((42,45,15),(32,46,16))),
    39: (((20,147,117),(4,148,118)), ((40,75,47),(7,76,48)), ((43,54,24),(22,55,25)), ((10,45,15),(67,46,16))),
    40: (((19,148,118),(6,149,119)), ((18,75,47),(31,76,48)), ((34,54,24),(34,55,25)), ((20,45,15),(61,46,16))),
}

# Row/column coordinates of alignment-pattern centres, versions 2..40.
ALIGNMENT_POS = {
    2:(6,18), 3:(6,22), 4:(6,26), 5:(6,30), 6:(6,34), 7:(6,22,38), 8:(6,24,42),
    9:(6,26,46), 10:(6,28,50), 11:(6,30,54), 12:(6,32,58), 13:(6,34,62),
    14:(6,26,46,66), 15:(6,26,48,70), 16:(6,26,50,74), 17:(6,30,54,78),
    18:(6,30,56,82), 19:(6,30,58,86), 20:(6,34,62,90), 21:(6,28,50,72,94),
    22:(6,26,50,74,98), 23:(6,30,54,78,102), 24:(6,28,54,80,106),
    25:(6,32,58,84,110), 26:(6,30,58,86,114), 27:(6,34,62,90,118),
    28:(6,26,50,74,98,122), 29:(6,30,54,78,102,126), 30:(6,26,52,78,104,130),
    31:(6,30,56,82,108,134), 32:(6,34,60,86,112,138), 33:(6,30,58,86,114,142),
    34:(6,34,62,90,118,146), 35:(6,30,54,78,102,126,150),
    36:(6,24,50,76,102,128,154), 37:(6,28,54,80,106,132,158),
    38:(6,32,58,84,110,136,162), 39:(6,26,54,82,110,138,166),
    40:(6,30,58,86,114,142,170),
}

# EC level indicator value -> name.  These ARE the two bits stored in the
# format information, which is why the order looks scrambled.
ECL_NAME = {1: "L", 0: "M", 3: "Q", 2: "H"}
ECL_INDEX = {1: 0, 0: 1, 3: 2, 2: 3}          # into ECC_TABLE's (L, M, Q, H)

FINDER = ("1111111", "1000001", "1011101", "1011101", "1011101", "1000001", "1111111")

MASK_FUNCS = (
    lambda r, c: (r + c) % 2 == 0,
    lambda r, c: r % 2 == 0,
    lambda r, c: c % 3 == 0,
    lambda r, c: (r + c) % 3 == 0,
    lambda r, c: (r // 2 + c // 3) % 2 == 0,
    lambda r, c: (r * c) % 2 + (r * c) % 3 == 0,
    lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
    lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0,
)

ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


# --------------------------------------------------------------------------- #
#  GF(256) and Reed-Solomon with erasures                                      #
# --------------------------------------------------------------------------- #

class RSError(Exception):
    pass


_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D                      # QR's primitive polynomial
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def gf_mul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def gf_div(a, b):
    if b == 0:
        raise ZeroDivisionError
    return 0 if a == 0 else _EXP[(_LOG[a] - _LOG[b]) % 255]


def gf_pow(a, n):
    return _EXP[(_LOG[a] * n) % 255]


def gf_inv(a):
    return _EXP[255 - _LOG[a]]


def poly_scale(p, x):
    return [gf_mul(c, x) for c in p]


def poly_add(p, q):
    r = [0] * max(len(p), len(q))
    for i, c in enumerate(p):
        r[i + len(r) - len(p)] = c
    for i, c in enumerate(q):
        r[i + len(r) - len(q)] ^= c
    return r


def poly_mul(p, q):
    r = [0] * (len(p) + len(q) - 1)
    for j, b in enumerate(q):
        if b:
            for i, a in enumerate(p):
                r[i + j] ^= gf_mul(a, b)
    return r


def poly_eval(p, x):
    y = 0
    for c in p:
        y = gf_mul(y, x) ^ c
    return y


def rs_syndromes(msg, nsym):
    return [0] + [poly_eval(msg, gf_pow(2, i)) for i in range(nsym)]


def rs_errata_locator(pos):
    loc = [1]
    for p in pos:
        loc = poly_mul(loc, poly_add([1], [gf_pow(2, p), 0]))
    return loc


def rs_error_evaluator(synd, loc, nsym):
    return poly_mul(synd, loc)[-(nsym + 1):]


def rs_correct_errata(msg, synd, pos):
    coef = [len(msg) - 1 - p for p in pos]
    loc = rs_errata_locator(coef)
    ev = rs_error_evaluator(synd[::-1], loc, len(loc) - 1)[::-1]
    X = [gf_pow(2, -(255 - c)) for c in coef]
    E = [0] * len(msg)
    for i, Xi in enumerate(X):
        Xi_inv = gf_inv(Xi)
        denom = 1
        for j, Xj in enumerate(X):
            if j != i:
                denom = gf_mul(denom, 1 ^ gf_mul(Xi_inv, Xj))
        num = poly_eval(ev[::-1], Xi_inv)
        num = gf_mul(gf_pow(Xi, 1), num)
        if denom == 0:
            raise RSError("degenerate errata locator")
        E[pos[i]] = gf_div(num, denom)
    return poly_add(msg, E)


def rs_error_locator(synd, nsym, erase_loc=None, erase_count=0):
    err_loc = list(erase_loc) if erase_loc else [1]
    old_loc = list(erase_loc) if erase_loc else [1]
    shift = len(synd) - nsym if len(synd) > nsym else 0
    for i in range(nsym - erase_count):
        K = (erase_count + i + shift) if erase_loc else (i + shift)
        delta = synd[K]
        for j in range(1, len(err_loc)):
            delta ^= gf_mul(err_loc[-(j + 1)], synd[K - j])
        old_loc = old_loc + [0]
        if delta != 0:
            if len(old_loc) > len(err_loc):
                new_loc = poly_scale(old_loc, delta)
                old_loc = poly_scale(err_loc, gf_inv(delta))
                err_loc = new_loc
            err_loc = poly_add(err_loc, poly_scale(old_loc, delta))
    while err_loc and err_loc[0] == 0:
        err_loc.pop(0)
    errs = len(err_loc) - 1
    if (errs - erase_count) * 2 + erase_count > nsym:
        raise RSError("too many errors to correct")
    return err_loc


def rs_find_errors(err_loc, nmess):
    errs = len(err_loc) - 1
    pos = [nmess - 1 - i for i in range(nmess) if poly_eval(err_loc, gf_pow(2, i)) == 0]
    if len(pos) != errs:
        raise RSError("Chien search failed (%d roots for degree %d)" % (len(pos), errs))
    return pos


def rs_forney_syndromes(synd, pos, nmess):
    rev = [nmess - 1 - p for p in pos]
    f = list(synd[1:])
    for i in range(len(pos)):
        x = gf_pow(2, rev[i])
        for j in range(len(f) - 1):
            f[j] = gf_mul(f[j], x) ^ f[j + 1]
    return f


def rs_decode(msg_in, nsym, erase_pos=()):
    """Return (corrected_codewords, error_positions).  Raises RSError."""
    msg = list(msg_in)
    erase_pos = list(erase_pos)
    if len(erase_pos) > nsym:
        raise RSError("%d erasures exceed the %d correction codewords" % (len(erase_pos), nsym))
    for p in erase_pos:
        msg[p] = 0
    synd = rs_syndromes(msg, nsym)
    if max(synd) == 0:
        return msg, []
    fsynd = rs_forney_syndromes(synd, erase_pos, len(msg))
    err_loc = rs_error_locator(fsynd, nsym, erase_count=len(erase_pos))
    err_pos = rs_find_errors(err_loc[::-1], len(msg))
    out = rs_correct_errata(msg, synd, erase_pos + err_pos)
    if max(rs_syndromes(out, nsym)) > 0:
        raise RSError("decoding did not converge")
    return out, err_pos


# --------------------------------------------------------------------------- #
#  Image -> module grid                                                        #
# --------------------------------------------------------------------------- #

DARK, LIGHT, UNK = 1, 0, -1        # module states; -1 means obscured


def _majority(mask, radius):
    """Keep only pixels whose neighbourhood is mostly set - kills speckle noise."""
    if radius < 1:
        return mask
    ii = np.zeros((mask.shape[0] + 1, mask.shape[1] + 1), np.int32)
    ii[1:, 1:] = np.cumsum(np.cumsum(mask.astype(np.int32), 0), 1)
    H, W = mask.shape
    y = np.arange(H); x = np.arange(W)
    y0 = np.clip(y - radius, 0, H); y1 = np.clip(y + radius + 1, 0, H)
    x0 = np.clip(x - radius, 0, W); x1 = np.clip(x + radius + 1, 0, W)
    s = (ii[np.ix_(y1, x1)] - ii[np.ix_(y0, x1)] - ii[np.ix_(y1, x0)] + ii[np.ix_(y0, x0)])
    area = (y1 - y0)[:, None] * (x1 - x0)[None, :]
    return s * 2 >= area


def classify_pixels(rgb, occl_rgb=None, tolerance=70, sat_thresh=0.33, no_colour=False,
                    smooth=2):
    """Return (dark_mask, light_mask, occluded_mask) as boolean arrays."""
    a = rgb.astype(np.int16)
    mx = a.max(axis=2)
    mn = a.min(axis=2)
    luma = (0.299 * a[..., 0] + 0.587 * a[..., 1] + 0.114 * a[..., 2])

    if no_colour:
        occl = np.zeros(luma.shape, bool)
    elif occl_rgb is not None:
        d = np.sqrt(((a - np.array(occl_rgb)) ** 2).sum(axis=2))
        occl = d <= tolerance
    else:
        # anything appreciably coloured cannot be a printed QR module
        with np.errstate(divide="ignore", invalid="ignore"):
            sat = np.where(mx > 0, (mx - mn) / np.maximum(mx, 1), 0.0)
        occl = (sat >= sat_thresh) & (mx >= 60)
    occl = _majority(occl, smooth)

    thr = _otsu(luma[~occl]) if (~occl).any() else 128
    # Otsu returns the last grey level belonging to the dark class
    dark = (luma <= thr) & ~occl
    light = (luma > thr) & ~occl
    return dark, light, occl


def _otsu(v):
    hist, _ = np.histogram(v, bins=256, range=(0, 256))
    total = hist.sum()
    if total == 0:
        return 128
    s_all = np.dot(np.arange(256), hist)
    s_b = w_b = 0.0
    best, thr = -1.0, 128
    for t in range(256):
        w_b += hist[t]
        if w_b == 0:
            continue
        w_f = total - w_b
        if w_f == 0:
            break
        s_b += t * hist[t]
        m_b = s_b / w_b
        m_f = (s_all - s_b) / w_f
        var = w_b * w_f * (m_b - m_f) ** 2
        if var > best:
            best, thr = var, t
    return thr


def _runs(line):
    """Vectorised run-length encoding -> [(value, start, length), ...]."""
    a = np.asarray(line)
    if a.size == 0:
        return []
    idx = np.flatnonzero(np.diff(a)) + 1
    starts = np.concatenate(([0], idx))
    ends = np.concatenate((idx, [a.size]))
    vals = a[starts]
    return list(zip(vals.tolist(), starts.tolist(), (ends - starts).tolist()))


def find_finders(dark, occl=None):
    """Locate finder-pattern centres by the 1:1:3:1:1 dark/light run signature."""
    h, w = dark.shape
    cands = []
    step = max(1, h // 400)
    for y in range(0, h, step):
        rr = _runs(dark[y])
        for i in range(len(rr) - 4):
            seg = rr[i:i + 5]
            if [bool(s[0]) for s in seg] != [True, False, True, False, True]:
                continue
            ln = [s[2] for s in seg]
            m = float(sum(ln)) / 7.0          # the five runs span exactly 7 modules
            if m < 1.5:
                continue
            ok = (abs(ln[0] - m) <= m * .6 and abs(ln[1] - m) <= m * .6 and
                  abs(ln[2] - 3 * m) <= m * .9 and abs(ln[3] - m) <= m * .6 and
                  abs(ln[4] - m) <= m * .6)
            if not ok:
                continue
            cx = seg[2][1] + seg[2][2] / 2.0
            if _verify_vertical(dark, int(round(cx)), y, m):
                cands.append((cx, y, m))
    # cluster
    groups = []
    for cx, cy, m in cands:
        for g in groups:
            if abs(g[0][0] - cx) < m * 2 and abs(g[0][1] - cy) < m * 4:
                g.append((cx, cy, m))
                break
        else:
            groups.append([(cx, cy, m)])
    out = []
    for g in groups:
        if len(g) < 2:
            continue
        xs = [p[0] for p in g]
        ys = [p[1] for p in g]
        ms = sorted(p[2] for p in g)
        out.append((float(np.median(xs)), (min(ys) + max(ys)) / 2.0,
                    ms[len(ms) // 2], len(g)))
    if not out:
        return []
    strict = [o for o in out if _template_ok(dark, occl, o[0], o[1], o[2])]
    out = strict or out
    med = float(np.median([o[2] for o in out]))
    out = [o for o in out if abs(o[2] - med) <= 0.25 * med] or out
    out.sort(key=lambda o: -o[3])
    return [o[:3] for o in out[:3]]


def _template_ok(dark, occl, cx, cy, m):
    """Demand a textbook 7x7 finder plus the light ring that always surrounds it."""
    H, W = dark.shape
    half = max(1, int(round(m * 0.25)))
    for i in range(-4, 5):
        for j in range(-4, 5):
            y = int(round(cy + i * m)); x = int(round(cx + j * m))
            outer = max(abs(i), abs(j)) == 4
            y0, y1 = max(0, y - half), min(H, y + half + 1)
            x0, x1 = max(0, x - half), min(W, x + half + 1)
            if y1 <= y0 or x1 <= x0:
                if outer:
                    continue            # quiet zone may be cropped away
                return False
            if occl is not None and occl[y0:y1, x0:x1].mean() > 0.5:
                return False
            want = 0 if outer else int(FINDER[i + 3][j + 3])
            if int(dark[y0:y1, x0:x1].mean() >= 0.5) != want:
                return False
    return True


def _verify_vertical(dark, x, y, m):
    h = dark.shape[0]
    if not (0 <= x < dark.shape[1]) or not dark[y, x]:
        return False
    up = y
    while up > 0 and dark[up - 1, x]:
        up -= 1
    dn = y
    while dn < h - 1 and dark[dn + 1, x]:
        dn += 1
    core = dn - up + 1
    if abs(core - 3 * m) > m * 1.2:
        return False
    # light ring
    u2 = up - 1
    n = 0
    while u2 >= 0 and not dark[u2, x]:
        u2 -= 1
        n += 1
    if abs(n - m) > m * .8:
        return False
    d2 = dn + 1
    n = 0
    while d2 < h and not dark[d2, x]:
        d2 += 1
        n += 1
    return abs(n - m) <= m * .8


@dataclass
class Geometry:
    x0: float
    y0: float
    module: float
    n: int
    finders: list = field(default_factory=list)


def locate_symbol(dark, occl=None, forced_n=None):
    fs = find_finders(dark, occl)
    if not fs:
        raise SystemExit("No finder pattern could be located. Is the image an upright QR "
                         "scan? Try --grid to set the geometry manually.")
    m = float(np.median([f[2] for f in fs]))
    left = min(f[0] for f in fs) - 3.5 * m
    right = max(f[0] for f in fs) + 3.5 * m
    top = min(f[1] for f in fs) - 3.5 * m
    bottom = max(f[1] for f in fs) + 3.5 * m
    if len(fs) < 2:
        # only one corner survived - fall back to the extent of the printed ink
        ys, xs = np.where(dark)
        if len(xs):
            left = min(left, xs.min()); right = max(right, xs.max() + 1)
            top = min(top, ys.min()); bottom = max(bottom, ys.max() + 1)
    size = max(right - left, bottom - top)
    n = forced_n or _snap_version_size(size / m)
    return Geometry(left, top, size / n, n, fs)


def _snap_version_size(approx):
    """Nearest legal module count.  choose_grid() re-checks this properly."""
    return min(((abs(approx - (17 + 4 * v)), 17 + 4 * v) for v in range(1, 41)))[1]


def _boxsums(mask, ya, yb, xa, xb):
    """Sum of `mask` over every (row-band x col-band) box, vectorised."""
    ii = np.zeros((mask.shape[0] + 1, mask.shape[1] + 1), np.int64)
    ii[1:, 1:] = np.cumsum(np.cumsum(mask.astype(np.int64), 0), 1)
    return (ii[np.ix_(yb, xb)] - ii[np.ix_(ya, xb)]
            - ii[np.ix_(yb, xa)] + ii[np.ix_(ya, xa)])


def sample_grid(dark, light, occl, geo):
    """Sample the module grid.  Returns int8 array: 1 dark, 0 light, -1 obscured."""
    n, m = geo.n, geo.module
    H, W = dark.shape
    i = np.arange(n)
    ya = np.clip(np.round(geo.y0 + (i + 0.28) * m).astype(int), 0, H - 1)
    yb = np.clip(np.round(geo.y0 + (i + 0.72) * m).astype(int), 0, H)
    xa = np.clip(np.round(geo.x0 + (i + 0.28) * m).astype(int), 0, W - 1)
    xb = np.clip(np.round(geo.x0 + (i + 0.72) * m).astype(int), 0, W)
    yb = np.maximum(yb, ya + 1); xb = np.maximum(xb, xa + 1)
    area = np.maximum(1, (yb - ya)[:, None] * (xb - xa)[None, :])
    d = _boxsums(dark, ya, yb, xa, xb) / area
    l = _boxsums(light, ya, yb, xa, xb) / area
    o = _boxsums(occl, ya, yb, xa, xb) / area
    out = np.where(o >= 0.5, UNK, np.where(d >= l, DARK, LIGHT))
    return out.astype(np.int8)


# --------------------------------------------------------------------------- #
#  Structure of a symbol                                                       #
# --------------------------------------------------------------------------- #

def function_map(n, version):
    f = [[False] * n for _ in range(n)]
    for r in range(n):
        for c in range(n):
            if (r < 9 and c < 9) or (r < 9 and c >= n - 8) or (r >= n - 8 and c < 9):
                f[r][c] = True
            if r == 6 or c == 6:
                f[r][c] = True
    for (ar, ac) in alignment_centres(version, n):
        for i in range(-2, 3):
            for j in range(-2, 3):
                f[ar + i][ac + j] = True
    if version >= 7:
        for i in range(6):
            for j in range(3):
                f[i][n - 11 + j] = True
                f[n - 11 + j][i] = True
    return f


def alignment_centres(version, n):
    if version < 2:
        return []
    pos = ALIGNMENT_POS[version]
    out = []
    for r in pos:
        for c in pos:
            if (r < 9 and c < 9) or (r < 9 and c > n - 10) or (r > n - 10 and c < 9):
                continue
            out.append((r, c))
    return out


def expected_fixed(n, version):
    """Matrix of the modules the standard fixes: value or None."""
    e = [[None] * n for _ in range(n)]
    for (r0, c0) in ((0, 0), (0, n - 7), (n - 7, 0)):
        for i in range(7):
            for j in range(7):
                e[r0 + i][c0 + j] = int(FINDER[i][j])
    for i in range(8):
        e[7][i] = 0; e[i][7] = 0
        e[7][n - 1 - i] = 0; e[i][n - 8] = 0
        e[n - 8][i] = 0; e[n - 1 - i][7] = 0
    for i in range(8, n - 8):
        e[6][i] = 1 if i % 2 == 0 else 0
        e[i][6] = 1 if i % 2 == 0 else 0
    e[n - 8][8] = 1                              # the always-dark module
    for (ar, ac) in alignment_centres(version, n):
        for i in range(-2, 3):
            for j in range(-2, 3):
                e[ar + i][ac + j] = 0 if max(abs(i), abs(j)) == 1 else 1
    return e


def format_positions(n):
    """(copy1, copy2); each is a list of 15 (row, col) from bit 14 down to bit 0."""
    c1 = [(8, i) for i in range(6)] + [(8, 7), (8, 8), (7, 8)] + [(5 - i, 8) for i in range(6)]
    c2 = [(n - 1 - i, 8) for i in range(7)] + [(8, n - 8 + i) for i in range(8)]
    return c1, c2


def valid_formats():
    out = {}
    g = 0b10100110111
    for ecl in range(4):
        for mask in range(8):
            d = (ecl << 3) | mask
            t = d << 10
            while t.bit_length() - 1 >= 10:
                t ^= g << (t.bit_length() - 11)
            out[((d << 10) | t) ^ 0b101010000010010] = (ecl, mask)
    return out


VALID_FORMATS = valid_formats()


def valid_versions():
    out = {}
    g = 0b1111100100101      # x^12+x^11+x^10+x^9+x^8+x^5+x^2+1
    for v in range(7, 41):
        t = v << 12
        while t.bit_length() - 1 >= 12:
            t ^= g << (t.bit_length() - 13)
        out[(v << 12) | t] = v
    return out


VALID_VERSIONS = valid_versions()


def read_format(known, n):
    """Best (ecl, mask, hamming_distance, margin) over both copies."""
    c1, c2 = format_positions(n)
    obs = []
    for pos in (c1, c2):
        obs.append([int(known[r][c]) for (r, c) in pos])
    scores = []
    for val, (ecl, mask) in VALID_FORMATS.items():
        bits = [(val >> (14 - i)) & 1 for i in range(15)]
        d = 0
        for o in obs:
            d += sum(1 for i in range(15) if o[i] != UNK and o[i] != bits[i])
        scores.append((d, val, ecl, mask))
    scores.sort()
    margin = scores[1][0] - scores[0][0]
    return scores[0][2], scores[0][3], scores[0][0], margin, scores[0][1]


def module_order(n, version):
    f = function_map(n, version)
    order = []
    col = n - 1
    up = True
    while col > 0:
        if col == 6:
            col -= 1
        for r in (range(n - 1, -1, -1) if up else range(n)):
            for c in (col, col - 1):
                if not f[r][c]:
                    order.append((r, c))
        up = not up
        col -= 2
    return order


# --------------------------------------------------------------------------- #
#  Orientation search                                                          #
# --------------------------------------------------------------------------- #

def _rot(mat):
    return np.rot90(mat, -1).copy()


def _mirror(mat):
    return np.fliplr(mat).copy()


_FIXED_CACHE = {}


def fixed_index(version):
    """(rows, cols, values) of every module the standard fixes, as arrays."""
    if version not in _FIXED_CACHE:
        n = 17 + 4 * version
        e = expected_fixed(n, version)
        rs, cs, vs = [], [], []
        for r in range(n):
            for c in range(n):
                if e[r][c] is not None:
                    rs.append(r); cs.append(c); vs.append(e[r][c])
        _FIXED_CACHE[version] = (np.array(rs), np.array(cs), np.array(vs, np.int8))
    return _FIXED_CACHE[version]


def score_matrix(mat, version):
    """How well does this sampled matrix agree with the parts the standard fixes?"""
    rs, cs, vs = fixed_index(version)
    got = mat[rs, cs]
    seen = got != UNK
    hits = int(np.count_nonzero(seen & (got == vs)))
    miss = int(np.count_nonzero(seen & (got != vs)))
    _, _, d, _, _ = read_format(mat, len(mat))
    total = max(1, hits + miss)
    return (hits - 3 * miss - 2 * d) / float(total), hits, miss, d


def orient(known, version):
    """Try the 8 rigid transforms and keep the one that fits the standard best."""
    best = None
    for mir in range(2):
        m = _mirror(known) if mir else known
        for rot in range(4):
            s, hits, miss, d = score_matrix(m, version)
            if best is None or s > best[0]:
                best = (s, m, rot, mir, hits, miss, d)
            m = _rot(m)
    return best[1], {"rotations": best[2], "mirrored": bool(best[3]),
                     "fixed_ok": best[4], "fixed_bad": best[5],
                     "format_hamming": best[6], "fit": round(best[0], 4)}


def choose_grid(dark, light, occl, geo, forced_version=None):
    """Pick the module count that actually fits, then the orientation."""
    span = geo.module * geo.n
    if forced_version:
        cands = [forced_version]
    else:
        raw = span / geo.module
        cands = sorted(range(1, 41), key=lambda v: abs(raw - (17 + 4 * v)))[:4]
    best = None
    for v in cands:
        n = 17 + 4 * v
        g = Geometry(geo.x0, geo.y0, span / n, n, geo.finders)
        mat = sample_grid(dark, light, occl, g)
        mat, info = orient(mat, v)
        s, hits, miss, d = score_matrix(mat, v)
        if best is None or s > best[0]:
            best = (s, v, g, mat, info)
    if best is None or best[0] < 0.2:
        raise SystemExit("Could not lock onto the module grid (best fit %.2f). "
                         "Use --grid or --version, or crop the image to the symbol."
                         % (best[0] if best else -1))
    _, v, g, mat, info = best
    info["grid_fit"] = round(best[0], 4)
    return v, g, mat, info


# --------------------------------------------------------------------------- #
#  Decode                                                                      #
# --------------------------------------------------------------------------- #

@dataclass
class Result:
    version: int
    ecl: str
    mask: int
    text: str
    segments: list
    obscured_modules: int
    erased_data_bits: int
    blocks: list
    certain: bool
    notes: list
    matrix: list
    orientation: dict


def decode(known, version, orientation_info):
    n = len(known)
    raw = known.copy()                       # what we actually saw, before repair
    ecl_ind, mask, fdist, fmargin, fval = read_format(known, n)
    ecl = ECL_NAME[ecl_ind]
    notes = []
    if fmargin == 0:
        notes.append("Format information is ambiguous - more than one (EC level, mask) "
                     "combination fits the surviving bits equally well.")
    if fdist:
        notes.append("Format information needed %d bit correction(s)." % fdist)

    # write the recovered format bits back so the rebuilt image is clean
    for pos in format_positions(n):
        for i, (r, c) in enumerate(pos):
            known[r][c] = (fval >> (14 - i)) & 1
    exp = expected_fixed(n, version)
    for r in range(n):
        for c in range(n):
            if exp[r][c] is not None:
                known[r][c] = exp[r][c]
    if version >= 7:
        vval = [k for k, v in VALID_VERSIONS.items() if v == version][0]
        for i in range(6):
            for j in range(3):
                bit = (vval >> (i * 3 + j)) & 1
                known[i][n - 11 + j] = bit
                known[n - 11 + j][i] = bit

    order = module_order(n, version)
    mf = MASK_FUNCS[mask]
    bits, erased_bits = [], []
    for i, (r, c) in enumerate(order):
        v = int(known[r][c])
        if v == UNK:
            bits.append(0)
            erased_bits.append(i)
        else:
            bits.append(v ^ (1 if mf(r, c) else 0))

    groups = ECC_TABLE[version][ECL_INDEX[ecl_ind]]
    total_cw = sum(g[0] * g[1] for g in groups)
    if len(bits) // 8 < total_cw:
        raise SystemExit("Grid does not hold enough codewords - version/geometry is wrong.")
    stream = [int("".join(str(b) for b in bits[i * 8:i * 8 + 8]), 2) for i in range(total_cw)]
    erased_cw = sorted({i // 8 for i in erased_bits if i // 8 < total_cw})

    # de-interleave
    blk_data_len, blk_ec_len = [], []
    for nb, tot, dat in groups:
        for _ in range(nb):
            blk_data_len.append(dat)
            blk_ec_len.append(tot - dat)
    nblocks = len(blk_data_len)
    n_data = sum(blk_data_len)
    dblocks = [[] for _ in range(nblocks)]
    eblocks = [[] for _ in range(nblocks)]
    dmap = [[] for _ in range(nblocks)]
    emap = [[] for _ in range(nblocks)]
    idx = 0
    for k in range(max(blk_data_len)):
        for b in range(nblocks):
            if k < blk_data_len[b]:
                dblocks[b].append(stream[idx]); dmap[b].append(idx); idx += 1
    for k in range(max(blk_ec_len)):
        for b in range(nblocks):
            if k < blk_ec_len[b]:
                eblocks[b].append(stream[idx]); emap[b].append(idx); idx += 1

    # RS decode block by block
    certain = True
    binfo = []
    fixed_data = []
    for b in range(nblocks):
        cw = dblocks[b] + eblocks[b]
        pos = dmap[b] + emap[b]
        er = [i for i, p in enumerate(pos) if p in set(erased_cw)]
        nsym = blk_ec_len[b]
        try:
            out, errpos = rs_decode(cw, nsym, er)
        except RSError as e:
            raise SystemExit("Block %d could not be corrected: %s\n"
                             "Too much of the symbol is destroyed." % (b + 1, e))
        # write corrected codewords back into the interleaved stream
        for i, p in enumerate(pos):
            stream[p] = out[i]
        fixed_data.append(out[:blk_data_len[b]])
        bound_ok = 2 * len(errpos) + len(er) <= nsym
        certain &= bound_ok
        binfo.append({"block": b + 1, "data_cw": blk_data_len[b], "ec_cw": nsym,
                      "erasures": len(er), "errors": len(errpos),
                      "capacity": nsym, "used": 2 * len(errpos) + len(er),
                      "within_bound": bound_ok})

    # the message is the concatenation of the corrected blocks, in block order
    data = [cw for blk in fixed_data for cw in blk]

    text, segs = parse_segments(data, version)

    # rebuild a perfect matrix from the corrected stream
    matrix = known.copy()
    allbits = "".join(format(b, "08b") for b in stream)
    for i, (r, c) in enumerate(order):
        b = int(allbits[i]) if i < len(allbits) else 0
        matrix[r][c] = b ^ (1 if mf(r, c) else 0)

    # Independent check: everything we could actually see must agree with the
    # reconstruction.  A disagreement means a misread module - or a wrong answer.
    mm = (raw != UNK) & (raw != matrix)
    mismatch = list(zip(*np.nonzero(mm)))
    if mismatch:
        certain = False
        notes.append("%d visible module(s) disagree with the reconstruction "
                     "(first at row %d, col %d). The sampling grid or the payload is wrong."
                     % (len(mismatch), mismatch[0][0], mismatch[0][1]))
    orientation_info["visible_mismatches"] = len(mismatch)

    return Result(version, ecl, mask, text, segs,
                  orientation_info.get("obscured_total", len(erased_bits)),
                  len(erased_bits), binfo, certain, notes, matrix, orientation_info)


def parse_segments(data, version):
    bs = "".join(format(b, "08b") for b in data)
    p = 0
    out, segs = "", []
    enc = "iso-8859-1"

    def cnt_bits(mode):
        if version <= 9:
            return {1: 10, 2: 9, 4: 8, 8: 8}[mode]
        if version <= 26:
            return {1: 12, 2: 11, 4: 16, 8: 10}[mode]
        return {1: 14, 2: 13, 4: 16, 8: 12}[mode]

    while p + 4 <= len(bs):
        mode = int(bs[p:p + 4], 2); p += 4
        if mode == 0:
            segs.append(("TERMINATOR", 0, ""))
            break
        if mode == 7:                                # ECI
            b0 = int(bs[p:p + 8], 2)
            if b0 >> 7 == 0:
                eci = b0 & 0x7F; p += 8
            elif b0 >> 6 == 0b10:
                eci = int(bs[p:p + 16], 2) & 0x3FFF; p += 16
            else:
                eci = int(bs[p:p + 24], 2) & 0x1FFFFF; p += 24
            enc = {3: "iso-8859-1", 20: "shift_jis", 26: "utf-8", 27: "ascii",
                   28: "big5", 29: "gb18030", 30: "euc_kr"}.get(eci, enc)
            segs.append(("ECI", eci, enc))
            continue
        if mode in (5, 9):                           # FNC1
            segs.append(("FNC1", mode, ""))
            if mode == 9:
                p += 8
            continue
        if mode == 3:                                # structured append
            segs.append(("STRUCTURED-APPEND", 0, bs[p:p + 20])); p += 20
            continue
        if mode not in (1, 2, 4, 8):
            segs.append(("UNKNOWN-MODE", mode, "")); break
        nb = cnt_bits(mode)
        cnt = int(bs[p:p + nb], 2); p += nb
        if mode == 1:
            s, i = "", 0
            while i < cnt:
                k = min(3, cnt - i)
                w = {1: 4, 2: 7, 3: 10}[k]
                s += str(int(bs[p:p + w], 2)).zfill(k); p += w; i += k
            segs.append(("NUMERIC", cnt, s)); out += s
        elif mode == 2:
            s, i = "", 0
            while i + 1 < cnt:
                v = int(bs[p:p + 11], 2); p += 11
                s += ALNUM[v // 45] + ALNUM[v % 45]; i += 2
            if i < cnt:
                s += ALNUM[int(bs[p:p + 6], 2)]; p += 6
            segs.append(("ALPHANUMERIC", cnt, s)); out += s
        elif mode == 4:
            raw = bytes(int(bs[p + 8 * i:p + 8 * i + 8], 2) for i in range(cnt)); p += 8 * cnt
            try:
                s = raw.decode(enc)
            except Exception:
                s = raw.decode("iso-8859-1")
            segs.append(("BYTE", cnt, s)); out += s
        else:
            s = ""
            for _ in range(cnt):
                v = int(bs[p:p + 13], 2); p += 13
                v = (v // 0xC0) * 256 + v % 0xC0
                v += 0x8140 if v < 0x1F00 else 0xC140
                try:
                    s += bytes([v >> 8, v & 0xFF]).decode("shift_jis")
                except Exception:
                    s += "?"
            segs.append(("KANJI", cnt, s)); out += s
    return out, segs


# --------------------------------------------------------------------------- #
#  Output                                                                      #
# --------------------------------------------------------------------------- #

def render(matrix, scale=8, quiet=4, path="rebuilt.png"):
    a = (255 - 255 * np.asarray(matrix).astype(np.uint8)).astype(np.uint8)
    a = np.pad(a, quiet, constant_values=255)
    a = np.kron(a, np.ones((scale, scale), np.uint8))
    Image.fromarray(a).save(path)
    return path


def report(res: Result, geo: Geometry, path=None):
    L = []
    A = L.append
    A("=" * 68)
    A("  QR RECOVERY REPORT")
    A("=" * 68)
    A("Symbol            : version %d  (%dx%d modules)" % (res.version, len(res.matrix), len(res.matrix)))
    A("Error correction  : level %s" % res.ecl)
    A("Data mask         : %d" % res.mask)
    A("Module pitch      : %.3f px   origin (%.1f, %.1f)" % (geo.module, geo.x0, geo.y0))
    A("Finders located   : %d of 3" % len(geo.finders))
    A("Orientation       : %d x 90deg%s" % (res.orientation["rotations"],
                                            ", mirrored" if res.orientation["mirrored"] else ""))
    A("Structure fit     : %.3f  (1.0 = every visible fixed module as the standard says)"
      % res.orientation.get("grid_fit", res.orientation.get("fit", 0)))
    A("Visible conflicts : %d module(s) read differently from the reconstruction"
      % res.orientation.get("visible_mismatches", 0))
    A("Obscured modules  : %d total; %d of them sit in the data/EC area"
      % (res.obscured_modules, res.erased_data_bits))
    A("")
    A("Reed-Solomon per block")
    A("  blk  data  ec   erasures  errors   budget(2e+E<=n)")
    for b in res.blocks:
        A("  %3d  %4d  %3d  %8d  %6d   %3d/%-3d %s"
          % (b["block"], b["data_cw"], b["ec_cw"], b["erasures"], b["errors"],
             b["used"], b["capacity"], "OK" if b["within_bound"] else "OVER"))
    A("")
    A("Verdict           : %s" % ("CERTAIN - every block decoded inside the unique-decoding "
                                  "bound, so no other message could produce this symbol."
                                  if res.certain else
                                  "UNCERTAIN - a block exceeded the unique-decoding bound. "
                                  "Treat the payload as a best guess."))
    for nte in res.notes:
        A("Note              : " + nte)
    A("")
    A("Segments")
    for kind, cnt, val in res.segments:
        A("  %-18s %4s  %s" % (kind, cnt if cnt else "", (val[:60] + "...") if len(str(val)) > 60 else val))
    A("")
    A("-" * 68)
    A("PAYLOAD:")
    A(res.text)
    A("-" * 68)
    txt = "\n".join(L)
    if path:
        with open(path, "w") as fh:
            fh.write(txt + "\n")
    return txt


def grid_text(known):
    return "\n".join("".join("#" if v == 1 else ("." if v == 0 else "?") for v in row)
                     for row in np.asarray(known).tolist())


# --------------------------------------------------------------------------- #
#  RGB-packed symbols - three codes stacked in the colour channels             #
# --------------------------------------------------------------------------- #
#
# A favourite trick in forensics exercises: take three separate QR codes, put
# one in the red channel, one in the green and one in the blue, and save the
# result as a single colour PNG.  Every pixel is then one of the eight pure RGB
# corner colours, and no ordinary reader sees anything but noise.  Splitting the
# channels gives three perfectly ordinary symbols back - which may of course
# each have their finder patterns erased, which is what the rest of this file
# is for.

CHANNEL_NAMES = ("red", "green", "blue")


def detect_packed(rgb, purity=0.98, near=40):
    """True when the image is essentially the eight pure RGB corner colours and
    the three channels are not all identical."""
    a = rgb.astype(np.int16)
    pure = (np.minimum(a, 255 - a) <= near).all(axis=2)
    if pure.mean() < purity:
        return False
    b = a >= 128
    return not (np.array_equal(b[..., 0], b[..., 1]) and
                np.array_equal(b[..., 1], b[..., 2]))


def packed_modules(rgb, tol=0.02):
    """Sample the module grid of a packed image.

    Packed symbols are synthetic: axis aligned, one exact module pitch, no
    perspective.  So rather than hunting for finder patterns - which may have
    been erased in every channel - measure the pitch from the run lengths and
    keep the grid that actually reproduces the image.

    Returns (n, bools) with bools[r, c, channel] True where the channel is
    bright, or (None, None) if no grid fits.
    """
    b = rgb.astype(np.int16) >= 128
    H, W = b.shape[:2]
    packed = b[..., 0] | (b[..., 1] << 1) | (b[..., 2] << 2)

    def take(n):
        ys = np.clip((np.arange(n) * (H / n) + H / (2 * n)).astype(int), 0, H - 1)
        xs = np.clip((np.arange(n) * (W / n) + W / (2 * n)).astype(int), 0, W - 1)
        return b[np.ix_(ys, xs)]

    # Module pitch from run lengths.  Ignore lengths that account for a
    # negligible share of the image: a scaled PNG leaves 1px seams at module
    # boundaries, and those must not be mistaken for the pitch.
    lens = []
    for line in list(packed[::max(1, H // 64)]) + list(packed.T[::max(1, W // 64)]):
        idx = np.flatnonzero(np.diff(line)) + 1
        lens.append(np.diff(np.concatenate(([0], idx, [line.size]))))
    runs = np.concatenate(lens) if lens else np.array([], int)
    if runs.size == 0:
        return None, None
    counts = np.bincount(runs)
    covered = counts * np.arange(counts.size)
    significant = np.flatnonzero(covered >= 0.05 * covered.sum())
    if significant.size == 0:
        return None, None
    units = {int(significant[0]), int(counts.argmax()), int(np.median(runs))}

    cands, seen = [], set()
    for u in sorted(units):
        n0 = int(round(W / max(1, u)))
        for d in range(-4, 5):
            n = n0 + d
            if 21 <= n <= 400 and n not in seen:
                seen.add(n)
                cands.append((abs(d), n))
    for _, n in sorted(cands):
        if H / n < 1 or W / n < 1:
            continue
        yi = np.clip(np.arange(H) * n // H, 0, n - 1)
        xi = np.clip(np.arange(W) * n // W, 0, n - 1)
        if (take(n)[np.ix_(yi, xi)] != b).any(axis=2).mean() < tol:
            return n, take(n)
    return None, None


def packed_symbol_box(mods):
    """Locate the symbol inside the sampled grid: (row0, col0, size)."""
    n = mods.shape[0]
    diff = (mods != mods[0, 0]).any(axis=2)          # differs from the quiet zone
    if not diff.any():
        return 0, 0, n
    ys, xs = np.nonzero(diff)
    r0, c0 = int(ys.min()), int(xs.min())
    span = max(int(ys.max()) - r0, int(xs.max()) - c0) + 1
    legal = [17 + 4 * v for v in range(1, 41)]
    size = min(legal, key=lambda s: abs(s - span))
    r0 = max(0, min(r0, n - size))
    c0 = max(0, min(c0, n - size))
    return r0, c0, size


def blank_erased_finders(mat):
    """Mark any finder-plus-separator corner that is uniformly light as unknown.

    A blank corner is not a light corner: it is a corner somebody deleted.
    Calling it unknown keeps it out of the structure score, and decode() puts
    the standard's own modules back in its place.
    """
    n = len(mat)
    for r0, c0 in ((0, 0), (0, n - 8), (n - 8, 0)):
        if not mat[r0:r0 + 8, c0:c0 + 8].any():
            mat[r0:r0 + 8, c0:c0 + 8] = UNK
    return mat


def packed_channel_matrix(mods, r0, c0, size, ci, version):
    """Best matrix for one channel, choosing the polarity that fits the standard."""
    sub = mods[r0:r0 + size, c0:c0 + size, ci]
    best = None
    for bright_is_dark in (True, False):
        m = np.where(sub == bright_is_dark, DARK, LIGHT).astype(np.int8)
        m = blank_erased_finders(m)
        m, info = orient(m, version)
        s = score_matrix(m, version)[0]
        if best is None or s > best[0]:
            info["bright_modules_are_dark"] = bool(bright_is_dark)
            best = (s, m, info)
    return best[1], best[2]


def recover_packed(rgb, args):
    """Decode every channel of an RGB-packed image.  Returns a list of
    (channel_name, Result or None, error message or None), or None if the image
    turns out not to be a packed symbol after all."""
    n, mods = packed_modules(rgb)
    if n is None:
        return None
    r0, c0, size = packed_symbol_box(mods)
    version = (size - 17) // 4
    if not 1 <= version <= 40:
        return None
    if args.version and args.version != version:
        version = args.version
        size = 17 + 4 * version
    out = []
    for ci, name in enumerate(CHANNEL_NAMES):
        mat, info = packed_channel_matrix(mods, r0, c0, size, ci, version)
        info["obscured_total"] = int(np.count_nonzero(mat == UNK))
        info["packed_grid"] = "%d modules, symbol %dx%d at (%d,%d)" % (n, size, size, r0, c0)
        try:
            out.append((name, decode(mat, version, info), None))
        except SystemExit as exc:
            out.append((name, None, str(exc)))
    return out


# --------------------------------------------------------------------------- #

def print_packed(results, args):
    """Report an RGB-packed image: one symbol per colour channel."""
    ok = 0
    lines = []
    for name, res, err in results:
        if res is None:
            lines.append("%-6s : FAILED - %s" % (name, err.replace("\n", " ")))
            continue
        ok += 1
        lines.append("%-6s : %s%s" % (name, res.text,
                                      "" if res.certain else "   [UNCERTAIN]"))
        if args.rebuild:
            stem = args.rebuild[:-4] if args.rebuild.lower().endswith(".png") else args.rebuild
            render(res.matrix, path="%s-%s.png" % (stem, name))
    if args.quiet:
        for name, res, err in results:
            if res is not None:
                print(res.text)
        return 0 if ok else 1

    print("=" * 68)
    print("  RGB-PACKED SYMBOL - three codes, one per colour channel")
    print("=" * 68)
    for name, res, err in results:
        if res is None:
            continue
        print("%-6s : version %d, level %s, mask %d, %d obscured module(s), %s"
              % (name, res.version, res.ecl, res.mask, res.obscured_modules,
                 "CERTAIN" if res.certain else "UNCERTAIN"))
    print("-" * 68)
    print("PAYLOADS:")
    for line in lines:
        print("  " + line)
    print("-" * 68)
    if args.rebuild:
        stem = args.rebuild[:-4] if args.rebuild.lower().endswith(".png") else args.rebuild
        print("Repaired symbols written to %s-{red,green,blue}.png" % stem)
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Recover the payload of a damaged or redacted QR code.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Obscured modules are treated as Reed-Solomon erasures, which doubles the\n"
               "correcting power compared with an ordinary scanner.")
    ap.add_argument("image")
    ap.add_argument("--occlusion", metavar="HEX",
                    help="colour of the redaction, e.g. '#2a81fc'. Default: auto-detect "
                         "any strongly coloured pixels.")
    ap.add_argument("--tolerance", type=float, default=70,
                    help="RGB distance for --occlusion matching (default 70)")
    ap.add_argument("--smooth", type=int, default=2,
                    help="speckle filter radius for the redaction mask (default 2, 0 = off)")
    ap.add_argument("--no-colour-occlusion", action="store_true",
                    help="treat every pixel as readable ink or paper (no redaction layer)")
    ap.add_argument("--version", type=int, help="force the symbol version (1-40)")
    ap.add_argument("--grid", metavar="X0,Y0,MODULE,N",
                    help="bypass detection and give the grid directly")
    ap.add_argument("--rebuild", metavar="PNG", default="rebuilt.png",
                    help="where to write the repaired, scannable QR (default rebuilt.png)")
    ap.add_argument("--report", metavar="TXT", help="also write the report to a file")
    ap.add_argument("--grid-dump", metavar="TXT", help="write the sampled module grid")
    ap.add_argument("--json", metavar="JSON", help="write machine-readable results")
    ap.add_argument("--no-split", action="store_true",
                    help="do not treat an 8-colour image as three codes packed into "
                         "the R, G and B channels")
    ap.add_argument("--quiet", action="store_true", help="print only the payload")
    args = ap.parse_args(argv)

    rgb = np.array(Image.open(args.image).convert("RGB"))

    if not args.no_split and detect_packed(rgb):
        packed = recover_packed(rgb, args)
        if packed:
            return print_packed(packed, args)

    occ = None
    if args.occlusion:
        h = args.occlusion.lstrip("#")
        occ = tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
    dark, light, occl = classify_pixels(rgb, occ, args.tolerance,
                                        no_colour=args.no_colour_occlusion,
                                        smooth=args.smooth)

    if args.grid:
        x0, y0, m, n = args.grid.split(",")
        geo = Geometry(float(x0), float(y0), float(m), int(n))
        version = (n_int := int(n) - 17) // 4
        if not 1 <= version <= 40:
            sys.exit("--grid gave %s modules, which is not a valid QR size." % n)
        known = sample_grid(dark, light, occl, geo)
        known, oinfo = orient(known, version)
    else:
        geo = locate_symbol(dark, occl,
                            17 + 4 * args.version if args.version else None)
        version, geo, known, oinfo = choose_grid(dark, light, occl, geo, args.version)
    oinfo["obscured_total"] = int(np.count_nonzero(known == UNK))
    if args.grid_dump:
        with open(args.grid_dump, "w") as fh:
            fh.write(grid_text(known) + "\n")

    res = decode(known, version, oinfo)
    txt = report(res, geo, args.report)
    if args.quiet:
        print(res.text)
    else:
        print(txt)
    if args.rebuild:
        render(res.matrix, path=args.rebuild)
        if not args.quiet:
            print("Repaired symbol written to %s" % args.rebuild)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"payload": res.text, "version": res.version, "ec_level": res.ecl,
                       "mask": res.mask, "certain": res.certain, "blocks": res.blocks,
                       "obscured_modules": res.obscured_modules,
                       "segments": [[k, c, v] for k, c, v in res.segments],
                       "notes": res.notes}, fh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
