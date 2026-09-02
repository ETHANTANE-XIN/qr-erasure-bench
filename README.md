# QR Erasure Bench

**Live tool: https://ethantane-xin.github.io/qr-erasure-bench/**

Recovers the payload of a QR Code whose image has been scribbled over, torn,
stained or deliberately redacted. Ordinary readers give up the moment a finder
pattern is covered; this rebuilds every module the standard fixes by definition
and decodes the painted-over data modules as **Reed–Solomon erasures**.

Two front ends over one algorithm:

| | |
|---|---|
| `index.html` | The web bench. Pure client-side JavaScript, no build step, no upload — open the link, drop an image in. |
| `qrrecover.py` | Offline CLI with a full report, JSON output and a repaired PNG. |

## Why erasures

Covering a corner destroys nothing that ISO/IEC 18004 does not already specify.
Finder patterns, separators, timing rows, alignment patterns and one of the two
format-information copies are all recoverable from the surviving corners. Rebuild
those, and every remaining obscured module becomes an error whose *position* is
known — an erasure.

| Correctable per block, `n` EC codewords | |
|---|---|
| Errors (position unknown) | `n / 2` |
| Erasures (position known) | `n` |

Twice the correcting power an ordinary scanner gets, and enough information to
say whether the answer is proven or merely likely.

## CLI

```bash
pip install pillow numpy
python qrrecover.py secret.png
```

```
python qrrecover.py secret.png --quiet                # payload only
python qrrecover.py scan.png   --occlusion "#2a81fc"  # name the marker colour
python qrrecover.py scan.png   --no-colour-occlusion  # black or grey redaction
python qrrecover.py scan.png   --version 4            # pin the version
python qrrecover.py scan.png   --grid 759,546,29.15,33
python qrrecover.py scan.png   --report r.txt --json r.json --grid-dump g.txt
```

| Option | Purpose |
|---|---|
| `--occlusion HEX` | exact redaction colour; default auto-detects any strongly coloured pixels |
| `--tolerance N` | RGB distance for `--occlusion` (default 70) |
| `--smooth N` | speckle-filter radius for the redaction mask (default 2, `0` off) |
| `--no-colour-occlusion` | treat every pixel as ink or paper |
| `--version N` | pin the symbol version (1–40) |
| `--grid X0,Y0,MODULE,N` | bypass detection entirely |
| `--rebuild PNG` | repaired, scannable symbol (default `rebuilt.png`) |
| `--report` / `--json` / `--grid-dump` | text report, machine-readable results, sampled module grid |

## Reading the verdict

```
Structure fit     : 1.000   every visible fixed module matches the standard
Visible conflicts : 0       the reconstruction agrees with everything we could see
Obscured modules  : 100 total; 25 of them sit in the data/EC area

  blk  data  ec   erasures  errors   budget(2e+E<=n)
    1    80   20         6       0     6/20  OK

Verdict           : CERTAIN
```

**CERTAIN** — every block decoded inside the unique-decoding bound
(`2 × errors + erasures ≤ ec_codewords`) *and* the re-encoded symbol agrees with
every module that was actually visible. No other message could have produced
this image.

**UNCERTAIN / PROBABLE** — a block went past that bound, or a visible module
disagrees with the reconstruction. Treat the payload as a lead, not evidence.

When the damage exceeds the correcting capacity the tool refuses rather than
inventing an answer.

## Coverage

Versions 1–40, all four error-correction levels, all eight data masks,
multi-block interleaving, numeric / alphanumeric / byte / kanji / ECI / FNC1 /
structured-append segments, any 90° rotation, mirrored symbols, missing quiet
zone, JPEG artefacts, sensor noise and rescaled scans.

Both front ends assume the symbol is **upright and not perspective-distorted** —
deskew a photograph first. A redaction drawn in black ink is indistinguishable
from dark modules, so use `--no-colour-occlusion` (or the *None* setting in the
web tool) and fall back to ordinary error correction.

## Tests

```bash
pip install segno                 # test-only, builds the reference symbols
python tests/test_qrrecover.py    # 158 round trips: every version x every EC level
python tests/test_robust.py       # noise, JPEG, rescale, crop, colour variations
```

`tests/test_qrrecover.py` also asserts the property that matters for forensic
use: the tool never reports **CERTAIN** with a wrong payload. Set `DAMAGE=0.30`
to raise the fraction of each symbol destroyed.

## Licence

MIT.
