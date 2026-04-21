#!/usr/bin/env python3
"""
07_luhn_filter.py -- validate candidate credit card (PAN), ABA routing
numbers, and NPIs using the appropriate checksum. Produces an index the
join step uses to mark findings as luhn_valid=true/false.

Output: $OUT/luhn_index.tsv  (unc_path, detector, raw, valid)
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys
from pathlib import Path

OUT = Path(os.environ.get("OUT") or sys.exit("OUT env var unset"))
MANIFEST = OUT / "manifest.tsv"
TH_SRC = OUT / "th_src.jsonl"
TH_OCR = OUT / "th_ocr.jsonl"
INDEX = OUT / "luhn_index.tsv"

PAN_DETECTOR = "Credit Card PAN"
ABA_DETECTOR = "US ABA Routing Number"
NPI_DETECTOR = "US NPI"
CHECKSUM_DETECTORS = (PAN_DETECTOR, ABA_DETECTOR, NPI_DETECTOR)


def luhn_ok(digits: str) -> bool:
    """Standard Luhn mod-10 checksum, used for PAN validation."""
    if not digits or not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def aba_ok(digits: str) -> bool:
    """
    ABA routing number checksum. Must be exactly 9 digits.
    3*(d1+d4+d7) + 7*(d2+d5+d8) + (d3+d6+d9) must be a multiple of 10.
    """
    if len(digits) != 9 or not digits.isdigit():
        return False
    d = [int(c) for c in digits]
    s = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])
    return s % 10 == 0


def npi_ok(digits: str) -> bool:
    # CMS NPI check digit: prepend Issuer ID "80840" to the 10-digit NPI
    # and the 15-digit string must satisfy standard Luhn mod-10.
    if len(digits) != 10 or not digits.isdigit():
        return False
    return luhn_ok("80840" + digits)


def load_manifest() -> dict[str, str]:
    """path -> UNC"""
    m: dict[str, str] = {}
    if not MANIFEST.exists():
        return m
    with MANIFEST.open() as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 6:
                continue
            sha, size, mtime, unc, src, mirror = parts[:6]
            m[src] = unc
            m[mirror] = unc
    return m


def iter_candidates(path: Path):
    if not path.exists():
        return
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            det = rec.get("DetectorName") or rec.get("DetectorType") or ""
            if det not in CHECKSUM_DETECTORS:
                continue
            file_path = (
                rec.get("SourceMetadata", {})
                .get("Data", {})
                .get("Filesystem", {})
                .get("file")
            )
            raw = (rec.get("Raw") or rec.get("RawV2") or "").strip()
            if not file_path or not raw:
                continue
            yield det, file_path, raw


def main() -> int:
    manifest = load_manifest()
    rows = []
    for source in (TH_SRC, TH_OCR):
        for det, path, raw in iter_candidates(source):
            unc = manifest.get(path, path)
            digits = re.sub(r"\D", "", raw)
            if det == PAN_DETECTOR:
                valid = luhn_ok(digits)
            elif det == ABA_DETECTOR:
                valid = aba_ok(digits)
            else:  # NPI
                valid = npi_ok(digits)
            rows.append((unc, det, raw, valid))

    with INDEX.open("w", newline="") as out:
        w = csv.writer(out, delimiter="\t")
        w.writerow(["unc_path", "detector", "raw", "valid"])
        for unc, det, raw, valid in rows:
            w.writerow([unc, det, raw, "true" if valid else "false"])

    n_valid = sum(1 for *_, v in rows if v)
    print(f"[luhn] wrote {INDEX} ({len(rows)} candidates, {n_valid} valid)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
