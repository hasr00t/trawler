#!/usr/bin/env python3
"""
06_join.py -- merge TruffleHog + Presidio findings, the manifest, and
the ACL snapshot into a single CSV keyed on UNC path.

Inputs (all in $OUT, except ACL which is optional):
  manifest.tsv           from 01_crawl.sh
  th_src.jsonl           from 03_scan_trufflehog.sh (source mount pass)
  th_ocr.jsonl           from 03_scan_trufflehog.sh (OCR mirror pass)
  presidio.jsonl         from 04_scan_presidio.py (optional)
  luhn_index.tsv         from 07_luhn_filter.py   (optional; enriches PAN)
  acls.tsv               from 05_acl_snapshot.ps1 (optional; from Windows)

Output:
  $OUT/findings.csv      one row per finding, redacted match excerpt, joined
                         with ACL exposure classification.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

OUT = Path(os.environ.get("OUT") or sys.exit("OUT env var unset"))
MOUNT = os.environ.get("MOUNT") or sys.exit("MOUNT env var unset")
MIRROR = os.environ.get("MIRROR") or sys.exit("MIRROR env var unset")

MANIFEST = OUT / "manifest.tsv"
TH_SRC = OUT / "th_src.jsonl"
TH_OCR = OUT / "th_ocr.jsonl"
PRESIDIO = OUT / "presidio.jsonl"
LUHN = OUT / "luhn_index.tsv"
ACLS = OUT / "acls.tsv"
FINDINGS_CSV = OUT / "findings.csv"

# --- ACL classification -------------------------------------------------
# These identity names indicate "effectively public" in most enterprises.
PUBLIC = {
    "Everyone",
    "NT AUTHORITY\\Authenticated Users",
    "BUILTIN\\Users",
    "Authenticated Users",
    "Users",
}
# Wide exposure: big groups that aren't quite "everyone" but are close.
WIDE_PATTERNS = [
    re.compile(r"(?i)domain users$"),
    re.compile(r"(?i)all[- ]employees"),
    re.compile(r"(?i)all staff"),
]


def classify_acl(principals: list[str]) -> str:
    if not principals:
        return "unknown"
    for p in principals:
        if p in PUBLIC:
            return "public"
    for p in principals:
        for pat in WIDE_PATTERNS:
            if pat.search(p):
                return "wide"
    # Heuristic: many principals -> team-level; few -> restricted
    distinct = {p for p in principals if not p.startswith(("NT AUTHORITY", "BUILTIN"))}
    if len(distinct) >= 10:
        return "team"
    return "restricted"


# --- Loaders ------------------------------------------------------------
def load_manifest() -> dict[str, dict]:
    """Key by source path AND mirror path so both TruffleHog passes resolve."""
    by_path: dict[str, dict] = {}
    cols = ["sha256", "size", "mtime", "unc", "src", "mirror", "is_pdf", "ext"]
    with MANIFEST.open() as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) != len(cols):
                continue
            row = dict(zip(cols, parts))
            by_path[row["src"]] = row
            by_path[row["mirror"]] = row
    return by_path


def load_acls() -> dict[str, dict]:
    """
    Returns {unc_path_lower: {'owner': str, 'principals': [...]}}.
    Keys are lowercased because Windows shares are case-insensitive.
    """
    if not ACLS.exists():
        return {}
    acls: dict[str, dict] = defaultdict(lambda: {"owner": "", "principals": []})
    with ACLS.open(encoding="utf-8-sig") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for r in reader:
            k = (r.get("UncPath") or "").lower()
            if not k:
                continue
            acls[k]["owner"] = r.get("Owner", "") or acls[k]["owner"]
            principal = r.get("Principal", "")
            rights = r.get("Rights", "")
            # Only record principals that actually have read access
            if principal and re.search(r"(?i)read|listdirectory|fullcontrol|modify", rights):
                acls[k]["principals"].append(principal)
    return acls


def load_luhn_index() -> dict[tuple[str, str], bool]:
    """
    Returns {(unc_path, raw_match): luhn_valid_bool} for PAN/ABA findings.
    """
    if not LUHN.exists():
        return {}
    idx: dict[tuple[str, str], bool] = {}
    with LUHN.open() as f:
        reader = csv.DictReader(f, delimiter="\t")
        for r in reader:
            idx[(r["unc_path"], r["raw"])] = r["valid"].lower() == "true"
    return idx


# --- TruffleHog record normalization -----------------------------------
def th_iter(path: Path, source_tag: str):
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
            # TruffleHog v3 filesystem: path at
            # SourceMetadata.Data.Filesystem.file
            p = (
                rec.get("SourceMetadata", {})
                .get("Data", {})
                .get("Filesystem", {})
                .get("file")
            )
            if not p:
                continue
            raw = rec.get("Raw", "") or rec.get("RawV2", "")
            yield {
                "scan_path": p,
                "detector": rec.get("DetectorName") or rec.get("DetectorType") or "unknown",
                "verified": rec.get("Verified"),
                "raw": raw,
                "source_tag": source_tag,  # "trufflehog-src" or "trufflehog-ocr"
            }


def presidio_iter():
    if not PRESIDIO.exists():
        return
    with PRESIDIO.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield {
                "scan_path": r.get("source_path") or r.get("mirror_path"),
                "detector": f"Presidio:{r.get('entity')}",
                "verified": None,
                "raw": r.get("snippet", ""),
                "source_tag": "presidio",
                "score": r.get("score"),
            }


# --- Match redaction ----------------------------------------------------
def redact(raw: str) -> str:
    """Always mask the middle of a raw match so the CSV is safe to share."""
    if not raw:
        return ""
    s = raw.strip().splitlines()[0][:200]
    if len(s) <= 4:
        return "*" * len(s)
    return s[:2] + "*" * max(0, len(s) - 4) + s[-2:]


# --- Main ---------------------------------------------------------------
def main() -> int:
    if not MANIFEST.exists():
        print(f"manifest missing: {MANIFEST}", file=sys.stderr)
        return 1

    manifest = load_manifest()
    acls = load_acls()
    luhn = load_luhn_index()
    print(f"[join] manifest entries={len(manifest)//2} acls={len(acls)} luhn={len(luhn)}")

    seen: set[tuple[str, str, str]] = set()  # dedup across the src/ocr passes
    with FINDINGS_CSV.open("w", newline="") as out:
        w = csv.writer(out)
        w.writerow([
            "unc_path", "sha256", "size", "mtime", "detector", "verified",
            "luhn_valid", "match_excerpt", "acl_exposure", "acl_owner",
            "acl_principals", "source", "scan_path",
        ])

        def emit(rec: dict):
            m = manifest.get(rec["scan_path"])
            if not m:
                # Findings whose path doesn't map to manifest (rare; e.g.
                # scans that ran against directories we don't have rows for)
                return
            unc = m["unc"]
            redacted = redact(rec["raw"])
            key = (unc, rec["detector"], redacted)
            if key in seen:
                return
            seen.add(key)

            luhn_valid = ""
            if rec["detector"] in ("Credit Card PAN", "US ABA Routing Number", "US NPI"):
                luhn_valid = str(luhn.get((unc, rec["raw"].strip()), "")).lower()

            acl = acls.get(unc.lower(), {})
            principals = acl.get("principals", [])
            exposure = classify_acl(principals)

            w.writerow([
                unc, m["sha256"], m["size"], m["mtime"],
                rec["detector"], "" if rec["verified"] is None else str(rec["verified"]).lower(),
                luhn_valid, redacted, exposure, acl.get("owner", ""),
                "|".join(sorted(set(principals))), rec["source_tag"],
                rec["scan_path"],
            ])

        for r in th_iter(TH_SRC, "trufflehog-src"):
            emit(r)
        for r in th_iter(TH_OCR, "trufflehog-ocr"):
            emit(r)
        for r in presidio_iter():
            emit(r)

    print(f"[join] wrote {FINDINGS_CSV} ({len(seen)} unique findings)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
