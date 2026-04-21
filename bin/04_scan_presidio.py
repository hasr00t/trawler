#!/usr/bin/env python3
"""
04_scan_presidio.py -- NER-backed PII detection with Microsoft Presidio.

Complements TruffleHog's regex pass by catching entities that regex alone
struggles with (PERSON names, LOCATION, street addresses) and by providing
a second opinion on SSN / phone / email / credit card matches with
context-aware scoring.

Input:
  $OUT/manifest.tsv
  OCR text sidecars at "${mirror_path}.txt" (produced by 02_ocr.sh)
  For non-PDF text-like files, reads the source path directly.

Output:
  $OUT/presidio.jsonl   -- one JSON object per finding:
     {"source_path", "mirror_path", "unc_path", "sha256",
      "entity", "start", "end", "score", "snippet"}
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Iterable

# --- Config -------------------------------------------------------------
OUT = os.environ.get("OUT") or sys.exit("OUT env var unset")
MOUNT = os.environ.get("MOUNT") or sys.exit("MOUNT env var unset")
MIRROR = os.environ.get("MIRROR") or sys.exit("MIRROR env var unset")
MIN_SCORE = float(os.environ.get("PRESIDIO_MIN_SCORE", "0.6"))
MANIFEST = Path(OUT) / "manifest.tsv"
OUT_JSONL = Path(OUT) / "presidio.jsonl"

# Entities to report. Presidio ships with these; add custom recognizers below.
ENTITIES = [
    "US_SSN",
    "US_ITIN",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
    "US_BANK_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "PERSON",
    "LOCATION",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "DATE_TIME",
    "MEDICAL_LICENSE",
]

# Text-like extensions we'll feed directly. PDFs use their OCR sidecar.
TEXT_EXTS = {
    "txt", "log", "csv", "tsv", "md", "rst", "ini", "cfg", "conf", "yaml",
    "yml", "json", "xml", "html", "htm", "ps1", "sh", "bat", "py", "js",
    "sql", "env", "properties",
}

# --- Lazy imports so the script can at least print a useful error -------
try:
    from presidio_analyzer import AnalyzerEngine
except ImportError:
    sys.exit(
        "presidio_analyzer not installed.\n"
        "  pip install presidio-analyzer presidio-anonymizer\n"
        "  python3 -m spacy download en_core_web_lg"
    )


def iter_manifest() -> Iterable[dict]:
    cols = ["sha256", "size", "mtime", "unc", "src", "mirror", "is_pdf", "ext"]
    with MANIFEST.open() as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) != len(cols):
                continue
            yield dict(zip(cols, parts))


def load_text(row: dict) -> str | None:
    """Return the text we want Presidio to analyze for this file."""
    is_pdf = row["is_pdf"] == "1"
    if is_pdf:
        sidecar = Path(row["mirror"] + ".txt")
        if sidecar.exists():
            try:
                return sidecar.read_text(errors="replace")
            except OSError:
                return None
        return None

    # non-PDF: only read recognizably text-like files
    ext = row["ext"].lower()
    if ext not in TEXT_EXTS:
        return None
    src = Path(row["src"])
    try:
        # Cap at 10 MB per file to keep the analyzer snappy.
        return src.read_text(errors="replace")[: 10 * 1024 * 1024]
    except OSError:
        return None


def redact(text: str, start: int, end: int, pad: int = 20) -> str:
    """Produce a short snippet with the match middle masked."""
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    before = text[a:start].replace("\n", " ")
    after = text[end:b].replace("\n", " ")
    hit = text[start:end]
    # Mask: keep first/last char, asterisk the rest.
    if len(hit) > 4:
        masked = hit[0] + "*" * (len(hit) - 2) + hit[-1]
    else:
        masked = "*" * len(hit)
    return f"...{before}[{masked}]{after}..."


def main() -> int:
    if not MANIFEST.exists():
        print(f"manifest missing: {MANIFEST}", file=sys.stderr)
        return 1

    print(f"[presidio] loading analyzer (this can take ~10s on first run)")
    analyzer = AnalyzerEngine()

    n_files = 0
    n_findings = 0
    with OUT_JSONL.open("w") as out:
        for row in iter_manifest():
            text = load_text(row)
            if not text:
                continue
            n_files += 1
            try:
                results = analyzer.analyze(
                    text=text, entities=ENTITIES, language="en"
                )
            except Exception as exc:
                print(f"[presidio] skip {row['src']}: {exc}", file=sys.stderr)
                continue
            for r in results:
                if r.score < MIN_SCORE:
                    continue
                finding = {
                    "source_path": row["src"],
                    "mirror_path": row["mirror"],
                    "unc_path": row["unc"],
                    "sha256": row["sha256"],
                    "entity": r.entity_type,
                    "start": r.start,
                    "end": r.end,
                    "score": round(r.score, 3),
                    "snippet": redact(text, r.start, r.end),
                }
                out.write(json.dumps(finding, ensure_ascii=False) + "\n")
                n_findings += 1
            if n_files % 500 == 0:
                print(f"[presidio] scanned {n_files} files, {n_findings} findings")

    print(f"[presidio] done. files scanned={n_files}  findings={n_findings}")
    print(f"[presidio] output: {OUT_JSONL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
