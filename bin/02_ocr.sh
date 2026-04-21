#!/usr/bin/env bash
# 02_ocr.sh -- OCR every PDF listed in the manifest into the mirror tree.
#
# Non-destructive: the source share is never written to. ocrmypdf adds an
# invisible text layer to the original PDF and writes the result to
# $MIRROR/<relative path>. --skip-text leaves already-searchable PDFs alone
# and just copies them into the mirror (so downstream scanning sees a
# complete tree of PDFs, regardless of whether OCR was needed).

set -euo pipefail

# shellcheck disable=SC1091
[ -f ./.env ] && { set -a; . ./.env; set +a; }
: "${MOUNT:?set MOUNT}"
: "${MIRROR:?set MIRROR}"
: "${OUT:?set OUT}"
: "${LOGS:?set LOGS}"
: "${JOBS:=4}"

MANIFEST="$OUT/manifest.tsv"
LOG="$LOGS/02_ocr.$(date -u +%Y%m%dT%H%M%SZ).log"
[ -f "$MANIFEST" ] || { echo "manifest missing: $MANIFEST (run 01_crawl.sh first)" >&2; exit 1; }

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }

ocr_one() {
    # args: src_path mirror_path
    local src="$1"
    local dst="$2"
    mkdir -p -- "$(dirname -- "$dst")"
    # --skip-text: if it already has text, just embed a copy and move on
    # --rotate-pages / --deskew: best-effort cleanup for printer scans
    # --quiet: ocrmypdf is chatty; we collect errors separately
    # --sidecar: write extracted text alongside for quick grepping later
    if ocrmypdf \
        --skip-text \
        --rotate-pages \
        --deskew \
        --optimize 0 \
        --quiet \
        --sidecar "${dst}.txt" \
        -- "$src" "$dst" 2>>"$LOG.err"; then
        printf 'OK\t%s\n' "$dst"
    else
        rc=$?
        printf 'FAIL(%d)\t%s\n' "$rc" "$src" >>"$LOG.err"
        # Fall back: at least put the original bytes in the mirror so scans
        # still see it (a blob-only PDF is better than nothing).
        cp -n -- "$src" "$dst" 2>/dev/null || true
        printf 'COPY\t%s\n' "$dst"
    fi
}
export -f ocr_one
export LOG

log "OCR starting. JOBS=$JOBS  mirror=$MIRROR"
log "Per-file errors will be logged to ${LOG}.err"

# Feed the PDF rows only (column 7 == 1) to parallel ocrmypdf workers.
# Columns: 1=sha 2=size 3=mtime 4=unc 5=src 6=mirror 7=is_pdf
awk -F'\t' '$7==1 {print $5 "\t" $6}' "$MANIFEST" \
    | xargs -d '\n' -n1 -P "$JOBS" -I {} bash -c '
        line="{}"
        src="${line%%	*}"
        dst="${line#*	}"
        ocr_one "$src" "$dst"
      ' | tee -a "$LOG"

total_pdfs=$(awk -F'\t' '$7==1' "$MANIFEST" | wc -l)
ocrd=$(find "$MIRROR" -type f -iname '*.pdf' | wc -l)
log "OCR complete. source PDFs=$total_pdfs  mirror PDFs=$ocrd"
