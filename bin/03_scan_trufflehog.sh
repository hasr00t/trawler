#!/usr/bin/env bash
# 03_scan_trufflehog.sh -- run TruffleHog against both the source mount
# (catches everything that's already text-readable) and the OCR mirror
# (catches anything inside scanned PDFs that only became readable after
# ocrmypdf added a text layer).
#
# Outputs two JSONL files; 06_join.py unions and deduplicates them.

set -euo pipefail

# shellcheck disable=SC1091
[ -f ./.env ] && { set -a; . ./.env; set +a; }
: "${MOUNT:?set MOUNT}"
: "${MIRROR:?set MIRROR}"
: "${OUT:?set OUT}"
: "${LOGS:?set LOGS}"
: "${TRUFFLEHOG_CONFIG:?set TRUFFLEHOG_CONFIG}"
: "${TRUFFLEHOG_VERIFY:=false}"

LOG="$LOGS/03_trufflehog.$(date -u +%Y%m%dT%H%M%SZ).log"
OUT_SRC="$OUT/th_src.jsonl"
OUT_OCR="$OUT/th_ocr.jsonl"

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }

# Verification can hit third-party APIs. Default is OFF; opt in explicitly.
VERIFY_FLAG='--no-verification'
if [ "$TRUFFLEHOG_VERIFY" = "true" ]; then
    VERIFY_FLAG=''
    log "WARNING: TruffleHog verification ENABLED. Discovered credentials will be probed against their target services."
fi

log "TruffleHog pass 1: source mount ($MOUNT)"
# shellcheck disable=SC2086
trufflehog filesystem \
    --config="$TRUFFLEHOG_CONFIG" \
    --json \
    $VERIFY_FLAG \
    "$MOUNT" > "$OUT_SRC" 2>>"$LOG" || {
        rc=$?
        log "TruffleHog pass 1 exited $rc (findings may still be present)"
    }

log "TruffleHog pass 2: OCR mirror ($MIRROR)"
# shellcheck disable=SC2086
trufflehog filesystem \
    --config="$TRUFFLEHOG_CONFIG" \
    --json \
    $VERIFY_FLAG \
    "$MIRROR" > "$OUT_OCR" 2>>"$LOG" || {
        rc=$?
        log "TruffleHog pass 2 exited $rc"
    }

src_n=$(wc -l < "$OUT_SRC" || echo 0)
ocr_n=$(wc -l < "$OUT_OCR" || echo 0)
log "Findings: source=$src_n  ocr=$ocr_n"
log "Raw output:"
log "  $OUT_SRC"
log "  $OUT_OCR"
