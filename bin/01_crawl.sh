#!/usr/bin/env bash
# 01_crawl.sh -- enumerate the share and build a manifest that ties every
# file's local mirror path back to its canonical UNC path and SHA-256.
#
# Output: $OUT/manifest.tsv
#   Columns (tab-separated, no header):
#     1. sha256
#     2. size_bytes
#     3. mtime_epoch
#     4. unc_path
#     5. source_path (on analysis host, inside $MOUNT)
#     6. mirror_path (where OCR output will land; may not exist yet)
#     7. is_pdf  (1/0)
#     8. ext

set -euo pipefail

# shellcheck disable=SC1091
[ -f ./.env ] && { set -a; . ./.env; set +a; }
: "${SHARE_UNC:?set SHARE_UNC}"
: "${MOUNT:?set MOUNT}"
: "${MIRROR:?set MIRROR}"
: "${OUT:?set OUT}"
: "${LOGS:?set LOGS}"
: "${JOBS:=4}"
: "${MAX_SIZE_MB:=500}"
: "${EXCLUDE_GLOBS:=.DS_Store;Thumbs.db;*.tmp;~\$*;desktop.ini}"

mkdir -p "$OUT" "$LOGS"
MANIFEST="$OUT/manifest.tsv"
LOG="$LOGS/01_crawl.$(date -u +%Y%m%dT%H%M%SZ).log"

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }

# Build find exclude predicates from EXCLUDE_GLOBS
EXCLUDE_ARGS=()
IFS=';' read -r -a _excl <<< "$EXCLUDE_GLOBS"
for g in "${_excl[@]}"; do
    [ -z "$g" ] && continue
    EXCLUDE_ARGS+=( -not -iname "$g" )
done

MAX_BYTES=$((MAX_SIZE_MB * 1024 * 1024))

log "Crawl starting. MOUNT=$MOUNT SHARE_UNC=$SHARE_UNC JOBS=$JOBS MAX_SIZE_MB=$MAX_SIZE_MB"
log "Writing manifest to $MANIFEST"

: > "$MANIFEST"

# Worker: for a single source path, produce a manifest row.
# Keeps tabs/newlines out of paths by refusing (warning) files that contain them.
worker() {
    local src="$1"
    case "$src" in
        *$'\t'*|*$'\n'*)
            printf '[WARN] skipping path with tab/newline: %q\n' "$src" >&2
            return 0
            ;;
    esac

    local size mtime ext lowext is_pdf rel unc mirror sha
    size=$(stat -c%s -- "$src" 2>/dev/null) || return 0
    mtime=$(stat -c%Y -- "$src" 2>/dev/null) || return 0
    [ "$size" -le "$MAX_BYTES" ] || return 0

    ext="${src##*.}"
    lowext=$(printf '%s' "$ext" | tr '[:upper:]' '[:lower:]')
    is_pdf=0
    [ "$lowext" = "pdf" ] && is_pdf=1

    rel="${src#"$MOUNT"/}"
    # Convert POSIX slashes to Windows backslashes for UNC display
    unc="${SHARE_UNC}\\${rel//\//\\}"
    mirror="${MIRROR}/${rel}"

    sha=$(sha256sum -- "$src" | awk '{print $1}')
    [ -z "$sha" ] && return 0

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$sha" "$size" "$mtime" "$unc" "$src" "$mirror" "$is_pdf" "$lowext"
}
export -f worker
export MOUNT SHARE_UNC MIRROR MAX_BYTES

# Enumerate, parallel-hash, append to manifest.
# `sort -u` deduplicates in case of repeated paths (rare but safe).
find "$MOUNT" -type f "${EXCLUDE_ARGS[@]}" -print0 \
    | xargs -0 -P "$JOBS" -I {} bash -c 'worker "$@"' _ {} \
    | sort -u >> "$MANIFEST"

rows=$(wc -l < "$MANIFEST")
pdfs=$(awk -F'\t' '$7==1' "$MANIFEST" | wc -l)
bytes=$(awk -F'\t' '{s+=$2} END {print s+0}' "$MANIFEST")
log "Manifest rows: $rows ; PDFs: $pdfs ; bytes: $bytes"
log "Crawl complete"
