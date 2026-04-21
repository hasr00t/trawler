#!/usr/bin/env bash
# 99_teardown.sh -- securely destroy the analysis volume at the end of the
# engagement. This is the single most important operational step: the OCR
# mirror and extracted sidecars contain the highest-concentration copy of
# the client's sensitive data you will ever create.
#
# By default this is a DRY RUN. Set CONFIRM=DESTROY to actually wipe.

set -euo pipefail

# shellcheck disable=SC1091
[ -f ./.env ] && { set -a; . ./.env; set +a; }
: "${ANALYSIS_ROOT:?set ANALYSIS_ROOT}"
: "${MOUNT:?set MOUNT}"

CONFIRM="${CONFIRM:-}"

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }

# 1) unmount the source share first so we don't accidentally rm into it
if mountpoint -q "$MOUNT"; then
    log "Unmounting source share at $MOUNT"
    if [ "$CONFIRM" = "DESTROY" ]; then
        sudo umount "$MOUNT" || sudo umount -l "$MOUNT"
    else
        log "DRY RUN: would unmount $MOUNT"
    fi
fi

# 2) list what we're about to destroy
log "Analysis root contents:"
du -sh "$ANALYSIS_ROOT" 2>/dev/null || true
find "$ANALYSIS_ROOT" -maxdepth 2 -type d 2>/dev/null | head -50

if [ "$CONFIRM" != "DESTROY" ]; then
    echo
    echo "DRY RUN. To actually wipe, re-run with:"
    echo "  CONFIRM=DESTROY bin/99_teardown.sh"
    exit 0
fi

# 3) Overwrite sensitive files. `shred` is pointless on COW/journaling/SSD
#    filesystems; what actually matters is FDE + removal of the keys on the
#    host. Still, we do a best-effort pass on the OCR sidecars and findings.
log "Shredding OCR sidecars and findings (best-effort)"
find "$ANALYSIS_ROOT" \( -iname '*.txt' -o -iname '*.jsonl' -o -iname '*.csv' -o -iname '*.tsv' -o -iname '*.pdf' \) -type f -print0 \
    | xargs -0 -r -n1 -P 4 shred -u -n 1 2>/dev/null || true

# 4) Recursively remove the analysis tree
log "Removing $ANALYSIS_ROOT"
rm -rf "$ANALYSIS_ROOT"

# 5) Optional: if analysis volume is a dedicated LUKS device, suggest
#    destroying the keyslots. This is the only wipe that's reliable on SSD.
cat <<'EOF'

NOTE: on solid-state storage, only destruction of the FDE master key
reliably renders data unrecoverable. If your analysis volume is a LUKS
container, consider:

    sudo cryptsetup luksErase /dev/<device>

and then re-format. Coordinate with whoever owns the engagement host.
EOF

log "Teardown complete"
