#!/usr/bin/env bash
# 00_preflight.sh -- verify dependencies and environment before a scan
set -euo pipefail

# shellcheck disable=SC1091
[ -f ./.env ] && { set -a; . ./.env; set +a; }

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
die() { printf '\033[31m[FATAL]\033[0m %s\n' "$*" >&2; exit 1; }
ok()  { printf '\033[32m[ OK ]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[WARN]\033[0m %s\n' "$*"; }

cat <<'BANNER'
                    |
                   _|_
                  /___\
              ___|     |___
             |    ___       |                     /\
             |   |   |      |                    /  \
             |   |___|  o o |                   /    \
             |______________|__________________/______\
            /                                          \
            |  o   o   o   o   o   o   o   o   o      |
            \__________________________________________/
          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                           T R A W L E R
              on-prem file share PII / PHI / creds
BANNER
log "Trawler preflight starting"

# ---- required binaries --------------------------------------------------
need() {
    command -v "$1" >/dev/null 2>&1 || die "missing required binary: $1"
    ok "found $1 ($(command -v "$1"))"
}
need ocrmypdf
need tesseract
need trufflehog
need jq
need python3
need sha256sum
need find
need xargs
need shred

# ---- recommended binaries -----------------------------------------------
for b in pdftotext rsync scrub; do
    if command -v "$b" >/dev/null 2>&1; then ok "found $b"
    else warn "optional binary not found: $b"; fi
done

# ---- versions -----------------------------------------------------------
log "trufflehog: $(trufflehog --version 2>&1 | head -n1)"
log "ocrmypdf:  $(ocrmypdf --version)"
log "tesseract: $(tesseract --version 2>&1 | head -n1)"
log "python:    $(python3 --version)"

# ---- env vars -----------------------------------------------------------
for v in SHARE_UNC MOUNT ANALYSIS_ROOT MIRROR OUT LOGS JOBS TRUFFLEHOG_CONFIG; do
    if [ -z "${!v:-}" ]; then die "env var $v is unset (source .env)"; fi
    ok "$v=${!v}"
done

# ---- directories --------------------------------------------------------
[ -d "$MOUNT" ]         || die "MOUNT does not exist: $MOUNT"
mountpoint -q "$MOUNT"  || warn "$MOUNT is not a mountpoint (proceed only for test data)"
mkdir -p "$MIRROR" "$OUT" "$LOGS"
ok "analysis tree ready under $ANALYSIS_ROOT"

# ---- read-only check ----------------------------------------------------
if findmnt -n -o OPTIONS "$MOUNT" 2>/dev/null | grep -q '\bro\b'; then
    ok "$MOUNT is mounted read-only"
else
    warn "$MOUNT is NOT read-only. Re-mount with -o ro before continuing"
fi

# ---- disk headroom ------------------------------------------------------
src_bytes=$(du -sb "$MOUNT" 2>/dev/null | awk '{print $1}')
free_bytes=$(df -B1 --output=avail "$ANALYSIS_ROOT" | tail -n1)
need_bytes=$((src_bytes * 2))
hr() { numfmt --to=iec --suffix=B "$1"; }
log "source size: $(hr "$src_bytes") | analysis free: $(hr "$free_bytes") | recommended: $(hr "$need_bytes")"
[ "$free_bytes" -ge "$need_bytes" ] || warn "analysis volume may be too small (needs ~2x source size for OCR mirror)"

# ---- Presidio (optional) ------------------------------------------------
if [ "${ENABLE_PRESIDIO:-false}" = "true" ]; then
    if python3 -c "import presidio_analyzer" 2>/dev/null; then
        ok "presidio_analyzer importable"
    else
        warn "presidio_analyzer not installed. Run: pip install presidio-analyzer presidio-anonymizer"
        warn "Also: python3 -m spacy download en_core_web_lg"
    fi
fi

# ---- TruffleHog config validation --------------------------------------
if [ -f "$TRUFFLEHOG_CONFIG" ]; then
    if python3 -c "import yaml,sys; yaml.safe_load(open('$TRUFFLEHOG_CONFIG'))" 2>/dev/null; then
        ok "trufflehog custom config parses: $TRUFFLEHOG_CONFIG"
    else
        die "trufflehog custom config is invalid YAML: $TRUFFLEHOG_CONFIG"
    fi
else
    die "trufflehog custom config missing: $TRUFFLEHOG_CONFIG"
fi

log "preflight complete"
