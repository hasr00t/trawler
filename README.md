# Trawler

```
                    |
                   _|_
                  /___\
              ___|     |___
             |    ___       |                     /\
             |   |   |      |        ___         /  \
             |   |___|  o o |       /===\       /    \
             |______________|_______\===/______/______\
            /                                          \
            |  o   o   o   o   o   o   o   o   o      |
            \__________________________________________/
          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```

**Credential, PII, and PHI discovery for on-prem file shares.**

Trawler is a runnable pipeline for finding secrets, regulated PII, and Protected
Health Information (including inside scanned PDFs) on on-prem SMB/NFS file
shares, and producing a remediation worklist that maps every finding back to
its original UNC path and NTFS ACL.

Built for engagements where the share sits behind the firewall, the data can't
leave the client site, and your report has to tell somebody which files to
quarantine and who to email about it.

## What it finds

**Credentials & secrets** — AWS/GCP/Azure keys (via TruffleHog built-ins),
private keys (PEM, PuTTY), database connection strings, Wi-Fi PSKs, printed
passwords from scanned onboarding docs and helpdesk screenshots.

**Regulated PII** — SSN, ITIN, EIN, credit card PAN (Luhn validated), US bank
routing (ABA validated), passport, driver's license, IBAN, date of birth.

**Protected Health Information (PHI)** — NPI (Luhn validated with CMS 80840
prefix), Medical Record Numbers, Medicare Beneficiary Identifier (MBI) and
legacy HICN, DEA registration, ICD-10 diagnosis codes, CPT/HCPCS procedure
codes, medication/Rx context.

**NER-backed PII (optional)** — names, locations, addresses via Microsoft
Presidio. Catches what regex alone can't.

## How it works

```
+--------------------+
|  SMB/NFS share(s)  |   (mounted read-only on analysis host)
+---------+----------+
          |
          v
   [ 01_crawl.sh ] ----> manifest.tsv  (sha256, size, mtime, UNC, src, mirror)
          |
          v
   [ 02_ocr.sh  ] ----> /analysis/ocr/**/*.pdf   (OCR'd copies + sidecar .txt)
          |
          v
   [ 03_scan_trufflehog.sh ]  --> th_src.jsonl   (scan against original mount)
                              --> th_ocr.jsonl   (scan against OCR mirror)
   [ 04_scan_presidio.py   ]  --> presidio.jsonl (optional, NER-backed PII)
   [ 05_acl_snapshot.ps1   ]  --> acls.tsv       (Windows: NTFS ACLs)
          |
          v
   [ 07_luhn_filter.py ] --> validate PAN / ABA / NPI
          |
          v
   [ 06_join.py ] --> findings.csv (UNC + detector + hash + ACL exposure)
          |
          v
   [ 08_remediation.py ] --> worklist.csv + per_owner/*.eml + quarantine.sh
          |
          v
   [ 99_teardown.sh ]   --> secure-wipe analysis volume
```

Findings trace back to the canonical `\\server\share\path\to\file` the client
sees — not the local mount path — so the worklist is actionable on the Windows
side.

## Safety model

Read this before you run anything. This tool creates the
highest-concentration copy of the client's sensitive data that will ever
exist. Treat the analysis host accordingly.

- **Source share is read-only.** The scripts never write to `$MOUNT`. Mount
  with `-o ro` and let `00_preflight.sh` verify.
- **OCR output goes to an isolated analysis volume**, never back to the share.
  Host should have full-disk encryption, a segregated network, access logging,
  and auto-wipe on engagement end.
- **TruffleHog verification is OFF by default.** Turning it on probes
  third-party APIs (AWS, GitHub, Slack, etc.) with discovered credentials.
  Get written client authorization before enabling.
- **Nothing phones home.** Presidio and TruffleHog run locally. No cloud OCR.
- **Hash before remediation.** `quarantine.sh` re-hashes every file before
  acting and refuses to move anything that's changed since scan.
- **Teardown is dry-run by default.** `99_teardown.sh` requires
  `CONFIRM=DESTROY` to wipe the analysis volume.
- **Quarantine is dry-run by default.** `quarantine.sh` requires `DRY_RUN=0`
  to actually move files.
- **Every script writes a timestamped log to `./logs/`.** Keep them for the
  engagement record.

## Prerequisites

**Analysis host** — hardened Ubuntu 22.04 recommended, isolated VLAN, FDE,
no outbound internet (except TruffleHog verification endpoints if you've
explicitly enabled verification):

- `ocrmypdf`, `tesseract-ocr` (`apt install ocrmypdf tesseract-ocr`)
- `trufflehog` v3.x ([installation](https://github.com/trufflesecurity/trufflehog))
- `python3` with `pandas`, `tqdm`
- `presidio-analyzer`, `presidio-anonymizer` (optional, for NER PII)
- `jq`, `rsync`, `cifs-utils` / `nfs-common`
- `shred` or `scrub` for teardown
- ~2× the share size of free disk (for OCR mirror + extracted text)

**Windows host** — domain-joined, low-privilege user with share read access
is sufficient:

- PowerShell 5+

## Quick start

```bash
# 1. Configure
cp examples/env.example .env
$EDITOR .env                    # SHARE_UNC, MOUNT, ANALYSIS_ROOT, JOBS, ...
set -a; source .env; set +a

# 2. Preflight
bin/00_preflight.sh

# 3. Mount the share read-only (example -- adjust to your auth model)
sudo mkdir -p "$MOUNT"
sudo mount -t cifs "//$SMB_SERVER/$SMB_SHARE" "$MOUNT" \
    -o "ro,username=$SMB_USER,domain=$SMB_DOMAIN,vers=3.0,uid=$(id -u)"

# 4. Build manifest
bin/01_crawl.sh

# 5. OCR scanned PDFs in parallel
bin/02_ocr.sh

# 6. Scan
bin/03_scan_trufflehog.sh
bin/04_scan_presidio.py         # optional; slower, catches names/addresses
bin/07_luhn_filter.py           # validates PAN / ABA / NPI

# 7. From a Windows host: snapshot NTFS ACLs
#    powershell -ExecutionPolicy Bypass -File bin\05_acl_snapshot.ps1 `
#        -SharePath "\\fs01\data" -OutFile "\\analysishost\drop\acls.tsv"

# 8. Join into a single findings CSV
bin/06_join.py

# 9. Per-owner remediation worklist
bin/08_remediation.py

# 10. End of engagement
CONFIRM=DESTROY bin/99_teardown.sh
```

## Output

`findings.csv` — one row per finding:

| column           | description                                              |
|------------------|----------------------------------------------------------|
| unc_path         | `\\server\share\path\to\file.pdf`                        |
| sha256           | Content hash at scan time                                |
| size             | Bytes                                                    |
| mtime            | Source mtime (epoch)                                     |
| detector         | TruffleHog detector name or `Presidio:<entity>`          |
| verified         | `true`/`false`/`n/a` (TruffleHog built-in verification)  |
| luhn_valid       | `true`/`false`/`n/a` (PAN, routing, and NPI)             |
| match_excerpt    | Redacted snippet (first/last 2 chars, middle masked)     |
| acl_exposure     | `public`/`wide`/`team`/`restricted`                      |
| acl_principals   | Pipe-separated list of identities with read access       |
| source           | `trufflehog-src`/`trufflehog-ocr`/`presidio`             |

`worklist.csv` adds:

- `priority` — 1-4; 1 = public-readable SSN/PAN/NPI, 4 = restricted low-risk
- `recommended_action` — quarantine / rotate / redact / review
- `acl_owner` — file owner from the ACL snapshot

Plus `per_owner/<owner>.csv`, draft `.eml` notifications, and a dry-run
`quarantine.sh`.

## Tuning

- **Too noisy?** Edit `config/trufflehog-custom.yaml` to remove detectors or
  tighten their keyword lists. SSN, CPT, and the raw DL regexes are the usual
  noise sources — consider restricting to detector-specific keywords only.
- **Missing things?** Presidio catches names/addresses that regex can't.
  Client-specific patterns (internal employee IDs, customer account numbers,
  site-specific MRN formats) should be added to `trufflehog-custom.yaml` as
  new detectors — they'll flow through the join and remediation steps without
  further changes, as long as you also list the detector name in
  `HIGH_RISK_DETECTORS` / `MEDIUM_RISK_DETECTORS` in `bin/08_remediation.py`.
- **Slow?** OCR is the bottleneck. Raise `$JOBS`, drop `--optimize` in
  `02_ocr.sh` for speed over file-size. For bad scans, consider PaddleOCR over
  Tesseract.

## Project layout

```
trawler/
  README.md
  CLAUDE.md
  config/
    trufflehog-custom.yaml
  bin/
    00_preflight.sh           # dependency + environment checks
    01_crawl.sh               # manifest builder (sha256, UNC mapping)
    02_ocr.sh                 # ocrmypdf of scanned PDFs
    03_scan_trufflehog.sh     # 2-pass: source mount + OCR mirror
    04_scan_presidio.py       # optional NER-backed PII
    05_acl_snapshot.ps1       # Windows: NTFS ACLs
    06_join.py                # merge findings + manifest + ACLs
    07_luhn_filter.py         # PAN / ABA / NPI checksums
    08_remediation.py         # per-owner worklists + quarantine.sh
    99_teardown.sh            # secure-wipe analysis volume
  examples/
    env.example
```

## Status

Used in live engagements. Expect sharp edges; read the script you're about to
run first. Issues and PRs welcome, especially client-specific detector
contributions (MRN patterns, internal ID formats).
