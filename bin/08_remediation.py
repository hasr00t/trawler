#!/usr/bin/env python3
"""
08_remediation.py -- turn findings.csv into actionable remediation artifacts:

  - worklist.csv:
      findings enriched with priority (1-4) and recommended action.

  - per_owner/<owner>.csv:
      per-file-owner worklists for distributed remediation.

  - per_owner/<owner>.eml:
      draft email (EML) to each owner listing their files needing attention.
      Drafts only; does not send. Review before dispatching.

  - quarantine.sh:
      safe re-hash-then-move script for the highest-priority findings.
      MOVES files on the share from their current location to a quarantine
      share. Will refuse to act if the file's SHA-256 has changed since
      scan. Dry-run by default; must be edited to execute.

Priority scoring (lower = more urgent):
  1 = public-readable regulated PII/credential (SSN, PAN w/ Luhn, private key,
      DB conn string, verified cloud credential)
  2 = wide-readable regulated PII, or public-readable weaker matches
  3 = team-readable regulated PII, or wide-readable weaker matches
  4 = restricted-readable anything, or unverified weak matches
"""
from __future__ import annotations

import csv
import email.message
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

OUT = Path(os.environ.get("OUT") or sys.exit("OUT env var unset"))
FINDINGS = OUT / "findings.csv"
WORKLIST = OUT / "worklist.csv"
PER_OWNER = OUT / "per_owner"
QUARANTINE_SH = OUT / "quarantine.sh"

# Quarantine destination (UNC). Must be writable by the remediation user.
# Override via env QUARANTINE_UNC if you don't want the default placeholder.
QUARANTINE_UNC = os.environ.get("QUARANTINE_UNC", r"\\sec-quarantine\trawler")

# --- Severity buckets ----------------------------------------------------
HIGH_RISK_DETECTORS = {
    # Regulated PII
    "US Social Security Number",
    "US ITIN",
    "Credit Card PAN",
    "US Passport Number",
    "Presidio:US_SSN",
    "Presidio:CREDIT_CARD",
    "Presidio:US_PASSPORT",
    # PHI (HIPAA-regulated patient identifiers)
    "DEA Number",
    "US NPI",
    "Medical Record Number",
    "Medicare Beneficiary Identifier",
    "Medicare HICN (legacy)",
    # Live credentials
    "PEM Private Key Block",
    "PuTTY Private Key",
    "DB Connection String",
    "Document Username Password Pair",
}
MEDIUM_RISK_DETECTORS = {
    # Weaker PII / financial
    "US EIN",
    "US ABA Routing Number",
    "IBAN",
    "US Drivers License",
    "Date of Birth",
    "Presidio:US_BANK_NUMBER",
    "Presidio:IBAN_CODE",
    "Presidio:US_DRIVER_LICENSE",
    # PHI context (not identifiers on their own, but sensitive in combo).
    # CPT is intentionally excluded -- too noisy (every 5-digit number, ZIP
    # codes, etc.); it defaults to low severity.
    "ICD-10 Diagnosis Code",
    "Medication / Rx",
    "Presidio:MEDICAL_LICENSE",
    # Weak credentials
    "WiFi PSK",
    "Document Password Pattern",
}

EXPOSURE_RANK = {"public": 0, "wide": 1, "team": 2, "restricted": 3, "unknown": 3}


def priority(detector: str, exposure: str, verified: str, luhn_valid: str) -> int:
    sev = (
        2 if detector in HIGH_RISK_DETECTORS
        else 1 if detector in MEDIUM_RISK_DETECTORS
        else 0
    )
    # PAN / ABA / NPI that failed their checksum are almost certainly noise; demote.
    if detector in ("Credit Card PAN", "US ABA Routing Number", "US NPI") and luhn_valid == "false":
        sev = 0
    # Verified third-party creds are the worst case; promote.
    if verified == "true":
        sev = 2

    exp = EXPOSURE_RANK.get(exposure, 3)
    # Combine: prio = 1 + exp - sev_delta (clamped 1..4)
    score = 4 - sev + exp - 2
    return max(1, min(4, score))


def recommended_action(detector: str, prio: int) -> str:
    if prio == 1:
        return "quarantine immediately; notify owner; reset credential if live"
    if prio == 2:
        if "Private Key" in detector or "Password" in detector or "Credential" in detector:
            return "rotate credential; quarantine file; notify owner"
        return "redact or move to restricted share; notify owner"
    if prio == 3:
        return "review with owner; redact or relocate as appropriate"
    return "log and review"


def sanitize_for_filename(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("._-") or "unknown"


def owner_key(owner: str) -> str:
    if not owner:
        return "unknown_owner"
    # Strip domain prefix: CORP\jsmith -> jsmith
    return sanitize_for_filename(owner.split("\\")[-1])


def main() -> int:
    if not FINDINGS.exists():
        print(f"findings.csv missing; run 06_join.py first", file=sys.stderr)
        return 1

    PER_OWNER.mkdir(parents=True, exist_ok=True)

    rows_by_owner: dict[str, list[dict]] = defaultdict(list)
    prio1_rows: list[dict] = []
    all_rows: list[dict] = []

    with FINDINGS.open() as f, WORKLIST.open("w", newline="") as wl:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames + ["priority", "recommended_action"]
        writer = csv.DictWriter(wl, fieldnames=fieldnames)
        writer.writeheader()

        for r in reader:
            p = priority(r["detector"], r["acl_exposure"], r["verified"], r["luhn_valid"])
            r["priority"] = p
            r["recommended_action"] = recommended_action(r["detector"], p)
            writer.writerow(r)
            all_rows.append(r)
            rows_by_owner[owner_key(r["acl_owner"])].append(r)
            if p == 1:
                prio1_rows.append(r)

    print(f"[rem] worklist rows: {len(all_rows)}")
    print(f"[rem] priority-1 findings: {len(prio1_rows)}")

    # Per-owner CSVs
    for owner, rs in rows_by_owner.items():
        p = PER_OWNER / f"{owner}.csv"
        with p.open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            rs.sort(key=lambda x: (int(x["priority"]), x["unc_path"]))
            w.writerows(rs)

    # Per-owner draft emails (EML)
    for owner, rs in rows_by_owner.items():
        rs_by_prio = defaultdict(list)
        for r in rs:
            rs_by_prio[int(r["priority"])].append(r)
        body_parts = [
            "Hello,",
            "",
            f"As part of a file share cleanup effort, we identified files under",
            f"your ownership that appear to contain sensitive data. Please review",
            f"and either remediate (delete, redact, or relocate) within 5 business",
            f"days, or reply with context if a finding is a false positive.",
            "",
        ]
        for p in sorted(rs_by_prio):
            body_parts.append(f"--- Priority {p} ({len(rs_by_prio[p])} files) ---")
            for r in rs_by_prio[p][:25]:  # cap the per-email list
                body_parts.append(f"  {r['unc_path']}")
                body_parts.append(f"    detector: {r['detector']}  exposure: {r['acl_exposure']}")
                body_parts.append(f"    action:   {r['recommended_action']}")
            if len(rs_by_prio[p]) > 25:
                body_parts.append(f"  ... and {len(rs_by_prio[p]) - 25} more (see attached CSV)")
            body_parts.append("")
        body_parts.append("Questions: reach out to the security team.")
        body = "\n".join(body_parts)

        msg = email.message.EmailMessage()
        msg["Subject"] = f"[Action Required] Sensitive data found in files you own ({len(rs)})"
        msg["From"] = "security-team@example.com"
        msg["To"] = f"{owner}@example.com"  # adjust to your directory convention
        msg.set_content(body)
        (PER_OWNER / f"{owner}.eml").write_bytes(bytes(msg))

    # Quarantine script (priority 1 only, dry-run by default)
    with QUARANTINE_SH.open("w") as f:
        f.write("#!/usr/bin/env bash\n")
        f.write("# quarantine.sh -- re-hash and relocate priority-1 findings.\n")
        f.write("#\n")
        f.write("# DRY RUN BY DEFAULT. Review every line before setting DRY_RUN=0.\n")
        f.write("# Refuses to act if a file's SHA-256 has changed since scan.\n")
        f.write("#\n")
        f.write("# Requires: smbclient or a mounted quarantine target, sha256sum.\n")
        f.write("set -euo pipefail\n")
        f.write(': "${DRY_RUN:=1}"\n')
        f.write(f'QUARANTINE="{QUARANTINE_UNC}"\n\n')

        # Dedup on UNC path -- don't issue multiple moves for the same file
        seen_paths: set[str] = set()
        for r in prio1_rows:
            unc = r["unc_path"]
            if unc in seen_paths:
                continue
            seen_paths.add(unc)
            sha = r["sha256"]
            f.write("# -----------------------------------------------------------\n")
            f.write(f"# detector={r['detector']}  exposure={r['acl_exposure']}\n")
            f.write(f"# UNC: {unc}\n")
            f.write(f"echo '--- {unc} ---'\n")
            # Convert UNC to Linux-style for local mount check; adjust as needed.
            linux_path = unc.replace("\\", "/").replace("//", "/mnt/share/", 1)
            # Actually, safer: we produce a commented command; operators fill in.
            f.write("# Expected SHA-256 (must match before quarantine):\n")
            f.write(f"EXPECT='{sha}'\n")
            f.write("# Replace MAPPED_PATH with your mounted equivalent of the UNC above:\n")
            f.write(f'MAPPED_PATH="{linux_path}"\n')
            f.write('ACTUAL=$(sha256sum -- "$MAPPED_PATH" 2>/dev/null | awk "{print \\$1}" || true)\n')
            f.write('if [ "$ACTUAL" != "$EXPECT" ]; then\n')
            f.write('  echo "SKIP: file changed or missing since scan ($ACTUAL != $EXPECT)" >&2\n')
            f.write('elif [ "$DRY_RUN" = "1" ]; then\n')
            f.write('  echo "DRY RUN: would move $MAPPED_PATH -> $QUARANTINE"\n')
            f.write("else\n")
            f.write('  # Example using rsync+rm; swap for smbclient/robocopy as needed.\n')
            f.write('  rsync -a --remove-source-files -- "$MAPPED_PATH" "$QUARANTINE/" && \\\n')
            f.write('    echo "MOVED: $MAPPED_PATH"\n')
            f.write("fi\n\n")

    QUARANTINE_SH.chmod(0o750)
    print(f"[rem] wrote {WORKLIST}")
    print(f"[rem] wrote {PER_OWNER}/*.csv and per_owner/*.eml")
    print(f"[rem] wrote {QUARANTINE_SH} (DRY RUN by default)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
