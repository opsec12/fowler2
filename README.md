# AWS GovCloud Audit Toolkit

Three scripts that together pull security/compliance data from an AWS GovCloud
account, and turn it into a spreadsheet and a visual dashboard for review.

| File | What it does | Where it runs | Needs AWS access? |
|---|---|---|---|
| `audit.sh` | Pulls findings/inventory from AWS via the CLI, writes raw JSON + `<ACCOUNT_ID>_<REGION>_flat.csv` | AWS CloudShell (or anywhere with AWS CLI + credentials) | Yes |
| `workbook.py` | Turns that JSON/CSV into a tabbed `<ACCOUNT_ID>_<REGION>_audit.xlsx` | Anywhere with Python 3 (CloudShell or your desktop) | No |
| `dashboard.py` | Turns that JSON/CSV into a single-file `<ACCOUNT_ID>_<REGION>_dashboard.html` | Anywhere with Python 3 (CloudShell or your desktop) | No |

`audit.sh` automatically runs `workbook.py` and `dashboard.py` for you at the
end — see **Quick start** below. You only need to run them separately if
you're re-building the workbook/dashboard from an already-pulled data folder
without re-hitting AWS.

---

## Prerequisites

- **AWS CLI** configured with credentials that can read Security Hub, Config,
  Inspector, GuardDuty, IAM, Access Analyzer, CloudTrail, Trusted Advisor
  (Business/Enterprise support plan), S3, KMS, Detective, Macie, SSM, EC2,
  ACM, Secrets Manager, RDS, and Organizations. CloudShell has the CLI
  preinstalled and picks up your console credentials automatically.
- **`jq`** — preinstalled in CloudShell. Used to parse the JSON AWS returns.
- **Python 3** — preinstalled in CloudShell; on Windows use `python` instead
  of `python3` if the latter isn't recognized. No `pip install` is required —
  `workbook.py` and `dashboard.py` use only the Python standard library on
  purpose, since `pip install openpyxl` failed in this GovCloud CloudShell
  environment (see Troubleshooting).

All three files must be **in the same folder** to run as one pipeline — see
Setup below.

---

## Setup

1. Save `audit.sh`, `workbook.py`, and `dashboard.py` into the same directory
   (your CloudShell home directory is fine).
2. Make the shell script executable (only needed once):
   ```bash
   chmod +x audit.sh
   ```
3. Confirm all three are together:
   ```bash
   ls audit.sh workbook.py dashboard.py
   ```
   All three should list without error. If any is missing, `audit.sh` will
   still run — it just skips building the `.xlsx` or `.html` and tells you
   why.

---

## Quick start (the whole pipeline, one command)

```bash
./audit.sh
```

This pulls all AWS data into a new folder named after the **account and
region it just audited** (e.g.
`aws-audit-123456789012-US-Gov-West-20260824-171203/` — `audit.sh` looks up
the account number itself via `aws sts get-caller-identity`, you don't need
to know it ahead of time), builds the flat findings CSV, then automatically
calls `workbook.py` and `dashboard.py` against that same folder. At the end
it prints something like:

```
==================================================
All done. Account 123456789012 — deliverables in: aws-audit-123456789012-US-Gov-West-20260824-171203

Full paths (use these with CloudShell Actions -> Download file):
  /home/cloudshell-user/aws-audit-123456789012-US-Gov-West-20260824-171203/123456789012_US-Gov-West_flat.csv
  /home/cloudshell-user/aws-audit-123456789012-US-Gov-West-20260824-171203/123456789012_US-Gov-West_audit.xlsx
  /home/cloudshell-user/aws-audit-123456789012-US-Gov-West-20260824-171203/123456789012_US-Gov-West_dashboard.html
==================================================
```

`REGION` is translated into a friendly label for these names —
`us-gov-west-1` → `US-Gov-West`, `us-gov-east-1` → `US-Gov-East`, and the
four commercial regions become `US-East-1`, `US-East-2`, `US-West-1`,
`US-West-2` — so files sort and read clearly without exposing the raw AWS
region code.

Every run creates a **new** timestamped folder — nothing gets overwritten,
so you can re-run this on a schedule and keep a history. **If you're
auditing many accounts**, this naming is what makes sorting them
manageable: every deliverable is prefixed with the account number and
region it came from, so you can drop all of them into one shared folder
(Downloads, S3, a network share) and still tell them apart —
`123456789012_US-Gov-West_flat.csv`, `123456789012_US-Gov-West_audit.xlsx`,
`123456789012_US-Gov-West_dashboard.html`, one triplet per account/region,
sorting naturally by account number.

If `audit.sh` can't determine the account number (e.g. the credentials
don't have `sts:GetCallerIdentity`), it falls back to `UNKNOWN-ACCOUNT` in
the folder and file names and prints a warning — worth fixing your
credentials rather than working around this, since account attribution is
the whole point of the naming scheme.

### Downloading the results from CloudShell

CloudShell has no GUI file browser, so use its **Actions menu → Download
file**, and paste in one of the full paths printed above. Do this for the
`_audit.xlsx` and `_dashboard.html` files — those are the two you'll
actually want to open in a browser/Excel.

---

## Running the pieces individually

You don't need to re-pull AWS data every time you want to rebuild the
workbook or dashboard — both read from an existing output folder.

**Rebuild just the Excel workbook:**
```bash
python3 workbook.py aws-audit-123456789012-US-Gov-West-20260824-171203 123456789012 US-Gov-West
```

**Rebuild just the HTML dashboard:**
```bash
python3 dashboard.py aws-audit-123456789012-US-Gov-West-20260824-171203 123456789012 US-Gov-West
```

(swap in your actual folder name, account number, and region label — check
with `ls -d aws-audit-*`). The trailing account number and region label are
both optional, and independent of each other, for both scripts — leave
either or both off and `workbook.py`/`dashboard.py` just use whatever
combination they were given to build the output name (falling back to
`aws-audit.xlsx`/`leadership-dashboard.html` if neither is passed).
`dashboard.py` also falls back to looking for any `*_flat.csv` file in the
folder (or the legacy `master-findings.csv` name from older versions of
`audit.sh`) if it can't find a CSV matching the account/region it was
given. Passing both is what gives you the fully account-and-region-prefixed
filenames described above.

Both scripts print a clear error and exit if you point them at something
that isn't a real folder from `audit.sh` (e.g. accidentally pointing at the
`.xlsx` file instead of the folder) — no more silent failures.

---

## What's inside each output

### `<ACCOUNT_ID>_<REGION>_flat.csv`
(named `master-findings.csv` in older versions of this toolkit)

One flat table, one row per finding, with columns:
`Source, Severity, ResourceId, ResourceType, Title, Description, Status, Region, Timestamp`

Feeds from: Security Hub, Config, Inspector, GuardDuty, Access Analyzer,
Detective (Investigations), Macie, CloudTrail health.

### `<ACCOUNT_ID>_<REGION>_audit.xlsx`
(named `aws-audit.xlsx` in older versions of this toolkit)

One tab per service — `SecurityHub`, `Config`, `Inspector`, `GuardDuty`,
`AccessAnalyzer`, `Detective`, `Macie`, `SSM_PatchStates`,
`EC2_SSM_Coverage`, `SecurityGroups`, `FlowLogs`, `ACM_Certificates`,
`SecretsManager`, `RDS`, `CloudTrail_Health`, `OrgSCPs`, `IAM_CredReport`,
`TrustedAdvisor` — each tab only appears if that service actually returned
data (an empty result isn't a bug, it just means nothing to show).

### `cloudtrail-health.json`
One object per CloudTrail trail, covering logging/delivery health beyond
just "does the trail exist": `IsLogging`, `S3Bucket`,
`BucketReachableByAuditor` (can *this script's own AWS identity* reach the
trail's destination bucket via `head-bucket` — separate from whether
CloudTrail's own service-linked delivery can reach it), `LogFileValidationEnabled`,
`LatestDeliveryError`, `LatestDeliveryTime`, `LatestNotificationError`,
`LatestCloudWatchLogsDeliveryError`, `LatestDigestDeliveryError`,
`StartLoggingTime`, `StopLoggingTime`. Trails with `IsLogging: false` or any
non-`"None"` error field, or a `BucketReachableByAuditor` other than `"OK"`,
are also added to the flat CSV as `CRITICAL` (not logging) or `HIGH`
(degraded delivery/notification/bucket access) findings, and rolled into a
"CloudTrail Issues" tile on the dashboard.

### `<ACCOUNT_ID>_<REGION>_dashboard.html`
(named `leadership-dashboard.html` in older versions of this toolkit)

A single self-contained page (no server, no internet needed to view it):
KPI tiles (total findings, Critical, High, plus SSM coverage / open security
groups / expiring certs / CloudTrail issues if available), a
findings-by-severity chart, a findings-by-source chart split by severity,
and a searchable/sortable table of every finding.

---

## Known limitations (worth knowing before you brief leadership)

- **This toolkit is an aggregator, not an independent scanner.** It only
  surfaces what Security Hub/Config/GuardDuty/etc. already decided to flag —
  it doesn't run its own checks. For deeper, independently-verified coverage
  (~639 AWS checks across 47 compliance frameworks), consider running
  [Prowler](https://github.com/prowler-cloud/prowler) alongside this and
  comparing results.
- **Trusted Advisor** in GovCloud only exposes a subset of checks compared
  to commercial AWS, and most require a Business/Enterprise support plan.
- **AWS Audit Manager** is in maintenance mode (closed to new customers as
  of April 30, 2026) — not included in this toolkit; AWS's own suggested
  replacement is Config Conformance Packs.
- **Detective, Macie, and Organizations SCPs** all print a skip message and
  produce no data if they're not enabled, not available in your account, or
  (for SCPs) if you're not the Organizations management/delegated-admin
  account. That's expected behavior, not a bug.
- Severity values from different services (Security Hub's `CRITICAL/HIGH/...`,
  GuardDuty's numeric scale, Macie's `Low/Medium/High`) are normalized into
  a common `Critical/High/Medium/Low` bucket for the CSV and dashboard —
  check the original JSON in the output folder if you need a service's exact
  native severity value.

---

## Troubleshooting

**`NoSuchConfigRuleException` / `TrailNotFoundException` naming a literal
placeholder** — you're running an old copy of `audit.sh`. The current
version discovers real rule names and trail ARNs automatically instead of
using placeholders; re-save the latest version.

**`ModuleNotFoundError: No module named 'openpyxl'`** — expected in this
environment; `workbook.py` and `dashboard.py` don't use `openpyxl` or any
other external package, so this shouldn't come up with the current versions.
If you see it, you're running an old copy.

**`SyntaxError: unterminated f-string literal` (usually on Windows)** —
caused by copy-pasting code through a rich-text path (browser, Word,
Notepad autocorrect) that converts straight quotes into curly "smart
quotes," or inserts a stray line break into a long line. Fix: download the
`.py` file directly rather than copy-pasting it as text.

**`FileNotFoundError` when running `workbook.py`/`dashboard.py`** — you
pointed the script at the wrong thing. It needs the **folder** `audit.sh`
created (e.g. `aws-audit-123456789012-US-Gov-West-20260824-171203`), not
the `.xlsx` file and not a duplicate-download name like `123456789012_audit
(2).xlsx`. Run `ls -d aws-audit-*` to find the real folder name.

**`aws-audit-UNKNOWN-ACCOUNT-...` folder/file names** — `audit.sh` couldn't
determine your AWS account number via `aws sts get-caller-identity`, most
likely because the credentials in use don't have `sts:GetCallerIdentity`
permission (rare — almost every identity has this by default) or STS isn't
reachable in that region. Check `aws sts get-caller-identity` runs cleanly
on its own before re-running `audit.sh`.

**Terminal looks "frozen" with a `>>>` prompt** — you ran `python3` (or
`python`) with no script name, which opens the interactive Python shell.
Type `exit()` or press `Ctrl+D`, then run the full command:
`python3 dashboard.py <folder>`.

**`workbook.py not found next to audit.sh` / `dashboard.py not found...`**
— the three files aren't in the same directory. Find them with
`find ~ -maxdepth 3 -name "audit.sh" -o -name "workbook.py" -o -name "dashboard.py"`
and move them together with `mv`.

**A section prints "not enabled" / "skipping"** (GuardDuty, Access Analyzer,
Detective, Macie, SCPs) — that service genuinely isn't enabled/available/
authorized in this account, not a script error. The rest of the run
continues normally.
