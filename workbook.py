# workbook.py
# Usage: python3 workbook.py <OUTDIR>
# No external dependencies — builds .xlsx by hand using stdlib only.
import json, sys, os, base64, csv, io, zipfile, re
from xml.sax.saxutils import escape

outdir = sys.argv[1]
sheets = []  # list of (name, headers, rows)

def load(fname):
    path = os.path.join(outdir, fname)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return None

def add_sheet(name, headers, rows):
    if not rows:
        return
    safe_name = re.sub(r'[:\\/?*\[\]]', '_', name)[:31]
    sheets.append((safe_name, headers, rows))

# ---------- Security Hub ----------
data = load("securityhub-findings.json")
if data:
    rows = []
    for f in data.get("Findings", []):
        resources = f.get("Resources", [{}])
        rows.append([
            f.get("Severity", {}).get("Label", "N/A"),
            resources[0].get("Id", "N/A") if resources else "N/A",
            resources[0].get("Type", "N/A") if resources else "N/A",
            f.get("Title", "N/A"),
            f.get("Description", "N/A"),
            f.get("Compliance", {}).get("Status") or f.get("RecordState", "N/A"),
            f.get("Region", "N/A"),
            f.get("UpdatedAt", "N/A"),
        ])
    add_sheet("SecurityHub", ["Severity","ResourceId","ResourceType","Title","Description","Status","Region","Timestamp"], rows)

# ---------- Config ----------
rule_catalog = load("config-all-rules.json")
rule_desc = {}
if rule_catalog:
    for r in rule_catalog.get("ConfigRules", []):
        rule_desc[r.get("ConfigRuleName")] = r.get("Description", "N/A")

rows = []
if os.path.isdir(outdir):
    for fname in os.listdir(outdir):
        if fname.startswith("config-detail-") and fname.endswith(".json"):
            data = load(fname)
            if not data:
                continue
            for r in data.get("EvaluationResults", []):
                q = r.get("EvaluationResultIdentifier", {}).get("EvaluationResultQualifier", {})
                rule_name = q.get("ConfigRuleName", "N/A")
                rows.append([
                    r.get("ComplianceType", "N/A"),
                    q.get("ResourceId", "N/A"),
                    q.get("ResourceType", "N/A"),
                    rule_name,
                    rule_desc.get(rule_name, "N/A"),
                    r.get("Annotation", "N/A"),
                    r.get("ResultRecordedTime", "N/A"),
                ])
add_sheet("Config", ["ComplianceType","ResourceId","ResourceType","RuleName","RuleDescription","Description","Timestamp"], rows)

# ---------- Inspector ----------
data = load("inspector-findings.json")
if data:
    rows = []
    for f in data.get("findings", []):
        resources = f.get("resources", [{}])
        rows.append([
            f.get("severity", "N/A"),
            resources[0].get("id", "N/A") if resources else "N/A",
            resources[0].get("type", "N/A") if resources else "N/A",
            f.get("title", "N/A"),
            f.get("description", "N/A"),
            f.get("status", "N/A"),
            f.get("firstObservedAt", "N/A"),
        ])
    add_sheet("Inspector", ["Severity","ResourceId","ResourceType","Title","Description","Status","FirstObserved"], rows)

# ---------- GuardDuty ----------
data = load("guardduty-findings.json")
if data:
    rows = []
    for f in data.get("Findings", []):
        rows.append([
            f.get("Severity", "N/A"),
            f.get("Id", "N/A"),
            f.get("Resource", {}).get("ResourceType", "N/A"),
            f.get("Title", "N/A"),
            f.get("Description", "N/A"),
            f.get("Type", "N/A"),
            f.get("Region", "N/A"),
            f.get("UpdatedAt", "N/A"),
        ])
    add_sheet("GuardDuty", ["Severity","Id","ResourceType","Title","Description","Type","Region","Timestamp"], rows)

# ---------- Access Analyzer ----------
data = load("access-analyzer-findings.json")
if data:
    rows = []
    for f in data.get("findings", []):
        rows.append([
            "HIGH" if f.get("isPublic") else "MEDIUM",
            f.get("resource", "N/A"),
            f.get("resourceType", "N/A"),
            f.get("status", "N/A"),
            json.dumps(f.get("condition", {})),
            f.get("updatedAt", "N/A"),
        ])
    add_sheet("AccessAnalyzer", ["Severity","Resource","ResourceType","Status","Condition","Timestamp"], rows)

# ---------- Amazon Detective: Investigations ----------
rows = []
if os.path.isdir(outdir):
    for fname in os.listdir(outdir):
        if fname.startswith("detective-investigation-") and fname.endswith(".json"):
            inv = load(fname)
            if not inv:
                continue
            inv_id = inv.get("InvestigationId", "N/A")
            entity_arn = inv.get("EntityArn", "N/A")
            account_id = "N/A"
            parts = entity_arn.split(":") if entity_arn else []
            if len(parts) > 4:
                account_id = parts[4]

            indicators = load(f"detective-indicators-{inv_id}.json")
            related_findings = []
            related_groups = []
            indicator_counts = {}
            if indicators:
                for ind in indicators.get("Indicators", []):
                    itype = ind.get("IndicatorType", "N/A")
                    indicator_counts[itype] = indicator_counts.get(itype, 0) + 1
                    detail = ind.get("IndicatorDetail", {})
                    if itype == "RELATED_FINDING":
                        related_findings.append(detail.get("RelatedFindingDetail", {}).get("Arn", "N/A"))
                    elif itype == "RELATED_FINDING_GROUP":
                        related_groups.append(detail.get("RelatedFindingGroupDetail", {}).get("Id", "N/A"))

            summary = "; ".join(f"{k}: {v}" for k, v in indicator_counts.items()) or "N/A"

            rows.append([
                inv_id,
                account_id,
                entity_arn,
                inv.get("EntityType", "N/A"),
                inv.get("Severity", "N/A"),
                inv.get("Status", "N/A"),
                inv.get("State", "N/A"),
                len(related_findings),
                "; ".join(related_findings) if related_findings else "N/A",
                "; ".join(related_groups) if related_groups else "N/A",
                summary,
                inv.get("CreatedTime", "N/A"),
            ])
add_sheet("Detective", ["InvestigationId","AWSAccount","InvolvedEntity","EntityType","Severity","Status","State","InvolvedFindingsCount","InvolvedFindings","InvolvedFindingGroups","IndicatorSummary","CreatedTime"], rows)

# ---------- Amazon Macie ----------
data = load("macie-findings.json")
if data:
    rows = []
    for f in data.get("findings", []):
        resources = f.get("resourcesAffected", {})
        resource_id = resources.get("s3Object", {}).get("key") or resources.get("s3Bucket", {}).get("name", "N/A")
        rows.append([
            f.get("severity", {}).get("description", "N/A"),
            resource_id,
            "S3",
            f.get("title", "N/A"),
            f.get("description", "N/A"),
            "ARCHIVED" if f.get("archived") else "ACTIVE",
            f.get("region", "N/A"),
            f.get("updatedAt", "N/A"),
        ])
    add_sheet("Macie", ["Severity","ResourceId","ResourceType","Title","Description","Status","Region","Timestamp"], rows)

# ---------- SSM: Patch States ----------
rows = []
if os.path.isdir(outdir):
    for fname in os.listdir(outdir):
        if fname.startswith("ssm-patch-states-batch-") and fname.endswith(".json"):
            data = load(fname)
            if not data:
                continue
            for p in data.get("InstancePatchStates", []):
                rows.append([
                    p.get("InstanceId", "N/A"),
                    p.get("PatchGroup", "N/A"),
                    p.get("MissingCount", 0),
                    p.get("InstalledCount", 0),
                    p.get("FailedCount", 0),
                    p.get("CriticalNonCompliantCount", 0),
                    p.get("SecurityNonCompliantCount", 0),
                    p.get("OperationEndTime", "N/A"),
                ])
add_sheet("SSM_PatchStates", ["InstanceId","PatchGroup","MissingCount","InstalledCount","FailedCount","CriticalNonCompliant","SecurityNonCompliant","LastOperationTime"], rows)

# ---------- EC2 <-> SSM coverage (unmanaged instance check) ----------
ec2_data = load("ec2-instances.json")
ssm_data = load("ssm-managed-instances.json")
if ec2_data:
    all_instances = {}
    for res in ec2_data.get("Reservations", []):
        for inst in res.get("Instances", []):
            iid = inst.get("InstanceId", "N/A")
            all_instances[iid] = inst.get("State", {}).get("Name", "N/A")
    managed_ids = set()
    if ssm_data:
        managed_ids = {i.get("InstanceId") for i in ssm_data.get("InstanceInformationList", [])}
    rows = [[iid, state, "Yes" if iid in managed_ids else "No"] for iid, state in sorted(all_instances.items())]
    add_sheet("EC2_SSM_Coverage", ["InstanceId","State","SSMManaged"], rows)

# ---------- VPC: Security Groups ----------
data = load("ec2-security-groups.json")
if data:
    rows = []
    for sg in data.get("SecurityGroups", []):
        gid = sg.get("GroupId", "N/A")
        gname = sg.get("GroupName", "N/A")
        vpc = sg.get("VpcId", "N/A")
        perms = sg.get("IpPermissions", [])
        if not perms:
            rows.append([gid, gname, vpc, "N/A", "N/A", "N/A", "No ingress rules"])
        for perm in perms:
            proto = perm.get("IpProtocol", "N/A")
            from_port = perm.get("FromPort", "N/A")
            to_port = perm.get("ToPort", "N/A")
            ranges = perm.get("IpRanges", [])
            if not ranges:
                rows.append([gid, gname, vpc, proto, from_port, to_port, "N/A"])
            for r in ranges:
                cidr = r.get("CidrIp", "N/A")
                flag = " OPEN TO INTERNET" if cidr == "0.0.0.0/0" else ""
                rows.append([gid, gname, vpc, proto, from_port, to_port, f"{cidr}{flag}"])
    add_sheet("SecurityGroups", ["GroupId","GroupName","VpcId","Protocol","FromPort","ToPort","CIDR"], rows)

# ---------- VPC: Flow Logs ----------
data = load("ec2-flow-logs.json")
if data:
    rows = []
    for fl in data.get("FlowLogs", []):
        rows.append([
            fl.get("FlowLogId", "N/A"),
            fl.get("ResourceId", "N/A"),
            fl.get("FlowLogStatus", "N/A"),
            fl.get("TrafficType", "N/A"),
            fl.get("LogDestinationType", "N/A"),
            fl.get("CreationTime", "N/A"),
        ])
    add_sheet("FlowLogs", ["FlowLogId","ResourceId","Status","TrafficType","DestinationType","CreationTime"], rows)

# ---------- ACM Certificates ----------
rows = []
if os.path.isdir(outdir):
    for fname in os.listdir(outdir):
        if fname.startswith("acm-cert-detail-") and fname.endswith(".json"):
            data = load(fname)
            if not data:
                continue
            cert = data.get("Certificate", {})
            rows.append([
                cert.get("CertificateArn", "N/A"),
                cert.get("DomainName", "N/A"),
                cert.get("Status", "N/A"),
                cert.get("NotBefore", "N/A"),
                cert.get("NotAfter", "N/A"),
                cert.get("Type", "N/A"),
            ])
add_sheet("ACM_Certificates", ["CertificateArn","DomainName","Status","NotBefore","NotAfter","Type"], rows)

# ---------- Secrets Manager ----------
data = load("secretsmanager-secrets.json")
if data:
    rows = []
    for s in data.get("SecretList", []):
        rows.append([
            s.get("Name", "N/A"),
            s.get("ARN", "N/A"),
            s.get("RotationEnabled", False),
            s.get("LastRotatedDate", "N/A"),
            s.get("LastChangedDate", "N/A"),
        ])
    add_sheet("SecretsManager", ["Name","ARN","RotationEnabled","LastRotatedDate","LastChangedDate"], rows)

# ---------- RDS ----------
data = load("rds-db-instances.json")
if data:
    rows = []
    for db in data.get("DBInstances", []):
        rows.append([
            db.get("DBInstanceIdentifier", "N/A"),
            db.get("Engine", "N/A"),
            db.get("StorageEncrypted", False),
            db.get("PubliclyAccessible", False),
            db.get("BackupRetentionPeriod", "N/A"),
            db.get("MultiAZ", False),
        ])
    add_sheet("RDS", ["DBInstanceIdentifier","Engine","StorageEncrypted","PubliclyAccessible","BackupRetentionDays","MultiAZ"], rows)

# ---------- CloudTrail Health ----------
data = load("cloudtrail-health.json")
if data:
    rows = []
    for t in data:
        rows.append([
            t.get("Trail", "N/A"),
            t.get("IsLogging", "N/A"),
            t.get("S3Bucket", "N/A"),
            t.get("BucketReachableByAuditor", "N/A"),
            t.get("LogFileValidationEnabled", "N/A"),
            t.get("LatestDeliveryError", "N/A"),
            t.get("LatestDeliveryTime", "N/A"),
            t.get("LatestNotificationError", "N/A"),
            t.get("LatestCloudWatchLogsDeliveryError", "N/A"),
            t.get("LatestDigestDeliveryError", "N/A"),
            t.get("StartLoggingTime", "N/A"),
            t.get("StopLoggingTime", "N/A"),
        ])
    add_sheet("CloudTrail_Health", ["Trail","IsLogging","S3Bucket","BucketReachableByAuditor",
        "LogFileValidationEnabled","LatestDeliveryError","LatestDeliveryTime","LatestNotificationError",
        "LatestCloudWatchLogsDeliveryError","LatestDigestDeliveryError","StartLoggingTime","StopLoggingTime"], rows)

# ---------- Organizations SCPs ----------
data = load("org-scps.json")
if data:
    rows = []
    for p in data.get("Policies", []):
        rows.append([
            p.get("Name", "N/A"),
            p.get("Id", "N/A"),
            p.get("Description", "N/A"),
            p.get("AwsManaged", False),
        ])
    add_sheet("OrgSCPs", ["Name","Id","Description","AWSManaged"], rows)

# ---------- IAM Credential Report (already CSV under the hood) ----------
cred_json = load("iam-credential-report.json")
if cred_json and "Content" in cred_json:
    decoded = base64.b64decode(cred_json["Content"]).decode("utf-8")
    reader = csv.reader(io.StringIO(decoded))
    all_rows = list(reader)
    if all_rows:
        add_sheet("IAM_CredReport", all_rows[0], all_rows[1:])

# ---------- Trusted Advisor check catalog ----------
data = load("trustedadvisor-checks-list.json")
if data:
    rows = [[c.get("id","N/A"), c.get("name","N/A"), c.get("category","N/A"), c.get("description","N/A")]
            for c in data.get("checks", [])]
    add_sheet("TrustedAdvisor", ["CheckId","Name","Category","Description"], rows)

if not sheets:
    print("No data found — no JSON files with findings were located in that folder.")
    sys.exit(1)

# ---------- Minimal .xlsx writer (stdlib only) ----------
def _col_letter(idx):
    idx += 1
    letters = ""
    while idx > 0:
        idx, rem = divmod(idx - 1, 26)
        letters = chr(65 + rem) + letters
    return letters

def _sheet_xml(headers, rows):
    parts = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
             '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>']
    for r_idx, row in enumerate([headers] + list(rows), start=1):
        parts.append(f'<row r="{r_idx}">')
        for c_idx, val in enumerate(row):
            col = _col_letter(c_idx)
            text = escape("" if val is None else str(val))
            parts.append(f'<c r="{col}{r_idx}" t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>')
        parts.append('</row>')
    parts.append('</sheetData></worksheet>')
    return "".join(parts)

def save_workbook(path, sheets):
    content_types = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
        '<Default Extension="xml" ContentType="application/xml"/>',
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>']
    for i in range(len(sheets)):
        content_types.append(f'<Override PartName="/xl/worksheets/sheet{i+1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
    content_types.append('</Types>')

    root_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        '</Relationships>')

    workbook_sheets_xml = "".join(
        f'<sheet name="{escape(name)}" sheetId="{i+1}" r:id="rId{i+1}"/>'
        for i, (name, _, _) in enumerate(sheets)
    )
    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<sheets>{workbook_sheets_xml}</sheets></workbook>'
    )

    workbook_rels = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
    for i in range(len(sheets)):
        workbook_rels.append(f'<Relationship Id="rId{i+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i+1}.xml"/>')
    workbook_rels.append('</Relationships>')

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "".join(content_types))
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", workbook_xml)
        z.writestr("xl/_rels/workbook.xml.rels", "".join(workbook_rels))
        for i, (name, headers, rows) in enumerate(sheets):
            z.writestr(f"xl/worksheets/sheet{i+1}.xml", _sheet_xml(headers, rows))

out_path = os.path.join(outdir, "aws-audit.xlsx")
save_workbook(out_path, sheets)
print(f"Workbook saved: {out_path}")
