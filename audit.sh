#!/bin/bash
# AWS GovCloud Audit Data Pull + Master CSV + Workbook + Dashboard — run from CloudShell in us-gov-west-1
# One-shot: pulls all AWS data, builds master-findings.csv, aws-audit.xlsx, and leadership-dashboard.html.

# Pass a region as the first argument to skip the prompt, e.g.:
#   ./audit.sh us-gov-east-1
if [ -n "$1" ]; then
  REGION="$1"
else
  echo "Which AWS region should this audit target?"
  PS3="Enter a number: "
  options=(
    "us-gov-west-1 (AWS GovCloud West)"
    "us-gov-east-1 (AWS GovCloud East)"
    "us-east-1 (N. Virginia)"
    "us-east-2 (Ohio)"
    "us-west-1 (N. California)"
    "us-west-2 (Oregon)"
  )
  select opt in "${options[@]}"; do
    case $REPLY in
      1) REGION="us-gov-west-1"; break ;;
      2) REGION="us-gov-east-1"; break ;;
      3) REGION="us-east-1"; break ;;
      4) REGION="us-east-2"; break ;;
      5) REGION="us-west-1"; break ;;
      6) REGION="us-west-2"; break ;;
      *) echo "Invalid choice — enter a number 1-6." ;;
    esac
  done
fi

# ---------- Friendly region label used in output file/folder names ----------
# (REGION itself stays the raw AWS region code — every --region flag below
# needs that; REGION_LABEL is only for naming things for humans.)
case "$REGION" in
  us-gov-west-1) REGION_LABEL="US-Gov-West" ;;
  us-gov-east-1) REGION_LABEL="US-Gov-East" ;;
  us-east-1)     REGION_LABEL="US-East-1" ;;
  us-east-2)     REGION_LABEL="US-East-2" ;;
  us-west-1)     REGION_LABEL="US-West-1" ;;
  us-west-2)     REGION_LABEL="US-West-2" ;;
  *)             REGION_LABEL="$REGION" ;;
esac

# ---------- Identify the account so multi-account output is easy to sort ----------
ACCOUNT_ID=$(aws sts get-caller-identity --region $REGION --output text --query 'Account' 2>/dev/null)
if [ -z "$ACCOUNT_ID" ] || [ "$ACCOUNT_ID" = "None" ]; then
  echo "WARNING: could not determine the AWS account number via 'aws sts get-caller-identity'."
  echo "         Falling back to 'UNKNOWN-ACCOUNT' in output file/folder names — check your credentials."
  ACCOUNT_ID="UNKNOWN-ACCOUNT"
fi

STAMP=$(date +%Y%m%d-%H%M%S)
OUTDIR="aws-audit-${ACCOUNT_ID}-${REGION_LABEL}-${STAMP}"
mkdir -p "$OUTDIR"

echo ""
echo "AWS Account: $ACCOUNT_ID"
echo "Running audit against region: $REGION ($REGION_LABEL)"
if [[ "$REGION" == us-gov-* ]]; then
  echo "Note: AWS Organizations always routes to us-gov-west-1 internally regardless of this setting."
else
  echo "Note: AWS Organizations always routes to us-east-1 internally regardless of this setting."
fi
echo ""

# ---------- Ensure companion scripts (workbook.py, dashboard.py) are present ----------
# If this copy of audit.sh isn't already sitting next to workbook.py/dashboard.py,
# pull them from the fowler repo instead of requiring you to download each file by hand.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$SCRIPT_DIR"

if [ ! -f "$SCRIPT_DIR/workbook.py" ] || [ ! -f "$SCRIPT_DIR/dashboard.py" ]; then
  echo "workbook.py/dashboard.py not found next to this script — fetching them from the fowler repo..."
  if [ -d "$SCRIPT_DIR/fowler" ]; then
    (cd "$SCRIPT_DIR/fowler" && git pull)
  else
    git clone https://github.com/opsec12/fowler.git "$SCRIPT_DIR/fowler"
  fi
  REPO_DIR="$SCRIPT_DIR/fowler"
  chmod +x "$REPO_DIR/audit.sh" 2>/dev/null
  echo ""
  echo "NOTE: if fowler is a private repo and the clone above just hung waiting for a"
  echo "username/password, either make the repo public on GitHub, or set up cached git"
  echo "credentials (a Personal Access Token via a git credential helper) beforehand —"
  echo "this step can't respond to an interactive password prompt on its own."
  echo ""
fi

# ---------- Security Hub ----------
aws securityhub get-findings \
  --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"},{"Value":"HIGH","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' \
  --region $REGION --output json > "$OUTDIR/securityhub-findings.json"

# ---------- AWS Config ----------
aws configservice describe-config-rules \
  --region $REGION --output json > "$OUTDIR/config-all-rules.json"

aws configservice describe-conformance-packs \
  --region $REGION --output json > "$OUTDIR/config-conformance-packs.json"

aws configservice describe-compliance-by-config-rule \
  --compliance-types NON_COMPLIANT \
  --region $REGION --output json > "$OUTDIR/config-noncompliant-rules.json"

for rule in $(aws configservice describe-compliance-by-config-rule \
  --compliance-types NON_COMPLIANT --region $REGION \
  --output text --query 'ComplianceByConfigRules[].ConfigRuleName'); do
  aws configservice get-compliance-details-by-config-rule \
    --config-rule-name "$rule" \
    --compliance-types NON_COMPLIANT \
    --region $REGION --output json > "$OUTDIR/config-detail-${rule}.json"
done

# ---------- Inspector ----------
aws inspector2 list-findings \
  --filter-criteria '{"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}]}' \
  --region $REGION --output json > "$OUTDIR/inspector-findings.json"

aws inspector2 batch-get-account-status \
  --region $REGION --output json > "$OUTDIR/inspector-enablement-status.json"

# ---------- GuardDuty ----------
DETECTOR_ID=$(aws guardduty list-detectors --region $REGION --output text --query 'DetectorIds[0]')

if [ -z "$DETECTOR_ID" ] || [ "$DETECTOR_ID" = "None" ]; then
  echo "No GuardDuty detector found in $REGION — skipping GuardDuty."
else
  # Pull ALL findings (no severity filter) — the workbook/dashboard/CSV need
  # every severity present to report accurately, not just High+.
  GD_FINDING_IDS=$(aws guardduty list-findings \
    --detector-id $DETECTOR_ID \
    --region $REGION --output text --query 'FindingIds')

  if [ -n "$GD_FINDING_IDS" ]; then
    aws guardduty get-findings \
      --detector-id $DETECTOR_ID \
      --finding-ids $GD_FINDING_IDS \
      --region $REGION --output json > "$OUTDIR/guardduty-findings.json"
  else
    echo "GuardDuty detector found but no findings currently exist in $REGION."
  fi
fi

# ---------- IAM ----------
aws iam generate-credential-report --region $REGION

while true; do
  STATUS=$(aws iam generate-credential-report --region $REGION --query 'State' --output text)
  if [ "$STATUS" = "COMPLETE" ]; then
    break
  fi
  echo "Credential report status: $STATUS — waiting..."
  sleep 3
done

aws iam get-credential-report \
  --region $REGION --output json > "$OUTDIR/iam-credential-report.json"

ANALYZER_ARN=$(aws accessanalyzer list-analyzers --region $REGION --output text --query 'analyzers[0].arn')

if [ -z "$ANALYZER_ARN" ] || [ "$ANALYZER_ARN" = "None" ]; then
  echo "No Access Analyzer found in $REGION — skipping Access Analyzer."
else
  aws accessanalyzer list-findings \
    --analyzer-arn $ANALYZER_ARN \
    --filter '{"status":{"eq":["ACTIVE"]}}' \
    --region $REGION --output json > "$OUTDIR/access-analyzer-findings.json"
fi

# ---------- CloudTrail ----------
aws cloudtrail describe-trails \
  --region $REGION --output json > "$OUTDIR/cloudtrail-trails.json"

CT_HEALTH_JSONL="$OUTDIR/.cloudtrail-health-entries.jsonl"
> "$CT_HEALTH_JSONL"

while IFS=$'\t' read -r trail_arn home_region bucket_name log_validation; do
  [ -z "$trail_arn" ] && continue
  trail_short=$(basename "$trail_arn")
  status_file="$OUTDIR/cloudtrail-status-${trail_short}.json"

  aws cloudtrail get-trail-status \
    --name "$trail_arn" \
    --region "$home_region" --output json > "$status_file"

  aws cloudtrail get-event-selectors \
    --trail-name "$trail_arn" \
    --region "$home_region" --output json > "$OUTDIR/cloudtrail-event-selectors-${trail_short}.json"

  # Can the AUDITOR's own identity reach the trail's destination bucket at all?
  # This is separate from LatestDeliveryError below, which is whether CloudTrail's
  # own service-linked delivery can reach it — the two can fail independently.
  BUCKET_CHECK="OK"
  if [ -n "$bucket_name" ] && [ "$bucket_name" != "None" ]; then
    if ! aws s3api head-bucket --bucket "$bucket_name" --region "$home_region" \
      2>"$OUTDIR/cloudtrail-bucket-check-${trail_short}.log"; then
      BUCKET_CHECK="INACCESSIBLE_TO_AUDITOR"
    fi
  else
    BUCKET_CHECK="NO_BUCKET_CONFIGURED"
  fi

  if [ -s "$status_file" ]; then
    jq --arg trail "$trail_short" --arg bucket "$bucket_name" \
       --arg bucketcheck "$BUCKET_CHECK" --arg logval "$log_validation" '{
      Trail: $trail,
      S3Bucket: $bucket,
      LogFileValidationEnabled: $logval,
      BucketReachableByAuditor: $bucketcheck,
      IsLogging: (.IsLogging // false),
      LatestDeliveryError: (.LatestDeliveryError // "None"),
      LatestDeliveryTime: (.LatestDeliveryTime // "N/A"),
      LatestNotificationError: (.LatestNotificationError // "None"),
      LatestCloudWatchLogsDeliveryError: (.LatestCloudWatchLogsDeliveryError // "None"),
      LatestDigestDeliveryError: (.LatestDigestDeliveryError // "None"),
      StartLoggingTime: (.StartLoggingTime // "N/A"),
      StopLoggingTime: (.StopLoggingTime // "N/A")
    }' "$status_file" >> "$CT_HEALTH_JSONL"
  fi
done < <(aws cloudtrail describe-trails --region $REGION --output text \
  --query 'trailList[].[TrailARN,HomeRegion,S3BucketName,LogFileValidationEnabled]')

if [ -s "$CT_HEALTH_JSONL" ]; then
  jq -s '.' "$CT_HEALTH_JSONL" > "$OUTDIR/cloudtrail-health.json"
fi
rm -f "$CT_HEALTH_JSONL"

# ---------- Trusted Advisor ----------
aws support describe-trusted-advisor-checks \
  --language en \
  --region $REGION --output json > "$OUTDIR/trustedadvisor-checks-list.json"

# ---------- S3 + KMS ----------
aws s3control get-public-access-block \
  --account-id $(aws sts get-caller-identity --region $REGION --output text --query 'Account') \
  --region $REGION --output json > "$OUTDIR/s3-account-public-access-block.json"

aws kms list-keys --region $REGION --output json > "$OUTDIR/kms-keys.json"

# ---------- Amazon Detective: automated Investigations ----------
GRAPH_ARN=$(aws detective list-graphs --region $REGION --output text --query 'GraphList[0].Arn')

if [ -z "$GRAPH_ARN" ] || [ "$GRAPH_ARN" = "None" ]; then
  echo "No Detective behavior graph found in $REGION — skipping Detective."
else
  aws detective list-investigations \
    --graph-arn "$GRAPH_ARN" \
    --region $REGION --output json > "$OUTDIR/detective-investigations.json"

  for inv_id in $(jq -r '.InvestigationDetails[]?.InvestigationId' "$OUTDIR/detective-investigations.json"); do
    aws detective get-investigation \
      --graph-arn "$GRAPH_ARN" \
      --investigation-id "$inv_id" \
      --region $REGION --output json > "$OUTDIR/detective-investigation-${inv_id}.json"

    aws detective list-indicators \
      --graph-arn "$GRAPH_ARN" \
      --investigation-id "$inv_id" \
      --region $REGION --output json > "$OUTDIR/detective-indicators-${inv_id}.json"
  done
fi

# ---------- Amazon Macie: sensitive data findings ----------
MACIE_STATUS=$(aws macie2 get-macie-session --region $REGION --output text --query 'status' 2>/dev/null)

if [ -z "$MACIE_STATUS" ] || [ "$MACIE_STATUS" != "ENABLED" ]; then
  echo "Macie not enabled (or unavailable in this partition) in $REGION — skipping Macie."
else
  MACIE_FINDING_IDS=$(aws macie2 list-findings --region $REGION --output text --query 'findingIds')
  if [ -n "$MACIE_FINDING_IDS" ]; then
    aws macie2 get-findings \
      --finding-ids $MACIE_FINDING_IDS \
      --region $REGION --output json > "$OUTDIR/macie-findings.json"
  else
    echo "Macie enabled but returned zero findings."
  fi
fi

# ---------- Systems Manager: patch compliance ----------
aws ec2 describe-instances --region $REGION --output json > "$OUTDIR/ec2-instances.json"

aws ssm describe-instance-information --region $REGION --output json > "$OUTDIR/ssm-managed-instances.json"

mapfile -t SSM_INSTANCE_IDS < <(jq -r '.InstanceInformationList[].InstanceId' "$OUTDIR/ssm-managed-instances.json")

if [ ${#SSM_INSTANCE_IDS[@]} -eq 0 ]; then
  echo "No SSM-managed instances found in $REGION — skipping patch state pull."
else
  batch_num=0
  for ((i=0; i<${#SSM_INSTANCE_IDS[@]}; i+=50)); do
    batch=("${SSM_INSTANCE_IDS[@]:i:50}")
    aws ssm describe-instance-patch-states \
      --instance-ids "${batch[@]}" \
      --region $REGION --output json > "$OUTDIR/ssm-patch-states-batch-${batch_num}.json"
    batch_num=$((batch_num+1))
  done
fi

# ---------- VPC: Security Groups + Flow Logs ----------
aws ec2 describe-security-groups --region $REGION --output json > "$OUTDIR/ec2-security-groups.json"
aws ec2 describe-flow-logs --region $REGION --output json > "$OUTDIR/ec2-flow-logs.json"

# ---------- ACM: certificates ----------
aws acm list-certificates --region $REGION --output json > "$OUTDIR/acm-certificates.json"

for cert_arn in $(jq -r '.CertificateSummaryList[].CertificateArn' "$OUTDIR/acm-certificates.json"); do
  cert_short=$(basename "$cert_arn")
  aws acm describe-certificate \
    --certificate-arn "$cert_arn" \
    --region $REGION --output json > "$OUTDIR/acm-cert-detail-${cert_short}.json"
done

# ---------- Secrets Manager ----------
aws secretsmanager list-secrets --region $REGION --output json > "$OUTDIR/secretsmanager-secrets.json"

# ---------- RDS ----------
aws rds describe-db-instances --region $REGION --output json > "$OUTDIR/rds-db-instances.json"

# ---------- AWS Organizations: SCPs ----------
aws organizations list-policies --filter SERVICE_CONTROL_POLICY \
  --region $REGION --output json > "$OUTDIR/org-scps.json" 2>"$OUTDIR/org-scps-error.log"

if [ ! -s "$OUTDIR/org-scps.json" ]; then
  echo "Could not retrieve SCPs (not org management/delegated admin, or Organizations not in use) — see org-scps-error.log"
fi

# ---------- Master findings CSV ----------
MASTER_CSV="$OUTDIR/${ACCOUNT_ID}_${REGION_LABEL}_flat.csv"
echo "Source,Severity,ResourceId,ResourceType,Title,Description,Status,Region,Timestamp" > "$MASTER_CSV"

jq -r '.Findings[]? | [
  "SecurityHub",(.Severity.Label // "N/A"),((.Resources[0].Id) // "N/A"),((.Resources[0].Type) // "N/A"),
  (.Title // "N/A"),(.Description // "N/A"),(.Compliance.Status // .RecordState // "N/A"),(.Region // "N/A"),(.UpdatedAt // "N/A")
] | @csv' "$OUTDIR/securityhub-findings.json" >> "$MASTER_CSV"

for f in "$OUTDIR"/config-detail-*.json; do
  [ -e "$f" ] || continue
  jq -r '.EvaluationResults[]? | [
    "Config",.ComplianceType,.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId,
    .EvaluationResultIdentifier.EvaluationResultQualifier.ResourceType,
    .EvaluationResultIdentifier.EvaluationResultQualifier.ConfigRuleName,
    (.Annotation // "N/A"),.ComplianceType,"N/A",.ResultRecordedTime
  ] | @csv' "$f" >> "$MASTER_CSV"
done

jq -r '.findings[]? | [
  "Inspector",.severity,((.resources[0].id) // "N/A"),((.resources[0].type) // "N/A"),
  .title,(.description // "N/A"),.status,"N/A",.firstObservedAt
] | @csv' "$OUTDIR/inspector-findings.json" >> "$MASTER_CSV"

jq -r '.Findings[]? | [
  "GuardDuty",
  (if .Severity >= 9 then "CRITICAL" elif .Severity >= 7 then "HIGH" elif .Severity >= 4 then "MEDIUM" else "LOW" end),
  (.Id // "N/A"),(.Resource.ResourceType // "N/A"),.Title,(.Description // "N/A"),.Type,.Region,.UpdatedAt
] | @csv' "$OUTDIR/guardduty-findings.json" >> "$MASTER_CSV" 2>/dev/null

jq -r '.findings[]? | [
  "AccessAnalyzer",(if .isPublic then "HIGH" else "MEDIUM" end),.resource,.resourceType,
  ("Externally shared: " + .resourceType),(.condition // {} | tostring),.status,"N/A",.updatedAt
] | @csv' "$OUTDIR/access-analyzer-findings.json" >> "$MASTER_CSV" 2>/dev/null

for f in "$OUTDIR"/detective-investigation-*.json; do
  [ -e "$f" ] || continue
  inv_id=$(jq -r '.InvestigationId' "$f")
  indicators_file="$OUTDIR/detective-indicators-${inv_id}.json"
  related_count=0
  if [ -e "$indicators_file" ]; then
    related_count=$(jq '[.Indicators[]? | select(.IndicatorType=="RELATED_FINDING")] | length' "$indicators_file")
  fi
  jq -r --arg relcount "$related_count" '[
    "Detective", .Severity, .EntityArn, .EntityType,
    ("Investigation " + .InvestigationId), ("Related findings: " + $relcount), .Status, "N/A", .CreatedTime
  ] | @csv' "$f" >> "$MASTER_CSV"
done

jq -r '.findings[]? | [
  "Macie",(.severity.description // "N/A"),
  ((.resourcesAffected.s3Object.key // .resourcesAffected.s3Bucket.name) // "N/A"),
  "S3",(.title // "N/A"),(.description // "N/A"),
  (if .archived then "ARCHIVED" else "ACTIVE" end),(.region // "N/A"),(.updatedAt // "N/A")
] | @csv' "$OUTDIR/macie-findings.json" >> "$MASTER_CSV" 2>/dev/null

if [ -s "$OUTDIR/cloudtrail-health.json" ]; then
  jq -r '.[]? | select(
      (.IsLogging == false) or
      (.LatestDeliveryError != "None") or
      (.LatestNotificationError != "None") or
      (.LatestCloudWatchLogsDeliveryError != "None") or
      (.LatestDigestDeliveryError != "None") or
      (.BucketReachableByAuditor != "OK")
    ) | [
      "CloudTrail",
      (if .IsLogging == false then "CRITICAL" else "HIGH" end),
      .Trail,"Trail",
      ("CloudTrail issue: " + .Trail),
      ("IsLogging=" + (.IsLogging|tostring)
        + "; DeliveryError=" + .LatestDeliveryError
        + "; NotificationError=" + .LatestNotificationError
        + "; CloudWatchLogsError=" + .LatestCloudWatchLogsDeliveryError
        + "; DigestError=" + .LatestDigestDeliveryError
        + "; BucketReachableByAuditor=" + .BucketReachableByAuditor
        + "; S3Bucket=" + .S3Bucket),
      (if .IsLogging == false then "NOT_LOGGING" else "DEGRADED" end),
      "N/A",
      (.LatestDeliveryTime // "N/A")
    ] | @csv' "$OUTDIR/cloudtrail-health.json" >> "$MASTER_CSV" 2>/dev/null
fi

echo "Master findings CSV: $MASTER_CSV"

aws iam get-credential-report --region $REGION --output text --query 'Content' \
  | base64 -d > "$OUTDIR/iam-credential-report.csv"

echo "IAM credential report CSV: $OUTDIR/iam-credential-report.csv"

# ---------- Build the Excel workbook and leadership dashboard automatically ----------
if [ -f "$REPO_DIR/workbook.py" ]; then
  echo ""
  echo "Building Excel workbook..."
  python3 "$REPO_DIR/workbook.py" "$OUTDIR" "$ACCOUNT_ID" "$REGION_LABEL"
else
  echo "workbook.py not found (checked $SCRIPT_DIR and $REPO_DIR) — skipping .xlsx build."
fi

if [ -f "$REPO_DIR/dashboard.py" ]; then
  echo ""
  echo "Building leadership dashboard..."
  python3 "$REPO_DIR/dashboard.py" "$OUTDIR" "$ACCOUNT_ID" "$REGION_LABEL"
else
  echo "dashboard.py not found (checked $SCRIPT_DIR and $REPO_DIR) — skipping HTML dashboard build."
fi

echo ""
echo "=================================================="
echo "All done. Account $ACCOUNT_ID — deliverables in: $OUTDIR"
echo ""
FULL_OUTDIR="$(cd "$OUTDIR" && pwd)"
echo "Full paths (use these with CloudShell Actions -> Download file):"
[ -f "$FULL_OUTDIR/${ACCOUNT_ID}_${REGION_LABEL}_flat.csv" ] && echo "  $FULL_OUTDIR/${ACCOUNT_ID}_${REGION_LABEL}_flat.csv"
[ -f "$FULL_OUTDIR/${ACCOUNT_ID}_${REGION_LABEL}_audit.xlsx" ] && echo "  $FULL_OUTDIR/${ACCOUNT_ID}_${REGION_LABEL}_audit.xlsx"
[ -f "$FULL_OUTDIR/${ACCOUNT_ID}_${REGION_LABEL}_dashboard.html" ] && echo "  $FULL_OUTDIR/${ACCOUNT_ID}_${REGION_LABEL}_dashboard.html"
echo "=================================================="
