# dashboard.py
# Usage: python3 dashboard.py <OUTDIR> [ACCOUNT_ID] [REGION_LABEL]
# Reads the flat findings CSV (+ a few optional JSON files, if present) from
# OUTDIR and writes OUTDIR/<ACCOUNT_ID>_<REGION_LABEL>_dashboard.html — one
# self-contained file, no dependencies, no internet required. Open it in any
# browser. ACCOUNT_ID + REGION_LABEL (both optional) name the output and are
# used to locate "<ACCOUNT_ID>_<REGION_LABEL>_flat.csv" — useful when
# auditing many accounts/regions and sorting the results later. audit.sh
# always passes both automatically.
import csv, json, os, sys, datetime
from collections import defaultdict, Counter

outdir = sys.argv[1]
account_id = sys.argv[2] if len(sys.argv) > 2 else None
region_label = sys.argv[3] if len(sys.argv) > 3 else None

if not os.path.isdir(outdir):
    print("Error: '{}' is not a folder.".format(outdir))
    print("Point this script at the aws-audit-<account>-<region>-<timestamp> FOLDER")
    print("produced by audit.sh (the one containing the *_flat.csv file) — not the .xlsx file.")
    sys.exit(1)

def read_csv(fname):
    path = os.path.join(outdir, fname)
    if not os.path.exists(path):
        return []
    with open(path, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))

def read_json(fname):
    path = os.path.join(outdir, fname)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return None

def find_findings_csv():
    # Preferred: "<ACCOUNT_ID>_<REGION_LABEL>_flat.csv" (or just one of the
    # two, if that's all we were given).
    name_parts = [p for p in (account_id, region_label) if p]
    if name_parts:
        candidate = "{}_flat.csv".format("_".join(name_parts))
        if os.path.exists(os.path.join(outdir, candidate)):
            return candidate
    # Fallback: any "*_flat.csv" sitting in the folder.
    for fname in sorted(os.listdir(outdir)):
        if fname.endswith("_flat.csv"):
            return fname
    # Legacy fallback: older audit.sh versions wrote "master-findings.csv".
    return "master-findings.csv"

findings = read_csv(find_findings_csv())

def norm_sev(raw):
    s = (raw or "").strip().upper()
    if s == "CRITICAL":
        return "Critical"
    if s == "HIGH":
        return "High"
    if s in ("MEDIUM", "MODERATE"):
        return "Medium"
    # Safety net: some services (e.g. GuardDuty) report severity as a raw
    # numeric score (1.0-10.0) rather than a string label. audit.sh converts
    # GuardDuty's score to a label before writing master-findings.csv, but
    # this catches any numeric value that slips through (old CSVs built
    # before that fix, or a future service added the same way), using
    # GuardDuty's own published bands: Critical 9.0-10.0, High 7.0-8.9,
    # Medium 4.0-6.9, Low 1.0-3.9.
    try:
        score = float(s)
        if score >= 9:
            return "Critical"
        if score >= 7:
            return "High"
        if score >= 4:
            return "Medium"
        return "Low"
    except ValueError:
        pass
    return "Low"  # LOW, INFORMATIONAL, NON_COMPLIANT, blank, etc.

SEV_ORDER = ["Critical", "High", "Medium", "Low"]
STATUS_COLOR = {
    "Critical": "#d03b3b",
    "High":     "#ec835a",
    "Medium":   "#fab219",
    "Low":      "#0ca30c",
}

sev_counts = Counter()
source_counts = Counter()
source_sev = defaultdict(Counter)
source_order = []

for row in findings:
    src = row.get("Source", "Unknown") or "Unknown"
    sev = norm_sev(row.get("Severity", ""))
    sev_counts[sev] += 1
    source_counts[src] += 1
    source_sev[src][sev] += 1
    if src not in source_order:
        source_order.append(src)

total_findings = len(findings)

# ---------- optional environment-health tiles ----------
extra_tiles = []

ec2 = read_json("ec2-instances.json")
ssm = read_json("ssm-managed-instances.json")
if ec2:
    all_ids = set()
    for res in ec2.get("Reservations", []):
        for inst in res.get("Instances", []):
            iid = inst.get("InstanceId")
            if iid:
                all_ids.add(iid)
    managed_ids = set()
    if ssm:
        managed_ids = {i.get("InstanceId") for i in ssm.get("InstanceInformationList", [])}
    if all_ids:
        covered = len(managed_ids & all_ids)
        pct = round(100 * covered / len(all_ids))
        extra_tiles.append(("SSM Coverage", f"{pct}%", f"{covered} of {len(all_ids)} instances managed"))

sg = read_json("ec2-security-groups.json")
if sg:
    open_count = 0
    for g in sg.get("SecurityGroups", []):
        for perm in g.get("IpPermissions", []):
            for r in perm.get("IpRanges", []):
                if r.get("CidrIp") == "0.0.0.0/0":
                    open_count += 1
                    break
    extra_tiles.append(("Open Security Group Rules", str(open_count), "Ingress rules allowing 0.0.0.0/0"))

acm_expiring = 0
if os.path.isdir(outdir):
    now = datetime.datetime.now(datetime.timezone.utc)
    for fname in os.listdir(outdir):
        if fname.startswith("acm-cert-detail-") and fname.endswith(".json"):
            cert_data = read_json(fname)
            if not cert_data:
                continue
            not_after = cert_data.get("Certificate", {}).get("NotAfter")
            if not_after:
                try:
                    exp = datetime.datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=datetime.timezone.utc)
                    if (exp - now).days <= 60:
                        acm_expiring += 1
                except Exception:
                    pass
if acm_expiring:
    extra_tiles.append(("Certs Expiring Soon", str(acm_expiring), "ACM certificates expiring within 60 days"))

ct_health = read_json("cloudtrail-health.json")
if ct_health:
    ct_not_logging = 0
    ct_degraded = 0
    for t in ct_health:
        if t.get("IsLogging") is False:
            ct_not_logging += 1
        elif (t.get("LatestDeliveryError", "None") != "None"
              or t.get("LatestNotificationError", "None") != "None"
              or t.get("LatestCloudWatchLogsDeliveryError", "None") != "None"
              or t.get("LatestDigestDeliveryError", "None") != "None"
              or t.get("BucketReachableByAuditor", "OK") != "OK"):
            ct_degraded += 1
    ct_issues = ct_not_logging + ct_degraded
    if ct_issues:
        extra_tiles.append((
            "CloudTrail Issues", str(ct_issues),
            "{} not logging, {} degraded (delivery/notification/bucket errors)".format(ct_not_logging, ct_degraded)
        ))

# ---------- SVG helpers ----------
def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))

def rounded_top_path(x, y, w, h, r=4):
    r = max(0, min(r, w / 2, h))
    if h <= 0:
        return ""
    if r == 0:
        return "M{},{} L{},{} L{},{} L{},{} Z".format(x, y + h, x, y, x + w, y, x + w, y + h)
    return (
        "M{},{} L{},{} Q{},{} {},{} L{},{} Q{},{} {},{} L{},{} Z".format(
            x, y + h,
            x, y + r,
            x, y, x + r, y,
            x + w - r, y,
            x + w, y, x + w, y + r,
            x + w, y + h,
        )
    )

def severity_bar_chart():
    w, h = 560, 260
    pad_l, pad_b, pad_t = 40, 40, 20
    plot_w, plot_h = w - pad_l - 20, h - pad_b - pad_t
    max_v = max([sev_counts.get(s, 0) for s in SEV_ORDER] + [1])
    n = len(SEV_ORDER)
    gap = 16
    bar_w = (plot_w - gap * (n - 1)) / n
    bars, labels = [], []
    for i, sev in enumerate(SEV_ORDER):
        val = sev_counts.get(sev, 0)
        bh = (val / max_v) * plot_h if max_v else 0
        x = pad_l + i * (bar_w + gap)
        y = pad_t + (plot_h - bh)
        color = STATUS_COLOR[sev]
        path = rounded_top_path(x, y, bar_w, bh, 4)
        bars.append(
            '<path d="{}" fill="{}" class="bar" data-label="{}" data-value="{}"/>'.format(
                path, color, esc(sev), val
            )
        )
        labels.append(
            '<text x="{}" y="{}" text-anchor="middle" class="axis-label">{}</text>'.format(
                x + bar_w / 2, pad_t + plot_h + 18, esc(sev)
            )
        )
        if val:
            labels.append(
                '<text x="{}" y="{}" text-anchor="middle" class="value-label">{}</text>'.format(
                    x + bar_w / 2, y - 6, val
                )
            )
    baseline = '<line x1="{}" y1="{}" x2="{}" y2="{}" class="baseline"/>'.format(
        pad_l, pad_t + plot_h, pad_l + plot_w, pad_t + plot_h
    )
    return (
        '<svg viewBox="0 0 {} {}" role="img" aria-label="Findings by severity">{}{}{}</svg>'
    ).format(w, h, baseline, "".join(bars), "".join(labels))

def stacked_source_chart():
    w, h = 640, 320
    pad_l, pad_b, pad_t = 40, 70, 20
    plot_w, plot_h = w - pad_l - 20, h - pad_b - pad_t
    stack_order = ["Low", "Medium", "High", "Critical"]  # most severe on top
    totals = {src: sum(source_sev[src].values()) for src in source_order}
    max_v = max(list(totals.values()) + [1])
    n = len(source_order)
    gap = 20
    bar_w = (plot_w - gap * (n - 1)) / max(n, 1) if n else plot_w
    parts, labels = [], []
    for i, src in enumerate(source_order):
        x = pad_l + i * (bar_w + gap)
        y_cursor = pad_t + plot_h
        seg_count = sum(1 for s in stack_order if source_sev[src].get(s, 0) > 0)
        seg_i = 0
        for s in stack_order:
            val = source_sev[src].get(s, 0)
            if not val:
                continue
            seg_h = (val / max_v) * plot_h if max_v else 0
            seg_i += 1
            is_top = (seg_i == seg_count)
            y_top = y_cursor - seg_h
            if is_top:
                path = rounded_top_path(x, y_top, bar_w, seg_h, 4)
                parts.append(
                    '<path d="{}" fill="{}" class="bar" data-label="{} — {}" data-value="{}"/>'.format(
                        path, STATUS_COLOR[s], esc(src), esc(s), val
                    )
                )
            else:
                parts.append(
                    '<rect x="{}" y="{}" width="{}" height="{}" fill="{}" class="bar" '
                    'stroke="var(--surface-1)" stroke-width="2" data-label="{} — {}" data-value="{}"/>'.format(
                        x, y_top, bar_w, seg_h, STATUS_COLOR[s], esc(src), esc(s), val
                    )
                )
            y_cursor = y_top
        labels.append(
            '<text x="{}" y="{}" text-anchor="middle" class="axis-label" transform="rotate(20 {} {})">{}</text>'.format(
                x + bar_w / 2, pad_t + plot_h + 18, x + bar_w / 2, pad_t + plot_h + 18, esc(src)
            )
        )
        if totals[src]:
            labels.append(
                '<text x="{}" y="{}" text-anchor="middle" class="value-label">{}</text>'.format(
                    x + bar_w / 2, y_cursor - 6, totals[src]
                )
            )
    baseline = '<line x1="{}" y1="{}" x2="{}" y2="{}" class="baseline"/>'.format(
        pad_l, pad_t + plot_h, pad_l + plot_w, pad_t + plot_h
    )
    return (
        '<svg viewBox="0 0 {} {}" role="img" aria-label="Findings by source, split by severity">{}{}{}</svg>'
    ).format(w, h, baseline, "".join(parts), "".join(labels))

def legend_html():
    items = "".join(
        '<span class="legend-item"><span class="swatch" style="background:{}"></span>{}</span>'.format(
            STATUS_COLOR[s], s
        )
        for s in SEV_ORDER
    )
    return '<div class="legend">{}</div>'.format(items)

def kpi_tiles():
    tiles = [
        ("Total Active Findings", str(total_findings), ""),
        ("Critical", str(sev_counts.get("Critical", 0)), "Fix first"),
        ("High", str(sev_counts.get("High", 0)), ""),
    ] + extra_tiles
    html = ""
    for label, value, sub in tiles:
        sub_html = '<div class="tile-sub">{}</div>'.format(esc(sub)) if sub else ""
        html += (
            '<div class="tile"><div class="tile-value">{}</div>'
            '<div class="tile-label">{}</div>{}</div>'
        ).format(esc(value), esc(label), sub_html)
    return html

def findings_table():
    rows = ""
    for r in findings:
        sev = norm_sev(r.get("Severity", ""))
        rows += (
            '<tr data-sev="{}"><td><span class="pill" style="background:{}22;color:{}">{}</span></td>'
            '<td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'
        ).format(
            esc(sev), STATUS_COLOR[sev], STATUS_COLOR[sev], esc(sev),
            esc(r.get("Source", "")), esc(r.get("Title", "")), esc(r.get("ResourceId", "")),
            esc(r.get("Status", "")), esc(r.get("Timestamp", "")),
        )
    return rows

generated = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

CSS = """
  .viz-root {
    color-scheme: light;
    --surface-1: #fcfcfb; --page: #f9f9f7;
    --text-primary: #0b0b0b; --text-secondary: #52514e; --text-muted: #898781;
    --gridline: #e1e0d9; --baseline: #c3c2b7; --border: rgba(11,11,11,0.10);
  }
  @media (prefers-color-scheme: dark) {
    .viz-root {
      color-scheme: dark;
      --surface-1: #1a1a19; --page: #0d0d0d;
      --text-primary: #ffffff; --text-secondary: #c3c2b7; --text-muted: #898781;
      --gridline: #2c2c2a; --baseline: #383835; --border: rgba(255,255,255,0.10);
    }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--page); font-family: system-ui,-apple-system,"Segoe UI",sans-serif; }
  .viz-root { max-width: 1100px; margin: 0 auto; padding: 32px 20px 60px; color: var(--text-primary); }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .subtitle { color: var(--text-secondary); font-size: 13px; margin-bottom: 28px; }
  .kpi-row { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 28px; }
  .tile { flex: 1 1 150px; background: var(--surface-1); border: 1px solid var(--border);
           border-radius: 10px; padding: 16px 18px; }
  .tile-value { font-size: 32px; font-weight: 600; line-height:1.1; }
  .tile-label { font-size: 13px; color: var(--text-secondary); margin-top: 4px; }
  .tile-sub { font-size: 11px; color: var(--text-muted); margin-top: 2px; }
  .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 28px; }
  @media (max-width: 800px) { .charts { grid-template-columns: 1fr; } }
  .chart-card { background: var(--surface-1); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
  .chart-card h2 { font-size: 14px; margin: 0 0 12px; color: var(--text-secondary); font-weight: 600; }
  svg { width: 100%; height: auto; overflow: visible; }
  .bar { cursor: pointer; }
  .axis-label { font-size: 10px; fill: var(--text-muted); }
  .value-label { font-size: 11px; fill: var(--text-primary); font-weight: 600; }
  .baseline { stroke: var(--baseline); stroke-width: 1; }
  .legend { display: flex; gap: 14px; margin-top: 10px; flex-wrap: wrap; }
  .legend-item { font-size: 12px; color: var(--text-secondary); display: flex; align-items: center; gap: 6px; }
  .swatch { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--gridline); }
  th { color: var(--text-secondary); font-weight: 600; cursor: pointer; user-select: none; }
  .pill { padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
  #search { padding: 8px 10px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface-1);
             color: var(--text-primary); width: 260px; margin-bottom: 12px; font-size: 13px; }
  #tooltip { position: fixed; pointer-events: none; background: var(--text-primary); color: var(--page);
              padding: 6px 10px; border-radius: 6px; font-size: 12px; opacity: 0; transition: opacity .1s; z-index: 10; }
"""

SCRIPT = """
  const tip = document.getElementById('tooltip');
  document.querySelectorAll('.bar').forEach(el => {
    el.addEventListener('mousemove', e => {
      tip.textContent = el.dataset.label + ': ' + el.dataset.value;
      tip.style.left = (e.clientX + 12) + 'px';
      tip.style.top = (e.clientY + 12) + 'px';
      tip.style.opacity = 1;
    });
    el.addEventListener('mouseleave', () => tip.style.opacity = 0);
  });

  const search = document.getElementById('search');
  const rows = Array.from(document.querySelectorAll('#findings-table tbody tr'));
  search.addEventListener('input', () => {
    const q = search.value.toLowerCase();
    rows.forEach(r => { r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none'; });
  });

  document.querySelectorAll('#findings-table th').forEach(th => {
    th.addEventListener('click', () => {
      const col = +th.dataset.col;
      const tbody = document.querySelector('#findings-table tbody');
      const sorted = rows.slice().sort((a, b) =>
        a.children[col].textContent.localeCompare(b.children[col].textContent));
      if (th.dataset.dir === 'asc') { sorted.reverse(); th.dataset.dir = 'desc'; } else { th.dataset.dir = 'asc'; }
      sorted.forEach(r => tbody.appendChild(r));
    });
  });
"""

html_out = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AWS Security Audit — {account_title}</title>
<style>{css}</style>
</head>
<body>
<div class="viz-root">
  <h1>AWS Security Audit — Leadership Summary{account_heading}</h1>
  <div class="subtitle">Generated {generated} · {total} active findings across {nsources} services</div>

  <div class="kpi-row">{kpis}</div>

  <div class="charts">
    <div class="chart-card">
      <h2>Findings by Severity</h2>
      {sev_chart}
    </div>
    <div class="chart-card">
      <h2>Findings by Source</h2>
      {source_chart}
      {legend}
    </div>
  </div>

  <div class="chart-card">
    <h2>All Findings</h2>
    <input id="search" type="text" placeholder="Filter by title, source, resource...">
    <table id="findings-table">
      <thead><tr>
        <th data-col="0">Severity</th><th data-col="1">Source</th><th data-col="2">Title</th>
        <th data-col="3">Resource</th><th data-col="4">Status</th><th data-col="5">Timestamp</th>
      </tr></thead>
      <tbody>{table_rows}</tbody>
    </table>
  </div>
</div>

<div id="tooltip"></div>
<script>{script}</script>
</body>
</html>""".format(
    css=CSS,
    account_title=(esc("_".join(p for p in (account_id, region_label) if p)) if (account_id or region_label) else "Leadership Summary"),
    account_heading=(" — Account {}".format(esc(" / ".join(p for p in (account_id, region_label) if p))) if (account_id or region_label) else ""),
    generated=generated,
    total=total_findings,
    nsources=len(source_order),
    kpis=kpi_tiles(),
    sev_chart=severity_bar_chart(),
    source_chart=stacked_source_chart(),
    legend=legend_html(),
    table_rows=findings_table(),
    script=SCRIPT,
)

name_parts = [p for p in (account_id, region_label) if p]
html_name = "{}_dashboard.html".format("_".join(name_parts)) if name_parts else "leadership-dashboard.html"
out_path = os.path.join(outdir, html_name)
with open(out_path, "w", encoding="utf-8") as f:
    f.write(html_out)
print("Dashboard saved: " + out_path)
print("Open it directly in a browser — no server needed.")
