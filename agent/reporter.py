"""
Report Generator
Produces a JSON report and a self-contained HTML report for each scan.
"""
import json
import datetime
from pathlib import Path

REPORTS_DIR = Path("reports")

SEV = {
    "critical": {"color": "#ef4444", "bg": "rgba(239,68,68,0.10)",  "text": "#b91c1c", "dot": "#ef4444"},
    "high":     {"color": "#f97316", "bg": "rgba(249,115,22,0.10)", "text": "#c2410c", "dot": "#f97316"},
    "medium":   {"color": "#eab308", "bg": "rgba(234,179,8,0.10)",  "text": "#854d0e", "dot": "#eab308"},
    "low":      {"color": "#3b82f6", "bg": "rgba(59,130,246,0.10)", "text": "#1d4ed8", "dot": "#3b82f6"},
    "info":     {"color": "#6b7280", "bg": "rgba(107,114,128,0.08)","text": "#374151", "dot": "#6b7280"},
}


def _t(sev: str) -> dict:
    return SEV.get(sev.lower(), SEV["info"])


def generate_report(report_data: dict, scan_id: str) -> dict:
    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base_name = f"scan_{scan_id}_{ts}"

    json_path = REPORTS_DIR / f"{base_name}.json"
    html_path = REPORTS_DIR / f"{base_name}.html"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, default=str)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(_build_html_report(report_data, scan_id))

    return {"json": str(json_path), "html": str(html_path)}


def generate_report_from_existing(report_data: dict, json_path: Path) -> dict:
    """Overwrites an existing report with new data and regenerates the HTML."""
    json_path = Path(json_path)
    html_path = json_path.with_suffix(".html")
    scan_id = report_data.get("scan_id", "")
    
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, default=str)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(_build_html_report(report_data, scan_id))

    return {"json": str(json_path), "html": str(html_path)}


def _badge(sev: str) -> str:
    t = _t(sev)
    return (
        f'<span class="badge" data-sev="{sev.lower()}" style="'
        f'background:{t["bg"]};color:{t["text"]};border:1.5px solid {t["color"]};'
        f'padding:3px 12px;border-radius:12px;font-size:11px;font-weight:700;'
        f'text-transform:uppercase;letter-spacing:.05em;white-space:nowrap;flex-shrink:0">'
        f'{sev.lower()}</span>'
    )


def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _build_html_report(data: dict, scan_id: str) -> str:
    findings = data.get("findings", [])
    sc       = data.get("severity_counts", {})
    summary  = data.get("summary", {})
    target   = data.get("target_url", "")
    pages    = data.get("pages_crawled", 0)
    started  = data.get("started_at", "")
    finished = data.get("finished_at", "")

    # Sort findings by severity
    sev_weight = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(findings, key=lambda f: (
        sev_weight.get((f.get("gemini_severity") or f.get("severity", "info")).lower(), 5),
        int(f.get("priority", 999)) if str(f.get("priority", "999")).isdigit() else 999
    ))


    overall_risk  = summary.get("overall_risk", "—")
    risk_color    = _t(overall_risk)["color"] if overall_risk != "—" else "#6b7280"

    # ── Finding cards ────────────────────────────────────────────────────────
    cards = ""
    for idx, f in enumerate(findings):
        sev = (f.get("gemini_severity") or f.get("severity", "info")).lower()
        t   = _t(sev)

        code_block = ""
        if f.get("code_example"):
            code_block = f'<pre class="code-block"><code>{_esc(f["code_example"])}</code></pre>'

        refs_html = ""
        if f.get("references"):
            chips = " ".join(
                f'<code class="chip-cwe">{_esc(r)}</code>'
                for r in f["references"] if r
            )
            refs_html = f'<div style="margin-top:6px">{chips}</div>'

        priority_html = ""
        if f.get("priority"):
            priority_html = (
                f'<span style="font-size:11px;color:{t["text"]};background:{t["bg"]};'
                f'padding:2px 9px;border-radius:10px;border:1px solid {t["color"]};white-space:nowrap">'
                f'#{f["priority"]}</span>'
            )

        # ── Occurrences (merged URLs) ─────────────────────────────────────
        occurrences = f.get("occurrences", [])
        if not occurrences:
            occurrences = [{"url": f.get("affected_url", ""), "evidence": f.get("evidence", "")}]

        occ_count = len(occurrences)
        count_label = (
            f'<span style="font-size:11px;color:{t["text"]};background:{t["bg"]};'
            f'padding:2px 9px;border-radius:10px;border:1px solid {t["color"]};white-space:nowrap;margin-left:4px">'
            f'{occ_count} location{"s" if occ_count > 1 else ""}</span>'
        )

        occ_rows = ""
        for i, occ in enumerate(occurrences, 1):
            url = occ.get("url", "")
            ev  = occ.get("evidence", "")
            occ_rows += f"""
            <div style="display:flex;gap:10px;align-items:flex-start;padding:8px 0;
                        border-bottom:1px solid #f1f5f9;font-size:13px">
              <span style="min-width:22px;height:22px;border-radius:50%;background:{t['bg']};
                           color:{t['text']};border:1px solid {t['color']};font-size:11px;
                           font-weight:700;display:flex;align-items:center;justify-content:center;
                           flex-shrink:0">{i}</span>
              <div style="flex:1;min-width:0">
                <a href="{_esc(url)}" target="_blank"
                   style="color:#2563eb;word-break:break-all">{_esc(url)}</a>
                {('<br><code style="font-size:11px;color:#64748b;word-break:break-all">' + _esc(ev[:200]) + '</code>') if ev else ''}
              </div>
            </div>"""

        occ_section = f"""
        <div class="detail-row">
          <div class="detail-label">Affected Location{"s" if occ_count > 1 else ""} ({occ_count})</div>
          <div style="margin-top:4px;border:1px solid #e2e8f0;border-radius:7px;
                      padding:0 10px;background:#fafafa">
            {occ_rows}
          </div>
        </div>"""

        cards += f"""
<div class="finding-card" data-sev="{sev}" style="border-left:3px solid {t['color']}">
  <div class="finding-row" style="background:{t['bg']}">
    {_badge(sev)}
    <span class="finding-title">{_esc(f.get('title',''))}</span>
    {count_label}
    <span class="finding-cat">{_esc(f.get('category',''))}</span>
    {priority_html}
    <button class="chevron-btn" onclick="toggleCard(this)" title="Show details"
      style="border:1px solid {t['color']};color:{t['text']};background:{t['bg']}">
      &#9660;
    </button>
  </div>
  <div class="finding-body">
    <div class="detail-row">
      <div class="detail-label">Description</div>
      <div class="detail-val">{_esc(f.get('description',''))}</div>
    </div>
    {'<div class="detail-row"><div class="detail-label">Real-World Impact</div><div class="detail-val">' + _esc(f.get('impact','')) + '</div></div>' if f.get('impact') else ''}
    {'<div class="detail-row"><div class="detail-label">Technical Details</div><div class="detail-val">' + _esc(f.get('technical_details','')) + '</div></div>' if f.get('technical_details') else ''}
    {occ_section}
    <div class="detail-row">
      <div class="detail-label">Fix Suggestion</div>
      <div class="detail-val fix-val">{_esc(f.get('fix_suggestion',''))}</div>
      {code_block}
    </div>
    {refs_html}
    <div class="tag-row">
      {'<code class="chip-owasp">OWASP ' + _esc(f.get("owasp","")) + '</code>' if f.get("owasp") else ''}
      {'<code class="chip-cwe">' + _esc(f.get("cwe","")) + '</code>' if f.get("cwe") else ''}
    </div>
  </div>
</div>"""

    # ── Summary bullets ──────────────────────────────────────────────────────
    kf_html  = "".join(f"<li>{_esc(k)}</li>" for k in summary.get("key_findings", []))
    act_html = "".join(f"<li>{_esc(a)}</li>" for a in summary.get("immediate_actions", []))

    # ── Filter buttons (counts per severity) ─────────────────────────────────
    total = data.get("total_findings", 0)
    filter_btns = f'<button class="fbtn active" data-f="all" onclick="filter(this)">All <span class="fcount">{total}</span></button>'
    for s in ["critical", "high", "medium", "low", "info"]:
        cnt = sc.get(s, 0)
        t2  = _t(s)
        filter_btns += (
            f'<button class="fbtn" data-f="{s}" onclick="filter(this)" '
            f'style="--fc:{t2["color"]};--fb:{t2["bg"]};--ft:{t2["text"]}">'
            f'<span class="fdot" style="background:{t2["dot"]}"></span>'
            f'{s.capitalize()} <span class="fcount">{cnt}</span></button>'
        )

    import jinja2

    template_path = Path("ui/templates/report_template.html")
    if not template_path.exists():
        return "<html><body><h1>Report Template Missing</h1></body></html>"
        
    template_str = template_path.read_text(encoding="utf-8")
    template = jinja2.Template(template_str)

    return template.render(
        target=_esc(target),
        scan_id=scan_id,
        started=started[:19].replace('T',' '),
        risk_color=risk_color,
        overall_risk=_esc(overall_risk),
        total=total,
        num_critical=sc.get('critical',0),
        num_high=sc.get('high',0),
        num_medium=sc.get('medium',0),
        num_low=sc.get('low',0),
        num_info=sc.get('info',0),
        pages=pages,
        summary_exec=_esc(summary.get("executive_summary","")) if summary.get("executive_summary") else "",
        kf_html=kf_html,
        act_html=act_html,
        filter_btns=filter_btns,
        cards=cards,
        finished=finished[:19].replace('T',' ')
    )
