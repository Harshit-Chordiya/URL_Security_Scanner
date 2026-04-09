// ── DOM & Rendering ───────────────────────────────────────────────────────

function setStatus(state) {
  const dot = document.getElementById("statusDot");
  const txt = document.getElementById("statusText");
  if (!dot || !txt) return;
  const states = {
    idle:     { cls: "",        label: "Idle" },
    running:  { cls: "running", label: "Scanning..." },
    complete: { cls: "",        label: "Complete" },
    error:    { cls: "error",   label: "Error" },
  };
  const s = states[state] || states.idle;
  dot.className = "status-dot " + s.cls;
  txt.textContent = s.label;
}

function renderFindings(findings) {
  currentFindings = findings;
  applyFilter(activeFilter);
}

function normSev(f) {
  return (f.gemini_severity || f.severity || "info").toLowerCase();
}

function applyFilter(sev) {
  activeFilter = sev;
  document.querySelectorAll(".filter-btn").forEach(b => {
    b.classList.toggle("active", b.dataset.sev === sev);
  });

  const filtered = sev === "all"
    ? currentFindings
    : currentFindings.filter(f => normSev(f) === sev);

  // Sort logically from most to least severe
  const sevWeight = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  filtered.sort((a, b) => {
    const wA = sevWeight[normSev(a)] ?? 5;
    const wB = sevWeight[normSev(b)] ?? 5;
    if (wA !== wB) return wA - wB;
    const pA = parseInt(a.priority) || 999;
    const pB = parseInt(b.priority) || 999;
    return pA - pB;
  });

  const container = document.getElementById("findingsList");
  container.innerHTML = "";

  if (!filtered.length) {
    container.innerHTML = `<p style="color:var(--muted);text-align:center;padding:40px">No findings for this filter.</p>`;
    return;
  }

  document.getElementById("findingsCount").textContent = `${filtered.length} of ${currentFindings.length} findings`;

  filtered.forEach(f => {
    const s = normSev(f);
    const theme = SEV_COLOR[s] || SEV_COLOR.info;

    // Build occurrences list
    const occs = (f.occurrences && f.occurrences.length)
      ? f.occurrences
      : [{ url: f.affected_url || "", evidence: f.evidence || "" }];
    const occCount = occs.length;
    const occLabel = `${occCount} location${occCount > 1 ? "s" : ""}`;

    const occRows = occs.map((o, i) => `
      <div style="display:flex;gap:10px;align-items:flex-start;padding:8px 0;
                  border-bottom:1px solid var(--border);font-size:12px">
        <span style="min-width:20px;height:20px;border-radius:50%;
                     background:${theme.bg};color:${theme.text};
                     border:1px solid ${theme.border};font-size:10px;font-weight:700;
                     display:flex;align-items:center;justify-content:center;flex-shrink:0">${i + 1}</span>
        <div style="flex:1;min-width:0">
          <a href="${escHtml(o.url)}" target="_blank" style="color:var(--accent);word-break:break-all">${escHtml(o.url)}</a>
          ${o.evidence ? `<div class="evidence-box" style="margin-top:4px">${escHtml(o.evidence.substring(0, 200))}</div>` : ""}
        </div>
      </div>`).join("");

    const card = document.createElement("div");
    card.className = "finding-card";
    card.dataset.id = f.id;
    card.dataset.severity = s;
    card.style.borderLeft = `3px solid ${theme.border}`;

    card.innerHTML = `
      <div class="finding-header" style="background:${theme.bg}">
        <span class="badge badge-${s}">${s}</span>
        <span class="finding-title">${escHtml(f.title)}</span>
        <span style="font-size:11px;color:${theme.text};background:${theme.bg};
                     padding:2px 8px;border-radius:10px;border:1px solid ${theme.border};
                     white-space:nowrap;flex-shrink:0">${occLabel}</span>
        <span class="finding-category">${escHtml(f.category || "")}</span>
        <button class="finding-chevron-btn" onclick="toggleFinding(this)"
          style="border:1px solid ${theme.border};color:${theme.text};background:${theme.bg};
                 width:26px;height:26px;border-radius:6px;cursor:pointer;font-size:11px;
                 display:flex;align-items:center;justify-content:center;flex-shrink:0;
                 transition:transform .2s;margin-left:auto">▼</button>
      </div>
      <div class="finding-body" style="display:none">
        <div class="detail-row">
          <div class="detail-label">Description</div>
          <div class="detail-value">${escHtml(f.description || "")}</div>
        </div>
        ${f.impact ? `<div class="detail-row"><div class="detail-label">Real-World Impact</div><div class="detail-value">${escHtml(f.impact)}</div></div>` : ""}
        ${f.technical_details ? `<div class="detail-row"><div class="detail-label">Technical Details</div><div class="detail-value">${escHtml(f.technical_details)}</div></div>` : ""}
        <div class="detail-row">
          <div class="detail-label">Affected Location${occCount > 1 ? "s" : ""} (${occCount})</div>
          <div style="border:1px solid var(--border);border-radius:7px;padding:0 10px;background:var(--bg);margin-top:4px">
            ${occRows}
          </div>
        </div>
        <div class="detail-row">
          <div class="detail-label">Fix Suggestion</div>
          <div class="detail-value" style="color:#86efac">${escHtml(f.fix_suggestion || "")}</div>
          ${f.code_example ? `<div class="code-block">${escHtml(f.code_example)}</div>` : ""}
        </div>
        <div style="margin-top:10px;display:flex;align-items:center;flex-wrap:wrap;gap:6px">
          ${f.owasp ? `<span class="owasp-tag">OWASP ${escHtml(f.owasp)}</span>` : ""}
          ${f.cwe ? `<span class="cwe-tag">${escHtml(f.cwe)}</span>` : ""}
          ${(f.references || []).filter(r => r).map(r => `<span class="cwe-tag">${escHtml(r)}</span>`).join("")}
          ${f.priority ? `<span style="margin-left:auto;font-size:11px;color:${theme.text};background:${theme.bg};padding:2px 8px;border-radius:4px;border:1px solid ${theme.border}">Priority #${f.priority}</span>` : ""}
        </div>
      </div>`;
    container.appendChild(card);
  });
}

function toggleFinding(btn) {
  const card = btn.closest(".finding-card");
  const body = card.querySelector(".finding-body");
  const open = body.style.display === "none";
  body.style.display = open ? "block" : "none";
  btn.style.transform = open ? "rotate(180deg)" : "";
}

function renderSummary(summary, sc, total) {
  if (!summary || !summary.overall_risk) return;
  const colors = { Critical: "#ef4444", High: "#f97316", Medium: "#eab308", Low: "#3b82f6" };
  const color = colors[summary.overall_risk] || "#6b7280";

  document.getElementById("summaryBox").innerHTML = `
    <div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap">
      <div>
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)">Overall Risk</div>
        <div class="overall-risk" style="color:${color}">${summary.overall_risk}</div>
        ${summary.risk_score != null ? `<div style="font-size:12px;color:var(--muted)">Risk Score: ${summary.risk_score}/100</div>` : ""}
      </div>
      <div style="flex:1;min-width:200px">
        ${summary.executive_summary ? `<div class="exec-summary">${escHtml(summary.executive_summary)}</div>` : ""}
      </div>
    </div>
    ${summary.immediate_actions?.length ? `
      <div style="margin-top:14px">
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:8px">Immediate Actions</div>
        <ul style="padding-left:18px;line-height:2;color:#86efac;font-size:13px">
          ${summary.immediate_actions.map(a => `<li>${escHtml(a)}</li>`).join("")}
        </ul>
      </div>` : ""}
    ${summary.key_findings?.length ? `
      <div style="margin-top:12px">
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:8px">Key Findings</div>
        <ul style="padding-left:18px;line-height:2;color:var(--muted);font-size:13px">
          ${summary.key_findings.map(k => `<li>${escHtml(k)}</li>`).join("")}
        </ul>
      </div>` : ""}`;
}

function clearSummary() {
  document.getElementById("summaryBox").innerHTML =
    `<p style="color:var(--muted);font-size:13px">Summary will appear after the scan completes.</p>`;
}

function updateMetrics(sc, total) {
  document.getElementById("metricTotal").textContent = total || 0;
  document.getElementById("metricCritical").textContent = sc?.critical || 0;
  document.getElementById("metricHigh").textContent = sc?.high || 0;
  document.getElementById("metricMedium").textContent = sc?.medium || 0;
  document.getElementById("metricLow").textContent = sc?.low || 0;
  document.getElementById("metricInfo").textContent = sc?.info || 0;
}

function updateChart(sc) {
  const ctx = document.getElementById("severityChart")?.getContext("2d");
  if (!ctx) return;

  const data = {
    labels: ["Critical", "High", "Medium", "Low", "Info"],
    datasets: [{
      data: [sc?.critical||0, sc?.high||0, sc?.medium||0, sc?.low||0, sc?.info||0],
      backgroundColor: ["#ef4444","#f97316","#eab308","#3b82f6","#6b7280"],
      borderWidth: 0,
    }]
  };

  if (severityChart) {
    severityChart.data = data;
    severityChart.update();
  } else {
    severityChart = new Chart(ctx, {
      type: "doughnut",
      data,
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: "#94a3b8", padding: 12, font: { size: 12 } } },
          tooltip: { callbacks: { label: (c) => ` ${c.label}: ${c.raw}` } }
        },
        cutout: "68%",
      }
    });
  }
}

function addLog(msg, type = "") {
  const time = new Date().toLocaleTimeString();
  document.querySelectorAll(".log-output").forEach(box => {
    const line = document.createElement("div");
    line.className = `log-line ${type}`;
    line.textContent = `[${time}] ${msg}`;
    box.appendChild(line);
    box.scrollTop = box.scrollHeight;
    while (box.children.length > 200) box.removeChild(box.firstChild);
  });
}

function updateScanButton() {
  const btn = document.getElementById("scanBtn");
  btn.disabled = scanRunning;
  btn.innerHTML = scanRunning
    ? `<span style="display:inline-block;animation:spin 1s linear infinite">⟳</span> Scanning...`
    : "▶ Run Scan Now";
}

function showProgressBar(show) {
  const bar = document.getElementById("progressBar");
  if (show) {
    bar.classList.add("indeterminate");
    bar.parentElement.style.display = "block";
  } else {
    bar.classList.remove("indeterminate");
    bar.parentElement.style.display = "none";
  }
}

function updateSchedulerStatus(enabled) {
  const el = document.getElementById("schedulerStatus");
  if (el) el.textContent = enabled ? "Auto-scan: ON (hourly)" : "Auto-scan: OFF";
  document.getElementById("autoScanToggle").checked = enabled;
}

function formatTime(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function switchNav(page) {
  document.querySelectorAll(".nav-item").forEach(n => n.classList.toggle("active", n.dataset.page === page));
  document.querySelectorAll(".page").forEach(p => p.style.display = p.dataset.page === page ? "block" : "none");
  if (page === "reports") loadReports();
}

function stepNumber(id, stepAmount, minVal, maxVal, toFixed=0) {
  const el = document.getElementById(id);
  if (!el) return;
  let val = parseFloat(el.value || 0) + stepAmount;
  if (val < minVal) val = minVal;
  if (val > maxVal) val = maxVal;
  el.value = toFixed ? val.toFixed(toFixed) : Math.round(val);
}
