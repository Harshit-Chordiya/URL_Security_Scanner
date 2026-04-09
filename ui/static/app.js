// Buyhatke Security Scanner — Frontend
const API = "";
let ws = null;
let scanRunning = false;
let currentFindings = [];
let activeFilter = "all";
let severityChart = null;

// ── WebSocket ─────────────────────────────────────────────────────────────

function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws`);

  ws.onopen = () => {
    addLog("Connected to scanner", "info");
  };

  ws.onmessage = (evt) => {
    const msg = JSON.parse(evt.data);
    handleWsMessage(msg);
  };

  ws.onclose = () => {
    addLog("Connection lost — reconnecting in 3s...", "error");
    setTimeout(connectWS, 3000);
  };

  ws.onerror = () => ws.close();
}

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

function handleWsMessage(msg) {
  switch (msg.type) {
    case "connected":
      scanRunning = msg.running;
      setStatus(msg.running ? "running" : "idle");
      updateScanButton();
      if (msg.scheduler_running) updateSchedulerStatus(true);
      break;

    case "scan_started":
      scanRunning = true;
      setStatus("running");
      updateScanButton();
      showProgressBar(true);
      currentFindings = [];
      renderFindings([]);
      clearSummary();
      updateMetrics({ critical: 0, high: 0, medium: 0, low: 0, info: 0 }, 0);
      updateChart({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
      document.getElementById("findingsCount").textContent = "";
      addLog(`Scan started → ${msg.target_url}`);
      break;

    case "progress":
      addLog(msg.message);
      break;

    case "scan_complete":
      scanRunning = false;
      setStatus("complete");
      updateScanButton();
      showProgressBar(false);
      addLog(`✓ Scan complete — ${msg.total_findings} findings`, "info");
      currentFindings = msg.findings || [];
      renderFindings(currentFindings);
      renderSummary(msg.summary, msg.severity_counts, msg.total_findings);
      updateMetrics(msg.severity_counts, msg.total_findings);
      updateChart(msg.severity_counts);
      loadReports();
      break;

    case "error":
      scanRunning = false;
      setStatus("error");
      updateScanButton();
      showProgressBar(false);
      addLog(`✗ Error: ${msg.message}`, "error");
      break;

    case "scheduler":
      addLog(`[Scheduler] ${msg.message}`, "info");
      break;
  }
}

// ── Scan controls ─────────────────────────────────────────────────────────

async function startScan() {
  if (scanRunning) return;
  const url = document.getElementById("targetUrl").value.trim();
  if (!url) { alert("Please enter a target URL first."); return; }

  // Save config first
  await saveConfig({ target_url: url });

  const res = await fetch(`${API}/api/scan/start`, { method: "POST" });
  if (!res.ok) {
    const err = await res.json();
    addLog(`Failed to start scan: ${err.detail}`, "error");
  }
}

async function saveConfig(overrides = {}) {
  const cfg = {
    target_url: document.getElementById("targetUrl").value.trim(),
    max_pages: parseInt(document.getElementById("maxPages").value) || 30,
    crawl_delay: parseFloat(document.getElementById("crawlDelay").value) || 1.0,
    hourly_scan_enabled: document.getElementById("autoScanToggle").checked,
    ...overrides,
  };
  await fetch(`${API}/api/config`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(cfg),
  });
}

async function loadConfig() {
  const res = await fetch(`${API}/api/config`);
  const cfg = await res.json();
  document.getElementById("targetUrl").value = cfg.target_url || "";
  document.getElementById("maxPages").value = cfg.max_pages || 30;
  document.getElementById("crawlDelay").value = cfg.crawl_delay || 1.0;
  document.getElementById("autoScanToggle").checked = cfg.hourly_scan_enabled || false;
  updateSchedulerStatus(cfg.hourly_scan_enabled || false);
  if (cfg.last_scan) {
    document.getElementById("lastScanTime").textContent = `Last scan: ${formatTime(cfg.last_scan)}`;
  }
}

// ── Findings ──────────────────────────────────────────────────────────────

function renderFindings(findings) {
  currentFindings = findings;
  applyFilter(activeFilter);
}

const SEV_COLOR = {
  critical: { border: "#ef4444", bg: "rgba(239,68,68,0.07)", text: "#fca5a5" },
  high:     { border: "#f97316", bg: "rgba(249,115,22,0.07)", text: "#fdba74" },
  medium:   { border: "#eab308", bg: "rgba(234,179,8,0.07)",  text: "#fde047" },
  low:      { border: "#3b82f6", bg: "rgba(59,130,246,0.07)", text: "#93c5fd" },
  info:     { border: "#6b7280", bg: "rgba(107,114,128,0.07)",text: "#9ca3af" },
};

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

// ── Summary ───────────────────────────────────────────────────────────────

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

// ── Chart ─────────────────────────────────────────────────────────────────

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

// ── Reports ───────────────────────────────────────────────────────────────

async function loadReports() {
  const res = await fetch(`${API}/api/reports`);
  const reports = await res.json();
  // Always sort newest first by started_at regardless of API order
  reports.sort((a, b) => new Date(b.started_at) - new Date(a.started_at));
  const list = document.getElementById("reportsList");
  list.innerHTML = "";

  if (!reports.length) {
    list.innerHTML = `<p style="color:var(--muted);text-align:center;padding:30px">No reports yet. Run a scan to generate one.</p>`;
    return;
  }

  reports.forEach(r => {
    const sc = r.severity_counts || {};
    const row = document.createElement("div");
    row.className = "report-row";
    row.innerHTML = `
      <div class="report-meta">
        <div class="report-url">${escHtml(r.target_url || "")}</div>
        <div class="report-time">${formatTime(r.started_at)} · ${r.total_findings} findings</div>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        ${sc.critical ? `<span class="badge badge-critical">${sc.critical}</span>` : ""}
        ${sc.high ? `<span class="badge badge-high">${sc.high}</span>` : ""}
        ${sc.medium ? `<span class="badge badge-medium">${sc.medium}</span>` : ""}
        ${sc.low ? `<span class="badge badge-low">${sc.low}</span>` : ""}
      </div>
      <span class="badge badge-${(r.overall_risk||"info").toLowerCase()}">${r.overall_risk || "—"}</span>
      <button class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="openReport('${r.file}',event)">View Details ↗</button>
      <button class="btn btn-ghost" style="color:var(--critical);border-color:var(--critical);font-size:11px;padding:4px 10px;margin-left:6px" onclick="deleteReport('${r.file}',event)">Delete</button>`;
    row.onclick = () => loadReportDetail(r.file);
    list.appendChild(row);
  });
}

async function loadReportDetail(filename) {
  const res = await fetch(`${API}/api/reports/${filename}`);
  const data = await res.json();
  currentFindings = data.findings || [];
  renderFindings(currentFindings);
  renderSummary(data.summary, data.severity_counts, data.total_findings);
  updateMetrics(data.severity_counts, data.total_findings);
  updateChart(data.severity_counts);
  switchTab("findings");
}

function openReport(filename, evt) {
  evt.stopPropagation();
  const htmlFile = filename.replace(".json", ".html");
  window.open(`${API}/api/reports/${htmlFile}/html`, "_blank");
}

async function deleteReport(filename, evt) {
  evt.stopPropagation();
  if (confirm("Are you sure you want to delete this scan report?")) {
    try {
      const res = await fetch(`${API}/api/reports/${filename}`, { method: "DELETE" });
      if (res.ok) {
        addLog(`Deleted report: ${filename}`, "info");
        await loadReports();
      } else {
        const data = await res.json();
        addLog(`Failed to delete report: ${data.detail}`, "error");
      }
    } catch (err) {
      addLog(`Error deleting report: ${err.message}`, "error");
    }
  }
}


// ── UI helpers ────────────────────────────────────────────────────────────

function addLog(msg, type = "") {
  const time = new Date().toLocaleTimeString();
  // Write to every .log-output element (dashboard preview + full log page)
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

function switchTab(tab) {
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === tab));
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.toggle("active", p.dataset.panel === tab));
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


// ── Auto-scan toggle ──────────────────────────────────────────────────────

document.getElementById("autoScanToggle").addEventListener("change", async (e) => {
  await saveConfig({ hourly_scan_enabled: e.target.checked });
  updateSchedulerStatus(e.target.checked);
  addLog(e.target.checked ? "Hourly auto-scan ENABLED" : "Hourly auto-scan DISABLED", "info");
});

// ── Init ──────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
  await loadConfig();
  await loadReports();
  connectWS();
  showProgressBar(false);
  updateScanButton();

  // Add CSS spinner keyframe dynamically
  const style = document.createElement("style");
  style.textContent = "@keyframes spin{to{transform:rotate(360deg)}}";
  document.head.appendChild(style);
});
