// ── API & Network ─────────────────────────────────────────────────────────

async function startScan() {
  if (scanRunning) return;
  const url = document.getElementById("targetUrl").value.trim();
  if (!url) { alert("Please enter a target URL first."); return; }

  // Save config first
  await saveConfig({ target_url: url });

  const res = await fetch(`${windowAPI}/api/scan/start`, { method: "POST" });
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
  await fetch(`${windowAPI}/api/config`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(cfg),
  });
}

async function loadConfig() {
  const res = await fetch(`${windowAPI}/api/config`);
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

async function loadReports() {
  const res = await fetch(`${windowAPI}/api/reports`);
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
  const res = await fetch(`${windowAPI}/api/reports/${filename}`);
  if (!res.ok) return;
  const data = await res.json();
  currentFindings = data.findings || [];
  renderFindings(currentFindings);
  renderSummary(data.summary, data.severity_counts, data.total_findings);
  updateMetrics(data.severity_counts, data.total_findings);
  updateChart(data.severity_counts);
  switchNav("findings");
}

function openReport(filename, evt) {
  evt.stopPropagation();
  const htmlFile = filename.replace(".json", ".html");
  window.open(`${windowAPI}/api/reports/${htmlFile}/html`, "_blank");
}

async function deleteReport(filename, evt) {
  evt.stopPropagation();
  if (confirm("Are you sure you want to delete this scan report?")) {
    try {
      const res = await fetch(`${windowAPI}/api/reports/${filename}`, { method: "DELETE" });
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
