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
