// Buyhatke Security Scanner — Core State & Init
const windowAPI = "";
let ws = null;
let scanRunning = false;
let currentFindings = [];
let activeFilter = "all";
let severityChart = null;

const SEV_COLOR = {
  critical: { border: "#ef4444", bg: "rgba(239,68,68,0.07)", text: "#fca5a5" },
  high:     { border: "#f97316", bg: "rgba(249,115,22,0.07)", text: "#fdba74" },
  medium:   { border: "#eab308", bg: "rgba(234,179,8,0.07)",  text: "#fde047" },
  low:      { border: "#3b82f6", bg: "rgba(59,130,246,0.07)", text: "#93c5fd" },
  info:     { border: "#6b7280", bg: "rgba(107,114,128,0.07)",text: "#9ca3af" },
};

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

document.getElementById("autoScanToggle")?.addEventListener("change", async (e) => {
  await saveConfig({ hourly_scan_enabled: e.target.checked });
  updateSchedulerStatus(e.target.checked);
  addLog(e.target.checked ? "Hourly auto-scan ENABLED" : "Hourly auto-scan DISABLED", "info");
});
