const statusPanel = document.getElementById("statusPanel");
const statusText = document.getElementById("statusText");
const deviceRecognition = document.getElementById("deviceRecognition");
const vulnerabilityResults = document.getElementById("vulnerabilityResults");
const analysisResults = document.getElementById("analysisResults");
const useRecognizedDevices = document.getElementById("useRecognizedDevices");
const neo4jPreview = document.getElementById("neo4jPreview");
const vulnTime = document.getElementById("vulnTime");
const assessmentForm = document.getElementById("assessmentForm");
const assessmentModeInputs = document.querySelectorAll('input[name="assessmentMode"]');
const assessmentPanels = document.querySelectorAll("[data-mode-panel]");
const targetIpInput = document.getElementById("targetIp");
const targetSubnetInput = document.getElementById("targetSubnet");
const targetMaskInput = document.getElementById("targetMask");
const targetFileInput = document.getElementById("targetFile");

const USE_MOCK_DATA = true;

const mockData = {
  ip: "192.168.1.10",
  fingerprint: {
    technologies: [
      { name: "OpenSSH", version: "8.4p1", category: "Remote Management" },
      { name: "nginx", version: "1.22", category: "Web Services" },
      { name: "Siemens S7", version: "V5.6", category: "Industrial Control" },
    ],
    os: "Embedded Linux (kernel 4.19)",
  },
  recognition: {
    primary: "Industrial Gateway / Router",
    confidence: 0.87,
    secondary: [
      { type: "Industrial Controller", score: 0.65 },
      { type: "Edge Computing Node", score: 0.42 },
    ],
    metadata: {
      manufacturer: "Siemens",
      productLine: "Scalance M Series",
      firmware: "V8.2.1",
      serial: "SCM-38210",
    },
    stats: {
      totalDevices: 13609,
      topDevices: [
        { name: "printer/hp", count: 2299, percentage: 16.9 },
        { name: "router/intelbras", count: 1203, percentage: 8.8 },
        { name: "router/bec", count: 876, percentage: 6.4 },
        { name: "gateway/zyxel", count: 709, percentage: 5.2 },
        { name: "router/tp-link", count: 543, percentage: 4.0 },
        { name: "router/netgear", count: 543, percentage: 4.0 },
        { name: "router/zyxel", count: 477, percentage: 3.5 },
        { name: "router/d-link", count: 307, percentage: 2.3 },
        { name: "printer/kyocera", count: 261, percentage: 1.9 },
        { name: "modem/tp-link", count: 185, percentage: 1.4 },
      ],
    },
  },
  vulnerabilities: [
    {
      cve: "CVE-2023-12345",
      severity: "high",
      score: 8.8,
      description: "An authentication bypass vulnerability in certain Scalance devices could allow unauthorized access.",
      published: "2023-11-18",
      exploit: "PoC",
    },
    {
      cve: "CVE-2022-55678",
      severity: "medium",
      score: 6.5,
      description: "The nginx HTTP/2 module can trigger a denial of service under specific conditions.",
      published: "2022-08-01",
      exploit: "Not available",
    },
    {
      cve: "CVE-2021-9876",
      severity: "low",
      score: 4.3,
      description: "OpenSSH may allow information disclosure under weak configurations in specific environments.",
      published: "2021-04-12",
      exploit: "Not available",
    },
  ],
  analysis: [
    {
      deviceType: "Industrial Gateway / Router",
      cpe: "cpe:/o:siemens:scalance_m745",
      relationship: "Asset type",
    },
    {
      deviceType: "Industrial Controller",
      cpe: "cpe:/a:siemens:wincc:8.1",
      relationship: "Companion software",
    },
    {
      deviceType: "Edge Computing Node",
      cpe: "cpe:/h:siemens:industrial_edge",
      relationship: "Alternative",
    },
  ],
};

const API_ENDPOINTS = {
  assessment: "/api/assessment",
  vulnerability: "/api/vulnerabilities",
  analysis: "/api/cpe-mapping",
};

const DEVICE_STATS_COLORS = [
  "#2563eb",
  "#38bdf8",
  "#22c55e",
  "#f97316",
  "#facc15",
  "#a855f7",
  "#ec4899",
  "#14b8a6",
  "#f87171",
  "#6366f1",
  "#0ea5e9",
  "#94a3b8",
];



function clone(data) {
  if (typeof structuredClone === "function") {
    return structuredClone(data);
  }
  return JSON.parse(JSON.stringify(data));
}

function sanitizeForHtml(value) {
  const input = String(value ?? "");
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatNumber(value) {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return "-";
  }
  return value.toLocaleString("en-US");
}

function formatPercentage(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "-";
  }
  return `${value.toFixed(1)}%`;
}

function getActiveAssessmentMode() {
  const checked = Array.from(assessmentModeInputs).find((input) => input.checked);
  return checked?.value ?? "single";
}

function setAssessmentMode(mode) {
  assessmentModeInputs.forEach((input) => {
    const isActive = input.value === mode;
    input.checked = isActive;
    input.parentElement?.classList.toggle("active", isActive);
  });

  assessmentPanels.forEach((panel) => {
    const isActive = panel.dataset.modePanel === mode;
    panel.hidden = !isActive;
    panel.classList.toggle("active", isActive);
    panel.querySelectorAll("input, textarea, select").forEach((field) => {
      if (!field.dataset.originalRequired) {
        field.dataset.originalRequired = field.required ? "true" : "false";
      }
      field.required = field.dataset.originalRequired === "true" && isActive;
      field.disabled = !isActive;
    });
  });
}

function buildSummaryFromInputs(mode) {
  if (mode === "file") {
    const file = targetFileInput?.files?.[0];
    return {
      mode,
      label: file ? `File: ${file.name}` : "File upload",
      targetsPreview: file ? [file.name] : [],
      totalTargets: file ? undefined : 0,
      message: file ? `Imported file ${file.name}` : undefined,
    };
  }

  if (mode === "subnet") {
    const subnet = targetSubnetInput?.value?.trim();
    const mask = targetMaskInput?.value?.trim();
    return {
      mode,
      label: subnet && mask ? `${subnet} / ${mask}` : "Subnet range",
      targetsPreview: subnet && mask ? [`${subnet}/${mask}`] : [],
      totalTargets: undefined,
      message: subnet && mask ? `Subnet ${subnet}/${mask} will be scanned` : undefined,
    };
  }

  const ip = targetIpInput?.value?.trim();
  return {
    mode: "single",
    label: ip || "Target IP",
    targetsPreview: ip ? [ip] : [],
    totalTargets: ip ? 1 : 0,
    message: ip ? `Target IP ${ip} is under assessment` : undefined,
  };
}

function updateStatus(state, message) {
  statusPanel.classList.remove("ready", "loading", "error");
  statusPanel.classList.add(state);
  statusText.textContent = message;
}

function renderVulnerabilities(vulnerabilities) {
  if (!vulnerabilityResults) {
    return;
  }
  if (!vulnerabilities || vulnerabilities.length === 0) {
    vulnerabilityResults.innerHTML = '<div class="alert">No related vulnerabilities were found.</div>';
    vulnerabilityResults.classList.remove("placeholder");
    return;
  }

  const table = document.createElement("table");
  const thead = document.createElement("thead");
  thead.innerHTML = `
    <tr>
      <th>CVE</th>
      <th>Severity</th>
      <th>CVSS</th>
      <th>Description</th>
      <th>Published</th>
      <th>Exploit</th>
    </tr>
  `;
  table.appendChild(thead);

  const tbody = document.createElement("tbody");

  vulnerabilities.forEach((vuln) => {
    const tr = document.createElement("tr");

    const severityClass = {
      high: "high",
      medium: "medium",
      low: "low",
    }[vuln.severity?.toLowerCase()] ?? "neutral";

    tr.innerHTML = `
      <td>${vuln.cve}</td>
      <td><span class="badge ${severityClass}">${vuln.severity}</span></td>
      <td>${vuln.score ?? "-"}</td>
      <td>${vuln.description ?? ""}</td>
      <td>${vuln.published ?? ""}</td>
      <td>${vuln.exploit ?? "-"}</td>
    `;

    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  vulnerabilityResults.classList.remove("placeholder");
  vulnerabilityResults.innerHTML = "";
  vulnerabilityResults.appendChild(table);
}

function renderAnalysis(analysis) {
  if (!analysisResults) {
    return;
  }
  if (!analysis || analysis.length === 0) {
    analysisResults.innerHTML = '<div class="placeholder">No mapping data available</div>';
    analysisResults.classList.add("placeholder");
    return;
  }

  const table = document.createElement("table");
  table.innerHTML = `
    <thead>
      <tr>
        <th>Device Type</th>
        <th>CPE</th>
        <th>Relationship</th>
      </tr>
    </thead>
  `;

  const tbody = document.createElement("tbody");
  analysis.forEach((item) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${item.deviceType}</td>
      <td><code>${item.cpe}</code></td>
      <td>${item.relationship ?? "Association"}</td>
    `;
    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  analysisResults.classList.remove("placeholder");
  analysisResults.innerHTML = "";
  analysisResults.appendChild(table);
}

function renderRecognition(recognition) {
  const dataset = prepareDeviceStatsDataset(recognition?.stats);

  if (!dataset.entries.length || dataset.total <= 0) {
    deviceRecognition.innerHTML = '<div class="placeholder">No device recognition statistics are available yet</div>';
    deviceRecognition.classList.add("placeholder");
    useRecognizedDevices.disabled = true;
    delete useRecognizedDevices.dataset.types;
    return;
  }

  const container = document.createElement("div");
  container.className = "recognition";
  container.appendChild(createDeviceStatisticsSection(dataset));

  deviceRecognition.classList.remove("placeholder");
  deviceRecognition.innerHTML = "";
  deviceRecognition.appendChild(container);

  useRecognizedDevices.dataset.types = JSON.stringify(dataset.topEntries.map((entry) => entry.label));
  useRecognizedDevices.disabled = dataset.topEntries.length === 0;
}

function createDeviceStatisticsSection(dataset) {
  const section = document.createElement("div");
  section.className = "device-stats";

  const title = document.createElement("h4");
  title.textContent = "Device recognition statistics";
  section.appendChild(title);

  const summary = document.createElement("p");
  summary.className = "stats-summary";
  summary.textContent = `Scanned ${formatNumber(dataset.total)} devices in total. The top ten device categories are listed below:`;
  section.appendChild(summary);

  const visual = document.createElement("div");
  visual.className = "stats-visual";

  const insights = document.createElement("div");
  insights.className = "stats-insights";
  insights.appendChild(createPieChartElement(dataset));
  insights.appendChild(createLegendElement(dataset));
  visual.appendChild(insights);

  visual.appendChild(createStatsTable(dataset));
  section.appendChild(visual);

  return section;
}

function prepareDeviceStatsDataset(stats) {
  if (!stats) {
    return { total: 0, entries: [], topEntries: [] };
  }

  const total = Number(stats.totalDevices) || 0;
  const topDevices = Array.isArray(stats.topDevices) ? stats.topDevices : [];

  const entries = topDevices
    .map((item) => {
      const count = Number(item.count) || 0;
      if (count <= 0) {
        return null;
      }
      const percentage =
        typeof item.percentage === "number"
          ? item.percentage
          : total > 0
          ? (count / total) * 100
          : 0;
      const label = item.label ?? item.name ?? item.type ?? "Unknown device";
      return { label, count, percentage, isOther: false };
    })
    .filter(Boolean);

  const sumCounts = entries.reduce((sum, entry) => sum + entry.count, 0);
  const remainder = total - sumCounts;

  if (remainder > 0) {
    entries.push({
      label: "Other",
      count: remainder,
      percentage: total > 0 ? (remainder / total) * 100 : 0,
      isOther: true,
    });
  }

  entries.forEach((entry, index) => {
    entry.color = DEVICE_STATS_COLORS[index % DEVICE_STATS_COLORS.length];
  });

  return {
    total,
    entries,
    topEntries: entries.filter((entry) => !entry.isOther),
    otherEntry: entries.find((entry) => entry.isOther),
  };
}

function createPieChartElement(dataset) {
  const wrapper = document.createElement("div");
  wrapper.className = "pie-wrapper";

  const pie = document.createElement("div");
  pie.className = "pie-chart";

  const segments = [];
  let cumulative = 0;

  dataset.entries.forEach((entry, index) => {
    const ratio = dataset.total > 0 ? entry.count / dataset.total : 0;
    const start = (cumulative * 100).toFixed(2);
    cumulative += ratio;
    const end = index === dataset.entries.length - 1 ? 100 : (cumulative * 100).toFixed(2);
    segments.push(`${entry.color} ${start}% ${end}%`);
  });

  pie.style.background = segments.length
    ? `conic-gradient(${segments.join(", ")})`
    : "var(--bg-elevated)";

  const center = document.createElement("div");
  center.className = "pie-center";
  center.innerHTML = `<strong>${formatNumber(dataset.total)}</strong><span>Devices in total</span>`;
  pie.appendChild(center);

  wrapper.appendChild(pie);
  return wrapper;
}

function createLegendElement(dataset) {
  const legend = document.createElement("ul");
  legend.className = "pie-legend";

  dataset.entries.forEach((entry) => {
    const item = document.createElement("li");
    item.className = "legend-item";
    if (entry.isOther) {
      item.classList.add("is-other");
    }

    const swatch = document.createElement("span");
    swatch.className = "legend-swatch";
    swatch.style.setProperty("--swatch-color", entry.color);
    item.appendChild(swatch);

    const meta = document.createElement("div");
    meta.className = "legend-meta";

    const label = document.createElement("strong");
    label.textContent = entry.label;
    meta.appendChild(label);

    item.appendChild(meta);
    legend.appendChild(item);
  });

  return legend;
}

function createStatsTable(dataset) {
  const wrapper = document.createElement("div");
  wrapper.className = "stats-table-wrapper";

  const table = document.createElement("table");
  table.className = "stats-table";

  table.innerHTML = `
    <thead>
      <tr>
        <th>Rank</th>
        <th>Device Type</th>
        <th>Count</th>
        <th>Share</th>
      </tr>
    </thead>
  `;

  const tbody = document.createElement("tbody");
  dataset.topEntries.forEach((entry, index) => {
    const tr = document.createElement("tr");

    const rank = document.createElement("td");
    rank.textContent = index + 1;
    tr.appendChild(rank);

    const label = document.createElement("td");
    label.textContent = entry.label;
    tr.appendChild(label);

    const count = document.createElement("td");
    count.textContent = `${formatNumber(entry.count)}`;
    tr.appendChild(count);

    const percentage = document.createElement("td");
    percentage.textContent = formatPercentage(entry.percentage);
    tr.appendChild(percentage);

    tbody.appendChild(tr);
  });

  if (dataset.otherEntry) {
    const tr = document.createElement("tr");
    tr.className = "other-row";

    const rank = document.createElement("td");
    rank.textContent = "-";
    tr.appendChild(rank);

    const label = document.createElement("td");
    label.textContent = dataset.otherEntry.label;
    tr.appendChild(label);

    const count = document.createElement("td");
    count.textContent = `${formatNumber(dataset.otherEntry.count)}`;
    tr.appendChild(count);

    const percentage = document.createElement("td");
    percentage.textContent = formatPercentage(dataset.otherEntry.percentage);
    tr.appendChild(percentage);

    tbody.appendChild(tr);
  }

  table.appendChild(tbody);
  wrapper.appendChild(table);
  return wrapper;
}

async function performAssessment(mode, useMock) {
  setLoadingState(true);
  updateStatus("loading", "Starting assessment task...");

  const summary = buildSummaryFromInputs(mode);

  if (useMock) {
    await delay(450);
    const data = clone(mockData);

    if (summary) {
      data.summary = {
        ...summary,
        message: summary.message
          ? `${summary.message} (demo data)`
          : "Demo data result",
      };

    }

    renderAssessment(data);
    updateStatus(
      "ready",
      summary?.label
        ? `Assessment complete (demo): ${summary.label}`
        : "Assessment complete (demo data)"
    );
    setLoadingState(false);
    return;
  }

  try {
    const response = await sendAssessmentRequest(mode);
    if (!response.ok) {
      throw new Error(await extractError(response));
    }

    const data = await response.json();
    renderAssessment(data);
    updateStatus("ready", data.summary?.message ?? "Assessment complete");
  } catch (error) {
    console.error(error);
    updateStatus("error", error.message || "Assessment failed. Please verify the backend service.");
  } finally {
    setLoadingState(false);
  }
}

function sendAssessmentRequest(mode) {
  if (mode === "file") {
    if (!targetFileInput?.files?.length) {
      throw new Error("Please select a file that contains IP addresses first.");
    }
    const formData = new FormData();
    formData.append("type", "file");
    formData.append("targetsFile", targetFileInput.files[0]);
    return fetch(API_ENDPOINTS.assessment, {
      method: "POST",
      body: formData,
    });
  }

  if (mode === "subnet") {
    const payload = {
      type: "subnet",
      subnet: targetSubnetInput.value.trim(),
      mask: targetMaskInput.value.trim(),
    };
    return fetch(API_ENDPOINTS.assessment, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  }

  const payload = {
    type: "single",
    ip: targetIpInput.value.trim(),
  };
  return fetch(API_ENDPOINTS.assessment, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

async function extractError(response) {
  try {
    const data = await response.json();
    return data?.message ?? response.statusText ?? "Unknown error";
  } catch (error) {
    return response.statusText || "Service error";
  }
}

function renderAssessment(data) {
  renderRecognition(data?.recognition);
}

async function handleVulnerabilitySearch(deviceTypes, useMock) {
  const devices = deviceTypes
    .split(/\n|,/)
    .map((item) => item.trim())
    .filter(Boolean);

  if (devices.length === 0) {
    if (vulnerabilityResults) {
      vulnerabilityResults.innerHTML = '<div class="alert">Please enter at least one device type.</div>';
      vulnerabilityResults.classList.remove("placeholder");
    }
    return;
  }

  const start = performance.now();
  vulnTime.textContent = "Searching...";

  if (useMock) {
    await delay(420);
    renderVulnerabilities(mockData.vulnerabilities);
    renderAnalysis(mockData.analysis);
    vulnTime.textContent = `Elapsed ${(performance.now() - start).toFixed(0)} ms (demo data)`;
    return;
  }

  try {
    const response = await fetch(API_ENDPOINTS.vulnerability, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ deviceTypes: devices }),
    });
    if (!response.ok) throw new Error("Vulnerability search failed");
    const data = await response.json();
    renderVulnerabilities(data.vulnerabilities);
    renderAnalysis(data.analysis);
    vulnTime.textContent = `Elapsed ${(performance.now() - start).toFixed(0)} ms`;
  } catch (error) {
    console.error(error);
    if (vulnerabilityResults) {
      vulnerabilityResults.innerHTML = `<div class="alert">${error.message}</div>`;
      vulnerabilityResults.classList.remove("placeholder");
    }
    vulnTime.textContent = "";
  }
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function setLoadingState(loading) {
  if (loading) {
    statusPanel.classList.add("loading");
    statusPanel.classList.remove("ready", "error");
  } else {
    statusPanel.classList.remove("loading");
    if (!statusPanel.classList.contains("error")) {
      statusPanel.classList.add("ready");
    }
  }
}

function resetDashboard() {
  assessmentForm?.reset();
  if (targetFileInput) {
    targetFileInput.value = "";
  }
  setAssessmentMode("single");

  deviceRecognition.innerHTML = "Waiting for recognition results";
  deviceRecognition.classList.add("placeholder");
  useRecognizedDevices.disabled = true;
  delete useRecognizedDevices.dataset.types;

  if (vulnerabilityResults) {
    vulnerabilityResults.innerHTML = "Vulnerability search has not started yet";
    vulnerabilityResults.classList.add("placeholder");
  }

  if (analysisResults) {
    analysisResults.innerHTML = "Awaiting correlation results";
    analysisResults.classList.add("placeholder");
  }

  vulnTime.textContent = "";
  document.getElementById("deviceTypes").value = "";
  const initialStatus = USE_MOCK_DATA ? "Awaiting action (demo mode)" : "Awaiting action";
  updateStatus("ready", initialStatus);
}

function preloadDemoRecognition() {
  if (!USE_MOCK_DATA) {
    return;
  }

  const data = clone(mockData);
  renderAssessment(data);
  updateStatus("ready", "Recognition complete");
}

function showNeo4jPlaceholder(message) {
  if (!neo4jPreview) {
    return;
  }
  const placeholder = document.createElement("div");
  placeholder.className = "placeholder";
  placeholder.textContent = message || "Searching for Neo4j graph image";
  neo4jPreview.innerHTML = "";
  neo4jPreview.appendChild(placeholder);
  neo4jPreview.classList.add("placeholder");
}

function loadNeo4jImage() {
  if (!neo4jPreview) {
    return;
  }
  const img = document.createElement("img");
  img.src = "neo4j.png";
  img.alt = "Neo4j graph preview";
  img.onload = () => {
    neo4jPreview.innerHTML = "";
    neo4jPreview.appendChild(img);
    neo4jPreview.classList.remove("placeholder");
  };
  img.onerror = () => {
    showNeo4jPlaceholder("neo4j.png was not found. Place the image in the project front-end directory.");
  };
}

function initNeo4jSection() {
  if (!neo4jPreview) {
    return;
  }
  loadNeo4jImage();
}

function initEventListeners() {
  assessmentForm.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!assessmentForm.reportValidity()) {
      return;
    }
    const mode = getActiveAssessmentMode();
    performAssessment(mode, USE_MOCK_DATA);
  });

  assessmentModeInputs.forEach((input) => {
    input.addEventListener("change", () => setAssessmentMode(input.value));
  });

  document.getElementById("vulnForm").addEventListener("submit", (event) => {
    event.preventDefault();
    const deviceTypes = event.target.deviceTypes.value;
    handleVulnerabilitySearch(deviceTypes, USE_MOCK_DATA);
  });

  document.getElementById("resetButton").addEventListener("click", resetDashboard);

  useRecognizedDevices.addEventListener("click", () => {
    const types = JSON.parse(useRecognizedDevices.dataset.types ?? "[]");
    document.getElementById("deviceTypes").value = types.join(", ");
  });
}

function bootstrap() {
  initEventListeners();
  initNeo4jSection();
  resetDashboard();
  preloadDemoRecognition();
}

bootstrap();
