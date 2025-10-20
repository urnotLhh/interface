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
      { name: "OpenSSH", version: "8.4p1", category: "远程管理" },
      { name: "nginx", version: "1.22", category: "Web 服务" },
      { name: "Siemens S7", version: "V5.6", category: "工业控制" },
    ],
    os: "Embedded Linux (kernel 4.19)",
  },
  recognition: {
    primary: "工业网关 / 路由器",
    confidence: 0.87,
    secondary: [
      { type: "工业控制器", score: 0.65 },
      { type: "边缘计算节点", score: 0.42 },
    ],
    metadata: {
      manufacturer: "Siemens",
      productLine: "Scalance M 系列",
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
      description: "某些 Scalance 设备中的身份验证绕过漏洞，可导致未授权访问。",
      published: "2023-11-18",
      exploit: "PoC",
    },
    {
      cve: "CVE-2022-55678",
      severity: "medium",
      score: 6.5,
      description: "nginx HTTP/2 模块在特定条件下可能导致拒绝服务。",
      published: "2022-08-01",
      exploit: "暂无",
    },
    {
      cve: "CVE-2021-9876",
      severity: "low",
      score: 4.3,
      description: "OpenSSH 在弱配置下可能允许信息泄露，需要特定环境。",
      published: "2021-04-12",
      exploit: "暂无",
    },
  ],
  analysis: [
    {
      deviceType: "工业网关 / 路由器",
      cpe: "cpe:/o:siemens:scalance_m745",
      relationship: "资产类型",
    },
    {
      deviceType: "工业控制器",
      cpe: "cpe:/a:siemens:wincc:8.1",
      relationship: "配套软件",
    },
    {
      deviceType: "边缘计算节点",
      cpe: "cpe:/h:siemens:industrial_edge",
      relationship: "备选方案",
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
  return value.toLocaleString("zh-CN");
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
      label: file ? `文件：${file.name}` : "文件上传",
      targetsPreview: file ? [file.name] : [],
      totalTargets: file ? undefined : 0,
      message: file ? `已导入文件 ${file.name}` : undefined,
    };
  }

  if (mode === "subnet") {
    const subnet = targetSubnetInput?.value?.trim();
    const mask = targetMaskInput?.value?.trim();
    return {
      mode,
      label: subnet && mask ? `${subnet} / ${mask}` : "子网段",
      targetsPreview: subnet && mask ? [`${subnet}/${mask}`] : [],
      totalTargets: undefined,
      message: subnet && mask ? `子网 ${subnet}/${mask} 将用于扫描` : undefined,
    };
  }

  const ip = targetIpInput?.value?.trim();
  return {
    mode: "single",
    label: ip || "目标 IP",
    targetsPreview: ip ? [ip] : [],
    totalTargets: ip ? 1 : 0,
    message: ip ? `目标 IP ${ip} 正在评估` : undefined,
  };
}

function updateStatus(state, message) {
  statusPanel.classList.remove("ready", "loading", "error");
  statusPanel.classList.add(state);
  statusText.textContent = message;
}

function renderVulnerabilities(vulnerabilities) {
  if (!vulnerabilities || vulnerabilities.length === 0) {
    vulnerabilityResults.innerHTML = '<div class="alert">未检索到相关漏洞。</div>';
    vulnerabilityResults.classList.remove("placeholder");
    return;
  }

  const table = document.createElement("table");
  const thead = document.createElement("thead");
  thead.innerHTML = `
    <tr>
      <th>CVE</th>
      <th>严重程度</th>
      <th>CVSS</th>
      <th>描述</th>
      <th>发布时间</th>
      <th>利用情况</th>
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
  if (!analysis || analysis.length === 0) {
    analysisResults.innerHTML = '<div class="placeholder">暂无映射数据</div>';
    analysisResults.classList.add("placeholder");
    return;
  }

  const table = document.createElement("table");
  table.innerHTML = `
    <thead>
      <tr>
        <th>设备类型</th>
        <th>CPE</th>
        <th>关系描述</th>
      </tr>
    </thead>
  `;

  const tbody = document.createElement("tbody");
  analysis.forEach((item) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${item.deviceType}</td>
      <td><code>${item.cpe}</code></td>
      <td>${item.relationship ?? "关联"}</td>
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
    deviceRecognition.innerHTML = '<div class="placeholder">暂无设备识别统计数据</div>';
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
  title.textContent = "设备识别统计";
  section.appendChild(title);

  const summary = document.createElement("p");
  summary.className = "stats-summary";
  summary.textContent = `共扫描 ${formatNumber(dataset.total)} 个设备，以下为数量排名前十的设备类型：`;
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
      const label = item.label ?? item.name ?? item.type ?? "未知设备";
      return { label, count, percentage, isOther: false };
    })
    .filter(Boolean);

  const sumCounts = entries.reduce((sum, entry) => sum + entry.count, 0);
  const remainder = total - sumCounts;

  if (remainder > 0) {
    entries.push({
      label: "其他",
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
  center.innerHTML = `<strong>${formatNumber(dataset.total)}</strong><span>设备总数</span>`;
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
        <th>排名</th>
        <th>设备类型</th>
        <th>数量</th>
        <th>占比</th>
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
    count.textContent = `${formatNumber(entry.count)} 台`;
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
    count.textContent = `${formatNumber(dataset.otherEntry.count)} 台`;
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
  updateStatus("loading", "正在发起评估任务...");

  const summary = buildSummaryFromInputs(mode);

  if (useMock) {
    await delay(450);
    const data = clone(mockData);

    if (summary) {
      data.summary = {
        ...summary,
        message: summary.message
          ? `${summary.message}（演示数据）`
          : "演示数据结果",
      };

    }

    renderAssessment(data);
    updateStatus(
      "ready",
      summary?.label
        ? `评估完成（演示）：${summary.label}`
        : "评估完成（演示数据）"
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
    updateStatus("ready", data.summary?.message ?? "评估完成");
  } catch (error) {
    console.error(error);
    updateStatus("error", error.message || "评估失败，请检查后端服务");
  } finally {
    setLoadingState(false);
  }
}

function sendAssessmentRequest(mode) {
  if (mode === "file") {
    if (!targetFileInput?.files?.length) {
      throw new Error("请先选择包含 IP 的文件");
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
    return data?.message ?? response.statusText ?? "未知错误";
  } catch (error) {
    return response.statusText || "服务异常";
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
    vulnerabilityResults.innerHTML = '<div class="alert">请至少输入一个设备类型。</div>';
    vulnerabilityResults.classList.remove("placeholder");
    return;
  }

  const start = performance.now();
  vulnTime.textContent = "检索中...";

  if (useMock) {
    await delay(420);
    renderVulnerabilities(mockData.vulnerabilities);
    renderAnalysis(mockData.analysis);
    vulnTime.textContent = `耗时 ${(performance.now() - start).toFixed(0)} ms（演示数据）`;
    return;
  }

  try {
    const response = await fetch(API_ENDPOINTS.vulnerability, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ deviceTypes: devices }),
    });
    if (!response.ok) throw new Error("漏洞检索失败");
    const data = await response.json();
    renderVulnerabilities(data.vulnerabilities);
    renderAnalysis(data.analysis);
    vulnTime.textContent = `耗时 ${(performance.now() - start).toFixed(0)} ms`;
  } catch (error) {
    console.error(error);
    vulnerabilityResults.innerHTML = `<div class="alert">${error.message}</div>`;
    vulnerabilityResults.classList.remove("placeholder");
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

  deviceRecognition.innerHTML = "等待识别结果";
  deviceRecognition.classList.add("placeholder");
  useRecognizedDevices.disabled = true;
  delete useRecognizedDevices.dataset.types;

  vulnerabilityResults.innerHTML = "尚未发起漏洞检索";
  vulnerabilityResults.classList.add("placeholder");

  analysisResults.innerHTML = "待输出关联结果";
  analysisResults.classList.add("placeholder");

  vulnTime.textContent = "";
  document.getElementById("deviceTypes").value = "";
  const initialStatus = USE_MOCK_DATA ? "等待操作（演示模式）" : "等待操作";
  updateStatus("ready", initialStatus);
}

function preloadDemoRecognition() {
  if (!USE_MOCK_DATA) {
    return;
  }

  const data = clone(mockData);
  renderAssessment(data);
  updateStatus("ready", "演示数据已加载，可直接查看识别结果");
}

function showNeo4jPlaceholder(message) {
  if (!neo4jPreview) {
    return;
  }
  const placeholder = document.createElement("div");
  placeholder.className = "placeholder";
  placeholder.textContent = message || "正在查找 Neo4j 图谱图片";
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
  img.alt = "Neo4j 图谱预览";
  img.onload = () => {
    neo4jPreview.innerHTML = "";
    neo4jPreview.appendChild(img);
    neo4jPreview.classList.remove("placeholder");
  };
  img.onerror = () => {
    showNeo4jPlaceholder("未找到 neo4j.png，请将图片放在项目前端目录下。");
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
