const statusPanel = document.getElementById("statusPanel");
const statusText = document.getElementById("statusText");
const deviceRecognition = document.getElementById("deviceRecognition");
const vulnerabilityResults = document.getElementById("vulnerabilityResults");
const analysisResults = document.getElementById("analysisResults");
const useRecognizedDevices = document.getElementById("useRecognizedDevices");
const neo4jPreview = document.getElementById("neo4jPreview");
const neo4jImageInput = document.getElementById("neo4jImage");
const neo4jModeInputs = document.querySelectorAll('input[name="neo4jMode"]');
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

const NEO4J_LINK_COLORS = {
  default: "#60a5fa",
  cpe: "#ef4444",
};
const DEFAULT_NEO4J_LINK_WIDTH = 3.2;

const neo4jDemoGraph = {
  width: 960,
  height: 540,
  groups: {
    issue: {
      label: "漏洞 / 通告节点",
      color: "#f28d52",
      stroke: "#dd6b27",
    },
    context: {
      label: "系统 / 状态节点",
      color: "#c9ced8",
      stroke: "#aeb6c3",
    },
    model: {
      label: "D-Link 摄像头型号",
      color: "#4f8df6",
      stroke: "#3564d4",
    },
    vendor: {
      label: "厂商",
      color: "#32b375",
      stroke: "#21925d",
    },
    marker: {
      label: "alpha 标记",
      color: "#f6d74b",
      stroke: "#ddb320",
    },
  },
  nodes: [
    { id: "alpha", label: "alpha", group: "marker", x: 130, y: 130, radius: 28 },
    { id: "dcs930l", label: "DCS-930L", group: "model", x: 240, y: 80, radius: 24 },
    { id: "dcs931l", label: "DCS-931L", group: "model", x: 250, y: 150, radius: 24 },
    { id: "dcs932l", label: "DCS-932L", group: "model", x: 250, y: 220, radius: 24 },
    { id: "dcs933l", label: "DCS-933L", group: "model", x: 360, y: 110, radius: 24 },
    { id: "dcs934l", label: "DCS-934L", group: "model", x: 360, y: 190, radius: 24 },
    { id: "dcs935l", label: "DCS-935L", group: "model", x: 360, y: 270, radius: 24 },
    { id: "dcs942l", label: "DCS-942L", group: "model", x: 460, y: 90, radius: 24 },
    {
      id: "dcs900",
      label: "DCS-900\nInternet",
      group: "model",
      x: 460,
      y: 170,
      radius: 28,
    },
    { id: "dshc310", label: "DSH-C310", group: "model", x: 460, y: 250, radius: 26 },
    { id: "dcs25", label: "DCS-25", group: "model", x: 320, y: 330, radius: 24 },
    {
      id: "dcs-series",
      label: "The D-Link\nDCS series",
      group: "context",
      x: 420,
      y: 200,
      radius: 44,
    },
    { id: "camera", label: "Camera", group: "context", x: 540, y: 120, radius: 28 },
    { id: "etc-rc", label: "/etc/rc", group: "context", x: 540, y: 220, radius: 28 },
    { id: "stackb", label: "Stack-b", group: "context", x: 400, y: 330, radius: 26 },
    { id: "recorders", label: "recorders", group: "context", x: 540, y: 300, radius: 30 },
    { id: "dlink", label: "D-Link", group: "vendor", x: 600, y: 200, radius: 50 },
    {
      id: "issue-discovered",
      label: "An issue was\ndiscovered",
      group: "issue",
      x: 700,
      y: 110,
      radius: 32,
    },
    {
      id: "issue-privilege",
      label: "An Elevated\nPrivilege",
      group: "issue",
      x: 700,
      y: 240,
      radius: 32,
    },
    {
      id: "issue-comm",
      label: "A Comm",
      group: "issue",
      x: 780,
      y: 180,
      radius: 28,
    },
    {
      id: "issue-vulnerability",
      label: "A vulnerability",
      group: "issue",
      x: 660,
      y: 180,
      radius: 32,
    },
  ],
  links: [
    {
      source: "alpha",
      target: "dcs930l",
      label: "banner_影响_cpe",
      labelOffset: { x: -30, y: -20 },
    },
    {
      source: "alpha",
      target: "dcs931l",
      label: "banner_影响_cpe",
      labelOffset: { x: -34, y: -6 },
    },
    {
      source: "alpha",
      target: "dcs932l",
      label: "banner_影响_cpe",
      labelOffset: { x: -36, y: 12 },
    },
    { source: "alpha", target: "dcs933l", label: "cpe_影响_设备", labelOffset: { x: -28, y: 12 } },
    { source: "alpha", target: "dcs934l", label: "cpe_影响_设备", labelOffset: { x: -26, y: 24 } },
    {
      source: "alpha",
      target: "dcs935l",
      label: "banner_影响_cpe",
      labelOffset: { x: -26, y: 26 },
    },
    { source: "alpha", target: "dcs942l", label: "cpe_影响_设备", labelOffset: { x: -24, y: -6 } },
    {
      source: "alpha",
      target: "dcs900",
      label: "banner_影响_cpe",
      labelOffset: { x: -18, y: 2 },
    },
    { source: "alpha", target: "dshc310", label: "cpe_影响_设备", labelOffset: { x: -18, y: 18 } },
    {
      source: "alpha",
      target: "dcs25",
      label: "banner_影响_cpe",
      labelOffset: { x: -34, y: 32 },
    },
    { source: "dcs-series", target: "dcs930l", label: "型号", labelOffset: { x: -20, y: -22 } },
    { source: "dcs-series", target: "dcs931l", label: "型号", labelOffset: { x: -18, y: -10 } },
    { source: "dcs-series", target: "dcs932l", label: "型号", labelOffset: { x: -20, y: 6 } },
    { source: "dcs-series", target: "dcs933l", label: "型号", labelOffset: { x: -10, y: -24 } },
    { source: "dcs-series", target: "dcs934l", label: "型号", labelOffset: { x: -10, y: -10 } },
    { source: "dcs-series", target: "dcs935l", label: "型号", labelOffset: { x: -10, y: 6 } },
    { source: "dcs-series", target: "dcs942l", label: "型号", labelOffset: { x: 12, y: -18 } },
    { source: "dcs-series", target: "dcs900", label: "型号", labelOffset: { x: 12, y: -2 } },
    { source: "dcs-series", target: "dshc310", label: "型号", labelOffset: { x: 12, y: 12 } },
    { source: "dcs-series", target: "dcs25", label: "型号", labelOffset: { x: -4, y: 30 } },
    { source: "dcs930l", target: "dcs-series", label: "型号_banner", labelOffset: { x: 8, y: -22 } },
    { source: "dcs931l", target: "dcs-series", label: "型号_banner", labelOffset: { x: 4, y: -10 } },
    { source: "dcs933l", target: "camera", label: "Ca_型号_漏洞", labelOffset: { x: 14, y: -18 } },
    { source: "dcs934l", target: "camera", label: "Ca_型号_漏洞", labelOffset: { x: 16, y: -12 } },
    { source: "dcs933l", target: "etc-rc", label: "cpe_影响_设备", labelOffset: { x: -4, y: 18 } },
    { source: "dcs934l", target: "etc-rc", label: "cpe_影响_设备", labelOffset: { x: 0, y: 20 } },
    { source: "dcs900", target: "recorders", label: "型号_banner", labelOffset: { x: 16, y: 8 } },
    { source: "dcs25", target: "stackb", label: "型号", labelOffset: { x: -4, y: 16 } },
    { source: "dcs930l", target: "issue-vulnerability", label: "Ca_型号_漏洞", labelOffset: { x: 16, y: -14 } },
    { source: "dcs931l", target: "issue-vulnerability", label: "Ca_型号_漏洞", labelOffset: { x: 20, y: -6 } },
    { source: "dcs932l", target: "issue-privilege", label: "Ca_型号_漏洞", labelOffset: { x: 16, y: 20 } },
    { source: "dcs934l", target: "issue-privilege", label: "Ca_型号_漏洞", labelOffset: { x: 12, y: 28 } },
    { source: "dcs935l", target: "issue-discovered", label: "Ca_厂商_漏洞", labelOffset: { x: 22, y: -4 } },
    { source: "dcs933l", target: "issue-discovered", label: "Ca_厂商_漏洞", labelOffset: { x: 24, y: -18 } },
    { source: "dcs942l", target: "issue-vulnerability", label: "Ca_型号_漏洞", labelOffset: { x: 20, y: -6 } },
    { source: "dcs900", target: "issue-comm", label: "Ca_型号_漏洞", labelOffset: { x: 18, y: 0 } },
    { source: "dshc310", target: "issue-comm", label: "Ca_型号_漏洞", labelOffset: { x: 18, y: 0 } },
    { source: "dcs25", target: "issue-vulnerability", label: "Ca_型号_漏洞", labelOffset: { x: 20, y: 12 } },
    { source: "dlink", target: "dcs-series", label: "型号_banner", labelOffset: { x: -48, y: -6 } },
    { source: "camera", target: "dlink", label: "cpe_影响_设备", labelOffset: { x: 4, y: -28 } },
    { source: "etc-rc", target: "dlink", label: "cpe_影响_设备", labelOffset: { x: 10, y: 22 } },
    { source: "dlink", target: "issue-discovered", label: "Ca_厂商_漏洞", labelOffset: { x: 32, y: -20 } },
    { source: "dlink", target: "issue-privilege", label: "Ca_厂商_漏洞", labelOffset: { x: 30, y: 26 } },
    { source: "dlink", target: "issue-comm", label: "Ca_厂商_漏洞", labelOffset: { x: 40, y: 2 } },
    { source: "dlink", target: "issue-vulnerability", label: "Ca_厂商_漏洞", labelOffset: { x: 24, y: 14 } },
  ],
};

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
  if (!recognition) {
    deviceRecognition.innerHTML = '<div class="placeholder">未识别到设备信息</div>';
    deviceRecognition.classList.add("placeholder");
    useRecognizedDevices.disabled = true;
    delete useRecognizedDevices.dataset.types;
    return;
  }

  const recognizedTypes = new Set();
  if (recognition.primary) {
    recognizedTypes.add(recognition.primary);
  }
  recognition.secondary?.forEach((item) => {
    if (item?.type) {
      recognizedTypes.add(item.type);
    }
  });

  useRecognizedDevices.dataset.types = JSON.stringify([...recognizedTypes]);
  useRecognizedDevices.disabled = recognizedTypes.size === 0;

  const container = document.createElement("div");
  container.className = "recognition";

  deviceRecognition.classList.remove("placeholder");

  const confidence =
    typeof recognition.confidence === "number"
      ? `${(recognition.confidence * 100).toFixed(1)}%`
      : "-";

  const primary = document.createElement("div");
  primary.innerHTML = `
    <h4>主设备类型</h4>
    <p><span class="badge neutral">${confidence}</span> ${recognition.primary}</p>
  `;
  container.appendChild(primary);

  if (recognition.metadata) {
    const metaList = document.createElement("div");
    metaList.className = "list-grid";
    Object.entries(recognition.metadata).forEach(([key, value]) => {
      const item = document.createElement("div");
      item.className = "list-item";
      item.innerHTML = `<h4>${translateMetaKey(key)}</h4><p>${value}</p>`;
      metaList.appendChild(item);
    });
    container.appendChild(metaList);
  }

  if (recognition.secondary?.length) {
    const secondaryTitle = document.createElement("h4");
    secondaryTitle.textContent = "候选类型";
    container.appendChild(secondaryTitle);

    const secondaryList = document.createElement("div");
    secondaryList.className = "list-grid";
    recognition.secondary.forEach((item) => {
      const node = document.createElement("div");
      node.className = "list-item";
      const scoreText =
        typeof item.score === "number" ? `置信度 ${(item.score * 100).toFixed(1)}%` : "置信度未知";
      node.innerHTML = `
        <h4>${item.type}</h4>
        <p>${scoreText}</p>
      `;
      secondaryList.appendChild(node);
    });
    container.appendChild(secondaryList);
  }

  deviceRecognition.innerHTML = "";
  deviceRecognition.appendChild(container);
}

function translateMetaKey(key) {
  const mapping = {
    manufacturer: "厂商",
    productLine: "产品线",
    firmware: "固件版本",
    serial: "序列号",
    campaign: "目标范围",
  };
  return mapping[key] ?? key;
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

function createSvgElement(name, attributes = {}) {
  const element = document.createElementNS("http://www.w3.org/2000/svg", name);
  Object.entries(attributes).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      element.setAttribute(key, value);
    }
  });
  return element;
}

function renderNeo4jDemoGraph() {
  if (!neo4jPreview) {
    return;
  }

  const nodes = neo4jDemoGraph.nodes.map((node) => ({ ...node }));
  const nodeIndex = new Map(nodes.map((node) => [node.id, node]));
  const adjacency = new Map();

  function registerLink(nodeId, record) {
    if (!adjacency.has(nodeId)) {
      adjacency.set(nodeId, []);
    }
    adjacency.get(nodeId).push(record);
  }

  function computeLinkEndpoints(source, target, meta = {}) {
    const dx = target.x - source.x;
    const dy = target.y - source.y;
    const distance = Math.hypot(dx, dy) || 1;

    let sourcePadding =
      meta.sourcePadding ?? Math.max(0, (source.radius ?? 0) * 0.65 + 6);
    let targetPadding =
      meta.targetPadding ?? Math.max(0, (target.radius ?? 0) + 10);

    const maxTotal = Math.max(0, distance - 2);
    if (sourcePadding + targetPadding > maxTotal && maxTotal > 0) {
      const scale = maxTotal / (sourcePadding + targetPadding);
      sourcePadding *= scale;
      targetPadding *= scale;
    }

    const ux = dx / distance;
    const uy = dy / distance;

    return {
      x1: source.x + ux * sourcePadding,
      y1: source.y + uy * sourcePadding,
      x2: target.x - ux * targetPadding,
      y2: target.y - uy * targetPadding,
    };
  }

  function updateLinkPosition(record) {
    const { line, label, source, target, meta } = record;
    const { x1, y1, x2, y2 } = computeLinkEndpoints(source, target, meta);
    line.setAttribute("x1", x1);
    line.setAttribute("y1", y1);
    line.setAttribute("x2", x2);
    line.setAttribute("y2", y2);

    if (label) {
      const midX = (x1 + x2) / 2;
      const midY = (y1 + y2) / 2;
      const offsetX = meta.labelOffset?.x ?? 0;
      const offsetY = meta.labelOffset?.y ?? -8;
      label.setAttribute("x", midX + offsetX);
      label.setAttribute("y", midY + offsetY);
    }
  }

  function updateLinksForNode(node) {
    const records = adjacency.get(node.id) ?? [];
    records.forEach(updateLinkPosition);
  }

  function getSvgPoint(svgElement, event) {
    const point = svgElement.createSVGPoint();
    point.x = event.clientX;
    point.y = event.clientY;
    const ctm = svgElement.getScreenCTM();
    if (!ctm) {
      return { x: point.x, y: point.y };
    }
    const transformed = point.matrixTransform(ctm.inverse());
    return { x: transformed.x, y: transformed.y };
  }

  let activeDrag = null;

  const handlePointerMove = (event) => {
    if (!activeDrag || event.pointerId !== activeDrag.pointerId) {
      return;
    }
    event.preventDefault();
    const point = getSvgPoint(activeDrag.svg, event);
    const newX = point.x - activeDrag.offsetX;
    const newY = point.y - activeDrag.offsetY;
    activeDrag.node.x = newX;
    activeDrag.node.y = newY;
    activeDrag.element.setAttribute("transform", `translate(${newX}, ${newY})`);
    updateLinksForNode(activeDrag.node);
  };

  const handlePointerUp = (event) => {
    if (!activeDrag || event.pointerId !== activeDrag.pointerId) {
      return;
    }
    activeDrag.element.classList.remove("is-dragging");
    activeDrag.svg.classList.remove("neo4j-demo-canvas--dragging");
    if (activeDrag.element.releasePointerCapture) {
      activeDrag.element.releasePointerCapture(activeDrag.pointerId);
    }
    window.removeEventListener("pointermove", handlePointerMove);
    window.removeEventListener("pointerup", handlePointerUp);
    window.removeEventListener("pointercancel", handlePointerUp);
    activeDrag = null;
  };

  const svg = createSvgElement("svg", {
    viewBox: `0 0 ${neo4jDemoGraph.width} ${neo4jDemoGraph.height}`,
    class: "neo4j-demo-canvas",
    role: "img",
    "aria-label": "D-Link 设备及漏洞关联的模拟图谱",
  });
  const fallbackLinkColor = NEO4J_LINK_COLORS.default;

  const defs = createSvgElement("defs");
  const markerCache = new Map();

  function ensureArrowMarker(color) {
    const resolvedColor = color ?? fallbackLinkColor;
    const key = resolvedColor.toLowerCase();
    if (markerCache.has(key)) {
      return markerCache.get(key);
    }

    const sanitized = key.replace(/[^a-z0-9]+/g, "");
    const markerId = `neo4j-arrowhead-${sanitized || markerCache.size}`;
    const marker = createSvgElement("marker", {
      id: markerId,
      viewBox: "0 0 12 12",
      refX: "10.5",
      refY: "6",
      markerWidth: "3.6",
      markerHeight: "3.6",
      orient: "auto",
      "markerUnits": "strokeWidth",
    });
    const markerPath = createSvgElement("path", {
      d: "M2,1 L11,6 L2,11 z",
      fill: resolvedColor,
      stroke: resolvedColor,
      "stroke-linejoin": "round",
    });
    marker.appendChild(markerPath);
    defs.appendChild(marker);
    markerCache.set(key, markerId);
    return markerId;
  }

  svg.appendChild(defs);

  const linkGroup = createSvgElement("g", { class: "neo4j-links" });
  const labelGroup = createSvgElement("g", { class: "neo4j-link-labels" });

  neo4jDemoGraph.links.forEach((link) => {
    const source = nodeIndex.get(link.source);
    const target = nodeIndex.get(link.target);
    if (!source || !target) {
      return;
    }

    const labelText = (link.label ?? "").toLowerCase();
    let strokeColor = link.color;
    if (!strokeColor) {
      if (labelText.includes("cpe_影响_设备")) {
        strokeColor = NEO4J_LINK_COLORS.cpe;
      } else {
        strokeColor = fallbackLinkColor;
      }
    }
    const strokeWidth = link.width ?? DEFAULT_NEO4J_LINK_WIDTH;
    const markerId = ensureArrowMarker(strokeColor);
    const meta = {
      ...link,
      sourcePadding:
        link.sourcePadding ?? Math.max(0, (source.radius ?? 0) * 0.65 + 6),
      targetPadding:
        link.targetPadding ?? Math.max(0, (target.radius ?? 0) + 10),
    };

    const { x1, y1, x2, y2 } = computeLinkEndpoints(source, target, meta);

    const line = createSvgElement("line", {
      x1,
      y1,
      x2,
      y2,
      stroke: strokeColor,
      "stroke-width": strokeWidth,
      "stroke-linecap": "round",
      "stroke-linejoin": "round",
      "marker-end": `url(#${markerId})`,
    });
    linkGroup.appendChild(line);

    let label = null;
    if (link.label) {
      const midX = (x1 + x2) / 2;
      const midY = (y1 + y2) / 2;
      label = createSvgElement("text", {
        x: midX + (link.labelOffset?.x ?? 0),
        y: midY + (link.labelOffset?.y ?? -8),
      });
      label.textContent = link.label;
      labelGroup.appendChild(label);
    }

    const record = { line, label, source, target, meta };
    registerLink(link.source, record);
    registerLink(link.target, record);
  });

  svg.appendChild(linkGroup);
  svg.appendChild(labelGroup);

  const nodeGroup = createSvgElement("g", { class: "neo4j-nodes" });
  nodes.forEach((node) => {
    const group = createSvgElement("g", {
      class: `neo4j-node neo4j-node--${node.group}`,
      transform: `translate(${node.x}, ${node.y})`,
    });
    const groupMeta = neo4jDemoGraph.groups[node.group];
    if (groupMeta) {
      group.style.setProperty("--neo4j-node-fill", groupMeta.color);
      group.style.setProperty(
        "--neo4j-node-stroke",
        groupMeta.stroke ?? "rgba(148, 163, 184, 0.6)"
      );
    }
    const radius = node.radius ?? 30;
    const circle = createSvgElement("circle", { r: radius });
    group.appendChild(circle);

    const lines = String(node.label ?? "").split(/\n+/);
    lines.forEach((line, index) => {
      const offset = (index - (lines.length - 1) / 2) * 16;
      const text = createSvgElement("text", { y: offset });
      text.textContent = line;
      group.appendChild(text);
    });

    group.addEventListener("pointerdown", (event) => {
      event.preventDefault();
      const point = getSvgPoint(svg, event);
      activeDrag = {
        node,
        element: group,
        svg,
        pointerId: event.pointerId,
        offsetX: point.x - node.x,
        offsetY: point.y - node.y,
      };
      if (group.setPointerCapture) {
        group.setPointerCapture(event.pointerId);
      }
      group.classList.add("is-dragging");
      svg.classList.add("neo4j-demo-canvas--dragging");
      window.addEventListener("pointermove", handlePointerMove);
      window.addEventListener("pointerup", handlePointerUp);
      window.addEventListener("pointercancel", handlePointerUp);
    });

    nodeGroup.appendChild(group);
  });
  svg.appendChild(nodeGroup);

  const figure = document.createElement("figure");
  figure.className = "neo4j-demo";
  figure.appendChild(svg);

  const caption = document.createElement("figcaption");
  caption.className = "neo4j-demo-caption";
  caption.innerHTML =
    '示例图谱复刻参考图：<strong>D-Link</strong> 中心节点与 <strong>alpha</strong> 标记、各型号摄像头及漏洞公告之间的关联。颜色依次对应漏洞/公告（橙）、系统/状态（灰）、设备型号（蓝）、厂商（绿）、标记（黄）。';

  const legend = document.createElement("ul");
  legend.className = "neo4j-demo-legend";

  Object.entries(neo4jDemoGraph.groups).forEach(([key, meta]) => {
    const item = document.createElement("li");
    const swatch = document.createElement("span");
    swatch.className = "legend-swatch";
    if (meta?.color) {
      swatch.style.setProperty("--legend-color", meta.color);
      swatch.style.setProperty(
        "--legend-stroke",
        meta.stroke ?? "rgba(148, 163, 184, 0.6)"
      );
    }
    item.appendChild(swatch);
    item.appendChild(document.createTextNode(meta.label));
    legend.appendChild(item);
  });

  caption.appendChild(legend);
  figure.appendChild(caption);

  neo4jPreview.innerHTML = "";
  neo4jPreview.classList.remove("placeholder");
  neo4jPreview.classList.add("graph-mode");
  neo4jPreview.appendChild(figure);
}

function handleNeo4jModeChange(mode) {
  if (!neo4jPreview) {
    return;
  }

  if (mode === "demo") {
    renderNeo4jDemoGraph();
    return;
  }

  neo4jPreview.classList.remove("graph-mode");
  neo4jPreview.innerHTML = "";
  const placeholder = document.createElement("div");
  placeholder.className = "placeholder";
  placeholder.textContent = "请上传一张示例图片";
  neo4jPreview.appendChild(placeholder);
  neo4jPreview.classList.add("placeholder");
}

function handleNeo4jImageUpload(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (event) => {
    neo4jPreview.innerHTML = "";
    const img = document.createElement("img");
    img.src = event.target.result;
    img.alt = "Neo4j 节点关联示例图";
    neo4jPreview.appendChild(img);
    neo4jPreview.classList.remove("placeholder");
    neo4jPreview.classList.remove("graph-mode");
  };
  reader.readAsDataURL(file);
}

function initNeo4jSection() {
  if (!neo4jPreview) {
    return;
  }

  const inputs = Array.from(neo4jModeInputs);
  inputs.forEach((input) => {
    input.addEventListener("change", (event) => {
      const mode = event.target.value;
      if (neo4jImageInput) {
        neo4jImageInput.disabled = mode !== "image";
        if (mode !== "image") {
          neo4jImageInput.value = "";
        }
      }
      handleNeo4jModeChange(mode);
    });
  });

  if (neo4jImageInput) {
    neo4jImageInput.disabled = true;
    neo4jImageInput.addEventListener("change", (event) =>
      handleNeo4jImageUpload(event.target.files[0])
    );
  }

  const initialMode = inputs.find((input) => input.checked)?.value ?? "demo";
  if (neo4jImageInput) {
    neo4jImageInput.disabled = initialMode !== "image";
  }
  handleNeo4jModeChange(initialMode);
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
}

bootstrap();
