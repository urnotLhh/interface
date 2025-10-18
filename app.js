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

const neo4jDemoGraph = {
  width: 940,
  height: 480,
  groups: {
    actor: { label: "攻击源", color: "#e85c41" },
    device: { label: "D-Link 设备", color: "#4aa3df" },
    series: { label: "产品系列", color: "#95c4e6" },
    vendor: { label: "厂商节点", color: "#f7b347" },
    vulnerability: { label: "关联漏洞", color: "#ef8455" },
  },
  nodes: [
    { id: "alphad", label: "alphad", group: "actor", x: 100, y: 240, radius: 32 },
    { id: "dcs-932l", label: "DCS-932L", group: "device", x: 250, y: 50, radius: 26 },
    { id: "dcs-930l", label: "DCS-930L", group: "device", x: 250, y: 130, radius: 26 },
    { id: "dcs-931l", label: "DCS-931L", group: "device", x: 250, y: 210, radius: 26 },
    { id: "dcs-933l", label: "DCS-933L", group: "device", x: 250, y: 290, radius: 26 },
    { id: "dcs-934l", label: "DCS-934L", group: "device", x: 250, y: 370, radius: 26 },
    {
      id: "dcs-series",
      label: "The D-Link\nDCS series",
      group: "series",
      x: 440,
      y: 220,
      radius: 54,
    },
    { id: "d-link", label: "D-Link", group: "vendor", x: 650, y: 220, radius: 52 },
    { id: "vuln-1", label: "A vulners", group: "vulnerability", x: 810, y: 120, radius: 24 },
    { id: "vuln-2", label: "A vulners", group: "vulnerability", x: 810, y: 190, radius: 24 },
    { id: "vuln-3", label: "A vulners", group: "vulnerability", x: 810, y: 260, radius: 24 },
    { id: "vuln-4", label: "A vulners", group: "vulnerability", x: 810, y: 330, radius: 24 },
  ],
  links: [
    { source: "alphad", target: "dcs-932l", label: "攻击路径", labelOffset: { x: -34, y: -18 } },
    { source: "alphad", target: "dcs-930l", label: "攻击路径", labelOffset: { x: -34, y: -10 } },
    { source: "alphad", target: "dcs-931l", label: "攻击路径", labelOffset: { x: -34, y: -2 } },
    { source: "alphad", target: "dcs-933l", label: "攻击路径", labelOffset: { x: -34, y: 8 } },
    { source: "alphad", target: "dcs-934l", label: "攻击路径", labelOffset: { x: -34, y: 18 } },
    { source: "dcs-932l", target: "dcs-series", label: "同系列", labelOffset: { y: -22 } },
    { source: "dcs-930l", target: "dcs-series", label: "同系列", labelOffset: { y: -12 } },
    { source: "dcs-931l", target: "dcs-series", label: "同系列", labelOffset: { y: -2 } },
    { source: "dcs-933l", target: "dcs-series", label: "同系列", labelOffset: { y: 10 } },
    { source: "dcs-934l", target: "dcs-series", label: "同系列", labelOffset: { y: 20 } },
    { source: "dcs-series", target: "d-link", label: "厂商归属", labelOffset: { y: -22 } },
    { source: "vuln-1", target: "d-link", label: "公开漏洞", labelOffset: { x: 18, y: -18 } },
    { source: "vuln-2", target: "d-link", label: "公开漏洞", labelOffset: { x: 18, y: -6 } },
    { source: "vuln-3", target: "d-link", label: "公开漏洞", labelOffset: { x: 18, y: 6 } },
    { source: "vuln-4", target: "d-link", label: "公开漏洞", labelOffset: { x: 18, y: 18 } },
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

  const nodeIndex = new Map();
  neo4jDemoGraph.nodes.forEach((node) => {
    nodeIndex.set(node.id, node);
  });

  const svg = createSvgElement("svg", {
    viewBox: `0 0 ${neo4jDemoGraph.width} ${neo4jDemoGraph.height}`,
    class: "neo4j-demo-canvas",
    role: "img",
    "aria-label": "D-Link 设备及漏洞关联的模拟图谱",
  });

  const defs = createSvgElement("defs");
  const marker = createSvgElement("marker", {
    id: "neo4j-arrowhead",
    viewBox: "0 0 12 12",
    refX: "12",
    refY: "6",
    markerWidth: "12",
    markerHeight: "12",
    orient: "auto-start-reverse",
  });
  const markerPath = createSvgElement("path", {
    d: "M0,0 L12,6 L0,12 z",
    fill: "currentColor",
  });
  marker.appendChild(markerPath);
  defs.appendChild(marker);
  svg.appendChild(defs);

  const linkGroup = createSvgElement("g", { class: "neo4j-links" });
  const labelGroup = createSvgElement("g", { class: "neo4j-link-labels" });

  neo4jDemoGraph.links.forEach((link) => {
    const source = nodeIndex.get(link.source);
    const target = nodeIndex.get(link.target);
    if (!source || !target) {
      return;
    }

    const line = createSvgElement("line", {
      x1: source.x,
      y1: source.y,
      x2: target.x,
      y2: target.y,
      "marker-end": "url(#neo4j-arrowhead)",
    });
    linkGroup.appendChild(line);

    if (link.label) {
      const midX = (source.x + target.x) / 2;
      const midY = (source.y + target.y) / 2;
      const label = createSvgElement("text", {
        x: midX + (link.labelOffset?.x ?? 0),
        y: midY + (link.labelOffset?.y ?? -8),
      });
      label.textContent = link.label;
      labelGroup.appendChild(label);
    }
  });

  svg.appendChild(linkGroup);
  svg.appendChild(labelGroup);

  const nodeGroup = createSvgElement("g", { class: "neo4j-nodes" });
  neo4jDemoGraph.nodes.forEach((node) => {
    const group = createSvgElement("g", {
      class: `neo4j-node neo4j-node--${node.group}`,
      transform: `translate(${node.x}, ${node.y})`,
    });
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

    nodeGroup.appendChild(group);
  });
  svg.appendChild(nodeGroup);

  const figure = document.createElement("figure");
  figure.className = "neo4j-demo";
  figure.appendChild(svg);

  const caption = document.createElement("figcaption");
  caption.className = "neo4j-demo-caption";
  caption.innerHTML =
    '示例图谱展示攻击源 <strong>alphad</strong> 与 D-Link 摄像头系列及其公开漏洞之间的拓扑关系。';

  const legend = document.createElement("ul");
  legend.className = "neo4j-demo-legend";

  Object.entries(neo4jDemoGraph.groups).forEach(([key, meta]) => {
    const item = document.createElement("li");
    const swatch = document.createElement("span");
    swatch.className = `legend-swatch legend-swatch--${key}`;
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
