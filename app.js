const statusPanel = document.getElementById("statusPanel");
const statusText = document.getElementById("statusText");
const scanResults = document.getElementById("scanResults");
const fingerprintResults = document.getElementById("fingerprintResults");
const deviceRecognition = document.getElementById("deviceRecognition");
const statistics = document.getElementById("statistics");
const vulnerabilityResults = document.getElementById("vulnerabilityResults");
const analysisResults = document.getElementById("analysisResults");
const useRecognizedDevices = document.getElementById("useRecognizedDevices");
const neo4jPreview = document.getElementById("neo4jPreview");
const neo4jUrlInput = document.getElementById("neo4jUrl");
const neo4jImageInput = document.getElementById("neo4jImage");
const vulnTime = document.getElementById("vulnTime");
const assessmentForm = document.getElementById("assessmentForm");
const assessmentSummary = document.getElementById("assessmentSummary");
const assessmentModeInputs = document.querySelectorAll('input[name="assessmentMode"]');
const assessmentPanels = document.querySelectorAll("[data-mode-panel]");
const targetIpInput = document.getElementById("targetIp");
const targetSubnetInput = document.getElementById("targetSubnet");
const targetMaskInput = document.getElementById("targetMask");
const targetFileInput = document.getElementById("targetFile");

const mockData = {
  ip: "192.168.1.10",
  scan: {
    overview: [
      { title: "端口 22", status: "开放", service: "OpenSSH 8.4" },
      { title: "端口 80", status: "开放", service: "nginx 1.22" },
      { title: "端口 502", status: "开放", service: "Modbus/TCP" },
    ],
    statistics: [
      { label: "开放端口", value: 6 },
      { label: "TCP 服务", value: 4 },
      { label: "UDP 服务", value: 2 },
      { label: "最近扫描", value: "2024-05-22 14:23" },
    ],
  },
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

function clone(data) {
  if (typeof structuredClone === "function") {
    return structuredClone(data);
  }
  return JSON.parse(JSON.stringify(data));
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

function getModeLabel(mode) {
  return (
    {
      single: "单个 IP",
      subnet: "子网 + 掩码",
      file: "文件上传",
    }[mode] ?? mode
  );
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

function renderList(container, items, options = {}) {
  if (!items || items.length === 0) {
    container.innerHTML = '<div class="placeholder">暂无数据</div>';
    container.classList.add("placeholder");
    return;
  }

  const list = document.createElement("div");
  list.className = options.className ?? "list-grid";

  items.forEach((item) => {
    const card = document.createElement("div");
    card.className = "list-item";

    if (typeof item === "string") {
      card.textContent = item;
    } else {
      if (item.title || item.name || item.type) {
        const heading = document.createElement("h4");
        heading.textContent = item.title ?? item.name ?? item.type;
        card.appendChild(heading);
      }

      if (item.status || item.version || item.score) {
        const sub = document.createElement("p");
        const parts = [item.status, item.version, item.score && `得分 ${item.score}`].filter(Boolean);
        sub.textContent = parts.join(" · ");
        if (parts.length) {
          card.appendChild(sub);
        }
      }

      if (item.service || item.category) {
        const extra = document.createElement("p");
        extra.textContent = item.service ?? item.category;
        card.appendChild(extra);
      }
    }

    list.appendChild(card);
  });

  container.innerHTML = "";
  container.classList.remove("placeholder");
  container.appendChild(list);
}

function renderStatistics(stats) {
  if (!stats || stats.length === 0) {
    statistics.innerHTML = '<div class="placeholder">暂无统计数据</div>';
    return;
  }

  const fragment = document.createDocumentFragment();
  statistics.classList.remove("placeholder");
  statistics.innerHTML = "";

  stats.forEach((stat) => {
    const card = document.createElement("div");
    card.className = "stat-card";

    const label = document.createElement("h4");
    label.textContent = stat.label;
    card.appendChild(label);

    const value = document.createElement("div");
    value.className = "stat-value";
    value.textContent = stat.value;
    card.appendChild(value);

    fragment.appendChild(card);
  });

  statistics.appendChild(fragment);
}

function renderAssessmentSummary(summary) {
  if (!summary) {
    assessmentSummary.textContent = "尚未开始评估";
    assessmentSummary.classList.add("placeholder");
    return;
  }

  assessmentSummary.classList.remove("placeholder");

  const fragments = [];
  fragments.push(
    `<p><strong>输入方式：</strong>${getModeLabel(summary.mode)}</p>`
  );

  if (summary.label) {
    fragments.push(
      `<p><strong>目标范围：</strong>${summary.label}</p>`
    );
  }

  if (typeof summary.totalTargets === "number" && summary.totalTargets > 0) {
    fragments.push(
      `<p><strong>目标数量：</strong>${summary.totalTargets}</p>`
    );
  }

  const preview = summary.targetsPreview ?? summary.preview ?? [];
  if (preview.length > 0) {
    const extra =
      summary.totalTargets && summary.totalTargets > preview.length
        ? `（共 ${summary.totalTargets} 项）`
        : "";
    fragments.push(
      `<div class="summary-preview"><strong>样本：</strong><span>${preview
        .slice(0, 5)
        .join("、")}${extra}</span></div>`
    );
  }

  if (summary.message) {
    fragments.push(`<p class="muted">${summary.message}</p>`);
  }

  assessmentSummary.innerHTML = fragments.join("");
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

      if (Array.isArray(data.scan?.statistics)) {
        data.scan.statistics = [
          {
            label: "评估目标",
            value:
              summary.totalTargets ?? summary.targetsPreview?.length ?? "-",
          },
          ...data.scan.statistics,
        ];
      }
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
  renderAssessmentSummary(data?.summary);
  renderList(scanResults, data?.scan?.overview);

  const fingerprintItems = [...(data?.fingerprint?.technologies ?? [])];
  if (data?.fingerprint?.os) {
    fingerprintItems.unshift({
      title: "操作系统",
      status: data.fingerprint.os,
    });
  }
  renderList(fingerprintResults, fingerprintItems);

  renderRecognition(data?.recognition);
  renderStatistics(data?.scan?.statistics);
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
  renderAssessmentSummary(null);

  scanResults.innerHTML = "尚未开始扫描";
  scanResults.classList.add("placeholder");

  fingerprintResults.innerHTML = "暂无数据";
  fingerprintResults.classList.add("placeholder");

  deviceRecognition.innerHTML = "等待识别结果";
  deviceRecognition.classList.add("placeholder");
  useRecognizedDevices.disabled = true;
  delete useRecognizedDevices.dataset.types;

  statistics.innerHTML = "暂无统计数据";
  statistics.classList.add("placeholder");

  vulnerabilityResults.innerHTML = "尚未发起漏洞检索";
  vulnerabilityResults.classList.add("placeholder");

  analysisResults.innerHTML = "待输出关联结果";
  analysisResults.classList.add("placeholder");

  vulnTime.textContent = "";
  document.getElementById("deviceTypes").value = "";
  updateStatus("ready", "等待操作");
}

function handleNeo4jModeChange(mode) {
  if (mode === "embed") {
    neo4jPreview.innerHTML = "";
    const iframe = document.createElement("iframe");
    iframe.src = neo4jUrlInput.value || "http://localhost:7474/browser/";
    iframe.title = "Neo4j 浏览器";
    neo4jPreview.appendChild(iframe);
    neo4jPreview.classList.remove("placeholder");
  } else {
    neo4jPreview.innerHTML = '<div class="placeholder">请上传一张示例图片</div>';
    neo4jPreview.classList.add("placeholder");
  }
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
  };
  reader.readAsDataURL(file);
}

function initNeo4jSection() {
  document.querySelectorAll('input[name="neo4jMode"]').forEach((input) => {
    input.addEventListener("change", (event) => {
      const mode = event.target.value;
      neo4jImageInput.disabled = mode !== "image";
      neo4jUrlInput.disabled = mode !== "embed";
      handleNeo4jModeChange(mode);
    });
  });

  neo4jUrlInput.addEventListener("change", () => handleNeo4jModeChange("embed"));
  neo4jImageInput.addEventListener("change", (event) => handleNeo4jImageUpload(event.target.files[0]));

  handleNeo4jModeChange("embed");
}

function initEventListeners() {
  assessmentForm.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!assessmentForm.reportValidity()) {
      return;
    }
    const mode = getActiveAssessmentMode();
    const useMock = document.getElementById("mockToggle").checked;
    performAssessment(mode, useMock);
  });

  assessmentModeInputs.forEach((input) => {
    input.addEventListener("change", () => setAssessmentMode(input.value));
  });

  document.getElementById("vulnForm").addEventListener("submit", (event) => {
    event.preventDefault();
    const deviceTypes = event.target.deviceTypes.value;
    const useMock = document.getElementById("mockToggle").checked;
    handleVulnerabilitySearch(deviceTypes, useMock);
  });

  document.getElementById("mockToggle").addEventListener("change", (event) => {
    if (!event.target.checked) {
      updateStatus("ready", "已切换到真实数据模式，请确保后端接口可用");
    } else {
      updateStatus("ready", "已切换到演示模式");
    }
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
