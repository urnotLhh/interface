const express = require("express");
const multer = require("multer");
const path = require("path");

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 5173;

app.post("/api/assessment", upload.single("targetsFile"), (req, res, next) => {
  try {
    const summary = createSummaryFromRequest(req);
    const payload = buildAssessmentResponse(summary);
    res.json(payload);
  } catch (error) {
    next(error);
  }
});

app.post("/api/vulnerabilities", (req, res) => {
  const deviceTypes = Array.isArray(req.body?.deviceTypes) ? req.body.deviceTypes : [];
  if (deviceTypes.length === 0) {
    return res.status(400).json({ message: "deviceTypes 不能为空" });
  }

  const normalized = deviceTypes.map((item) => item.toLowerCase());

  const vulnerabilities = VULNERABILITY_DATA.filter((item) =>
    item.deviceTypes.some((type) => normalized.includes(type.toLowerCase()))
  ).map((item) => ({ ...item }));

  const analysis = ANALYSIS_DATA.filter((item) =>
    normalized.includes(item.deviceType.toLowerCase())
  ).map((item) => ({ ...item }));

  res.json({
    vulnerabilities: vulnerabilities.length ? vulnerabilities : VULNERABILITY_DATA,
    analysis: analysis.length ? analysis : ANALYSIS_DATA,
  });
});

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use((error, _req, res, _next) => {
  console.error(error);
  const status = error.status ?? 500;
  res.status(status).json({ message: error.message ?? "服务器内部错误" });
});

app.listen(PORT, () => {
  console.log(`漏洞评估前端示例服务已启动：http://localhost:${PORT}`);
});

function createSummaryFromRequest(req) {
  const type = (req.body?.type ?? "single").toLowerCase();

  if (type === "file") {
    if (!req.file) {
      throw createHttpError(400, "请上传包含 IP 的文件");
    }
    const targets = parseTargetsFromFile(req.file.buffer);
    if (targets.length === 0) {
      throw createHttpError(400, "文件中未检测到有效目标");
    }
    return {
      mode: "file",
      label: `${req.file.originalname}（${targets.length} 条记录）`,
      targetsPreview: targets.slice(0, 5),
      totalTargets: targets.length,
      message: `已导入 ${targets.length} 个目标，开始评估`,
    };
  }

  if (type === "subnet") {
    const subnet = (req.body?.subnet ?? "").trim();
    const mask = (req.body?.mask ?? "").trim();
    if (!subnet || !mask) {
      throw createHttpError(400, "请提供子网和掩码/前缀");
    }

    const preview = generateSampleIps(subnet);
    if (!preview.length) {
      throw createHttpError(400, "子网格式不正确");
    }

    const prefix = maskToPrefix(mask);
    const totalTargets = prefix ? estimateHostCount(prefix) : preview.length;

    return {
      mode: "subnet",
      label: `${subnet}/${mask}`,
      targetsPreview: preview,
      totalTargets,
      message: `子网 ${subnet}/${mask} 预计扫描 ${totalTargets} 个目标`,
    };
  }

  const ip = (req.body?.ip ?? "").trim();
  if (!ip) {
    throw createHttpError(400, "请提供有效的 IP 地址");
  }

  return {
    mode: "single",
    label: ip,
    targetsPreview: [ip],
    totalTargets: 1,
    message: `已完成对 ${ip} 的单点评估`,
  };
}

function buildAssessmentResponse(summary) {
  const timestamp = new Date().toISOString().replace("T", " ").slice(0, 16);

  const overview = SAMPLE_SCAN_OVERVIEW.map((item, index) => {
    if (index === 0 && summary.targetsPreview?.length) {
      return {
        ...item,
        title: `${summary.targetsPreview[0]} · ${item.title}`,
      };
    }
    return { ...item };
  });

  const statistics = [
    {
      label: "评估目标数",
      value: summary.totalTargets ?? summary.targetsPreview?.length ?? 1,
    },
    {
      label: "目标样本",
      value: summary.targetsPreview?.slice(0, 3).join(", ") ?? "-",
    },
    ...SAMPLE_STATISTICS.slice(0, 3).map((item) => ({ ...item })),
    { label: "最近扫描", value: timestamp },
  ];

  const fingerprint = {
    os: SAMPLE_FINGERPRINT.os,
    technologies: SAMPLE_FINGERPRINT.technologies.map((item) => ({ ...item })),
  };

  const recognition = {
    ...SAMPLE_RECOGNITION,
    metadata: {
      ...SAMPLE_RECOGNITION.metadata,
      campaign: summary.label,
    },
  };

  return {
    summary,
    scan: {
      overview,
      statistics,
    },
    fingerprint,
    recognition,
    vulnerabilities: VULNERABILITY_DATA.map((item) => ({ ...item })),
    analysis: ANALYSIS_DATA.map((item) => ({ ...item })),
  };
}

function parseTargetsFromFile(buffer) {
  return Array.from(
    new Set(
      buffer
        .toString("utf-8")
        .split(/[\n,]/)
        .map((item) => item.trim())
        .filter(Boolean)
    )
  );
}

function generateSampleIps(subnet, count = 5) {
  const base = ipToNumber(subnet);
  if (base === null) return [];
  const samples = [];
  for (let i = 1; i <= count; i += 1) {
    const candidate = (base + i) % 0xffffffff;
    samples.push(numberToIp(candidate));
  }
  return samples;
}

function ipToNumber(ip) {
  const octets = ip.split(".").map((part) => Number(part));
  if (octets.length !== 4 || octets.some((part) => Number.isNaN(part) || part < 0 || part > 255)) {
    return null;
  }
  return ((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3];
}

function numberToIp(num) {
  return [
    Math.floor(num / 16777216) % 256,
    Math.floor(num / 65536) % 256,
    Math.floor(num / 256) % 256,
    num % 256,
  ].join(".");
}

function maskToPrefix(mask) {
  if (!mask) return null;
  if (!mask.includes(".")) {
    const prefix = Number(mask);
    return Number.isFinite(prefix) && prefix >= 0 && prefix <= 32 ? prefix : null;
  }
  const octets = mask.split(".").map((part) => Number(part));
  if (octets.length !== 4 || octets.some((part) => Number.isNaN(part) || part < 0 || part > 255)) {
    return null;
  }
  return octets.reduce((sum, value) => sum + countBits(value), 0);
}

function countBits(value) {
  let bits = 0;
  let current = value;
  while (current > 0) {
    bits += current & 1;
    current >>= 1;
  }
  return bits;
}

function estimateHostCount(prefix) {
  if (!Number.isFinite(prefix)) return 1;
  const hostBits = Math.max(0, 32 - prefix);
  const hosts = 2 ** hostBits;
  return hostBits >= 2 ? hosts - 2 : hosts;
}

function createHttpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

const SAMPLE_SCAN_OVERVIEW = [
  { title: "端口 22", status: "开放", service: "OpenSSH 8.4" },
  { title: "端口 80", status: "开放", service: "nginx 1.22" },
  { title: "端口 502", status: "开放", service: "Modbus/TCP" },
  { title: "端口 102", status: "开放", service: "Siemens S7" },
];

const SAMPLE_STATISTICS = [
  { label: "开放端口", value: 6 },
  { label: "TCP 服务", value: 4 },
  { label: "UDP 服务", value: 2 },
];

const SAMPLE_FINGERPRINT = {
  os: "Embedded Linux (kernel 4.19)",
  technologies: [
    { name: "OpenSSH", version: "8.4p1", category: "远程管理" },
    { name: "nginx", version: "1.22", category: "Web 服务" },
    { name: "Siemens S7", version: "V5.6", category: "工业控制" },
  ],
};

const SAMPLE_RECOGNITION = {
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
};

const VULNERABILITY_DATA = [
  {
    cve: "CVE-2023-12345",
    severity: "high",
    score: 8.8,
    description: "某些 Scalance 设备中的身份验证绕过漏洞，可导致未授权访问。",
    published: "2023-11-18",
    exploit: "PoC",
    deviceTypes: ["工业网关 / 路由器", "industrial router"],
  },
  {
    cve: "CVE-2022-55678",
    severity: "medium",
    score: 6.5,
    description: "nginx HTTP/2 模块在特定条件下可能导致拒绝服务。",
    published: "2022-08-01",
    exploit: "暂无",
    deviceTypes: ["nginx", "web server"],
  },
  {
    cve: "CVE-2021-9876",
    severity: "low",
    score: 4.3,
    description: "OpenSSH 在弱配置下可能允许信息泄露，需要特定环境。",
    published: "2021-04-12",
    exploit: "暂无",
    deviceTypes: ["openssh", "remote management"],
  },
];

const ANALYSIS_DATA = [
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
];
