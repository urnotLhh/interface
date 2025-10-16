# 漏洞评估平台前端界面

本项目是一个聚合 IP 扫描、指纹收集、设备识别与漏洞评估的前端原型，提供统一入口展示和操作入口。界面支持演示数据，也可以连接真实后端 API，并附带一个轻量级本地服务用于演示和二次开发。

## 功能概览

- **目标 IP 评估**：支持三种入口——单个 IP、子网 + 掩码、IP 列表文件上传。提交后自动串联扫描、指纹和识别工作流，并生成统计指标与目标概要。
- **漏洞检索**：支持针对一个或多个设备类型发起漏洞搜索，展示 CVE 列表并统计耗时。
- **漏洞分析**：展示设备类型与 CPE 的映射关系，辅助进一步分析。
- **Neo4j 嵌入**：可直接嵌入本地 Neo4j 浏览器（默认指向 `http://localhost:7474/browser/`），或上传示例图像进行展示。

## 本地运行

```bash
npm install
npm start
```

启动后访问 [http://localhost:5173](http://localhost:5173) 即可体验完整界面。右上角的“使用演示数据”开关用于在前端内置数据与真实接口之间切换。

## 接口约定

若切换到真实接口模式，请确保后端提供下列能力：

- `POST /api/assessment`
  - 单个 IP：`{ "type": "single", "ip": "192.168.1.10" }`
  - 子网：`{ "type": "subnet", "subnet": "10.0.0.0", "mask": "24" }`
  - 文件上传：`multipart/form-data`，字段 `type=file` 与 `targetsFile=<文件>`，文件支持逐行或逗号分隔的 IP/子网。
  - 返回值需包含扫描概览、指纹识别、识别信息、统计数组，以及一个 `summary` 字段，用于描述目标范围和示例。
- `POST /api/vulnerabilities`
  - 请求体：`{ "deviceTypes": ["Industrial Router", "PLC Controller"] }`
  - 返回值：`{ vulnerabilities: [...], analysis: [...] }`，其中 analysis 为设备类型与 CPE 的映射。
- （可选）`POST /api/cpe-mapping`
  - 若希望拆分分析接口，可单独返回 CPE 映射，前端提供常量 `API_ENDPOINTS.analysis` 以供调整。

如需调整接口路径，可修改 `app.js` 中的 `API_ENDPOINTS` 常量。

## Neo4j 图谱展示

- 默认以 iframe 方式嵌入本地 Neo4j 浏览器，如需访问请确保浏览器允许访问 `http://localhost:7474`。
- 若由于安全策略无法嵌入，可切换到“使用示例图片”模式，并上传一张导出的节点关联图作为示例。

## 自定义与扩展

- 可根据实际后端 API 的返回结构，调整 `app.js` 中 `renderAssessment`、`renderVulnerabilities` 和 `renderAnalysis` 的解析逻辑。
- 样式集中在 `styles.css`，可继续扩展主题、响应式布局或深色/浅色模式。
- 若需要国际化，可将界面文本抽取为配置文件或接入 i18n 库。

## 数据准备建议

- 文件上传支持 `.txt`、`.csv` 等纯文本格式，建议一行一个目标或使用逗号分隔。
- 若对接真实扫描结果，可在 `summary` 字段中返回总目标数、示例 IP，以及描述信息，以增强前端展示体验。
