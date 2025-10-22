# Vulnerability Assessment Platform Interface

This project provides a front-end prototype that brings together IP scanning, fingerprint collection, device recognition, and vulnerability assessment in a single dashboard. It ships with demo data, but you can also connect it to real APIs. A lightweight local server is included to support demos and quick iteration.

## Feature overview

- **Target assessment** – Submit a single IP, a subnet + mask, or an uploaded list of addresses. The workflow chains scanning, fingerprinting, and recognition while producing summary metrics.
- **Vulnerability search** – Query the vulnerability catalog for one or more device types and review the resulting CVE list, including timing statistics.
- **Vulnerability analysis** – Visualize the mapping between device types and CPE identifiers to assist deeper investigations.
- **Neo4j integration** – Embed the local Neo4j browser (defaults to `http://localhost:7474/browser/`) or display an exported reference image.

## Prerequisites

Ensure the following tools are available locally:

- [Node.js](https://nodejs.org/) **16.x** or later (verified on LTS releases).
- `npm` (bundled with Node.js) for dependency management.

Install dependencies from the project root:

```bash
npm install
```

The command installs `express`, `multer`, and other dependencies required by the demo backend service.

## Run locally

Start the bundled demo service after installing dependencies:

```bash
npm start
```

Open [http://localhost:5173](http://localhost:5173) in your browser to explore the interface. The "Use demo data" toggle in the top-right corner switches between built-in data and real API responses.

## API contracts

When connecting to a real backend, implement the following endpoints:

- `POST /api/assessment`
  - Single IP: `{ "type": "single", "ip": "192.168.1.10" }`
  - Subnet: `{ "type": "subnet", "subnet": "10.0.0.0", "mask": "24" }`
  - File upload: `multipart/form-data` with `type=file` and `targetsFile=<file>` containing line- or comma-separated IPs/subnets.
  - Response should include a scan overview, fingerprint data, recognition details, statistics, and a `summary` object describing the assessed scope.
- `POST /api/vulnerabilities`
  - Request body: `{ "deviceTypes": ["Industrial Router", "PLC Controller"] }`
  - Response: `{ vulnerabilities: [...], analysis: [...] }`, where `analysis` lists device-to-CPE mappings.
- (Optional) `POST /api/cpe-mapping`
  - Use this endpoint if you want to split the analysis API. Adjust `API_ENDPOINTS.analysis` in `app.js` accordingly.

Update the `API_ENDPOINTS` constant in `app.js` if you need to customize routes.

## Neo4j visualization

- By default the page embeds the local Neo4j browser; ensure your browser can access `http://localhost:7474`.
- If embedding is blocked by security policies, switch to an uploaded sample image exported from Neo4j.

## Customization and extension

- Modify the parsing logic in `app.js` (`renderAssessment`, `renderVulnerabilities`, `renderAnalysis`) to match your backend payloads.
- Styles live in `styles.css`. Extend the theme, add responsive breakpoints, or implement dark/light modes as needed.
- For internationalization, extract interface text into a config file or integrate an i18n library.

## Data preparation tips

- File uploads accept plain-text `.txt` or `.csv` files. Use one target per line or comma-separated values.
- When returning real scan results, populate the `summary` object with the total number of targets, sample addresses, and descriptive context to enrich the presentation.
