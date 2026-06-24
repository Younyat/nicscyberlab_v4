# View inventory and analysis — NICS | CyberLab

> Document generated from a direct analysis of the source code (`app_core/static/*.html`, their associated JS files, and the Flask blueprints they consume). Reflects the state of the project as of **2026-06-24**.

## 1. General navigation architecture

- **There is no Jinja templating**: every page under `app_core/static/` is a complete, independent HTML document (its own `<head>`, `<style>`, and `<script>`), served by a Flask catch-all route (`app_core/presentation/api.py`):
  - `GET /` → serves `index.html`.
  - `GET /<path>` → serves any file from `app_core/static/` by name (includes `/css/...`, `/js/...`, and any `<view>.html`).
- **`index.html` is a single-page "shell"**, not a traditional navigation menu. Every menu card calls `openView('<key>')`, which sets `iframe.src = '/<key>.html'` and slides in an overlay containing that view **inside an `<iframe>`**. `closeView()` clears the iframe's `src` after the close animation. This means that, except for `index.html` itself, no view is "navigated to" in the classic sense — they are all loaded embedded.
- Since all views live on the same origin, they share `localStorage` — that's why the recently-added theme switcher stays consistent between `index.html` and any view loaded into the iframe, without needing `postMessage`.

## 2. Count

| Category | Count |
|---|---|
| **Active, reachable views** (the real "views" of the platform) | **26** |
| Orphaned views (no UI entry point, but servable via direct URL) | 4 (`forensic.html`, `ssh_terminal.html`, `terminal.html`, `ot_gui_f35.html` partially) |
| Backup files / old copies (not real views) | 3 (`index copy.html`, `index copy_10_06_20216_16_24.html`, `index-tools _sin_host_tools.html`) |
| **Total `.html` files under `app_core/static/`** | 31 |

Of the 17 main-menu cards in `index.html` (`openView(...)`), there are also 2 additional views: one embedded as an iframe inside another view (`forensic_inventory.html` inside `nicscyberlab_dashboard.html`) and one gateway view reachable only from the AI Copilot (`ai_module.html`).

---

## 3. Summary table — how each view is reached

| # | View (file) | Title / menu label | How it's reached |
|---|---|---|---|
| 1 | `index.html` | — (root shell) | It is the `/` page itself |
| 2 | `initial.html` | Initial environment setup | No menu entry; direct access at `/initial.html` |
| 3 | `index-scenario.html` | 01 · IT Scenario | `openView('index-scenario')` |
| 4 | `index-tools.html` | 02 · Tool Deployment (active by default) | `openView('index-tools')` |
| 5 | `industrial.html` | 03 · OT Scenario | `openView('industrial')` |
| 6 | `inventory.html` | 04 · Inventory | `openView('inventory')` |
| 7 | `dashboard_especial.html` | 05 · Attack Lab | `openView('dashboard_especial')` |
| 8 | `dashboard.html` | 06 · Detection Layer | `openView('dashboard')` |
| 9 | `forensics.html` | 07 · Forensic Lab | `openView('forensics')` |
| 10 | `forensic_report_analysis.html` | 08 · Forensic Report | `openView('forensic_report_analysis')` |
| 11 | `foc_reconstruction.html` | 09 · FOC Reconstruction | `openView('foc_reconstruction')` |
| 12 | `foc_scientific_evidence_lifecycle.html` | 10 · FOC Scientific Lifecycle | `openView('foc_scientific_evidence_lifecycle')` |
| 13 | `foc_repetition_manager.html` | — | Direct access at `/foc_repetition_manager.html`; linked from `foc_scientific_evidence_lifecycle.html` |
| 14 | `foc_reconstruction_comparability.html` | — | Direct access at `/foc_reconstruction_comparability.html`; linked from `foc_scientific_evidence_lifecycle.html` |
| 15 | `nicscyberlab_dashboard.html` | 11 · Comparisons | `openView('nicscyberlab_dashboard')` |
| 16 | `modbus_traffic.html` | 12 · IT/OT Traffic Monitor | `openView('modbus_traffic')` |
| 17 | `node_health.html` | 13 · Node Health | `openView('node_health')` |
| 18 | `honeyv.html` | 14 · Lab Exchange | `openView('honeyv')` |
| 19 | `etc_lab.html` | 14 · ETC Lab | `openView('etc_lab')` |
| 20 | `ciberia_lab.html` | 15 · CiberIA Lab | `openView('ciberia_lab')` |
| 21 | `adv_detection.html` | 15 · advDetection | `openView('adv_detection')` (also servable via its own blueprint route `GET /adv-detection/`) |
| 22 | `ot_gui.html` | — | Tied to the `industrial`/tactical-HUD menu key; OT topology visualizer |
| 23 | `forensic_inventory.html` | — | Embedded as an `<iframe>` inside `nicscyberlab_dashboard.html` |
| 24 | `ai_module.html` | — | Automatic redirect from the AI Copilot in `index.html` when the module isn't deployed yet |
| 25 | `forensic.html` | — | **Orphaned**: no `openView` or iframe references it; only reachable by typing `/forensic.html` |
| 26 | `ot_gui_f35.html` | — | **Orphaned/prototype**: earlier version of `ot_gui.html`, no confirmed menu card |
| — | `ssh_terminal.html` | — | **Orphaned**: Socket.IO SSH client (port 8080), no UI entry point at all |
| — | `terminal.html` | — | **Orphaned**: Socket.IO log viewer (port 5050), no UI entry point at all |
| — | `index copy.html`, `index copy_10_06_20216_16_24.html`, `index-tools _sin_host_tools.html` | — | Backup files / old versions, not active views |

---

## 4. Detail per view

### 4.1 Platform core

#### `index.html` — Main shell / control panel
**What it is:** the entry point (`/`) and "control room" for the whole platform. It narrates a 6-phase workflow (Prepare → Build & Understand → Attack → Detect & Defend → Investigate & Report → Analyze & Improve).

**What you can see / do:**
- Top bar: "NICS | CyberLab" brand, language switcher (ES/EN), and theme switcher (the 5 visual themes described below), a strip of 6 live KPIs (OpenStack Instances, Installed Tools, Detected Alerts, Forensic Cases, Evidence Artifacts, FOC Readiness).
- Side menu with 12 numbered workflow steps, each with a live status badge (`ready`/`incomplete`/`missing`/`unknown`).
- Main carousel with 17 cards (one per view), each opening its view in an overlaid iframe.
- Phase strip (decorative, not clickable) and a bottom area with 5 summary panels (Scenario Readiness, Recent Activity, Detection Coverage, Attack Catalog Status, Forensic/FOC Readiness).
- Live alert bar showing the latest detection event.
- View overlay: "DFIR auto-preservation" terminal (via SSE), a real-time alert monitor (START/STOP MONITORING button + EventSource showing toast cards with OPEN/FORENSICS/CLOSE actions), and an "AI Copilot" chat widget.

**Backend it consumes:** `GET /api/forensics/alerts/latest`, `GET /api/dashboard/home-summary`, `GET /api/hud/instances`, `GET /api/hud/monitor/live_wazuh_stream` (SSE), `GET /api/dfir/orchestrator/auto/stream` (SSE), `GET /api/ai/status`, `POST /api/ai/ask`.

**JS:** all inline (no dedicated `.js` file); depends on `/css/theme.css` and `/js/theme-switcher.js`.

---

### 4.2 Scenario setup and configuration

#### `initial.html` — Initial environment setup
**What it is:** a global infrastructure setup step performed *before* any scenario exists (CIDR ranges, DNS, ports, base images, instance "flavors").
**How it's reached:** no menu card; direct access only.
**Features:** network/router form, base-image selection (Debian/Ubuntu/both), editable flavors table (tiny/small/medium/large), live output terminal, Save / Run Generator / Destroy Configuration buttons.
**Backend:** `POST /api/run_initial_environment_setup`, `GET /api/run-initial-generator-stream` (SSE), `POST /api/destroy_initial_environment_setup`.
**JS:** `js/initial.js` (~10.5 KB).

#### `index-scenario.html` — IT Scenario editor (step 01)
**What it is:** a visual topology editor for the IT side of the cyber range (Monitor/Attacker/Victim).
**Features:** Cytoscape.js canvas for placing and connecting nodes, live statistics panel, node-type buttons (Monitor/Attack/Victim/Connect), per-node property editor (network, image, flavor, security group, SSH key), Create/Load/Destroy scenario.
**Backend:** `POST /api/create_scenario`, `GET /api/deployment_status`, `POST /api/destroy_scenario`, `GET /api/destroy_status`, `GET /api/get_scenario/<name>`, `GET /api/console_url`.
**JS:** `js/script.js` (~20.4 KB).

#### `index-tools.html` — Tool deployment (step 02, active by default)
**What it is:** a console for installing sensors/IDS/forensic agents onto OpenStack instances, plus separate management of tools on the control node ("host").
**Features:** list of available instances, Cytoscape topology view of the current scenario, installation catalog + Add Tool/CONFIG/INSTALL buttons, log terminal, "Host Tools" section with per-tool cards (Tshark, Volatility 3) with Deploy/Audit/Uninstall driven by a live console.
**Backend:** `GET /api/openstack/instances`, `GET/POST /api/get_tools_for_instance`, `POST /api/add_tool_to_instance`, `GET /api/read_tools_configs`, `POST /api/install_tools`, `POST /api/uninstall_tool_from_instance`, `GET /api/host/inventory`, `GET /api/host/version/<tool>`, `GET /api/host/install/<tool>` (SSE), `GET /api/host/uninstall/<tool>` (SSE).
**JS:** `js/index-tools.js` (~36.8 KB, the largest in this group).

#### `industrial.html` — OT Scenario editor (step 03)
**What it is:** an industrial topology builder (PLC, SCADA, OT network).
**Features:** Cytoscape canvas, PLC/SCADA buttons (IoT Device/IoT Network appear disabled — not implemented yet), dynamic configuration panel based on the selected node, Load/Delete/Save industrial scenario.
**Backend:** `GET /api/industrial/state`, `GET /api/get_active_scenario`, `POST /api/add_industrial_tool`, `DELETE /api/delete_industrial_scenario`, `POST /api/save_industrial_scenario`, `POST /api/industrial/deploy`.
**JS:** `js/industrial.js` (~22.1 KB).

#### `inventory.html` — OpenStack inventory (step 04)
**What it is:** a read-only/refreshable panel showing the real state of the OpenStack cloud backing the lab.
**Features:** instance table, host-tools grid, usage gauges (vCPU/RAM/disk), flavors/networks/security-groups/keypairs tables, "detected roles" box, output terminal.
**Backend:** `GET /api/openstack/instances/full`, `GET /api/host/inventory`, `GET /api/openstack/flavors`, `GET /api/openstack/hypervisor-stats`, `GET /api/openstack/keypairs`, `GET /api/openstack/networks`, `GET /api/openstack/security-groups`, `GET /api/instance_roles`, `GET /api/openstack/traffic/<vmId>` (SSE).
**JS:** `js/inventory.js` (~15 KB).

---

### 4.3 Attack / operations dashboards

#### `dashboard.html` — Attack Control (step 06, "Detection Layer")
**What it is:** the original, simpler attack-control panel: three nodes (Attacker/Victim/Monitor) with buttons to launch tools and view their status.
**Features:** ON/OFF indicators per node, Caldera/Nmap/Metasploit/Nikto buttons (the last three only open an informational modal, not a real launch), real Wazuh control on the monitor node, real version-check for Snort/Suricata on the victim node, a draggable floating console (opens the real console via `window.open`, not an iframe), a "Launch Test Attack" log.
**Backend:** `POST /api/console_url`, `GET /api/instance_roles` (polled every 3s), `POST /api/check_wazuh`, `POST /api/change_password`, `POST /api/change_keyboard_layout`, `POST /api/run_tool_version`.
**JS:** all inline; no dedicated `.js` file.

#### `dashboard_especial.html` — "F-35 Tactical HUD" (step 05, "Attack Lab")
**What it is:** the most elaborate operations dashboard — a stylized tactical HUD (Orbitron font, green-on-black) that visualizes the lab topology as an interactive graph (Cytoscape) and lets the operator launch categorized, MITRE ATT&CK-tagged attack techniques while watching live defensive telemetry (Wazuh).
**Features:** interactive network graph with a context menu (Offensive/Defensive/Preventive), a "Scientific Attack Taxonomy" catalog (Reconnaissance T1595, Port Scan T1046, Unauthorized SSH T1110.001, Modbus register manipulation T0831, etc.) with MITRE info popups, a floating toolbar, a "THEATER STATUS" widget, two live telemetry terminals (victim / monitoring), an inspector for the selected node.
**Backend:** `GET /api/hud/instances`, `GET /api/hud/monitor/live_wazuh_stream` (SSE), `GET /api/openstack/instances/full`, `POST /api/hud/action`, `POST /api/hud/attack/execute`, `GET /api/hud/attack/launch` (SSE), `GET /api/hud/attack/catalog`, `/api/hud/victim/install_detector`, `/api/hud/monitor/start_listener`, `/api/hud/monitor/stop_listener`, `POST /api/hud/monitor/tools/open_nmap_terminal`, `GET /api/instance_roles`, `POST /api/check_wazuh`.
**JS:** all inline (~2100 lines inside the 3157-line HTML file — the largest file on the platform).

#### `nicscyberlab_dashboard.html` — IT/OT Environment Dashboard (step 11, "Comparisons")
**What it is:** a convergence dashboard joining IT infrastructure (attacker/victim/monitor instances) with OT components (SCADA via FUXA, PLC emulation node), host forensic inventory, tool deployment/audit, system health charts, and a DFIR alerts/indicators table.
**Features:** IT topology cards, OT component cards (SCADA/PLC), live alerts table, host forensic inventory panel, tool selector + Deploy/Audit/Uninstall buttons, Chart.js graphs for health (hypervisor) and traffic (SSE), operational log terminal.
**Backend:** `GET /api/host/instance_roles`, `GET /api/host/inventory`, `GET /api/host/forensic/tools`, `GET /api/host/version/<tool>`, `GET /api/host/install/<tool>` (SSE), `GET /api/host/uninstall/<tool>` (SSE), `GET /api/openstack/instances/full`, `GET /api/openstack/hypervisor-stats`, `GET /api/openstack/traffic/<vmId>` (SSE), `GET /api/forensics/alerts/latest`.
**JS:** all inline (~900 lines).
**Note:** embeds `forensic_inventory.html` as an iframe (`#inventory-frame`) — see 4.4.

#### `ai_module.html` — AI module deployment gate
**What it is:** **not** the AI chat itself, but a consent/deployment screen: checks whether the AI module backend is installed; if not, asks for explicit confirmation, shows a progress bar and live deployment logs (SSE), and on completion redirects the browser to the deployed module's GUI URL.
**How it's reached:** from the "AI Copilot" popup in `index.html`, when the module isn't deployed yet (`forceCopilotUnavailable()` → `openView("ai_module")`).
**Backend:** `GET /api/ai/status` (polled every 2s), `POST /api/ai/deploy`, `GET /api/ai/logs` (SSE).
**JS:** `js/ai_module.js` (~3.3 KB).

---

### 4.4 Forensics / DFIR suite

#### `forensics.html` — Live forensic workbench (step 07, "Forensic Lab")
**What it is:** the central acquisition-and-analysis workbench: pick a target VM, create/manage a case, run disk acquisition (Kolla/libvirt) + TSK analysis, memory acquisition (LiME over SSH) + Volatility 3 analysis (including symbol generation), and capture/preserve live network traffic.
**Features:** OpenStack instance picker, case selector/creator with manifest refresh, disk and memory acquisition/analysis panels, case artifact download table, console log, two full-screen SSE overlays: "Live DFIR Terminal" and "Live Traffic Analyzer" (Modbus/Profinet/TCP/UDP filters).
**Backend:** `/api/openstack/instances/full`, `/api/openstack/traffic/<vm_id>`, `/api/forensics/case/create`, `/api/forensics/case/list`, `/api/forensics/case/manifest`, `/api/forensics/case/download`, `/api/forensics/case/memory/list`, `/api/forensics/acquire/disk_kolla/stream` (SSE), `/api/forensics/acquire/memory_lime/stream` (SSE), `/api/forensics/analyze/disk_tsk/stream` (SSE), `/api/forensics/memory/analyze`, `/api/forensics/memory/analysis/<job_id>`, `/api/forensics/symbols/status`, `/api/forensics/symbols/generate`, `/api/forensics/symbols/jobs/<job_id>`, `/api/forensics/traffic/preserve/stream` (SSE).
**JS:** `js/forensics.js` (~35.4 KB). **Quirk:** the only view that does **not** load the Tailwind CDN — it ships its own hand-written stylesheet.

#### `forensic.html` — Legacy stub (orphaned)
**What it is:** an earlier, simpler "forensic readiness & guided analysis" panel — a precursor of `forensics.html`.
**How it's reached:** **it isn't** — no `openView` or iframe references it; only reachable by typing `/forensic.html` directly.
**Features:** instance list, detected forensic capabilities, guided actions, forensic log.
**Backend:** `/api/openstack/instances`, `/api/get_tools_for_instance`.
**JS:** `js/forensic.js` (~3.6 KB).

#### `forensic_inventory.html` — Forensic readiness inventory (embedded)
**What it is:** a passive, read-only inventory: host forensic-tool detection, global OpenStack inventory, per-instance snapshot (volumes, tools, evidence flags), hypervisor gauges, a JSON detail viewer per instance.
**How it's reached:** **not a top-level view** — it's embedded as `<iframe id="inventory-frame" src="forensic_inventory.html">` inside `nicscyberlab_dashboard.html` (step 11, "Comparisons").
**Backend:** `/api/host/forensic/tools`, `/api/host/forensic/install`, `/api/openstack/flavors`, `/api/openstack/networks`, `/api/openstack/security-groups`, `/api/openstack/keypairs`, `/api/openstack/instances/full`, `/api/openstack/hypervisor-stats`, `/api/host/inventory`.
**JS:** `js/forensic_inventory.js` (~18.2 KB).

#### `forensic_report_analysis.html` — Case report & chain of custody (step 08, "Forensic Report")
**What it is:** the reporting/analysis dashboard for completed cases — evidence inventory, integrity (hashes/sizes), chain of custody, and the end-to-end pipeline trace from alert to acquisition to preservation. Complements `forensics.html`'s live-acquisition workflow with the after-the-fact view.
**Features:** case selector, case-overview KPI strip, "preserved targets" scope panel, evidence-distribution chart (Chart.js), storage-footprint and integrity KPIs, searchable/filterable manifest table with a detail panel (hash, size, collected-at/by, download), chain-of-custody and pipeline-events timelines, analyst notes, raw manifest.
**Backend:** `/api/forensics/report/cases`, `/api/forensics/report/summary`, `/api/forensics/report/manifest`, `/api/forensics/report/chain-of-custody`, `/api/forensics/report/pipeline-events`, `/api/forensics/case/download`.
**JS:** `js/forensic_report_analysis.js` (~22.5 KB).

#### `node_health.html` — Node health (step 13, "Node Health")
**What it is:** operational health monitoring of the launched OpenStack instances — CPU/RAM/disk/service checks over SSH, topology visualization, clock-offset measurement/fix, per-node security-stack inspection (IDS/SIEM/agents), and safe remote disk cleanup. It validates that the scenario is in a state to produce reliable evidence (it does not handle evidence itself).
**Features:** action bar (Refresh nodes, Measure clock offset, Fix time sync, Safe disk cleanup), Cytoscape topology graph, identity/CPU/memory/disk cards, time-sync panel, installed-security-stack panels, top-CPU/memory process lists, action console with streaming.
**Backend:** `/api/node-health/nodes`, `/api/node-health/nodes/<id>/probe`, `/api/node-health/nodes/<id>/tooling`, `/api/node-health/nodes/<id>/time-sync/status`, `/api/node-health/nodes/<id>/time-sync/run`, `/api/node-health/nodes/<id>/cleanup/stream` (SSE).
**JS:** `js/node_health.js` (~50.2 KB — the largest in this group).

---

### 4.5 FOC — Forensic causal reconstruction

#### `foc_reconstruction.html` — Forensic Observational Context Reconstruction (step 09)
**What it is:** the technical scientific-validation surface for the FOC — scenario composition, installed tooling, timeline integrity, evidentiary traceability, reconstruction gaps, and reproducibility readiness. It's the "technical/detailed" view, complementing the executive summary in `foc_scientific_evidence_lifecycle.html`.
**Features:** Bootstrap FOC / Regenerate Reconstruction / Refresh buttons; "Reconstruction Readiness" panel; causal graph (nodes/edges with `confirmed`/`inferred`/`missing`/`updated` status); uncertainty budget and reconstruction metrics; detail modals per graph node/edge.
**Backend:** `GET/POST /api/foc/bootstrap`, `/api/foc/regenerate`, `/api/foc/cases`, `/api/foc/dashboard`, `/api/foc/causal/run`, `/api/foc/causal/status`, `/api/foc/causal/graph-summary`, `/api/foc/causal/report`, `/api/foc/causal/uncertainty`, `/api/foc/readiness-report`, `/api/foc/attack-attestation`, `/api/foc/detection-attestation`, `/api/foc/forensic-intervention`, `/api/foc/events/stream` (SSE).
**JS:** `js/foc_reconstruction.js` (~35 KB).

#### `foc_scientific_evidence_lifecycle.html` — Executive Evidence Lifecycle Dashboard (step 10)
**What it is:** the high-level decision surface covering the whole evidence lifecycle: controlled attack path, detections, acquisition trigger, preservation, multilayer forensic analysis, causal reconstruction, uncertainty budget, and auditable conclusions. This is where the **Evidence-Based Hypothesis Support** module lives (added in this session): per-layer triage (memory/network/disk/OT/alerts/timeline/custody/causal graph), cross-layer correlation, forensic storyline, a "claimability" report (what can be claimed and how strongly), and counter-evidence — all run strictly on explicit user demand, never automatically.
**Features:** case list, executive summary with tags and notes, the "Evidence Lifecycle Rail" (Attack → Conclusion) with per-edge evidence cards, action panel (Refresh / Generate summary / Run causal / Run multilayer analysis / Generate hypothesis support), 5 hypothesis-support cards (Summary, Layer Contribution Matrix, Forensic Storyline, Claimability Boundary, Evidence Gaps), modal with raw technical reports.
**Backend:** `GET /api/foc/cases`, `GET /api/foc/evidence-lifecycle-dashboard`, `POST /api/foc/lifecycle/generate-summary`, `GET /api/foc/lifecycle/job-status`, `POST /api/foc/lifecycle/run-causal`, `POST /api/foc/lifecycle/run-full`, `POST /api/foc/lifecycle/run-multilayer-analysis`, `POST /api/foc/evidence-support/run`, `POST /api/foc/evidence-support/regenerate`, `GET /api/foc/evidence-support/status`, `GET /api/foc/evidence-support/report`, `GET /api/foc/evidence-support/storyline`, `GET /api/foc/evidence-support/claimability`, `GET /api/foc/evidence-support/counter-evidence`, `GET /api/foc/evidence-support/atoms`, `GET /api/foc/reports/file`, `POST /api/foc/time-sync/measure`, `POST /api/foc/time-sync/fix`.
**JS:** `js/foc_scientific_evidence_lifecycle.js` (~84 KB — the largest JS file on the platform).

#### `foc_repetition_manager.html` — Forensic Repetition Manager
**What it is:** a new, optional experimentation surface dedicated to **campaign registration and execution workspace generation**, separate from the per-case executive scientific dashboard. It does not replace `foc_scientific_evidence_lifecycle.html` and does not run automatically on load.
**How it's reached:** direct access at `/foc_repetition_manager.html`, plus a navigation link from `foc_scientific_evidence_lifecycle.html`.
**Features:** campaign list, campaign creation form, source-case selector, campaign state controls (`Start`, `Pause`, `Stop`, `Run Next Execution`), execution registry, job-status panel, and methodological-reference panel.
**Backend:** `GET /api/foc/experimentation/health`, `GET /api/foc/experimentation/campaigns`, `POST /api/foc/experimentation/campaigns/create`, `GET /api/foc/experimentation/campaigns/<campaign_id>`, `POST /api/foc/experimentation/campaigns/<campaign_id>/start`, `POST /api/foc/experimentation/campaigns/<campaign_id>/pause`, `POST /api/foc/experimentation/campaigns/<campaign_id>/stop`, `POST /api/foc/experimentation/campaigns/<campaign_id>/run-next`, `GET /api/foc/experimentation/source-cases`, `GET /api/foc/experimentation/jobs/<job_id>`, `GET /api/foc/experimentation/methodological-basis`.
**JS:** `js/foc_repetition_manager.js`.

#### `foc_reconstruction_comparability.html` — Forensic Reconstruction Comparability View
**What it is:** a dedicated comparison surface for already-generated experimentation executions. It **does not create executions** and **does not rerun forensic tools**; it compares existing execution profiles, causal metrics, uncertainty, trigger alignment, and degradation state.
**How it's reached:** direct access at `/foc_reconstruction_comparability.html`, plus a navigation link from `foc_scientific_evidence_lifecycle.html`.
**Features:** campaign-scoped execution selector, background comparison job panel, comparability result surface, and methodological reference basis.
**Backend:** `POST /api/foc/experimentation/comparability/compare`, `GET /api/foc/experimentation/comparability/results/<comparison_id>`, `GET /api/foc/experimentation/comparability/profile/<execution_id>`, `GET /api/foc/experimentation/jobs/<job_id>`, `GET /api/foc/experimentation/methodological-basis`, `GET /api/foc/experimentation/campaigns`.
**JS:** `js/foc_reconstruction_comparability.js`.

---

### 4.6 OT/ICS and specialized labs

#### `modbus_traffic.html` — Host forensic inventory / Live traffic analyzer (step 12)
**What it is:** despite the name, its actual content is an instance-inventory panel plus a live traffic sniffer (Modbus TCP, Profinet, TCP/UDP) with color-highlighting in an overlay terminal.
**Features:** networked-instances table with an "Audit" action; host-tools grid with Deploy/Purge; a "Live Traffic Analyzer" overlay with protocol filters and a live-decoded-packet terminal (SSE).
**Backend:** `GET /api/openstack/instances/full`, `GET /api/openstack/traffic/<vm_id>` (SSE, decodes Modbus ADUs), `GET /api/host/inventory`.
**JS:** all inline (an orphaned `js/modbus_traffic.js` exists, identical to the inline script but never referenced).

#### `ot_gui.html` — OT tactical HUD (attack-topology visualizer)
**What it is:** not a mimic of a physical process (tanks/pumps/PLC registers) but an interactive network/attack-graph visualizer (Cytoscape) styled as a military HUD, over the lab's real topology (PLC, SCADA, attacker, monitor, victim).
**Features:** graph with role-colored nodes and typed edges (`network`/`modbus`/`attack`/`monitor`/`c2`/`manual`), a "Theater Status" overlay, a per-node context menu with Offensive/Defensive/Preventive actions, ICMP detector install, monitoring listener, "Tactical Ping" (live SSH-driven attack), telemetry log.
**Backend:** `GET /api/hud/instances`, `POST /api/hud/action`, `GET /api/hud/attack/launch` (SSE), `GET /api/hud/victim/install_detector` (SSE), `/api/hud/monitor/start_listener`, `/api/hud/monitor/stop_listener`.
**JS:** all inline (~987 lines).
**Technical note:** `app_core/main.py` has a broken import of a non-existent `dashboard_f35` symbol, wrapped in a `try/except: pass` — this doesn't affect functionality, since the real blueprint registration happens in `app_core/presentation/api.py`.

#### `ot_gui_f35.html` — Earlier prototype of the tactical HUD (orphaned)
**What it is:** an earlier iteration of the same concept as `ot_gui.html` — same visual style, but without manual connection mode, without ICMP detector/listener install, without "Tactical Ping"; attack strategies are hardcoded client-side instead of coming from the backend.
**How it's reached:** no confirmed menu card — appears to remain as a prototype/earlier version kept on disk.
**Backend:** `GET /api/hud/instances`, `POST /api/hud/action`.

#### `etc_lab.html` — Encrypted Traffic Classification Lab (step 14)
**What it is:** a control panel for an AI-based encrypted-traffic-classification module (a wrapper around a vendored package called `packet-level-etc`, under the external `etc_lab/` directory). It installs/runs the pipeline and embeds its resulting Dash analytics dashboard.
**Features:** status indicator (Checking/Installing/Running/Ready/Not installed), installation form (capture interface, capture seconds, base directory), live install log (SSE), Install/Start/Stop/Open-Dash buttons, embedded view of the external Dash dashboard (`http://127.0.0.1:8050/`).
**Backend:** `GET /api/etc/status`, `POST /api/etc/install`, `GET /api/etc/install/log` (SSE), `POST /api/etc/start`, `POST /api/etc/stop`.
**JS:** all inline. Backend lives in `etc_lab/routes/etc_lab_routes.py` (a top-level module separate from `app_core/`).

#### `ciberia_lab.html` — CiberIA Lab (step 15)
**What it is:** an operational UI for reproducing/retraining/evaluating ML-based network-intrusion-detection models, wrapping an external "CiberIA" framework (`ciberia_lab/external/CiberIA_O1_A1`), plus dataset management (built-in profiles CIC-IDS2017/2018, UNSW-NB15; custom datasets; PCAP→CSV conversion and PCAP-based inference).
**Features:** dataset profile selector, custom-dataset management, PCAP-based dataset generation, baseline reproduction / retraining / CSV export, inference on a prepared CSV, alternative PCAP conversion and inference.
**Backend:** `/api/ciberia/health`, `/profiles`, `/status`, `/datasets/custom/status`, `/datasets/import-split`, `/datasets/delete`, `/baseline/evaluate`, `/baseline/export-sample-csv`, `/retrain`, `/predict-csv`, `/extract-from-pcap`, `/predict-pcap`, `/datasets/import-from-pcap`.
**JS:** served by the module's own blueprint (`ciberia_lab/routes.py`), not from `app_core/static/js/` (though a duplicate copy exists there too).

#### `honeyv.html` — Lab Exchange / SSH bridge to a Windows lab host (step 14)
**What it is:** despite the name (suggesting a honeypot), its current function is a forensic-artifact exchange and remote-execution bridge to a Windows lab host over SSH/SFTP.
**Features:** remote directory browser, selection and ZIP packaging, file upload, SFTP send, SSH connection configuration and testing (password or key), remote-path verification, a remote JSON report reader (collapsible tree viewer), remote command/PowerShell execution with post-run verification.
**Backend:** prefix `/api/windows-lab-exchange` — `/health`, `/bootstrap`, `/api/list`, `/api/upload`, `/api/zip`, `/api/send`, `/api/ssh/config`, `/api/ssh/test`, `/api/ssh/verify-remote-file`, `/api/ssh/read-remote-json`, `/api/ssh/exec`.
**JS:** `js/honeyv.js` (~31 KB). Two unused leftover copies exist (`honeyv copy.js`, `honeyv copy 2.js`).

#### `adv_detection.html` — Adversarial Detection module (step 15)
**What it is:** a bridge UI to an external anomaly-detection research repository (vendored under `adv_detection/vendor/`). It doesn't implement its own detector — it lets the user browse, run (as a notebook/script/custom command), and review past runs of that vendored repository.
**Features:** mode selector (notebook/python_file/custom_command), entrypoint selector, arguments, timeout, run output, vendored-repo summary, recent-runs table with detail (stdout/stderr/files).
**Backend:** prefix `/adv-detection/api` — `/status`, `/config`, `/assets`, `/runs`, `/runs/<id>`, `/run`.
**JS:** `js/adv_detection.js` (~7.3 KB).

---

### 4.7 Orphaned views (no UI entry point)

#### `ssh_terminal.html`
A full web-based SSH client (host/user/key form, interactive terminal) that connects via **Socket.IO on port 8080** — not the Flask API backend (`5001`). Not referenced by any `openView` or iframe; only reachable by typing the URL directly. It has visible debug instrumentation (`alert()` on every click), confirming it's an abandoned dev build/prototype.

#### `terminal.html`
A read-only log viewer, connected via **Socket.IO on port 5050**. No buttons or inputs — it just displays the stream. Also not referenced anywhere in the UI.

> The "Open Console" buttons in `dashboard.html` and `dashboard_especial.html` do **not** use either of these two pages — they call `POST /api/console_url` and open the OpenStack/Horizon console URL in a new window (`window.open`), or spawn a `gnome-terminal` session server-side (`open_nmap_terminal` in `ssh_launcher.py`).

#### `forensic.html`
See section 4.4 — orphaned precursor of `forensics.html`.

#### `ot_gui_f35.html`
See section 4.6 — earlier prototype of `ot_gui.html`.

---

### 4.8 Backup files (not views)

- `index copy.html`
- `index copy_10_06_20216_16_24.html`
- `index-tools _sin_host_tools.html`

These are old copies kept on disk, with no active entry point. They should not be treated as current platform views.

---

## 5. Cross-cutting findings (dead code / inconsistencies detected)

1. **`js/modbus_traffic.js`** exists and is an almost identical copy of `modbus_traffic.html`'s inline script, but the page never loads it — an orphaned file.
2. **`js/ai_assistant.js`** implements a chat function (`askAI()` → `POST /api/ai/ask`) that no current HTML file includes — `index.html`'s Copilot has its own independent inline implementation. Likely a leftover from a refactor.
3. **`honeyv copy.js`** and **`honeyv copy 2.js`** are unused earlier iterations, alongside the current `js/honeyv.js`.
4. **`app_core/main.py`** imports a `dashboard_f35` symbol that doesn't exist in `dashboard_F35.py` (the module only defines `hud_bp`); the surrounding `try/except: pass` hides the `ImportError` without affecting real functionality, since blueprint registration actually happens in `app_core/presentation/api.py`.
5. **`forensics.html`** is the only view that doesn't load the Tailwind CDN — it uses its own hand-written stylesheet.
6. Three modules (`etc_lab`, `ciberia_lab`, `adv_detection`) follow the same integration pattern: wrapping an external/vendored research repository in its own top-level directory (a sibling of `app_core/`), with install → run → review-results from the UI.
7. `honeyv.html` also breaks the organizational pattern — its backend lives in `honeyv_app_core/` (another top-level directory), not under `app_core/infrastructure/`.

---

## 6. Theme switcher (added in this session)

The following 6 views already include the shared theme switcher (`/css/theme.css` + `/js/theme-switcher.js`, persisted in `localStorage`, with 5 themes: **Dark, Light, Mixed, Blue Team, Red Team**): `index.html`, `foc_scientific_evidence_lifecycle.html`, `foc_reconstruction.html`, `dashboard.html`, `dashboard_especial.html`, `nicscyberlab_dashboard.html`. The remaining views listed in this document don't have it yet — they're candidates for a progressive rollout if that's decided later.

---

## 7. Scientific data schemas (ground truth from backend source)

This section drills into the **forensic, FOC, and detection** views only — the ones where the exact shape of the data actually matters for the platform's scientific/evidentiary claims. Every field name below is taken verbatim from the Python source (file:line cited), not inferred from the UI. Where the code defines an enum, the enum is given in full.

### 7.1 `forensics.html` — acquisition & analysis schemas

**Case manifest** (`manifest.json`, `forensics_api.py`): top-level `case_dir`, `created_at`, `artifacts`. Each artifact entry (5 near-identical builder call sites, e.g. `:673-679`, `:1665-1671`, `:3459-3465`): `type` (free-form tag, e.g. `disk_raw`, `memory_lime`, `custody_log`, `network_pcap`, `vol3_output_dir`, `tsk_output_dir`), `rel_path`, `sha256` (nullable), `size` (nullable), `ts` (ISO UTC).

**Chain of custody** (`chain_of_custody.log`, JSONL, `:745-761`): `ts_utc`, `ts_epoch`, `run_id`, `actor`, `action`, `artifact_rel`, `outcome` (`ok`/`error`), `details`, `prev_hash`, `entry_hash`. **Hash-chain mechanism**: `entry_hash = sha256(json.dumps(entry, sort_keys=True, ensure_ascii=False))` computed over the entry *before* `entry_hash` is attached; each line's `prev_hash` equals the previous line's `entry_hash`; the genesis line uses `prev_hash = "0"*64`. This is what makes the custody log tamper-evident: altering any past entry breaks every subsequent hash link.

**Memory analysis** (`volatility_symbols.py:1139-1152`): `status`, `analysis_status`, `analysis_completed`, `completed_plugins`, `failed_plugins`, `partial_findings`, `limitations`, `tools_used`, `tool_versions`, `input_artifacts`, `output_files`, `selected_symbol` (blocked variant adds `reason: "missing_linux_symbols"`, `blocking_errors`, `symbols_required`, `symbols_found`). **Exact Volatility3 plugins invoked** (`VOL3_PLUGIN_SPECS`, `:25-32`): `banners.Banners`, `linux.pslist.PsList`, `linux.lsmod.Lsmod`, `linux.sockstat.Sockstat`, `linux.check_syscall.Check_syscall`, `linux.bash.Bash` — invoked as `vol -s <symbol_root> -f <dump_path> <plugin_name>`. Symbol-resolution enum (`resolve_status`): `symbol_available` / `symbol_ambiguous` / `symbol_missing`. Job enum (`status`): `queued` / `running` / `completed` / `failed` / `blocked`.

**Disk analysis**: real TSK (The Sleuth Kit) commands invoked — `mmls` (partition layout), `fsstat` (filesystem stats), `fls -r -m ... -o "$off"` (recursive file listing with mactime-compatible output), `mactime -b ... -d -y` (MAC-time timeline generation), `icat -o "$off"` (extracts `auth.log`, `bash_history_ubuntu`, `passwd` by inode), `strings -a -n 8` (string carving, min length 8). `disk_findings.json` keys: `phase`, `status`, `input_artifacts`, `tool_used: "sleuthkit"`, `findings.results[]` (`disk_image`, `command`, `exit_code`, `stdout_path`, `stderr_path`, `output_dir`, `produced_files`).

**Network/pcap metadata** (`traffic_api.py`): `vm_id`, `run_id`, `port_id`, `vm_ips`, `iface`, `bpf` (the actual BPF capture filter applied), `protos`, `start_epoch`/`end_epoch`, `pcap_file`, `packets_written`, `termination_reason` (enum: `fixed_duration_elapsed`, `sniffer_stopped_unexpectedly`, ...), `ot_modbus_packets_502_seen`, `ot_modbus_records_exported`.

**Report summary** (`forensics_report_api.py:474-499`): `case_id`, `case_status` (`active`/`stored`), `summary: {artifact_count, total_size_bytes, hashed_count, missing_hash_count, custody_entries, primary_count, derived_count, type_distribution}`, `manifest_overview: {scenario_name, created_at, acquisition_start, acquisition_end, manifest_hash, case_digest_hash, time_sync_max_offset_ms}`.

> **Important finding**: there is **no literal "integrity ratio" field** anywhere in the backend — only the raw counts `hashed_count` and `missing_hash_count` are computed (`:450-458`); no division happens server-side. Any "integrity %" shown by a view is either computed client-side from these two counts, or — for the FOC module specifically — is a *different*, already-computed ratio (`case_wide_integrity_ratio`, see §7.3). These two ratios are not interchangeable and documentation/UI copy should not conflate them.

**Pipeline events** (`metadata/pipeline_events.jsonl`, append-only, `_append_case_event:990-998`): `ts_utc`, `ts_epoch`, `event`, `run_id`, `meta`.

### 7.2 `node_health.html` — measurement methodology

Every measurement in this view is taken by SSHing into the lab node and running a shell script (`probe_node_health_inside_node.sh`) — **there is no Python monitoring agent on the nodes themselves**. Exact commands:

| Metric | Real command executed on the remote node |
|---|---|
| CPU usage | `top -bn1`, idle % parsed via `awk`, `usage = 100 - idle` |
| Memory | `free -m` (`Mem:` row → total/used/available) |
| Swap | `free -m` (`Swap:` row) |
| Disk (root) | `df -P -B1 /` (bytes) + `df -Pi /` (inode %) |
| Load average | `cat /proc/loadavg` |
| Directory sizes | `du -sb /var/log`, `/var/log/suricata`, `/tmp`, `/var/tmp`, `/var/cache/apt` |
| Installed security tools | `dpkg-query -W -f='${Status}'` for suricata/wazuh-agent/wazuh-manager/zeek/snort; `command -v` for nmap/mbpoll; directory/unit-file existence checks for caldera/caldera-agent |
| Service state | `systemctl is-active <service>` |
| Top processes | `ps -eo pid,comm,%cpu,%mem --sort=-%cpu|--sort=-%mem \| head -n 8` — returned as **raw unparsed text lines** (the backend does not tokenize `pid`/`comm`/`%cpu`/`%mem` into a JSON object; the frontend must split the whitespace-delimited columns itself) |

Severity thresholds applied server-side (`severity()`, `:569-576`): `>=95%` → `critical`, `>=85%` → `warning`, else `ok`.

**Time synchronization** is the most scientifically load-bearing measurement on this page, because forensic timestamp ordering depends on it. Primary method (`measure_offset_chrony()`): SSH-run `chronyc tracking | grep '^System time'` on the node and parse the offset chrony itself reports against NTP (the script does **not** independently query an NTP server — it trusts the node's own already-synced chrony daemon). Fallback (`measure_offset_fallback()`, used only if chrony is absent): a manual round-trip estimate — `host_before = local time()`, SSH to remote, read `remote_epoch_seconds()`, `host_after = local time()`, then `midpoint = (host_before+host_after)/2`, `offset_ms = (remote_epoch - midpoint) * 1000`, with `jitter_ms = (host_after - host_before) * 1000` reported as the round-trip-induced measurement uncertainty. Classification thresholds (`summarize()`): `synchronized` if `max_offset_ms <= 1000`, `degraded` if `<= 5000`, else `not_synchronized`.

**Policy gate on the "fix" action**: if a forensic case is currently active (read from `_active_case.txt`) and the operator requests a clock correction without `maintenance_override=True`, the fix is **blocked** (HTTP 409, `policy_state: "blocked_active_case"`) — because forcibly stepping the clock on a node that's mid-acquisition would corrupt the temporal ordering of evidence already being collected. When a fix does run, it executes `chronyc -a makestep` (a hard, instantaneous clock step — not a gradual slew) then restarts chrony, and journals the before/after offsets as an "intervention" record into `time_sync_interventions.jsonl`.

**Cleanup action safety boundary** (`pre_memory_cleanup_inside_node.sh`): operates only on `/var/lib/apt`, `/var/cache/apt`, `/var/log` (deletes `.gz`/rotated logs, truncates oversized live logs in place rather than deleting them), and `/tmp` — explicitly **excluding** `/tmp/LiME` (the memory-acquisition tool's working directory) from deletion. It never touches the controller's own evidence store or any case directory, since those live on a different filesystem than the node being cleaned.

### 7.3 FOC views — the causal/uncertainty model

This is the most rigorous part of the platform; the code deliberately separates three independent axes so that a high "execution progress" can never be read as a strong scientific conclusion (`status_model.py`, comment at the top of the file states this explicitly):

| Axis | Enum values | Meaning |
|---|---|---|
| `execution_status` | `not_started` / `running` / `completed` / `failed` | did the reconstruction job run to completion technically |
| `reconstruction_state` | `not_available` / `blocked` / `completed` / `completed_with_degradation` / `weak_reconstruction` / `failed` | how complete/clean the resulting causal graph is |
| `scientific_confidence` | `strong` / `limited` / `weak` / `ambiguous` / `unknown` | how much interpretive weight the result can actually carry |

`scientific_confidence` derivation (`status_model.py`, the `execution_phase == "ran"` branch): `unknown` if ground truth isn't `ok`; `ambiguous` if `ambiguous_edge_rate > 0.20`; `weak` if causal-path-recoverability (CPR) `< 0.25`; `limited` if `CPR < 0.80` OR integrity is `partial` OR the temporal state isn't `strong`; otherwise `strong`. This means a graph can have 100% of edges recovered and still be capped at `limited` confidence purely because clocks weren't synchronized or hashes weren't fully verified — confidence is a conjunction of recoverability, integrity, *and* temporal soundness, not recoverability alone.

**Causal graph edge schema** (`reports/writer.py:59-75`, one record per edge): `edge_id`, `meaning` (plain-language description of what the edge claims), `relation_type`, `support_status` (enum: `recovered` / `degraded` / `ambiguous` / `missing`), `confidence`, `temporal_status` (enum: `supported` / `ambiguous` / `contradicted` / `unknown` / `not_required`), `semantic_status`, `integrity_status`, `status_reason`, `required_evidence` (list), `evidence_refs` (list), `missing_evidence` (list), `limitations` (list).

**Reconstruction metrics formula** (`service.py:_metrics_from_edges`, `:529-613`) — the actual arithmetic behind "causal path recoverability":
- `causal_path_recoverability (CPR) = recovered_edges / expected_edges`
- `weighted_cpr = recovered_weight / total_weight` (per-edge weights come from the scenario's declared `ground_truth.expected_edges`, so not every edge counts equally)
- `evidence_completeness_ratio = recovered_expected_artifact_types / expected_artifacts`
- `reconstruction_confidence` (a single composite score, `0.0`-`1.0`) is a weighted sum: `+0.45 × weighted_cpr +0.20 × evidence_completeness_ratio +0.20 × integrity_verification_ratio +0.15 × analysis_coverage_ratio −0.08 × degraded_edge_rate −0.12 × ambiguous_edge_rate − temporal_penalty`, where `temporal_penalty` is `0.0/0.05/0.12/0.15` for `strong/limited/ambiguous/unknown` temporal state respectively. This is an explicit, auditable formula — not a black-box score.
- `recoverability_label` thresholds: `≥0.80` → `mostly_recoverable`, `≥0.50` → `partially_recoverable`, `≥0.25` → `weak_recoverability`, else `low_recoverability`.

**Temporal/clock model** (`uncertainty/budget.py`, added/extended this session) — four independent fields that together justify the platform's temporal confidence claims, rather than one opaque flag:
- `node_clock_synchronization_status` — derived from measured inter-node clock offset (this is the SAME offset measured by `node_health.html`'s time-sync feature, read from a shared source — confirming the two views are scientifically consistent rather than independently re-measuring).
- `evidence_timestamp_availability` / `evidence_timestamp_resolvability` — whether each evidence layer even *has* timestamps, and whether those timestamps are precise enough to resolve event ordering.
- `causal_temporal_ordering_confidence` (enum: `strong`/`limited`/`ambiguous`/`unknown`) — the actual value used by the reconstruction-confidence formula above; computed by taking the **weakest** of the three preceding signals (`limiting_factor` field records which one specifically dragged the confidence down — clock sync, timestamp availability, or timestamp resolvability — so the UI can explain *why*, not just *that*, temporal confidence is limited).

**Integrity model**: `case_wide_integrity_ratio = hash_validated / manifest_total` (distinct from `forensics_report_api`'s unratioed counts, see §7.1 caveat); `graph_artifact_integrity_status` (`verified`/`partial`, whether every artifact actually *used* by the graph was hash-verified) is tracked **separately** from `case_wide_integrity_status` (`verified`/`partial`, whether the *entire* case's artifacts are hash-verified, including ones the graph never touched) — a case can have a fully verified graph while still being globally "partial" if unrelated artifacts elsewhere weren't hashed, and the code keeps these two from collapsing into one misleading flag.

**Evidence atom schema** (`evidence_support/atoms.py:39-59`, one record per triaged fact across all 8 layers): `atom_id`, `case_id`, `evidence_layer`, `source_artifact`, `source_artifact_hash`, `node`, `node_role`, `ip_address`, `timestamp`, `timestamp_status` (enum: `precise`/`approximate`/`unavailable`/`not_resolvable`), `event_type`, `observed_entity`, `observed_value`, `extraction_method`, `relation_to_hypothesis`, `support_direction` (enum: `supports`/`partially_supports`/`contradicts`/`neutral`/`not_evaluable`), `support_strength` (enum: `strong`/`moderate`/`weak`/`indirect`/`unavailable`), `limitation`, `raw_reference` (list of source pointers, for traceability back to the exact preserved artifact).

**Cross-layer classification** (`evidence_support/correlation.py`) — per causal-graph edge, atoms are routed by explicit `event_type`→edge and `node`→edge mappings (not generic layer bucketing) and classified as one of: `confirmed_by_multiple_layers` (≥2 distinct layers support it, none contradict) / `supported_by_single_layer` / `partially_supported` / `inferred` / `contradicted` / `not_evaluable`, with a separate `temporally_unresolved` flag when every contributing atom's `timestamp_status` is `unavailable`/`not_resolvable`.

**Global support level hard rule** (`compute_global_support_level`): `strong_support` requires **≥2** `confirmed_by_multiple_layers` relations AND zero contradicted AND zero temporally-unresolved AND no atom anywhere with `support_direction="contradicts"`. Full `contradicted` requires every evaluable relation to be contradicted with none confirmed. Everything in between is `moderate_support` or `weak_support`. This hard rule is what currently keeps the platform's real test case capped at `moderate_support` rather than `strong_support`, despite having confirmed protocol-level evidence — because a small number of edge-specific contradictions (precision-level caveats, not full rejections) exist elsewhere in the graph.

### 7.4 Detection dashboards (`dashboard.html`, `dashboard_especial.html`) — alert and attack schemas

**Wazuh alert ingestion**: there is **no direct Wazuh API/Elasticsearch query** anywhere in this path. The live stream (`monitor/ssh_launcher.py`) runs a shell script over SSH that tails Wazuh's own local alert output on the monitor node; lines tagged `"NICS_ALERT_JSON"` are parsed into a normalized event (`event_id`, `ts_utc`, `source`, `alert_type`, `protocol`, `rule_id`, `rule_level`, `description`, `signature`, `src{}`, `dst{}`, `agent`, `raw`) and persisted to `alerts.jsonl`.

**Severity scoring** (`monitor/alerts_logger.py:compute_severity`, `:79-170`) is a deterministic, auditable rule, not an ML score: Wazuh `rule_level` `≥12` → `CRITICAL`, `≥7` → `HIGH`, `≥5` → `MEDIUM`, else `LOW`; `recommend_forensics=True` once level `≥10`. **Explicit override**: any Suricata signature ID `910836101`–`910836104` (Modbus register/coil write signatures) or signature text containing `"modbus write"` forces `severity=HIGH, recommend_forensics=True` *regardless of the numeric level* — this is the concrete rule that ties a single OT-specific signature family directly to the acquisition-trigger logic referenced elsewhere in the FOC module.

**Attack catalog → MITRE mapping** (`attack/catalog.py`), confirmed real technique IDs and their executed scripts:

| MITRE ID | Technique | Script | Backend |
|---|---|---|---|
| T1595 | Active Scanning (ICMP recon) | `ping_target.sh` | remote (SSH) |
| T1046 | Network Service Discovery (port scan) | `port_scan_recon.sh` | remote |
| T1110.001 | SSH Password Guessing | `unauthorized_ssh_attempt.sh` | remote |
| T1565.001 | Stored Data Manipulation (FIM trigger) | `file_tamper_sim.sh` | remote |
| T1048 | Exfiltration over Alternative Protocol | `data_exfiltration.sh` | remote |
| T0831 | Manipulation of Control (Modbus) | `t0831_manipulation_of_control_modbus.py` | **local** (runs on the platform server itself, not over SSH) |

Each catalog entry also carries `detection_engine` (e.g. `"Suricata + Wazuh"`), `severity`, `execution_mode` (`controlled`/`detection_validation`/`restore_by_default`/`controlled_chain`/`read_only`/`simulated`), `expected_alerts`, `expected_artifacts`, `rollback_required`, `dfir_escalation` — i.e. every attack is pre-annotated with what it *should* trigger downstream, which is what lets the FOC module later check whether the actual detections matched the declared expectation.

**Persisted execution result** (`attack/executor.py:build_execution_result`): includes a `chain_of_custody` list (`timestamp`, `action`, `operator: "dashboard_tactical_hud"`, `artifact`) attached to the attack's own result file — meaning attack executions carry their own lightweight custody trail from the moment of launch, before any forensic acquisition even starts.

> **Known bugs surfaced while extracting these schemas** (documented here since they directly affect data reliability, not just code style): (1) `GET /api/instance_roles` is implemented **twice** with two different role enums (`app_core/presentation/api.py` — 4 roles, name-substring match — vs. `host_tools_endpoints.py` under `/api/host/instance_roles` — 6 roles including `scada`/`plc`); the two should not be assumed interchangeable. (2) `app_core/main.py` imports a `dashboard_f35` symbol that doesn't exist in `dashboard_F35.py` (only `hud_bp` is defined there); the surrounding bare `except: pass` swallows the resulting `ImportError`, meaning `GET /api/hud/instances`/`POST /api/hud/action` as coded in that file may not actually be the route Flask serves for those paths — worth a direct check before relying on `ot_gui.html`'s topology graph as a precise reflection of `dashboard_F35.py`.
