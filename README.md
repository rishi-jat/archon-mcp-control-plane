# ARCHON — Autonomous Repository Control & Hardening Operations Network

> **An MCP-native autonomous operational control system built on [Archestra](https://archestra.ai)**
>
> 🏆 Built for the *2 Fast 2 MCP* Hackathon by WeMakeDevs

<p align="center">
  <a href="https://archon-dashboard.onrender.com/"><img src="https://img.shields.io/badge/🚀_Live_Demo-archon--dashboard.onrender.com-00d4ff?style=for-the-badge" alt="Live Demo"></a>
  <a href="https://www.youtube.com/watch?v=xKhBVqppKok"><img src="https://img.shields.io/badge/▶_Demo_Video-YouTube-FF0000?style=for-the-badge&logo=youtube" alt="YouTube Demo"></a>
  <a href="https://www.linkedin.com/posts/rishi-jat_built-archon-autonomous-repository-control-activity-7429130078292439040-a8xu"><img src="https://img.shields.io/badge/📝_Post-LinkedIn-0A66C2?style=for-the-badge&logo=linkedin" alt="LinkedIn Post"></a>
</p>

---

### Live Dashboard

<p align="center">
  <a href="https://archon-dashboard.onrender.com/">
    <img src="assets/dashboard-screenshot.png" alt="ARCHON Command Center Dashboard" width="900">
  </a>
</p>

<p align="center"><em>Real-time command center — type any GitHub repo and watch ARCHON analyze it live</em></p>

| | |
|---|---|
| 🚀 **Live Demo** | [archon-dashboard.onrender.com](https://archon-dashboard.onrender.com/) |
| 🎬 **Demo Video** | [Watch on YouTube](https://www.youtube.com/watch?v=xKhBVqppKok) |
| 💼 **LinkedIn** | [Project Post](https://www.linkedin.com/posts/rishi-jat_built-archon-autonomous-repository-control-activity-7429130078292439040-a8xu) |

---

## What is ARCHON?

ARCHON is a **self-orchestrating AI agent swarm** that continuously monitors GitHub repositories for security vulnerabilities, operational risks, and code quality issues — then **automatically takes action** by creating issues, generating reports, and escalating findings.

It demonstrates every major capability of the Archestra platform:

| Archestra Feature | How ARCHON Uses It |
|-------------------|--------------------|
| **MCP Registry** | 3 custom MCP servers registered and managed |
| **K8s Orchestrator** | Servers run as Docker containers via stdio transport |
| **Agent Delegation (A2A)** | Orchestrator delegates to analysis sub-agent for deep investigation |
| **Knowledge Graph (GraphRAG)** | Security playbook + incident response procedures loaded as RAG context |
| **Dual LLM Security** | All tool inputs/outputs validated by Archestra's security sub-agents |
| **OTEL Observability** | Every action logged with structured audit entries |
| **Cost Controls** | Agent configured with appropriate token limits |
| **Chat UI** | Users interact through Archestra's ChatGPT-style interface |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ARCHESTRA PLATFORM                        │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              ARCHON ORCHESTRATOR AGENT                │   │
│  │                                                      │   │
│  │   Signal ──▶ Correlate ──▶ Decide ──▶ Act            │   │
│  │     │              │           │          │          │   │
│  │     ▼              ▼           ▼          ▼          │   │
│  │  ┌──────┐   ┌──────────┐  ┌───────┐  ┌────────┐    │   │
│  │  │Gather│   │Cross-ref │  │ Risk  │  │Execute │    │   │
│  │  │Signals│   │& Weight  │  │Matrix │  │Actions │    │   │
│  │  └──────┘   └──────────┘  └───────┘  └────────┘    │   │
│  │     ▲                         │                      │   │
│  │     │              ┌──────────┘                      │   │
│  │     │              ▼ (A2A delegation)                │   │
│  │     │       ┌─────────────────┐                      │   │
│  │     │       │ Analysis Agent  │                      │   │
│  │     │       │ (sub-agent)     │                      │   │
│  │     │       └─────────────────┘                      │   │
│  └─────┼────────────────────────────────────────────────┘   │
│        │                                                     │
│  ┌─────┴───────────────────────────────────────────┐        │
│  │              MCP SERVER LAYER                    │        │
│  │                                                  │        │
│  │  ┌────────────┐ ┌───────────┐ ┌───────────┐    │        │
│  │  │ repo-intel │ │ security  │ │  actions   │    │        │
│  │  │            │ │           │ │            │    │        │
│  │  │• Commits   │ │• CVE/NVD  │ │• Issues    │    │        │
│  │  │• PRs       │ │• Deps     │ │• Reports   │    │        │
│  │  │• Health    │ │• Secrets  │ │• Audit Log │    │        │
│  │  │• Overview  │ │• Reports  │ │            │    │        │
│  │  └──────┬─────┘ └─────┬─────┘ └─────┬─────┘    │        │
│  └─────────┼─────────────┼─────────────┼──────────┘        │
│            │             │             │                     │
│  ┌─────────┼─────────────┼─────────────┼──────────┐        │
│  │         ▼             ▼             ▼          │        │
│  │    ┌─────────┐  ┌──────────┐  ┌──────────┐    │        │
│  │    │ GitHub  │  │ NIST NVD │  │  GitHub   │    │        │
│  │    │ REST API│  │ CVE API  │  │ REST API  │    │        │
│  │    └─────────┘  └──────────┘  └──────────┘    │        │
│  │              EXTERNAL APIs                     │        │
│  └────────────────────────────────────────────────┘        │
│                                                             │
│  ┌────────────────────────────────┐                         │
│  │       KNOWLEDGE GRAPH          │                         │
│  │  • security-playbook.md        │                         │
│  │  • incident-response.md        │                         │
│  └────────────────────────────────┘                         │
└─────────────────────────────────────────────────────────────┘
```

---

## Live Dashboard

ARCHON ships with a **real-time command-center dashboard** that visualizes the entire analysis pipeline as it runs:

- **Animated workflow pipeline** — Signal → Correlate → Decide → Act phases light up in real-time
- **Health score ring** — SVG gauge that draws itself, color-coded by grade
- **Risk cards** — commit, PR, and security risk levels with live updates
- **Streaming findings feed** — CVEs, secrets, and risky patterns appear as they're detected
- **Actions & decisions** — see the AI's reasoning and generated reports
- **Full Markdown reports** — security audit and operational status reports rendered in-browser

The dashboard uses **Server-Sent Events (SSE)** to stream every phase of the analysis from the FastAPI backend, giving judges (and users) a visual "mission control" experience.

```bash
cd dashboard && pip install -r requirements.txt && python api.py
# Open http://localhost:8501
```

---

## MCP Servers

### `archon-repo-intel` — Repository Intelligence

Connects to the **GitHub REST API** to analyze repository activity patterns.

| Tool | Description |
|------|-------------|
| `analyze_recent_commits` | Fetches recent commits and scores each for risk (sensitive files, large diffs, vague messages, off-hours activity) |
| `analyze_pull_requests` | Analyzes open PRs for staleness, size, review coverage, and sensitive file exposure |
| `get_repository_health` | Composite health score (0-100) across 6 dimensions: community, activity, issues, CI/CD, security, contributors |
| `get_repository_overview` | Repository metadata snapshot (languages, size, stars, forks, open issues) |

### `archon-security` — Security Scanner

Connects to the **NIST National Vulnerability Database (NVD) API** and performs code analysis.

| Tool | Description |
|------|-------------|
| `scan_dependencies` | Parses dependency manifests (pip, npm, Go, Cargo) and checks each package against NVD for known CVEs |
| `scan_for_secrets` | 12 regex patterns + Shannon entropy analysis to detect leaked credentials in source code |
| `lookup_cve` | Deep-dive into a single CVE — CVSS score, attack vector, affected versions, references |
| `generate_security_report` | Aggregates all findings into a scored risk report with severity distribution |

### `archon-actions` — Action Executor

Executes remediation actions through the **GitHub API** and structured report generation.

| Tool | Description |
|------|-------------|
| `create_security_issue` | Creates a formatted GitHub issue for security findings with severity labels |
| `create_incident_issue` | Creates an incident tracking issue with timeline, affected components, and action checkboxes |
| `generate_security_report` | Produces a comprehensive Markdown security audit report |
| `generate_operational_report` | Combines all signals into a unified operational status document |
| `log_action` | Structured audit log entry for every ARCHON action (feeds into OTEL) |

---

## Agents

### Orchestrator Agent

The main agent that drives the **Signal → Correlate → Decide → Act** workflow:

1. **Signal Collection** — Calls repo-intel and security tools concurrently
2. **Correlation** — Cross-references commit patterns with security findings
3. **Decision** — Applies risk matrix to determine severity and required actions
4. **Action** — Creates issues, generates reports, logs everything

### Analysis Sub-Agent (A2A)

A specialist agent invoked via Archestra's **Agent-to-Agent delegation** when the orchestrator needs deeper analysis:

- Severity classification with confidence scoring
- Pattern recognition (supply-chain attack, credential exposure, config drift)
- Ecosystem-specific risk assessment (npm vs pip vs Go)
- Returns structured JSON recommendations

---

## Quick Start

### Prerequisites

- Docker
- A GitHub personal access token (optional, for higher API rate limits)

### One-Command Setup

```bash
# Clone the repo
git clone https://github.com/your-org/archon.git
cd archon

# Set your tokens (optional but recommended)
export GITHUB_TOKEN=ghp_your_token_here
export NVD_API_KEY=your_nvd_key_here  # from https://nvd.nist.gov/developers/request-an-api-key

# Run setup — starts Archestra, builds servers, registers everything
chmod +x setup.sh && ./setup.sh
```

### What the Setup Script Does

1. **Starts Archestra** platform (Docker, ports 9000 + 3000)
2. **Builds** 3 MCP server Docker images
3. **Registers** servers with Archestra's MCP Registry
4. **Uploads** knowledge base documents to the Knowledge Graph
5. **Creates** the orchestrator agent with MCP server + KB bindings
6. **Creates** the analysis sub-agent for A2A delegation

### Demo

Open the Archestra chat UI at `http://localhost:3000` and try:

```
Analyze the security posture of facebook/react
```

ARCHON will:
1. Gather repository intelligence (commits, PRs, health)
2. Scan dependencies for CVEs
3. Scan code for leaked secrets
4. Correlate all findings
5. Generate a security report and operational report
6. Create GitHub issues for any critical/high findings
7. Log every action for audit

---

## Project Structure

```
archon/
├── mcp-servers/
│   ├── repo-intel/          # Repository intelligence MCP server
│   │   ├── server.py        # FastMCP entry point (4 tools)
│   │   ├── github_client.py # Async GitHub REST API client
│   │   ├── commit_analyzer.py
│   │   ├── pr_analyzer.py
│   │   ├── health_analyzer.py
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   │
│   ├── security/            # Security scanning MCP server
│   │   ├── server.py        # FastMCP entry point (4 tools)
│   │   ├── nvd_client.py    # NIST NVD 2.0 API client
│   │   ├── dependency_scanner.py
│   │   ├── secret_scanner.py
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   │
│   └── actions/             # Action execution MCP server
│       ├── server.py        # FastMCP entry point (5 tools)
│       ├── github_actions.py
│       ├── report_generator.py
│       ├── requirements.txt
│       └── Dockerfile
│
├── agent/
│   ├── orchestrator-prompt.md  # System prompt for main agent
│   └── analysis-agent-prompt.md # System prompt for A2A sub-agent
│
├── knowledge-base/
│   ├── security-playbook.md    # Security policies & SLAs
│   └── incident-response.md   # Incident response procedures
│
├── dashboard/
│   ├── api.py               # FastAPI backend (SSE streaming)
│   ├── requirements.txt
│   └── static/
│       ├── index.html        # Command-center dashboard
│       ├── css/styles.css    # Dark theme + animations
│       └── js/app.js         # Real-time SSE client
│
├── setup.sh                 # One-command deployment script
└── README.md
```

---

## Real APIs — No Mocks

Every data source in ARCHON is real:

| Source | API | Auth |
|--------|-----|------|
| GitHub Repository Data | [REST API v3](https://docs.github.com/en/rest) | `GITHUB_TOKEN` (optional, 60 req/hr without) |
| CVE / Vulnerability Data | [NIST NVD 2.0](https://nvd.nist.gov/developers/vulnerabilities) | `NVD_API_KEY` (optional, 5 req/30s without) |
| GitHub Issue Creation | [REST API v3](https://docs.github.com/en/rest/issues) | `GITHUB_TOKEN` (required for write operations) |

---

## Archestra Features Demonstrated

### 1. Private MCP Registry
All three servers are registered in Archestra's internal registry, not the public npm/pip one. This demonstrates enterprise-grade MCP server management.

### 2. K8s Orchestrator
Servers run as Docker containers with stdio transport, managed by Archestra's Kubernetes orchestrator. Each server is isolated with its own resource limits.

### 3. Agent-to-Agent Delegation (A2A)
The orchestrator uses the `agent__analysis` prefix to invoke the analysis sub-agent when findings are ambiguous. This showcases Archestra's A2A protocol for task decomposition.

### 4. Knowledge Graph (GraphRAG)
The security playbook and incident response procedures are loaded as knowledge base documents. The orchestrator queries them through Archestra's RAG pipeline for policy-aware decisions.

### 5. Dual LLM Security Sub-Agents
Archestra's built-in security layer validates all tool inputs and outputs. ARCHON benefits from this without any additional code.

### 6. OTEL Observability
Every tool invocation is traced through Archestra's OpenTelemetry pipeline. The `log_action` tool adds application-level audit entries on top of platform telemetry.

### 7. Cost Controls
Both agents are configured with token limits and temperature settings appropriate for their roles (orchestrator: `temperature=0.2`, analysis: `temperature=0.1`).

---

## License

MIT

---

*Built with ❤️ for the 2 Fast 2 MCP Hackathon on [Archestra](https://archestra.ai)*
