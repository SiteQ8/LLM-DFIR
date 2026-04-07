<div align="center">

# 🔍 LLM-DFIR

### Forensics for the LLM Era

[![SANS](https://img.shields.io/badge/SANS-DFIR_Summit-aa66ff?style=flat-square)]()
[![Artifacts](https://img.shields.io/badge/15-Artifact_Types-00ff88?style=flat-square)]()
[![Platforms](https://img.shields.io/badge/Win/Mac/Linux-00d4ff?style=flat-square)]()
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-gold?style=flat-square)]()

**Live Reference:** [siteq8.github.io/LLM-DFIR](https://siteq8.github.io/LLM-DFIR)

A reference taxonomy of LLM-era forensic artifacts, a working triage script, and incident response playbooks for Copilot, Cursor, Claude Code, MCP servers, browser AI assistants, vector DBs, and more.

</div>

---

## 🎯 The Problem

When an LLM-related incident happens — prompt injection, data leakage, supply-chain compromise via AI-generated code — traditional DFIR tools miss most of the evidence. EDR sees the process. SIEM sees the network connection. But neither captures:

- **MCP server transcripts** showing every tool call an AI agent made
- **IDE plugin SQLite databases** containing chat history and file context
- **Vector DB query logs** revealing what was indexed for RAG
- **Embedding caches** with the actual prompts
- **Browser-cached AI conversations** in IndexedDB and LevelDB

This repo gives you the artifact taxonomy, triage tooling, and incident playbooks to investigate LLM-era incidents.

---

## 🚀 Quick Start

```bash
git clone https://github.com/SiteQ8/LLM-DFIR.git
cd LLM-DFIR

# Run triage on the current host
python3 scripts/llm_triage.py --output ./evidence

# List all 15 artifact types
python3 scripts/llm_triage.py --list-artifacts

# Skip content scanning (faster, no IOC detection)
python3 scripts/llm_triage.py --no-content
```

**Outputs:**
- `evidence/timeline.json` — Sorted forensic timeline (Plaso/Timesketch ready)
- `evidence/evidence_inventory.csv` — Full artifact inventory with SHA-256
- `evidence/iocs.json` — Detected IOCs (API keys, prompt injection, exfil patterns)
- `evidence/report.html` — Standalone HTML report

---

## 📦 What's Inside

### `/scripts/llm_triage.py` — Triage Tool (685 lines)
Walks 15 artifact paths across Windows/macOS/Linux, hashes files, scans content for IOCs, generates timeline + inventory + IOC report + HTML output. Single Python file, no dependencies.

### `/taxonomy/ARTIFACTS.md` — Reference Taxonomy
Comprehensive reference for all 15 artifact types with file paths, parsing tips, and evidence value notes.

### `/playbooks/` — Incident Response Playbooks
- **01-prompt-injection.md** — Direct + indirect prompt injection
- **02-data-leakage.md** — Sensitive data leakage to third-party models
- **03-supply-chain.md** — Supply-chain compromise via AI-generated code

Each playbook includes: indicators, triage steps, containment actions, future detection.

### `/docs/` — Investigator GUI
Live web reference with full taxonomy, playbooks, detection gaps, and logging baseline.

---

## 🗃️ Artifact Categories

| Category | Tools Tracked |
|----------|---------------|
| **IDE Plugin** | GitHub Copilot, Cursor, Claude Code, Codeium/Windsurf |
| **MCP** | Claude Desktop config, MCP server logs |
| **Browser AI** | Chrome/Edge/Brave LevelDB, Firefox IndexedDB |
| **API Client** | OpenAI SDK, Anthropic SDK, Azure OpenAI |
| **Vector DB** | ChromaDB, FAISS index files |
| **Model Cache** | HuggingFace cache |
| **Agent Framework** | LangChain trace cache |
| **Local LLM** | Ollama logs and history |
| **Shell History** | bash, zsh, fish, PowerShell |

---

## 🎯 IOC Detection

The triage script content-scans files under 5MB for:

**API Keys:** `sk-*`, `sk-ant-*`, `AIza*`, `pcsk_*`, `hf_*`

**API Endpoints:** `api.openai.com`, `api.anthropic.com`, `*.openai.azure.com`, `generativelanguage.googleapis.com`

**Prompt Injection:** "ignore previous instructions", ChatML delimiters, jailbreak terms, code execution patterns

**Data Exfil:** password/secret/token keywords, BEGIN PRIVATE KEY, SSN regex, credit card regex

---

## ⚠️ Detection Gaps in Current EDR/SIEM

1. **MCP Server JSON-RPC traffic** — Application-layer, missed by network EDR
2. **IDE Plugin Telemetry** — No mainstream EDR captures Copilot/Cursor SQLite
3. **LLM API Request Bodies** — TLS metadata only; prompt content invisible
4. **Vector DB Queries** — No native EDR integration
5. **Embedding Cache Operations** — File hooks miss semantic content
6. **LLM Tool-Use Traces** — Application logs, not OS events
7. **Local LLM Activity (Ollama)** — Zero outbound traffic, zero cloud detection

---

## 📡 Minimal Logging Baseline

If you do nothing else, enable these 7 controls:

1. Network: TLS to LLM API endpoints
2. Network: Inference hosts (HuggingFace, Replicate, Together)
3. Process: LLM tool process names
4. File: MCP config changes (`claude_desktop_config.json`)
5. File: AI tool state directories (`~/.claude/`, `~/.cursor/`, etc.)
6. Process: Command lines with `--api-key`, `OPENAI_API_KEY`, `npx @modelcontextprotocol`
7. DNS: AI service lookups

See the [Logging Baseline](https://siteq8.github.io/LLM-DFIR/#b) tab in the GUI for implementation snippets (Sysmon, auditd, osquery, Suricata).

---

## 👤 Author

**Ali AlEnezi** · [@SiteQ8](https://github.com/SiteQ8) · [3li.info](https://3li.info)

Security Architecture Principal · National Bank of Kuwait (NBK Group) 🇰🇼

GPEN · GWEB · GDSA · GICSP · GCCC · CMU CISO · PCI DSS Professional · ISO 27001 LI

---

## ⚠️ Legal

This tool is for **authorized incident response only**. Always obtain proper authorization before running forensic collection on systems you do not own. The triage script reads files from the user's home directory and may capture sensitive content.
