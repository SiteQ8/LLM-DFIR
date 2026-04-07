<div align="center">

# 🔍 LLM-DFIR

### AI Forensics Collection Toolkit

[![Tools](https://img.shields.io/badge/15-Artifact_Types-39d0a8?style=flat-square)]()
[![Platforms](https://img.shields.io/badge/Win/Mac/Linux-5fa8ff?style=flat-square)]()
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square)]()
[![License](https://img.shields.io/badge/License-MIT-gold?style=flat-square)]()

**Web Tool:** [siteq8.github.io/LLM-DFIR](https://siteq8.github.io/LLM-DFIR)

A working DFIR toolkit for collecting and analyzing forensic artifacts from LLM-based tools — Copilot, Cursor, Claude Code, MCP servers, browser AI assistants, vector databases, and local LLM runtimes.

</div>

---

## What This Is

A two-part toolkit:

1. **`scripts/llm_triage.py`** — A Python collection script that walks 15 artifact paths across Windows, macOS, and Linux, hashes everything for chain of custody, scans content for IOCs, and produces timeline + inventory + IOC report files.

2. **Web tool (`docs/index.html`)** — An interactive analyst workbench. Drop the triage output files in and review them. Filter artifacts. Sort timelines. Triage IOCs. Generate collection commands. Look up paths. Test IOC patterns. Reference the artifact catalog.

Everything runs locally. The web tool is a single static HTML file — no backend, no upload, no telemetry.

---

## Quick Start

```bash
# 1. Run the collection script on a target host
git clone https://github.com/SiteQ8/LLM-DFIR.git
cd LLM-DFIR
python3 scripts/llm_triage.py --output ./evidence

# 2. Open the web tool
open docs/index.html  # or just visit siteq8.github.io/LLM-DFIR

# 3. Drag the files from ./evidence/ into the Import tab
#    (timeline.json, iocs.json, evidence_inventory.csv)
```

---

## Web Tool Features

**Workspace**
- **Dashboard** — Stats overview, quick start, recent activity
- **Import Evidence** — Drag-drop triage output files for review (parsed entirely in browser)
- **Artifacts** — Sortable, filterable, searchable artifact table with detail panel
- **IOCs** — Severity and category filtered view of detected indicators
- **Timeline** — Forensic timeline visualization sorted by mtime

**Tools**
- **Command Builder** — Generate ready-to-run triage commands for target hosts with options
- **Path Lookup** — Paste any file path, identify which AI artifact category it belongs to
- **IOC Scanner** — Paste content, run live IOC pattern detection
- **Reference** — Browse all 15 artifact types with paths for each OS

**Operations**
- **Playbooks** — IR playbooks for prompt injection, data leakage, supply-chain compromise
- **Baseline** — 7-point minimum logging configuration

---

## Triage Script

Single Python file, no dependencies, works on Python 3.9+.

```bash
python3 scripts/llm_triage.py --help

  --output PATH       Output directory (default: ./triage_TIMESTAMP)
  --no-content        Skip content scanning (faster)
  --list-artifacts    List all 15 artifact categories
```

**Outputs:**
- `timeline.json` — Sorted forensic timeline (Plaso/Timesketch ready)
- `evidence_inventory.csv` — Full artifact inventory with SHA-256 hashes
- `iocs.json` — Files matching IOC patterns
- `report.html` — Standalone HTML report

**IOC patterns detected:**
- API keys (`sk-*`, `sk-ant-*`, `AIza*`, `pcsk_*`, `hf_*`)
- LLM API endpoints (OpenAI, Anthropic, Azure, Google, Mistral, Cohere)
- Prompt injection patterns (ChatML, jailbreaks, ignore-previous)
- Data exfil indicators (private keys, SSN, CC patterns, sensitive keywords)

---

## Artifacts Tracked

| Category | Tools |
|----------|-------|
| **IDE Plugin** | GitHub Copilot · Cursor · Claude Code · Codeium/Windsurf |
| **MCP** | Claude Desktop config · MCP server logs |
| **Browser AI** | Chrome/Edge LevelDB · Firefox IndexedDB |
| **API Client** | OpenAI SDK · Anthropic SDK |
| **Vector DB** | ChromaDB · FAISS |
| **Model Cache** | HuggingFace |
| **Agent Framework** | LangChain |
| **Local LLM** | Ollama |
| **Shell History** | bash, zsh, fish, PowerShell |

Full artifact reference with paths and parsing tips: [`taxonomy/ARTIFACTS.md`](taxonomy/ARTIFACTS.md)

---

## Author

**Ali AlEnezi** · [@SiteQ8](https://github.com/SiteQ8) · [3li.info](https://3li.info)
