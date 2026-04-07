#!/usr/bin/env python3
"""
LLM-DFIR Triage Tool
Collects LLM-era forensic artifacts from Windows, macOS, and Linux endpoints
into a single timeline-ready output.

Artifacts collected:
  • IDE plugin telemetry (GitHub Copilot, Cursor, Claude Code, Codeium)
  • MCP server transcripts and config
  • Browser-based AI assistant residue (ChatGPT, Claude, Gemini, Copilot)
  • API call logs (OpenAI, Anthropic, Google, Azure OpenAI)
  • Vector DB query history (Chroma, Pinecone, Weaviate, FAISS)
  • Embedding caches
  • Tool-use traces and agent execution logs
  • Shell history references to LLM tools

Output: JSON timeline + CSV evidence inventory + HTML report

Usage:
  python3 llm_triage.py [--output ./triage] [--no-content] [--json] [--html]

Author: Ali AlEnezi (@SiteQ8) — NBK Group
License: MIT — For authorized incident response only
"""

import os, sys, json, hashlib, platform, getpass, glob, csv, argparse, re
from datetime import datetime
from pathlib import Path

VERSION = "1.0"
BANNER = f"""
╔═══════════════════════════════════════════════════════════╗
║  LLM-DFIR Triage Tool v{VERSION}                                ║
║  Forensic collection for LLM-era artifacts                ║
║  Ali AlEnezi (@SiteQ8) — NBK Group                        ║
╚═══════════════════════════════════════════════════════════╝
"""

# ═══ ARTIFACT TAXONOMY ═══

ARTIFACT_LOCATIONS = {
    # ═══ IDE PLUGIN TELEMETRY ═══
    "github_copilot": {
        "category": "IDE Plugin",
        "tool": "GitHub Copilot",
        "windows": [
            r"%APPDATA%\Code\User\globalStorage\github.copilot",
            r"%APPDATA%\Code\User\globalStorage\github.copilot-chat",
            r"%APPDATA%\Code\logs\*\exthost*\GitHub.copilot*",
            r"%LOCALAPPDATA%\github-copilot",
            r"%USERPROFILE%\.config\github-copilot",
        ],
        "macos": [
            "~/Library/Application Support/Code/User/globalStorage/github.copilot",
            "~/Library/Application Support/Code/User/globalStorage/github.copilot-chat",
            "~/Library/Application Support/Code/logs/*/exthost*/GitHub.copilot*",
            "~/.config/github-copilot",
        ],
        "linux": [
            "~/.config/Code/User/globalStorage/github.copilot",
            "~/.config/Code/User/globalStorage/github.copilot-chat",
            "~/.config/Code/logs/*/exthost*/GitHub.copilot*",
            "~/.config/github-copilot",
        ],
        "files_of_interest": ["state.vscdb", "*.json", "*.log", "hosts.json"],
        "evidence_value": "Suggestion history, conversation logs, file context sent to model"
    },
    "cursor_ide": {
        "category": "IDE Plugin",
        "tool": "Cursor",
        "windows": [
            r"%APPDATA%\Cursor\User\globalStorage",
            r"%APPDATA%\Cursor\User\workspaceStorage",
            r"%APPDATA%\Cursor\logs",
            r"%APPDATA%\Cursor\Code Cache",
        ],
        "macos": [
            "~/Library/Application Support/Cursor/User/globalStorage",
            "~/Library/Application Support/Cursor/User/workspaceStorage",
            "~/Library/Application Support/Cursor/logs",
        ],
        "linux": [
            "~/.config/Cursor/User/globalStorage",
            "~/.config/Cursor/User/workspaceStorage",
            "~/.config/Cursor/logs",
        ],
        "files_of_interest": ["state.vscdb", "*.json", "*.log"],
        "evidence_value": "Chat history, codebase indexing data, model interactions"
    },
    "claude_code": {
        "category": "IDE Plugin",
        "tool": "Claude Code",
        "windows": [
            r"%USERPROFILE%\.claude",
            r"%APPDATA%\Claude",
            r"%LOCALAPPDATA%\claude-code",
        ],
        "macos": [
            "~/.claude",
            "~/Library/Application Support/Claude",
            "~/Library/Logs/Claude",
        ],
        "linux": [
            "~/.claude",
            "~/.config/claude",
        ],
        "files_of_interest": ["*.json", "*.jsonl", "*.log", "history*", "session*"],
        "evidence_value": "Tool use traces, file edits, bash commands executed by agent"
    },
    "codeium": {
        "category": "IDE Plugin",
        "tool": "Codeium / Windsurf",
        "windows": [
            r"%USERPROFILE%\.codeium",
            r"%APPDATA%\Windsurf",
            r"%APPDATA%\Code\User\globalStorage\codeium.codeium",
        ],
        "macos": [
            "~/.codeium",
            "~/Library/Application Support/Windsurf",
            "~/Library/Application Support/Code/User/globalStorage/codeium.codeium",
        ],
        "linux": [
            "~/.codeium",
            "~/.config/Windsurf",
            "~/.config/Code/User/globalStorage/codeium.codeium",
        ],
        "files_of_interest": ["*.json", "*.log", "language_server*"],
        "evidence_value": "Code completions, indexed repos, telemetry"
    },

    # ═══ MCP SERVER ARTIFACTS ═══
    "mcp_servers": {
        "category": "MCP",
        "tool": "Model Context Protocol",
        "windows": [
            r"%USERPROFILE%\.config\Claude\claude_desktop_config.json",
            r"%APPDATA%\Claude\claude_desktop_config.json",
            r"%APPDATA%\Claude\logs",
            r"%USERPROFILE%\.mcp",
        ],
        "macos": [
            "~/Library/Application Support/Claude/claude_desktop_config.json",
            "~/Library/Application Support/Claude/logs",
            "~/Library/Logs/Claude",
            "~/.mcp",
        ],
        "linux": [
            "~/.config/Claude/claude_desktop_config.json",
            "~/.config/Claude/logs",
            "~/.mcp",
        ],
        "files_of_interest": ["claude_desktop_config.json", "mcp-server-*.log", "*.jsonl"],
        "evidence_value": "MCP server config (which tools are available!), tool invocations, transcripts"
    },

    # ═══ BROWSER AI ASSISTANTS ═══
    "browser_ai_chrome": {
        "category": "Browser AI",
        "tool": "Chrome AI Extensions",
        "windows": [
            r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Storage\leveldb",
            r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\IndexedDB",
            r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions",
            r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Session Storage",
        ],
        "macos": [
            "~/Library/Application Support/Google/Chrome/Default/Local Storage/leveldb",
            "~/Library/Application Support/Google/Chrome/Default/IndexedDB",
            "~/Library/Application Support/Google/Chrome/Default/Extensions",
        ],
        "linux": [
            "~/.config/google-chrome/Default/Local Storage/leveldb",
            "~/.config/google-chrome/Default/IndexedDB",
            "~/.config/google-chrome/Default/Extensions",
        ],
        "files_of_interest": ["*.ldb", "*.log", "MANIFEST*"],
        "evidence_value": "ChatGPT/Claude/Gemini conversation cache, extension state, session data"
    },
    "browser_ai_firefox": {
        "category": "Browser AI",
        "tool": "Firefox AI",
        "windows": [
            r"%APPDATA%\Mozilla\Firefox\Profiles\*\storage\default",
            r"%APPDATA%\Mozilla\Firefox\Profiles\*\extensions",
        ],
        "macos": [
            "~/Library/Application Support/Firefox/Profiles/*/storage/default",
            "~/Library/Application Support/Firefox/Profiles/*/extensions",
        ],
        "linux": [
            "~/.mozilla/firefox/*/storage/default",
            "~/.mozilla/firefox/*/extensions",
        ],
        "files_of_interest": ["*.sqlite", "*.json"],
        "evidence_value": "Browser-based AI assistant residue, cached conversations"
    },

    # ═══ API CLIENT ARTIFACTS ═══
    "openai_cli": {
        "category": "API Client",
        "tool": "OpenAI CLI/SDK",
        "windows": [
            r"%USERPROFILE%\.openai",
            r"%USERPROFILE%\.cache\openai",
            r"%APPDATA%\openai",
        ],
        "macos": [
            "~/.openai",
            "~/.cache/openai",
            "~/Library/Caches/openai",
        ],
        "linux": [
            "~/.openai",
            "~/.cache/openai",
            "~/.config/openai",
        ],
        "files_of_interest": ["config", "*.json", "*.log", "history"],
        "evidence_value": "API keys, usage history, cached responses"
    },
    "anthropic_cli": {
        "category": "API Client",
        "tool": "Anthropic SDK",
        "windows": [
            r"%USERPROFILE%\.anthropic",
            r"%USERPROFILE%\.cache\anthropic",
        ],
        "macos": [
            "~/.anthropic",
            "~/Library/Caches/anthropic",
        ],
        "linux": [
            "~/.anthropic",
            "~/.cache/anthropic",
        ],
        "files_of_interest": ["*.json", "*.log"],
        "evidence_value": "Anthropic API usage, cached prompts/responses"
    },

    # ═══ VECTOR DATABASES ═══
    "chromadb": {
        "category": "Vector DB",
        "tool": "ChromaDB",
        "windows": [
            r"%USERPROFILE%\.chroma",
            r"%USERPROFILE%\chroma",
            r"%LOCALAPPDATA%\chroma",
        ],
        "macos": [
            "~/.chroma",
            "~/chroma",
            "~/Library/Application Support/chroma",
        ],
        "linux": [
            "~/.chroma",
            "~/chroma",
            "/var/lib/chroma",
        ],
        "files_of_interest": ["chroma.sqlite3", "*.parquet", "*.bin"],
        "evidence_value": "Embedding queries, indexed documents, semantic search history"
    },
    "faiss_index": {
        "category": "Vector DB",
        "tool": "FAISS Index Files",
        "windows": [
            r"%USERPROFILE%\.cache\faiss",
            r"%TEMP%\faiss*",
        ],
        "macos": [
            "~/.cache/faiss",
            "/tmp/faiss*",
        ],
        "linux": [
            "~/.cache/faiss",
            "/tmp/faiss*",
        ],
        "files_of_interest": ["*.faiss", "*.index", "*.pkl"],
        "evidence_value": "Local embedding indices, semantic search caches"
    },
    "huggingface": {
        "category": "Model Cache",
        "tool": "HuggingFace Cache",
        "windows": [
            r"%USERPROFILE%\.cache\huggingface",
        ],
        "macos": [
            "~/.cache/huggingface",
            "~/Library/Caches/huggingface",
        ],
        "linux": [
            "~/.cache/huggingface",
        ],
        "files_of_interest": ["*.json", "tokenizer*", "config.json"],
        "evidence_value": "Downloaded models, embedding caches, tokenizers"
    },

    # ═══ AGENT FRAMEWORKS ═══
    "langchain": {
        "category": "Agent Framework",
        "tool": "LangChain",
        "windows": [
            r"%USERPROFILE%\.cache\langchain",
            r"%TEMP%\langchain*",
        ],
        "macos": [
            "~/.cache/langchain",
            "/tmp/langchain*",
        ],
        "linux": [
            "~/.cache/langchain",
            "/tmp/langchain*",
        ],
        "files_of_interest": ["*.json", "*.pkl", "*.db"],
        "evidence_value": "Agent traces, tool invocations, chain execution history"
    },
    "ollama": {
        "category": "Local LLM",
        "tool": "Ollama",
        "windows": [
            r"%USERPROFILE%\.ollama",
            r"%LOCALAPPDATA%\Ollama",
        ],
        "macos": [
            "~/.ollama",
            "~/Library/Application Support/Ollama",
        ],
        "linux": [
            "~/.ollama",
            "/usr/share/ollama",
        ],
        "files_of_interest": ["history", "*.json", "*.log", "models/*"],
        "evidence_value": "Local model usage, prompt history, model files"
    },

    # ═══ SHELL HISTORY ═══
    "shell_history": {
        "category": "Shell History",
        "tool": "Shell History (LLM tool usage)",
        "windows": [
            r"%USERPROFILE%\.bash_history",
            r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        ],
        "macos": [
            "~/.bash_history",
            "~/.zsh_history",
            "~/.local/share/fish/fish_history",
        ],
        "linux": [
            "~/.bash_history",
            "~/.zsh_history",
            "~/.local/share/fish/fish_history",
        ],
        "files_of_interest": [".bash_history", ".zsh_history", "ConsoleHost_history.txt"],
        "evidence_value": "Commands invoking openai/anthropic/claude/llm CLI tools, curl to API endpoints"
    },
}

# ═══ DETECTION PATTERNS ═══

LLM_PATTERNS = {
    "api_keys": [
        (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API Key"),
        (r"sk-ant-[a-zA-Z0-9-]{20,}", "Anthropic API Key"),
        (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
        (r"pcsk_[a-zA-Z0-9_]{20,}", "Pinecone API Key"),
        (r"hf_[a-zA-Z0-9]{30,}", "HuggingFace Token"),
    ],
    "api_endpoints": [
        (r"api\.openai\.com", "OpenAI API"),
        (r"api\.anthropic\.com", "Anthropic API"),
        (r"generativelanguage\.googleapis\.com", "Google Gemini API"),
        (r"\.openai\.azure\.com", "Azure OpenAI"),
        (r"api\.cohere\.ai", "Cohere API"),
        (r"api\.mistral\.ai", "Mistral API"),
    ],
    "prompt_injection_indicators": [
        (r"ignore (previous|all) (instructions|prompts)", "Classic prompt injection"),
        (r"system:?\s*you are", "System prompt override attempt"),
        (r"<\|im_start\|>", "ChatML delimiter injection"),
        (r"DAN mode|jailbreak|developer mode", "Jailbreak attempt"),
        (r"<script>|javascript:|data:text/html", "XSS via prompt injection"),
        (r"```bash\s+rm -rf|curl.*\|\s*(bash|sh)", "Code execution via prompt"),
    ],
    "data_exfil_indicators": [
        (r"(password|secret|token|api[_-]?key|credential)", "Sensitive keyword in prompt"),
        (r"BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY", "Private key in prompt"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "SSN pattern"),
        (r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "Credit card pattern"),
    ]
}

# ═══ COLLECTION ENGINE ═══

def get_os():
    s = platform.system().lower()
    if s == "darwin": return "macos"
    if s == "windows": return "windows"
    return "linux"

def expand_path(path, os_type):
    if os_type == "windows":
        for var in ["APPDATA", "LOCALAPPDATA", "USERPROFILE", "TEMP", "PROGRAMFILES", "PROGRAMDATA"]:
            path = path.replace(f"%{var}%", os.environ.get(var, ""))
        return path
    return os.path.expanduser(path)

def file_metadata(filepath):
    try:
        stat = os.stat(filepath)
        return {
            "path": filepath,
            "size_bytes": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "exists": True
        }
    except Exception as e:
        return {"path": filepath, "error": str(e), "exists": False}

def hash_file(filepath):
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

def scan_content_for_iocs(filepath, max_size=5*1024*1024):
    """Scan file content for LLM-related IOCs"""
    try:
        if os.path.getsize(filepath) > max_size:
            return {"skipped": "file too large"}
        with open(filepath, "rb") as f:
            content = f.read().decode("utf-8", errors="ignore")
        
        findings = {"api_keys": [], "endpoints": [], "injection": [], "exfil": []}
        
        for category, patterns in LLM_PATTERNS.items():
            key = {"api_keys": "api_keys", "api_endpoints": "endpoints",
                   "prompt_injection_indicators": "injection",
                   "data_exfil_indicators": "exfil"}[category]
            for pattern, label in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    findings[key].append({
                        "type": label,
                        "count": len(matches),
                        "sample": matches[0][:60] if matches else None
                    })
        
        # Filter empty
        findings = {k: v for k, v in findings.items() if v}
        return findings if findings else None
    except Exception as e:
        return {"error": str(e)}

def collect_artifacts(output_dir, scan_content=True):
    os_type = get_os()
    print(f"\n[+] Detected OS: {os_type}")
    print(f"[+] User: {getpass.getuser()}")
    print(f"[+] Hostname: {platform.node()}")
    print(f"[+] Output: {output_dir}\n")
    
    os.makedirs(output_dir, exist_ok=True)
    
    timeline = []
    inventory = []
    findings = []
    iocs = []
    
    print(f"[+] Scanning {len(ARTIFACT_LOCATIONS)} artifact categories...\n")
    
    for artifact_id, artifact in ARTIFACT_LOCATIONS.items():
        paths = artifact.get(os_type, [])
        for path_pattern in paths:
            expanded = expand_path(path_pattern, os_type)
            
            # Use glob for wildcards
            matches = glob.glob(expanded) if "*" in expanded else ([expanded] if os.path.exists(expanded) else [])
            
            for match in matches:
                if os.path.isdir(match):
                    # Walk directory
                    for root, dirs, files in os.walk(match):
                        # Skip massive dirs
                        if len(files) > 500:
                            continue
                        for fname in files:
                            full_path = os.path.join(root, fname)
                            process_file(full_path, artifact_id, artifact, timeline, inventory, findings, iocs, scan_content)
                else:
                    process_file(match, artifact_id, artifact, timeline, inventory, findings, iocs, scan_content)
    
    print(f"\n[+] Collection complete:")
    print(f"    Files found: {len(inventory)}")
    print(f"    Timeline entries: {len(timeline)}")
    print(f"    IOCs detected: {len(iocs)}")
    
    # Save outputs
    save_outputs(output_dir, timeline, inventory, iocs, os_type)
    
    return {"timeline": timeline, "inventory": inventory, "iocs": iocs}

def process_file(filepath, artifact_id, artifact, timeline, inventory, findings, iocs, scan_content):
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return
    
    meta = file_metadata(filepath)
    if not meta.get("exists"):
        return
    
    entry = {
        "artifact_id": artifact_id,
        "tool": artifact["tool"],
        "category": artifact["category"],
        "path": filepath,
        "size_bytes": meta["size_bytes"],
        "modified": meta["modified"],
        "accessed": meta["accessed"],
        "evidence_value": artifact["evidence_value"]
    }
    
    # Hash small files only (under 50MB)
    if meta["size_bytes"] < 50*1024*1024:
        entry["sha256"] = hash_file(filepath)
    
    inventory.append(entry)
    timeline.append({
        "timestamp": meta["modified"],
        "event": "file_modified",
        "tool": artifact["tool"],
        "category": artifact["category"],
        "path": filepath,
        "size": meta["size_bytes"]
    })
    
    print(f"  [{artifact['category']:15s}] {filepath}")
    
    # Scan content for IOCs
    if scan_content and meta["size_bytes"] < 5*1024*1024:
        ioc_findings = scan_content_for_iocs(filepath)
        if ioc_findings and not ioc_findings.get("error"):
            iocs.append({
                "path": filepath,
                "tool": artifact["tool"],
                "findings": ioc_findings
            })
            for cat, items in ioc_findings.items():
                for item in items:
                    print(f"      [!] {item['type']} found ({item['count']}x)")

def save_outputs(output_dir, timeline, inventory, iocs, os_type):
    # JSON timeline
    timeline_sorted = sorted(timeline, key=lambda x: x["timestamp"], reverse=True)
    with open(f"{output_dir}/timeline.json", "w") as f:
        json.dump({
            "metadata": {
                "tool": f"LLM-DFIR Triage v{VERSION}",
                "generated": datetime.now().isoformat(),
                "host": platform.node(),
                "user": getpass.getuser(),
                "os": os_type,
                "platform": platform.platform()
            },
            "timeline": timeline_sorted
        }, f, indent=2, default=str)
    
    # Evidence inventory CSV
    if inventory:
        with open(f"{output_dir}/evidence_inventory.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["artifact_id", "tool", "category", "path", "size_bytes", "modified", "accessed", "sha256", "evidence_value"])
            writer.writeheader()
            for entry in inventory:
                writer.writerow({k: entry.get(k, "") for k in writer.fieldnames})
    
    # IOCs JSON
    if iocs:
        with open(f"{output_dir}/iocs.json", "w") as f:
            json.dump({
                "scan_time": datetime.now().isoformat(),
                "total_files_with_iocs": len(iocs),
                "findings": iocs
            }, f, indent=2)
    
    # HTML report
    generate_html_report(output_dir, timeline_sorted, inventory, iocs, os_type)
    
    print(f"\n[+] Outputs saved:")
    print(f"    {output_dir}/timeline.json")
    print(f"    {output_dir}/evidence_inventory.csv")
    print(f"    {output_dir}/iocs.json")
    print(f"    {output_dir}/report.html")

def generate_html_report(output_dir, timeline, inventory, iocs, os_type):
    cat_counts = {}
    for entry in inventory:
        cat = entry.get("category", "Unknown")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
    
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>LLM-DFIR Triage Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;font-family:'SF Mono',Consolas,monospace}}
body{{background:#0a0a0f;color:#e0e0f0;padding:20px;font-size:13px}}
.h{{text-align:center;padding:30px;border-bottom:2px solid #1e1e32;margin-bottom:20px}}
.h h1{{font-size:1.8rem;color:#00ff88}}
.meta{{color:#7080a0;font-size:.7rem;margin-top:8px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-bottom:20px}}
.s{{background:#0d0d14;border:1px solid #1e1e32;border-radius:8px;padding:14px;text-align:center}}
.sv{{font-size:1.6rem;font-weight:900;color:#00ff88}}
.sl{{font-size:.55rem;color:#7080a0;text-transform:uppercase;margin-top:4px;letter-spacing:.5px}}
.section{{background:#0d0d14;border:1px solid #1e1e32;border-radius:10px;padding:18px;margin-bottom:14px}}
.title{{color:#00d4ff;font-size:.9rem;margin-bottom:12px;font-weight:700}}
.entry{{padding:8px;border-left:3px solid #1e1e32;margin-bottom:4px;background:#000;border-radius:4px;font-size:.65rem}}
.entry.crit{{border-left-color:#ff3366}}
.entry.high{{border-left-color:#ffaa00}}
.path{{color:#7080a0;word-break:break-all}}
.tool{{color:#00ff88;font-weight:700}}
.ts{{color:#aa66ff;font-size:.6rem}}
.ioc{{color:#ff3366;font-weight:700}}
table{{width:100%;border-collapse:collapse;font-size:.65rem}}
th,td{{text-align:left;padding:8px;border-bottom:1px solid #1e1e32}}
th{{color:#00d4ff;font-size:.6rem;text-transform:uppercase}}
</style></head><body>
<div class="h">
<h1>🔍 LLM-DFIR Triage Report</h1>
<div class="meta">Generated: {datetime.now().isoformat()}<br>Host: {platform.node()} · User: {getpass.getuser()} · OS: {os_type}</div>
</div>
<div class="stats">
<div class="s"><div class="sv">{len(inventory)}</div><div class="sl">Artifacts Found</div></div>
<div class="s"><div class="sv">{len(timeline)}</div><div class="sl">Timeline Events</div></div>
<div class="s"><div class="sv">{len(iocs)}</div><div class="sl">IOCs Detected</div></div>
<div class="s"><div class="sv">{len(cat_counts)}</div><div class="sl">Categories</div></div>
</div>
<div class="section">
<div class="title">📊 Artifacts by Category</div>
<table><thead><tr><th>Category</th><th>Count</th></tr></thead><tbody>
{''.join(f'<tr><td>{c}</td><td>{n}</td></tr>' for c,n in sorted(cat_counts.items(), key=lambda x:-x[1]))}
</tbody></table>
</div>
<div class="section">
<div class="title">⚠️ Indicators of Compromise ({len(iocs)})</div>
{''.join(f'<div class="entry crit"><span class="tool">{i["tool"]}</span> · <span class="path">{i["path"]}</span><br>'+'<br>'.join(f'<span class="ioc">[!]</span> {f["type"]} ({f["count"]}x)' for cat in i["findings"].values() for f in cat)+'</div>' for i in iocs[:50]) or '<div style="color:#7080a0;font-size:.7rem">No IOCs detected.</div>'}
</div>
<div class="section">
<div class="title">🕒 Recent Timeline (50 most recent)</div>
{''.join(f'<div class="entry"><span class="ts">{e["timestamp"]}</span> · <span class="tool">{e["tool"]}</span><br><span class="path">{e["path"]}</span></div>' for e in timeline[:50])}
</div>
</body></html>"""
    
    with open(f"{output_dir}/report.html", "w") as f:
        f.write(html)

# ═══ MAIN ═══

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLM-DFIR Triage Tool")
    parser.add_argument("--output", default=f"./triage_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                       help="Output directory")
    parser.add_argument("--no-content", action="store_true", help="Skip content scanning (faster)")
    parser.add_argument("--list-artifacts", action="store_true", help="List all artifact categories and exit")
    args = parser.parse_args()
    
    print(BANNER)
    
    if args.list_artifacts:
        print(f"[+] LLM-DFIR Triage tracks {len(ARTIFACT_LOCATIONS)} artifact types:\n")
        cats = {}
        for aid, a in ARTIFACT_LOCATIONS.items():
            cats.setdefault(a["category"], []).append((aid, a["tool"]))
        for cat in sorted(cats):
            print(f"\n  {cat}:")
            for aid, tool in cats[cat]:
                print(f"    • {tool} ({aid})")
        sys.exit(0)
    
    try:
        results = collect_artifacts(args.output, scan_content=not args.no_content)
        print(f"\n[+] Triage complete. {len(results['inventory'])} artifacts collected.")
        print(f"[+] Open {args.output}/report.html in a browser to review.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
