# LLM-Era Forensic Artifact Taxonomy

A reference catalog of forensic artifacts produced by LLM-based tools, AI assistants, agent frameworks, and the supporting infrastructure (vector DBs, embedding caches, MCP servers).

---

## 1. IDE Plugin Telemetry

### GitHub Copilot
| OS | Path |
|----|------|
| Windows | `%APPDATA%\Code\User\globalStorage\github.copilot` |
| Windows | `%APPDATA%\Code\User\globalStorage\github.copilot-chat` |
| Windows | `%APPDATA%\Code\logs\*\exthost*\GitHub.copilot*` |
| Windows | `%LOCALAPPDATA%\github-copilot` |
| macOS | `~/Library/Application Support/Code/User/globalStorage/github.copilot` |
| macOS | `~/Library/Application Support/Code/User/globalStorage/github.copilot-chat` |
| Linux | `~/.config/Code/User/globalStorage/github.copilot` |

**Files of interest:** `state.vscdb` (SQLite — chat history), `*.log` (telemetry), `hosts.json` (auth)

**Parsing tip:** `state.vscdb` is a SQLite database. Query with:
```sql
SELECT key, value FROM ItemTable WHERE key LIKE '%copilot%';
```
The `value` column often contains base64-encoded JSON with conversation history and file context that was sent to the model.

### Cursor
| OS | Path |
|----|------|
| Windows | `%APPDATA%\Cursor\User\globalStorage` |
| Windows | `%APPDATA%\Cursor\User\workspaceStorage` |
| macOS | `~/Library/Application Support/Cursor/User/globalStorage` |
| Linux | `~/.config/Cursor/User/globalStorage` |

**Files of interest:** `state.vscdb`, `workspaceStorage/*/state.vscdb`

**Evidence value:** Cursor's per-workspace state stores chat history, indexed codebase metadata, and sent-file logs. Workspace storage is keyed by directory hash — multiple per-project databases will exist.

### Claude Code
| OS | Path |
|----|------|
| Windows | `%USERPROFILE%\.claude` |
| macOS | `~/.claude` |
| macOS | `~/Library/Logs/Claude` |
| Linux | `~/.claude` |

**Files of interest:** Session JSONL files, tool use traces, bash command history

**Evidence value:** Claude Code logs every tool invocation (file edits, bash commands, web fetches). Session files are append-only JSONL — each line is a turn in the agent loop. Critical for understanding what an agent did on the host.

### Codeium / Windsurf
| OS | Path |
|----|------|
| Windows | `%USERPROFILE%\.codeium`, `%APPDATA%\Windsurf` |
| macOS | `~/.codeium`, `~/Library/Application Support/Windsurf` |
| Linux | `~/.codeium`, `~/.config/Windsurf` |

**Files of interest:** `language_server*.log`, telemetry JSON

---

## 2. MCP (Model Context Protocol) Servers

### Claude Desktop MCP Config
| OS | Path |
|----|------|
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

**This is the FIRST file to grab in any LLM-related incident.** It declares which MCP servers are configured and what they can access. Example:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem", "/Users/me/Documents"]
    },
    "github": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-github"],
      "env": {"GITHUB_TOKEN": "ghp_..."}
    }
  }
}
```

**Red flags in MCP config:**
- File system servers pointed at sensitive directories (`~/`, `/`, `/etc`)
- API tokens hardcoded in `env` blocks
- Custom MCP servers from unknown sources (`command: node /tmp/something.js`)
- Servers granted shell command execution capabilities

### MCP Server Logs
| OS | Path |
|----|------|
| Windows | `%APPDATA%\Claude\logs\mcp-server-*.log` |
| macOS | `~/Library/Logs/Claude/mcp-server-*.log` |
| Linux | `~/.config/Claude/logs/mcp-server-*.log` |

**Parsing tip:** Each MCP server gets its own log file named `mcp-server-{servername}.log`. These contain the JSON-RPC traffic between the client and server — every tool list request and tool call invocation. Grep for `"method":"tools/call"` to enumerate every action the AI agent took.

---

## 3. Browser-Based AI Assistant Residue

### Chrome / Edge / Brave
| OS | Path |
|----|------|
| Windows | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Storage\leveldb` |
| Windows | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\IndexedDB` |
| macOS | `~/Library/Application Support/Google/Chrome/Default/Local Storage/leveldb` |
| Linux | `~/.config/google-chrome/Default/Local Storage/leveldb` |

**Files of interest:** `*.ldb` (LevelDB), `*.log`, IndexedDB `.blob` files

**Parsing tip:** Chrome's LevelDB stores `chat.openai.com`, `claude.ai`, `gemini.google.com`, and `copilot.microsoft.com` session data including:
- Conversation IDs
- Cached message content (chunks)
- Authentication tokens (sometimes)
- Last accessed conversation

Tools: `python3 -m ccl_chromium_reader` or `pyleveldb` to parse.

### Firefox
| OS | Path |
|----|------|
| All | `<profile>/storage/default/https+++chat.openai.com` |
| All | `<profile>/storage/default/https+++claude.ai` |

Storage uses IndexedDB with SQLite backing — readable with standard SQLite tools.

---

## 4. API Client Artifacts

### OpenAI CLI / SDK
| OS | Path |
|----|------|
| Windows | `%USERPROFILE%\.openai`, `%USERPROFILE%\.cache\openai` |
| macOS | `~/.openai`, `~/Library/Caches/openai` |
| Linux | `~/.openai`, `~/.cache/openai` |

**Files of interest:** API key in environment files, request/response cache

### Anthropic SDK
| OS | Path |
|----|------|
| All | `~/.anthropic`, `~/.cache/anthropic` |

### Azure OpenAI
| OS | Path |
|----|------|
| All | `~/.azure`, environment variables `AZURE_OPENAI_*` |

**Triage tip:** Always check shell history (`.bash_history`, `.zsh_history`, PowerShell `ConsoleHost_history.txt`) for `OPENAI_API_KEY=`, `ANTHROPIC_API_KEY=`, `export OPENAI`, and `curl https://api.openai.com` patterns.

---

## 5. Vector Databases & Embedding Caches

### ChromaDB
| OS | Path |
|----|------|
| All | `~/.chroma`, `~/chroma`, `/var/lib/chroma` |

**Files of interest:** `chroma.sqlite3`, `*.parquet` (embeddings), `*.bin` (HNSW index)

**Parsing tip:** Open `chroma.sqlite3` and query:
```sql
SELECT collection_id, document FROM embeddings_queue;
SELECT * FROM collections;
```
Reveals what documents were indexed for RAG — often the entire codebase or document repository.

### FAISS Index Files
| OS | Path |
|----|------|
| All | `~/.cache/faiss`, `/tmp/faiss*` |

Binary index files paired with `.pkl` metadata containing original document text.

### HuggingFace Cache
| OS | Path |
|----|------|
| All | `~/.cache/huggingface` |

Downloaded model weights, tokenizers, datasets. Look for `models--*` directories.

### Pinecone / Weaviate
Cloud-hosted — no local artifacts except API keys in env files and SDK cache (`~/.pinecone`, `~/.weaviate`).

---

## 6. Agent Frameworks

### LangChain
| OS | Path |
|----|------|
| All | `~/.cache/langchain`, `/tmp/langchain*` |

**Files of interest:** `*.db` (LangSmith trace cache), `*.pkl` (serialized agent state), `*.json` (chain definitions)

### Ollama (Local LLM)
| OS | Path |
|----|------|
| Windows | `%USERPROFILE%\.ollama`, `%LOCALAPPDATA%\Ollama` |
| macOS | `~/.ollama`, `~/Library/Application Support/Ollama` |
| Linux | `~/.ollama`, `/usr/share/ollama` |

**Files of interest:** `history` (CLI history), `models/manifests/*` (downloaded models), `logs/server.log`

**Parsing tip:** Ollama logs every prompt to `~/.ollama/logs/server.log` with timestamps. Critical for local-LLM incident response — these models run completely offline so cloud telemetry won't see them.

---

## 7. Shell History (LLM Tool Usage)

| OS | Shell | Path |
|----|-------|------|
| Linux/macOS | bash | `~/.bash_history` |
| Linux/macOS | zsh | `~/.zsh_history` |
| Linux/macOS | fish | `~/.local/share/fish/fish_history` |
| Windows | PowerShell | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` |

**What to grep for:**
```
openai
anthropic
claude
ollama
ChatGPT
api.openai.com
api.anthropic.com
OPENAI_API_KEY
ANTHROPIC_API_KEY
litellm
langchain
llamaindex
mcp
```

---

## 8. Temporal Patterns & Timeline Reconstruction

When reconstructing an LLM-related incident timeline, correlate these timestamps:

1. **MCP config last modified** — When was tool access last changed?
2. **MCP server log first/last entry** — Window of agent activity
3. **Claude Code session JSONL mtime** — When did the agent last execute
4. **IDE plugin state.vscdb mtime** — When did Copilot/Cursor last interact
5. **Vector DB sqlite mtime** — When was RAG corpus last updated
6. **Shell history entries** — When did user invoke LLM CLI tools

**Pivot pattern:** A common compromise sequence is:
1. User installs MCP server from untrusted source → MCP config modified
2. MCP server given filesystem access → Logs show file enumeration
3. Sensitive files exfiltrated via API call → API client cache shows responses
4. Generated code committed → Git log shows author/timestamp anomalies

---

## 9. Detection Gap: What EDR/SIEM Misses Today

Current EDR products generally do NOT capture:
- MCP server JSON-RPC traffic
- IDE plugin telemetry
- LLM API request bodies (only TLS metadata)
- Vector DB queries
- Embedding cache operations
- LLM tool-use traces

**What you SHOULD log (minimal baseline):**

1. **Network:** All TLS connections to `api.openai.com`, `api.anthropic.com`, `*.openai.azure.com`, `generativelanguage.googleapis.com`, `api.mistral.ai`, `api.cohere.ai`
2. **Process:** Any process named `claude`, `cursor`, `ollama`, `copilot*`, `node` running MCP servers
3. **File:** Modifications to `claude_desktop_config.json` (alert on changes)
4. **File:** Creation of files in `.claude/`, `.cursor/`, `.codeium/`, `.ollama/`
5. **Process:** Command lines containing `--api-key`, `OPENAI_API_KEY`, `npx @modelcontextprotocol`
6. **Network:** Outbound to non-corporate LLM endpoints
7. **DNS:** Queries for `huggingface.co`, `replicate.com`, `together.ai`

---

## References

- MITRE ATLAS (Adversarial Threat Landscape for AI Systems): https://atlas.mitre.org/
- OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MCP Specification: https://modelcontextprotocol.io/specification
