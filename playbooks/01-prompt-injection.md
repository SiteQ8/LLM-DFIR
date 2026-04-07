# Playbook 1: Prompt Injection / Indirect Prompt Injection

## Threat Model

**Direct prompt injection:** Attacker submits a prompt that overrides system instructions. Goal: jailbreak, bypass safety, exfiltrate system prompt, or pivot the model's behavior.

**Indirect prompt injection:** Attacker plants malicious instructions in data the LLM will process — a webpage, PDF, email, code comment, or document. When the agent reads it, the instructions activate. Often more dangerous because the user isn't the attacker.

## Indicators

| Indicator | Where to look |
|-----------|---------------|
| `ignore previous instructions` | LLM tool logs, MCP transcripts, API request bodies |
| `<\|im_start\|>system` | ChatML delimiter injection in user input |
| Hidden text in PDFs (white-on-white, 0pt font) | Document forensics |
| `<!-- LLM: ignore -->` style HTML comments | Indexed web pages |
| Unicode tag characters (U+E0000–U+E007F) | Hidden instructions in text |
| Sudden agent behavior change mid-session | MCP server logs, tool-use traces |

## Triage Steps

### 1. Capture Volatile Evidence (First 15 minutes)
```bash
# Snapshot the current MCP config — attackers may modify it
cp ~/Library/Application\ Support/Claude/claude_desktop_config.json ./evidence/

# Snapshot active session files
cp -r ~/.claude/sessions ./evidence/

# Snapshot all MCP server logs
cp -r ~/Library/Logs/Claude/ ./evidence/

# Run triage script
python3 llm_triage.py --output ./evidence/triage
```

### 2. Identify the Injection Vector
Search collected artifacts for known injection patterns:
```bash
grep -ri "ignore.*previous.*instructions" ./evidence/
grep -ri "im_start" ./evidence/
grep -rP "<!--.*LLM.*-->" ./evidence/
```

### 3. Determine Blast Radius
For each MCP server that was active during the incident:
- What tools did it expose? → Read MCP config
- What did the agent invoke? → Read MCP server log
- Did any tool calls touch sensitive data?

### 4. Look for Lateral Effects
Indirect injection often chains:
- Did the agent write to disk? → File mtime sweep
- Did the agent execute commands? → Shell history + tool logs
- Did the agent make API calls? → Network logs to LLM endpoints
- Did the agent commit code? → Git log of repos in workspace

## Containment

1. **Disable the affected MCP server** — Comment out in `claude_desktop_config.json`
2. **Revoke API tokens** that were in scope (OpenAI, Anthropic, GitHub, etc.)
3. **Quarantine the source document** that contained the injection
4. **Reset the agent session** — kill running Claude/Cursor processes

## Detection Going Forward

- Implement prompt input/output guardrails (e.g., Lakera Guard, Rebuff, NeMo Guardrails)
- Monitor MCP server logs for sudden volume changes
- Sandboxed tool execution — agents should not have write access by default
- Content Security Policy on AI tool inputs (sanitize HTML, strip Unicode tags)
