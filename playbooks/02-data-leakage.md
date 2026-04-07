# Playbook 2: Sensitive Data Leakage to Third-Party Models

## Threat Model

A user (intentionally or accidentally) sends sensitive data to a third-party LLM API:
- Source code containing secrets
- Customer PII pasted into ChatGPT
- Database dumps shared with Copilot for "help"
- Internal documents uploaded to Claude.ai
- API responses containing tokens cached locally

The data is now in the model provider's logs, possibly used for training, and outside your data residency controls.

## Indicators

| Indicator | Where to look |
|-----------|---------------|
| Outbound TLS to `api.openai.com`, `api.anthropic.com` | Firewall/proxy logs |
| Large request bodies to LLM APIs | Network monitoring |
| API keys in ChatGPT/Claude conversation history | Browser leveldb |
| Customer data in Copilot suggestion logs | `state.vscdb` |
| `BEGIN PRIVATE KEY` strings in IDE plugin logs | Content scan |
| SSN/credit card patterns in chat history | Regex sweep |

## Triage Steps

### 1. Identify What Was Sent
```bash
# Run triage with content scanning enabled (default)
python3 llm_triage.py --output ./evidence

# Review the iocs.json — it flags:
#   - API keys (sk-, sk-ant-, AIza, etc.)
#   - Private keys
#   - SSN patterns
#   - Credit card patterns
cat ./evidence/iocs.json | jq '.findings[] | select(.findings.exfil)'
```

### 2. Determine Volume and Timing
```bash
# Sort timeline by tool to see what data hit which model
cat ./evidence/timeline.json | jq '.timeline[] | select(.tool | contains("Copilot"))'
```

### 3. Check Browser History
Browser-based AI tools (`chat.openai.com`, `claude.ai`, `gemini.google.com`) cache conversations in IndexedDB and LocalStorage. Use:
- `python3 -m ccl_chromium_reader` for Chrome
- SQLite browser for Firefox `webappsstore.sqlite`

Search for sensitive keywords in the cached conversation content.

### 4. Identify the User
- Match the artifact path's user directory to the employee
- Check IDE plugin telemetry for the GitHub account associated with Copilot
- Cross-reference with SSO logs for ChatGPT/Claude.ai sign-in events

## Containment

1. **Rotate credentials** found in leaked content (API keys, passwords, certificates)
2. **Notify legal/privacy team** if PII or regulated data was sent
3. **Submit data deletion requests** to the model provider (OpenAI, Anthropic both honor these for API/business tier)
4. **Quarantine the affected workstation** if leakage was systematic
5. **Force-rotate any tokens** found in the user's IDE plugin storage

## Detection Going Forward

- **DLP at egress:** Block patterns matching API keys, PII, source code from going to LLM API endpoints
- **Browser controls:** Block or sandbox `chat.openai.com`, `claude.ai`, etc., on corporate devices
- **Approved AI gateway:** Force all LLM traffic through a corporate proxy with logging and redaction (e.g., LiteLLM proxy, Portkey)
- **CASB integration:** Monitor SaaS LLM usage
- **Log everything:** Every prompt, every response, every embedding query through corporate AI platforms
