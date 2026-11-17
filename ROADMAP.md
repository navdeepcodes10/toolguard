# 🗺️ ToolGuard Project Roadmap

A phased plan for the development, ecosystem integration, and community growth of **ToolGuard**.

---

## 📍 Phase 1: Core Safety Engine & CLI (Completed ✅)
- [x] **Tri-State Evaluation Engine:** Real-time classification into `ALLOW`, `PROMPT`, and `BLOCK`.
- [x] **Destructive Command Guard:** Blocks root wipes (`rm -rf /`), raw disk formats (`mkfs`), DB drops, and git force-pushes.
- [x] **Secret & Credential Shield:** Detects leaked OpenAI, AWS, GitHub tokens, and `.env` exfiltration attempts.
- [x] **CLI Commands:**
  - `toolguard eval "<cmd>"` (inspect risk & mitigation without execution)
  - `toolguard run "<cmd>"` (transparent execution with user prompts)
  - `toolguard init` (generates `.toolguard.yaml`)
  - `toolguard audit` (structured history in `.toolguard/audit.jsonl`)
  - `toolguard mcp-proxy` (JSON-RPC stdio firewall)
- [x] **Automated Testing:** 12/12 unit tests passing in <50ms.
- [x] **GitHub & CI:** Repository initialized, GitHub Actions CI workflow, and brand logo live.

---

## 📍 Phase 2: Packaging, npm Release & Agent Integrations (Completed ✅)
- [x] **Lightweight npm Package Spec:** Reduced tarball size to < 14 KB with strict whitelist.
- [x] **Framework Security Presets:**
  - `docker` (Blocks `--privileged`, docker.sock mount, host root mount)
  - `node` (Blocks piped network execution `curl | sh`, prompts on `npm publish`)
  - `python` (Blocks `--break-system-packages`)
- [x] **IDE & Agent Integration Guides:**
  - [Cursor IDE Guide](./integrations/cursor.md) (`.cursorrules` configuration)
  - [Claude Code & MCP Guide](./integrations/claude-code.md) (JSON-RPC stdio proxy setup)
- [x] **One-Command Shell Hook:**
  - `toolguard hook` with transparent `rm` and `git` protection and `--install` flag.
- [x] **Automated Release Pipeline:**
  - Added GitHub Actions `.github/workflows/release.yml` for automated 1-click npm publishing.

---

## 📍 Phase 3: AST Parsing & Network Sandboxing (Next Up 🚀)
- [ ] **Abstract Syntax Tree (AST) Shell Parser:**
  - Move beyond regex matching to full shell AST parsing (handles command obfuscation, subshells, and piped commands like `echo aGVsbG8= | base64 -d | sh`).
- [ ] **Network & Outbound URL Filter:**
  - Whitelist allowed external domains (e.g., `github.com`, `registry.npmjs.org`, `pypi.org`).
  - Block tool calls attempting to ping untrusted external IPs.
- [ ] **Path Sandboxing:**
  - Enforce strict workspace boundaries (e.g., prevent agents from reading `~/.ssh/` or `/etc/hosts` even through symlinks).

---

## 📍 Phase 4: Open-Source Growth & Viral Launch
- [ ] **GitHub Polish:**
  - Add interactive demo GIF or SVG terminal recording using `vhs`.
  - Add GitHub release badges (npm version, test coverage, license).
  - Add `CONTRIBUTING.md` guide for adding custom community rules.
- [ ] **Public Launch:**
  - Launch on **Hacker News (Show HN)**: *"Show HN: ToolGuard – A security firewall for AI coding agents"*.
  - Share on Reddit (`r/LocalLLaMA`, `r/programming`, `r/ChatGPTCoding`, `r/node`).
  - Share on X / Twitter targeting AI agent builders and DevSecOps practitioners.

---

## 📍 Phase 5: Team & Enterprise Security (Future Horizon)
- [ ] **Centralized Policy Sync:** Fetch team security rules from a shared GitHub repo, S3 bucket, or internal URL.
- [ ] **Slack / Discord Security Alerts:** Webhook notifications when an agent attempts a critical prohibited action.
- [ ] **Lightweight Web Audit Dashboard:** Visual browser interface to search through agent tool calls, latency, and blocked violations.
