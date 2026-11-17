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

## 📍 Phase 2: Packaging, npm Release & Agent Integrations (Next Up 🚀)
- [ ] **Publish to npm Registry:**
  - Publish `@toolguard/cli` or `toolguard` so any developer can run `npx toolguard` without local setup.
- [ ] **IDE & Agent Guides:**
  - Add configuration guides for **Cursor IDE**, **Claude Code**, and **Antigravity**.
  - Show how to drop ToolGuard into `.cursorrules` or `mcpServers` config.
- [ ] **Framework Presets:**
  - Pre-packaged rule packs for common stacks (`preset-node`, `preset-python`, `preset-docker`, `preset-rails`).
- [ ] **One-Command Shell Hook:**
  - Allow developers to alias or hook `toolguard` into subshells easily.

---

## 📍 Phase 3: AST Parsing & Network Sandboxing
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
