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

## 📍 Phase 3: AST Parsing & Network Sandboxing (Completed ✅)
- [x] **Abstract Syntax & Command Chain Decomposer:**
  - Decomposes chained (`&&`, `||`, `;`), piped (`|`), and subshell (`$(...)`, `` `...` ``) commands.
  - Recursively evaluates each atomic segment independently.
  - Strips leading environment variable assignments (`FOO=bar rm -rf /`).
  - Detects and blocks obfuscated base64 pipe executions (`base64 -d | sh`).
- [x] **Network SSRF & Outbound Domain Filter:**
  - Hard-blocks access to Cloud Instance Metadata Services (`169.254.169.254`).
  - Evaluates outbound domains against configurable whitelist and blocklist.
  - Blocks direct raw IP connections when configured.
- [x] **Workspace Boundary & Symlink Sandboxing:**
  - Enforces strict boundary verification to prevent directory traversal and symlink escapes outside the workspace root.

---

## 📍 Phase 4: Community Polish & Launch Preparation (Completed ✅)
- [x] **GitHub Polish:**
  - Added interactive demo SVG terminal recording (`assets/demo.svg`).
  - Added GitHub release & status badges (CI passing, 40 tests, TypeScript 100%, Node >=18, MIT).
  - Added [`CONTRIBUTING.md`](./CONTRIBUTING.md) guide for contributing custom security rules and presets.
  - Added [`SECURITY.md`](./SECURITY.md) for responsible disclosure.
- [x] **Launch Materials Prepared:**
  - Authored Show HN announcement draft in [`LAUNCH.md`](./LAUNCH.md).
  - Authored tailored discussion templates for Reddit (`r/LocalLLaMA`, `r/programming`, `r/node`).
  - Authored 5-part release thread for X / Twitter.
- [ ] **Community Broadcast (Ready to Publish 🚀):**
  - [ ] Submit Show HN post to Hacker News.
  - [ ] Post announcement across developer subreddits.
  - [ ] Publish launch thread on X / Twitter.

---

## 📍 Phase 5: Team & Enterprise Security (Future Horizon)
- [ ] **Centralized Policy Sync:** Fetch team security rules from a shared GitHub repo, S3 bucket, or internal URL.
- [ ] **Slack / Discord Security Alerts:** Webhook notifications when an agent attempts a critical prohibited action.
- [ ] **Lightweight Web Audit Dashboard:** Visual browser interface to search through agent tool calls, latency, and blocked violations.
