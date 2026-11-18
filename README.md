<div align="center">
  <img src="./assets/logo.jpg" alt="ToolGuard Logo" width="220" style="border-radius: 20px;" />
  <h1>🛡️ ToolGuard</h1>
  <p><strong>The open-source security firewall & permission guard for AI coding assistants and MCP servers.</strong></p>

  <p>
    <a href="https://www.npmjs.com/package/@navdeepcodes10/toolguard"><img src="https://img.shields.io/npm/v/@navdeepcodes10/toolguard.svg?style=flat&color=CB3837" alt="npm version" /></a>
    <a href="https://github.com/navdeepcodes10/toolguard/actions"><img src="https://github.com/navdeepcodes10/toolguard/actions/workflows/ci.yml/badge.svg" alt="CI Status" /></a>
    <img src="https://img.shields.io/badge/tests-40%20passing-brightgreen.svg" alt="Tests: 40 passing" />
    <img src="https://img.shields.io/badge/typescript-100%25-blue.svg" alt="TypeScript" />
    <img src="https://img.shields.io/badge/node-%3E%3D18.0.0-informational.svg" alt="Node >= 18" />
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT" />
  </p>
</div>

---

<p align="center">
  <img src="./assets/demo.svg" alt="ToolGuard Interactive Terminal Demo" width="100%" />
</p>

---

Give autonomous AI tools the freedom to read code and run tests at lightning speed, while completely shielding your system from accidental file deletion, dangerous terminal commands, and secret credential leaks.

---

## ⚡ How It Works

Think of your AI assistant as a smart robot intern working on your computer.

- **Without ToolGuard:** You either have to confirm every single harmless command (exhausting), or turn off confirmations and pray the AI never hallucinates `rm -rf /` or leaks your passwords.
- **With ToolGuard:** An intelligent security guard stands right next to the assistant:
  - 🟢 **Safe commands** (`git status`, `npm test`, `ls`) run instantly without bugging you.
  - 🟡 **Sensitive commands** (installing packages, `git reset`) ask for quick confirmation.
  - 🔴 **Destructive commands** (`rm -rf /`, database wipes, credential exfiltration) are stopped cold.

---

## 🚀 Quick Start

### 1. Evaluate Any Command
Inspect what ToolGuard thinks of a command before running it:

```bash
npx @navdeepcodes10/toolguard eval "git status"
# Verdict: ALLOW (Risk: SAFE)

npx @navdeepcodes10/toolguard eval "rm -rf /"
# Verdict: BLOCK (Risk: CRITICAL)
```

### 2. Safely Run Commands
Wrap autonomous commands with the firewall:

```bash
npx @navdeepcodes10/toolguard run "npm test"
```

### 3. Community Rule Presets
List and enable pre-configured security packs for Docker, Node.js, and Python:

```bash
npx @navdeepcodes10/toolguard presets
```

### 4. One-Command Shell Shield
Automatically shield commands in your terminal or subshell:

```bash
# Install globally so toolguard is available in your PATH
npm install -g @navdeepcodes10/toolguard

# Add to ~/.zshrc or ~/.bashrc
eval "$(toolguard hook)"

# Or install hook automatically
toolguard hook --install
```

### 5. Initialize Custom Repository Rules
Create a `.toolguard.yaml` configuration in your repo:

```bash
npx @navdeepcodes10/toolguard init
```

### 6. Review Audit History
See past executions, blocked commands, and timestamps:

```bash
npx @navdeepcodes10/toolguard audit
```

---

## 🔌 Integrations

- [Cursor IDE Setup Guide](./integrations/cursor.md)
- [Claude Code & MCP Setup Guide](./integrations/claude-code.md)


---

## ⚙️ Configuration (`.toolguard.yaml`)

```yaml
version: "1.0"
mode: "enforce" # Options: enforce, audit, interactive

# Automatically allow these commands without prompting
allowedCommands:
  - "git status"
  - "git diff"
  - "npm test"
  - "npm run lint"

# Hard block these commands regardless of context
blockedCommands:
  - "rm -rf /"
  - "drop database"

# Protected file paths that agents should not read or modify
protectedPaths:
  - ".env"
  - ".env.production"
  - "~/.ssh"

# Network & Outbound Security (Phase 3)
network:
  blockCloudMetadata: true # Blocks SSRF to 169.254.169.254
  blockRawIPs: true        # Restricts connections to raw IP addresses
  blockedDomains:
    - "malicious-domain.com"
  allowedDomains:
    - "github.com"
    - "registry.npmjs.org"

# Enforce strict project boundary (blocks symlink escapes)
sandboxWorkspace: true

# Scan commands and tool inputs for leaked API keys
detectSecrets: true
```

---

## 📦 Use as an SDK in Custom Agents

```typescript
import { ToolGuardEngine } from '@navdeepcodes10/toolguard';

const engine = new ToolGuardEngine();
const result = engine.evaluate('rm -rf /');

if (result.verdict === 'BLOCK') {
  console.error(`Blocked by ToolGuard: ${result.reason}`);
}
```

---

## 🧪 Testing

Run the built-in test suite:

```bash
npm test
```

---

## 🤝 Community & Roadmap

- 📖 **[Contribution Guide](./CONTRIBUTING.md)** — Guidelines for contributing security rules and presets.
- 🔒 **[Security Policy](./SECURITY.md)** — Responsible disclosure and reporting.
- 🗺️ **[Project Roadmap](./ROADMAP.md)** — Development phases, upcoming features, and enterprise horizon.
- 🚀 **[Launch Kit](./LAUNCH.md)** — Discussion threads and release notes for HN, Reddit, and X.
