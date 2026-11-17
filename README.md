<div align="center">
  <img src="./assets/logo.jpg" alt="ToolGuard Logo" width="220" style="border-radius: 20px;" />
  <h1>🛡️ ToolGuard</h1>
  <p><strong>The open-source security firewall & permission guard for AI coding assistants and MCP servers.</strong></p>
</div>

---

Give autonomous AI tools the freedom to read code and run tests at lightning speed, while completely shielding your system from accidental file deletion, dangerous terminal commands, and secret credential leaks.

---

## ⚡ The Big Idea (Explain Like I'm 5)

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
npx toolguard eval "git status"
# Verdict: ALLOW (Risk: SAFE)

npx toolguard eval "rm -rf /"
# Verdict: BLOCK (Risk: CRITICAL)
```

### 2. Safely Run Commands
Wrap autonomous commands with the firewall:

```bash
npx toolguard run "npm test"
```

### 3. Initialize Custom Repository Rules
Create a `.toolguard.yaml` configuration in your repo:

```bash
npx toolguard init
```

### 4. Review Audit History
See past executions, blocked commands, and timestamps:

```bash
npx toolguard audit
```

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

# Scan commands and tool inputs for leaked API keys
detectSecrets: true
```

---

## 📦 Use as an SDK in Custom Agents

```typescript
import { ToolGuardEngine } from 'toolguard';

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

## 🤝 Contributing

Contributions, additional rule presets, and feature requests are welcome! Feel free to open an issue or pull request.
