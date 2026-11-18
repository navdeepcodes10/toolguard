# 🚀 ToolGuard Public Launch Kit

Ready-to-use launch drafts, messaging hooks, and discussion points for sharing ToolGuard across developer communities.

---

## 1. 🟠 Hacker News (Show HN)

**Title:**
> Show HN: ToolGuard – Open-source security firewall and permission proxy for AI coding agents

**Link:**
> https://github.com/navdeepcodes10/toolguard

**Post Text:**
> Hey HN,
>
> I built ToolGuard because I wanted autonomous coding agents (Claude Code, Cursor, MCP servers) to run builds and read files quickly without risking accidental system damage or credential leakage.
>
> **The Problem:**
> When running autonomous agents in your terminal or workspace, you face a dilemma:
> 1. Approve every single innocuous command (`git status`, `npm test`, `ls`) manually — which breaks the autonomous workflow.
> 2. Grant unrestricted execution and risk catastrophic mistakes (e.g., unintended `rm -rf /`, force-pushing over `main`, or leaking `.env` secrets into remote APIs).
>
> **How ToolGuard solves this:**
> ToolGuard operates as a lightweight, zero-latency policy engine and proxy:
> - **Tri-State Verdicts:** Classifies every tool or shell execution into `ALLOW` (harmless read-only commands proceed without prompts), `PROMPT` (sensitive operations like package installs require interactive confirmation), and `BLOCK` (destructive wipes, disk formatting, and credential exfiltration are stopped immediately).
> - **AST Command Decomposition:** Recursively breaks down compound commands (`&&`, `||`, `;`, pipes, subshells) to ensure hidden destructive segments cannot slip through.
> - **SSRF & Cloud Metadata Shield:** Blocks outbound attempts to query Cloud Instance Metadata (`169.254.169.254` and `fd00:ec2::254`).
> - **Filesystem Sandboxing:** Resolves symlinks in filesystem order to prevent directory traversal outside the active workspace.
> - **MCP Stdio Proxy:** Acts as an inline firewall between IDEs and Model Context Protocol servers.
>
> It runs in <15ms with zero external runtime dependencies.
>
> GitHub: https://github.com/navdeepcodes10/toolguard
>
> Feedback and contributions to community security rules are very welcome!

---

## 2. 🤖 Reddit (r/LocalLLaMA & r/programming)

**Title:**
> I built ToolGuard: A zero-latency firewall to stop autonomous coding agents from wiping files or leaking secrets

**Content:**
> If you give local LLMs or AI assistants terminal access, safety is always an issue: either you manually confirm every command, or you risk an agent running a destructive command or leaking your `.env` file.
>
> I created **ToolGuard**, an open-source security firewall written in TypeScript:
>
> 🔹 **Zero prompt fatigue:** Harmless commands like `npm test` or `git status` are allowed instantly.  
> 🔹 **Hard blocks:** Blocks `rm -rf /`, `mkfs`, force-pushes, and DB drops.  
> 🔹 **Secret leak prevention:** Catches OpenAI keys, GitHub tokens, and `.env` references before network dispatch.  
> 🔹 **AST & Subshell parsing:** Parses chained commands (`cmd1 && cmd2`), subshells (`$(...)`), and base64 decode pipes.  
> 🔹 **MCP Server Guard:** Run `toolguard mcp-proxy <server>` to inspect all incoming tool calls via standard JSON-RPC.  
>
> Fully tested (40/40 tests passing), ultra-lightweight (<30 KB tarball, <100 KB unpacked), and open source on GitHub.
>
> Repo: https://github.com/navdeepcodes10/toolguard

---

## 3. 🐦 X / Twitter Thread

**Tweet 1 (Hook):**
> Giving AI coding agents terminal access shouldn't mean risking your entire system.
>
> Announcing 🛡️ ToolGuard: An open-source security firewall & permission proxy for AI agents (Claude Code, Cursor, MCP).
>
> ⚡ Zero prompt fatigue. Zero accidental wipes.
> 🔗 https://github.com/navdeepcodes10/toolguard

**Tweet 2 (How it Works):**
> ToolGuard uses a tri-state classification engine:
>
> 🟢 ALLOW: `git status`, `npm test` execute instantly with 0ms delay.  
> 🟡 PROMPT: `git reset --hard` asks for interactive confirmation.  
> 🔴 BLOCK: `rm -rf /`, raw disk formats, and secret leaks are blocked cold.

**Tweet 3 (Compound Commands & AST):**
> Sneaky commands won't bypass it.
>
> ToolGuard decomposes compound commands (`&&`, `;`, `|`, `$(...)`), unmasks base64 pipes, strips env prefixes (`FOO=bar rm -rf /`), and verifies each atomic command.

**Tweet 4 (SSRF & Sandboxing):**
> It also blocks:
> - Cloud Instance Metadata SSRF (`169.254.169.254`)
> - Symlink traversal outside your workspace root
> - Transmission of `.env` files or API keys

**Tweet 5 (Get Started):**
> Try it instantly:
> ```bash
> npx toolguard eval "rm -rf /"
> ```
> Star the repo on GitHub: https://github.com/navdeepcodes10/toolguard
