export const DEFAULT_CONFIG_YAML = `# ToolGuard Security Configuration
# The open-source security firewall for AI coding agents & MCP servers
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
`;
