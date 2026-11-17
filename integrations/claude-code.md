# Integrating ToolGuard with Claude Code & MCP

Shield your Claude Code terminal sessions and Model Context Protocol (MCP) servers with ToolGuard.

## 1. Claude Code CLI Config
In your project or home directory, wrap any MCP server using ToolGuard's proxy:

```json
{
  "mcpServers": {
    "filesystem-shielded": {
      "command": "npx",
      "args": [
        "toolguard",
        "mcp-proxy",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/path/to/project"
      ]
    }
  }
}
```

## 2. Shell Command Wrapping
Whenever Claude Code executes terminal commands:
```bash
npx toolguard run "<command>"
```
Dangerous commands like `rm -rf /` or credential dumps will immediately halt with exit code 1, preventing damage.
