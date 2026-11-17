# Integrating ToolGuard with Cursor IDE

ToolGuard can be integrated into Cursor to prevent autonomous background agent tasks and terminal sessions from executing destructive commands.

## Option 1: Using `.cursorrules`
Add the following to your project's `.cursorrules` file:

```markdown
# Safety & Execution Rules
- Before running any destructive commands or modifying system files, verify with ToolGuard:
  \`npx toolguard eval "<command>"\`
- Run autonomous build and test scripts wrapped in ToolGuard:
  \`npx toolguard run "<command>"\`
- Never read, display, or upload credentials from \`.env\` or \`~/.ssh/\`.
```

## Option 2: Pre-execution Terminal Wrapper
In your Cursor terminal settings or task runner, alias sensitive operations through `toolguard run`.
