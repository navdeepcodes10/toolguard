import fs from 'fs';
import path from 'path';
import os from 'os';
import pc from 'picocolors';

export function generateShellHook(shell: string = 'zsh'): string {
  if (shell === 'fish') {
    return `# ToolGuard Shell Integration (fish)
function tg
    toolguard run -- $argv
end

function rm
    toolguard run -- rm $argv
end

function git
    toolguard run -- git $argv
end
`;
  }

  // Default to posix / zsh / bash
  return `# ToolGuard Shell Integration (zsh / bash)
# Automatically shields interactive and agent commands

# Quick shorthand
alias tg="toolguard run --"

# Protected critical command wrappers
_toolguard_shield_rm() {
  toolguard run -- rm "$@"
}
alias rm="_toolguard_shield_rm"

_toolguard_shield_git() {
  toolguard run -- git "$@"
}
alias git="_toolguard_shield_git"

# Status helper
toolguard_status() {
  echo "🛡️ ToolGuard active in shell session ($SHELL)"
}
`;
}

export function installShellHook(shell: string = 'zsh'): { success: boolean; message: string } {
  const home = os.homedir();

  if (shell === 'fish') {
    const fishDir = path.join(home, '.config', 'fish', 'conf.d');
    const targetFile = path.join(fishDir, 'toolguard.fish');
    try {
      if (!fs.existsSync(fishDir)) {
        fs.mkdirSync(fishDir, { recursive: true });
      }
      fs.writeFileSync(targetFile, generateShellHook('fish'), 'utf-8');
      return { success: true, message: `Successfully installed ToolGuard hook in ${targetFile}` };
    } catch (err: any) {
      return { success: false, message: `Failed to install fish hook: ${err.message}` };
    }
  }

  const targetFile = shell === 'zsh'
    ? path.join(home, '.zshrc')
    : path.join(home, '.bashrc');

  const hookLine = `\n# ToolGuard Shell Hook\neval "$(toolguard hook)"\n`;

  try {
    if (fs.existsSync(targetFile)) {
      const content = fs.readFileSync(targetFile, 'utf-8');
      if (content.includes('toolguard hook')) {
        return { success: true, message: `ToolGuard hook is already installed in ${targetFile}` };
      }
      fs.appendFileSync(targetFile, hookLine, 'utf-8');
      return { success: true, message: `Successfully added ToolGuard hook to ${targetFile}` };
    } else {
      fs.writeFileSync(targetFile, hookLine, 'utf-8');
      return { success: true, message: `Created ${targetFile} with ToolGuard hook` };
    }
  } catch (err: any) {
    return { success: false, message: `Failed to install hook: ${err.message}` };
  }
}
