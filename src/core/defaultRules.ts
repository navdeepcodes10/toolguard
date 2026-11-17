import { SecurityRule } from '../types';

export const DEFAULT_RULES: SecurityRule[] = [
  // ================= CRITICAL RULES (Hard BLOCK) =================
  {
    id: 'crit-root-wipe',
    name: 'Root or Home Wipe Prevention',
    description: 'Prevents recursive deletion of root, home directory, or parent paths',
    risk: 'CRITICAL',
    action: 'BLOCK',
    patterns: [
      /\brm\s+-[a-zA-Z]*[rf][a-zA-Z0-9]*\s+(\/|~|\.\.|\/\*|\$HOME)(\s+|$)/,
      /\brm\s+--recursive\s+--force\s+(\/|~|\.\.|\/\*|\$HOME)(\s+|$)/,
      /\brm\s+-rf\s+(\/|~|\.\.|\/\*|\$HOME)(\s+|$)/
    ],
    mitigation: 'Target a specific isolated subfolder instead of the entire root, home, or parent directory.'
  },
  {
    id: 'crit-disk-format',
    name: 'Raw Disk Overwrite or Format',
    description: 'Prevents direct write or formatting of raw disk blocks',
    risk: 'CRITICAL',
    action: 'BLOCK',
    patterns: [
      /\bmkfs(\.[a-zA-Z0-9]+)?\b/,
      /\bdd\s+if=.*of=\/dev\/(sd|hd|nvme|disk)/,
      /\bfdisk\b/,
      /\bparted\b/
    ],
    mitigation: 'Use standard file manipulation commands instead of raw block devices.'
  },
  {
    id: 'crit-fork-bomb',
    name: 'Denial of Service / Fork Bomb',
    description: 'Detects shell fork bombs and endless self-replicating commands',
    risk: 'CRITICAL',
    action: 'BLOCK',
    patterns: [
      /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
      /\bchmod\s+(-R\s+)?777\s+(\/|~|\/etc|\/usr)(\s+|$)/
    ],
    mitigation: 'Ensure proper permissions without granting blanket global 777 access to system directories.'
  },
  {
    id: 'crit-git-force-master',
    name: 'Git Main/Master Force Push Protection',
    description: 'Prevents overwriting git history on production branches',
    risk: 'CRITICAL',
    action: 'BLOCK',
    patterns: [
      /\bgit\s+push\b.*(--force|-f)\b.*(main|master|prod|production)\b/,
      /\bgit\s+push\b.*(main|master|prod|production)\b.*(--force|-f)\b/
    ],
    mitigation: 'Use normal git push or create a feature branch with a pull request.'
  },
  {
    id: 'crit-db-drop-all',
    name: 'Destructive Database Drop',
    description: 'Prevents unconfirmed dropping of whole databases or tables',
    risk: 'CRITICAL',
    action: 'BLOCK',
    patterns: [
      /\bDROP\s+(DATABASE|SCHEMA)\b/i,
      /\bDROP\s+TABLE\s+(users|accounts|customers|orders|payments|auth|production)/i,
      /\bTRUNCATE\s+(TABLE\s+)?(users|accounts|customers|orders|payments)/i
    ],
    mitigation: 'Run database migrations with a verified rollback strategy.'
  },

  // ================= HIGH RULES (BLOCK or SENSITIVE EXFILTRATION) =================
  {
    id: 'high-secret-exfil',
    name: 'Secret Exfiltration via HTTP/Net',
    description: 'Blocks piping or transmitting .env, tokens, or private keys to external servers',
    risk: 'HIGH',
    action: 'BLOCK',
    patterns: [
      /\b(curl|wget|nc|ncat|netcat)\b.*(\.env|id_rsa|id_ed25519|credentials\.json|\.aws\/credentials)/i,
      /\b(cat|head|tail)\s+.*(\.env|id_rsa|id_ed25519)\s*\|\s*(curl|wget|nc)/i
    ],
    mitigation: 'Never send secrets or environment files across remote networks.'
  },
  {
    id: 'high-system-identity',
    name: 'System Identity / Password File Tampering',
    description: 'Blocks tampering with system password files, crontab, or hosts',
    risk: 'HIGH',
    action: 'BLOCK',
    patterns: [
      /\b(>|>>)\s*\/etc\/(passwd|shadow|hosts|sudoers)/,
      /\bcrontab\s+-r\b/
    ],
    mitigation: 'System configuration must be edited manually with sudo privileges.'
  },

  // ================= MEDIUM RULES (PROMPT USER) =================
  {
    id: 'med-git-destructive',
    name: 'Destructive Local Git Action',
    description: 'Prompts before wiping local uncommitted changes or recent commits',
    risk: 'MEDIUM',
    action: 'PROMPT',
    patterns: [
      /\bgit\s+reset\s+--hard\b/,
      /\bgit\s+clean\s+-[a-zA-Z]*f[a-zA-Z]*\b/,
      /\bgit\s+checkout\s+--\s+\.\b/
    ],
    mitigation: 'Check if you have uncommitted changes with `git status` first.'
  },
  {
    id: 'med-package-global',
    name: 'Global Package Installation',
    description: 'Prompts before installing global binaries on the host system',
    risk: 'MEDIUM',
    action: 'PROMPT',
    patterns: [
      /\bnpm\s+(i|install)\s+(-g|--global)\b/,
      /\bpip\s+install\s+.*--break-system-packages\b/,
      /\bsudo\s+(apt|brew|dnf|pacman|yum)\b/
    ],
    mitigation: 'Prefer local project dependencies or virtual environments where possible.'
  },
  {
    id: 'med-shell-profile',
    name: 'Shell Profile Modification',
    description: 'Prompts before appending commands to shell startup profiles (.zshrc, .bashrc)',
    risk: 'MEDIUM',
    action: 'PROMPT',
    patterns: [
      /\b(>|>>)\s*~?\/?\.(zshrc|bashrc|bash_profile|profile)\b/
    ],
    mitigation: 'Review shell configuration additions carefully to prevent startup persistence hooks.'
  }
];

export const SAFE_COMMAND_PATTERNS: RegExp[] = [
  /^git\s+(status|diff|log|branch|show|remote|tag)(\s+.*)?$/,
  /^(ls|pwd|whoami|date|uptime|uname)(\s+.*)?$/,
  /^(cat|head|tail|grep|find|wc|sort|uniq)(\s+.*)?$/,
  /^(npm\s+test|npm\s+run\s+test|npm\s+run\s+lint|npm\s+run\s+build|npm\s+run\s+check)(\s+.*)?$/,
  /^(pytest|cargo\s+check|cargo\s+test|go\s+test|tsc\s+--noEmit)(\s+.*)?$/
];
