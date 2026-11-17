/**
 * Abstract Syntax & Command Chain Decomposer.
 * Deconstructs compound shell lines (&&, ||, ;, |, subshells) into discrete atomic commands.
 */

export interface AtomicCommand {
  raw: string;
  cleaned: string;
  isSubshell: boolean;
}

export function extractSubshells(input: string): string[] {
  const subshells: string[] = [];

  // 1. Match $(...) subshells (handles non-nested)
  const dollarParenRegex = /\$\(([^)]+)\)/g;
  let match: RegExpExecArray | null;
  while ((match = dollarParenRegex.exec(input)) !== null) {
    if (match[1]) subshells.push(match[1].trim());
  }

  // 2. Match `...` backtick subshells
  const backtickRegex = /`([^`]+)`/g;
  while ((match = backtickRegex.exec(input)) !== null) {
    if (match[1]) subshells.push(match[1].trim());
  }

  return subshells;
}

/**
 * Strips leading environment variable assignments (e.g. FOO=bar BAZ=123 npm test -> npm test)
 */
export function stripEnvPrefixes(cmd: string): string {
  let trimmed = cmd.trim();
  const envAssignRegex = /^[a-zA-Z_][a-zA-Z0-9_]*=(?:'[^']*'|"[^"]*"|\S+)\s+/;

  while (envAssignRegex.test(trimmed)) {
    trimmed = trimmed.replace(envAssignRegex, '').trim();
  }

  return trimmed;
}

/**
 * Decomposes a compound command line into atomic commands to evaluate individually
 */
export function decomposeCommands(commandLine: string): AtomicCommand[] {
  const results: AtomicCommand[] = [];

  // Extract subshells first
  const subshells = extractSubshells(commandLine);
  for (const sub of subshells) {
    results.push({
      raw: sub,
      cleaned: stripEnvPrefixes(sub),
      isSubshell: true
    });
  }

  // Split top-level by command chain operators: &&, ||, ;, |, &, newline
  // We respect quoted strings so quotes with ';' or '&&' aren't split
  const segments: string[] = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;
  let escape = false;

  for (let i = 0; i < commandLine.length; i++) {
    const char = commandLine[i];
    const next = commandLine[i + 1];

    if (escape) {
      current += char;
      escape = false;
      continue;
    }

    if (char === '\\') {
      escape = true;
      current += char;
      continue;
    }

    if (char === "'" && !inDouble) {
      inSingle = !inSingle;
      current += char;
      continue;
    }

    if (char === '"' && !inSingle) {
      inDouble = !inDouble;
      current += char;
      continue;
    }

    // Outside quotes: check operators
    if (!inSingle && !inDouble) {
      if ((char === '&' && next === '&') || (char === '|' && next === '|')) {
        if (current.trim()) segments.push(current.trim());
        current = '';
        i++; // skip next operator char
        continue;
      }

      if (char === ';' || char === '\n' || char === '|' || char === '&') {
        if (current.trim()) segments.push(current.trim());
        current = '';
        continue;
      }
    }

    current += char;
  }

  if (current.trim()) {
    segments.push(current.trim());
  }

  for (const seg of segments) {
    results.push({
      raw: seg,
      cleaned: stripEnvPrefixes(seg),
      isSubshell: false
    });
  }

  return results;
}

/**
 * Checks for obfuscated shell execution via base64 decoding
 */
export function detectBase64Execution(command: string): boolean {
  return /\b(base64\s+(-d|--decode)|openssl\s+base64\s+-d)\b.*\|\s*(sh|bash|zsh|python|node)\b/i.test(command);
}
