/**
 * Quote-aware shell command line tokenizer.
 * Preserves already-separated argument arrays directly.
 * Only tokenizes single-string command representations, respecting quotes, empty strings, and backslashes.
 */
export function parseCommandLine(cmdParts: string[]): string[] {
  // If caller already passed discrete separate arguments, preserve them directly
  if (cmdParts.length > 1) {
    return cmdParts;
  }

  if (cmdParts.length === 0) {
    return [];
  }

  const full = cmdParts[0].trim();
  if (!full) return [];

  const args: string[] = [];
  let current = '';
  let hasToken = false;
  let inSingle = false;
  let inDouble = false;
  let escape = false;

  for (let i = 0; i < full.length; i++) {
    const char = full[i];

    if (escape) {
      current += char;
      hasToken = true;
      escape = false;
      continue;
    }

    if (inSingle) {
      if (char === "'") {
        inSingle = false;
      } else {
        current += char;
      }
      hasToken = true;
      continue;
    }

    if (inDouble) {
      if (char === '"') {
        inDouble = false;
        hasToken = true;
        continue;
      }
      if (char === '\\') {
        const next = full[i + 1];
        // In POSIX double quotes, backslash only escapes $, `, ", \, and newline
        if (next === '$' || next === '`' || next === '"' || next === '\\' || next === '\n') {
          escape = true;
          hasToken = true;
          continue;
        }
      }
      current += char;
      hasToken = true;
      continue;
    }

    // Unquoted state
    if (char === '\\') {
      escape = true;
      hasToken = true;
      continue;
    }

    if (char === "'") {
      inSingle = true;
      hasToken = true;
      continue;
    }

    if (char === '"') {
      inDouble = true;
      hasToken = true;
      continue;
    }

    if (/\s/.test(char)) {
      if (hasToken) {
        args.push(current);
        current = '';
        hasToken = false;
      }
      continue;
    }

    current += char;
    hasToken = true;
  }

  if (hasToken) {
    args.push(current);
  }

  return args;
}
