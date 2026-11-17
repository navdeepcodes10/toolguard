/**
 * Quote-aware shell command line tokenizer.
 * Correctly strips shell quote boundaries (both wholly quoted and embedded fragments like --flag="val")
 * while preserving literal argument content without executing subshells.
 */
export function parseCommandLine(cmdParts: string[]): string[] {
  const full = cmdParts.join(' ').trim();
  if (!full) return [];

  const args: string[] = [];
  let current = '';
  let inSingle = false;
  let inDouble = false;
  let escape = false;

  for (let i = 0; i < full.length; i++) {
    const char = full[i];

    if (escape) {
      current += char;
      escape = false;
      continue;
    }

    if (char === '\\' && !inSingle) {
      escape = true;
      continue;
    }

    if (char === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }

    if (char === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }

    if (/\s/.test(char) && !inSingle && !inDouble) {
      if (current.length > 0) {
        args.push(current);
        current = '';
      }
      continue;
    }

    current += char;
  }

  if (current.length > 0) {
    args.push(current);
  }

  return args;
}
