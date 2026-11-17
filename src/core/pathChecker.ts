import path from 'path';
import fs from 'fs';

export const PROTECTED_SYSTEM_PATHS = [
  '/etc',
  '/boot',
  '/sys',
  '/proc',
  '/usr/bin',
  '/usr/sbin',
  '/System',
  '/Library/Preferences'
];

export const SENSITIVE_FILE_NAMES = [
  /^\.env(\.[a-zA-Z0-9_\-]+)?$/,
  /^id_rsa(\.pub)?$/,
  /^id_ed25519(\.pub)?$/,
  /^credentials\.json$/,
  /^service-account.*\.json$/
];

const MAX_SYMLINK_DEPTH = 40;

/**
 * Resolves path components in strict filesystem order, ensuring that parent-directory (..)
 * segments apply to the real directory reached through symlinks rather than collapsing lexically (CWE-59),
 * and following dangling symlinks recursively to verify their true boundary.
 */
export function resolveComponentsInOrder(startDir: string, targetPath: string, depth: number = 0): string {
  if (depth > MAX_SYMLINK_DEPTH) {
    throw new Error('Too many levels of symbolic links (possible symlink loop)');
  }

  const isWindows = process.platform === 'win32';
  const sepRegex = isWindows ? /[\\/]+/ : /\/+/;
  const isAbs = path.isAbsolute(targetPath);

  let current: string;
  let pathWithoutRoot = targetPath;

  if (isAbs) {
    const root = path.parse(targetPath).root || (isWindows ? 'C:\\' : '/');
    current = fs.existsSync(root) ? fs.realpathSync(root) : root;
    pathWithoutRoot = targetPath.slice(root.length);
  } else {
    current = fs.existsSync(startDir) ? fs.realpathSync(startDir) : startDir;
  }

  const parts = pathWithoutRoot.split(sepRegex).filter(Boolean);

  for (const part of parts) {
    if (part === '.') continue;

    if (part === '..') {
      current = path.dirname(current);
      if (fs.existsSync(current)) {
        current = fs.realpathSync(current);
      }
      continue;
    }

    const candidate = path.join(current, part);

    if (fs.existsSync(candidate)) {
      current = fs.realpathSync(candidate);
    } else {
      // Check for dangling or missing symlink at candidate
      let isSymlink = false;

      try {
        const stat = fs.lstatSync(candidate);
        isSymlink = stat.isSymbolicLink();
      } catch {
        // Expected lookup failure (file does not exist as symlink either)
      }

      if (isSymlink) {
        // Let readlinkSync errors propagate so TOCTOU race conditions (CWE-367)
        // fail safely to isWithinWorkspace's denial handler rather than recursing with empty target.
        const rawLink = fs.readlinkSync(candidate);

        const start = path.isAbsolute(rawLink)
          ? (path.parse(rawLink).root || (isWindows ? 'C:\\' : '/'))
          : path.dirname(candidate);

        current = resolveComponentsInOrder(start, rawLink, depth + 1);
        continue;
      }

      current = candidate;
    }
  }

  return current;
}

/**
 * Validates that a path stays strictly inside the designated workspace boundary,
 * preventing symlink escapes (CWE-59), dangling link bypasses, and directory traversal.
 */
export function isWithinWorkspace(targetPath: string, workspaceRoot: string): { allowed: boolean; reason?: string } {
  try {
    const resolvedRoot = path.resolve(workspaceRoot);
    const normRoot = fs.existsSync(resolvedRoot)
      ? fs.realpathSync(resolvedRoot)
      : resolvedRoot;

    // Always resolve components in strict filesystem order to prevent lexical .. traversal bypasses
    const resolvedTarget = resolveComponentsInOrder(normRoot, targetPath);

    if (resolvedTarget !== normRoot && !resolvedTarget.startsWith(normRoot + path.sep)) {
      return {
        allowed: false,
        reason: `Access outside workspace boundary is blocked (resolved to '${resolvedTarget}')`
      };
    }

    return { allowed: true };
  } catch (err: any) {
    return {
      allowed: false,
      reason: `Failed to verify path boundary safety: ${err.message}`
    };
  }
}

export function isPathProtected(
  targetPath: string,
  customProtectedPaths?: string[],
  workspaceRoot?: string
): { isProtected: boolean; reason?: string } {
  const normalized = path.normalize(targetPath);
  const baseName = path.basename(normalized);

  // Check sensitive file names
  for (const regex of SENSITIVE_FILE_NAMES) {
    if (regex.test(baseName)) {
      return {
        isProtected: true,
        reason: `Access to sensitive credential file '${baseName}' is restricted`
      };
    }
  }

  // Check system directories
  for (const sysPath of PROTECTED_SYSTEM_PATHS) {
    if (normalized === sysPath || normalized.startsWith(sysPath + path.sep)) {
      return {
        isProtected: true,
        reason: `Target path is located in critical system directory '${sysPath}'`
      };
    }
  }

  // Check user-defined protected paths
  if (customProtectedPaths) {
    for (const p of customProtectedPaths) {
      const normCustom = path.normalize(p);
      if (normalized === normCustom || normalized.startsWith(normCustom + path.sep)) {
        return {
          isProtected: true,
          reason: `Path matches user-protected location '${p}'`
        };
      }
    }
  }

  // Workspace sandbox boundary check
  if (workspaceRoot) {
    const wsCheck = isWithinWorkspace(targetPath, workspaceRoot);
    if (!wsCheck.allowed) {
      return {
        isProtected: true,
        reason: wsCheck.reason
      };
    }
  }

  // Path traversal check
  if (targetPath.includes('../../../') || targetPath.includes('..\\..\\..\\')) {
    return {
      isProtected: true,
      reason: 'Deep directory traversal detected'
    };
  }

  return { isProtected: false };
}
