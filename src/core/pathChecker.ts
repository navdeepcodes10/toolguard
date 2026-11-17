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

/**
 * Validates that a path stays strictly inside the designated workspace boundary,
 * preventing symlink escapes and directory traversal.
 */
export function isWithinWorkspace(targetPath: string, workspaceRoot: string): { allowed: boolean; reason?: string } {
  try {
    const normRoot = path.resolve(workspaceRoot);
    let resolvedTarget: string;

    if (fs.existsSync(targetPath)) {
      resolvedTarget = fs.realpathSync(targetPath);
    } else {
      resolvedTarget = path.resolve(targetPath);
    }

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
