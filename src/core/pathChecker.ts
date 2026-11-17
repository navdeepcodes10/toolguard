import path from 'path';

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

export function isPathProtected(targetPath: string, customProtectedPaths?: string[]): { isProtected: boolean; reason?: string } {
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

  // Path traversal check
  if (targetPath.includes('../../../') || targetPath.includes('..\\..\\..\\')) {
    return {
      isProtected: true,
      reason: 'Deep directory traversal detected'
    };
  }

  return { isProtected: false };
}
