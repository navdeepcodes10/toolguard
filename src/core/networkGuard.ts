import { EvaluationResult, RiskLevel } from '../types';

export interface NetworkGuardConfig {
  allowedDomains?: string[];
  blockedDomains?: string[];
  blockRawIPs?: boolean;
  blockCloudMetadata?: boolean;
}

// AWS, GCP, Azure, OpenStack instance metadata service IP
export const CLOUD_METADATA_IP = '169.254.169.254';

// Common trusted developer registries and repositories
export const DEFAULT_ALLOWED_DOMAINS = [
  'github.com',
  'api.github.com',
  'raw.githubusercontent.com',
  'registry.npmjs.org',
  'registry.yarnpkg.com',
  'pypi.org',
  'files.pythonhosted.org',
  'crates.io',
  'pkg.go.dev',
  'deno.land',
  'docker.io',
  'registry-1.docker.io'
];

/**
 * Extracts target hostnames, URLs, or IP addresses from network commands (curl, wget, etc.)
 */
export function extractNetworkTargets(command: string): string[] {
  const targets: string[] = [];

  // Match URLs (http, https, ftp, git)
  const urlRegex = /\b(?:https?|ftp|git):\/\/([a-zA-Z0-9_\-\.]+)(?::\d+)?(?:\/[^\s"']*)?/gi;
  let match: RegExpExecArray | null;

  while ((match = urlRegex.exec(command)) !== null) {
    if (match[1]) {
      targets.push(match[1].toLowerCase());
    }
  }

  // Match bare IPs or hostnames passed to ping, nc, ncat, telnet, curl, wget
  const hostParamRegex = /\b(?:curl|wget|nc|ncat|netcat|ping|ssh|scp)\s+(?:-[a-zA-Z0-9\-_=]+\s+)*([a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9_\-\.]+)/gi;
  while ((match = hostParamRegex.exec(command)) !== null) {
    const host = match[1].toLowerCase();
    if (!host.startsWith('-') && !targets.includes(host)) {
      targets.push(host);
    }
  }

  return targets;
}

/**
 * Checks if a target host is an IPv4 or IPv6 address
 */
export function isIpAddress(host: string): boolean {
  // IPv4
  const ipv4Regex = /^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(host) || host.includes(':');
}

/**
 * Evaluates network targets against security rules and domain policies
 */
export function evaluateNetworkTarget(
  target: string,
  config?: NetworkGuardConfig
): { blocked: boolean; risk: RiskLevel; reason: string } | null {
  const normalized = target.toLowerCase();

  // 1. Cloud Instance Metadata SSRF Protection (Critical)
  if (config?.blockCloudMetadata !== false) {
    if (normalized === CLOUD_METADATA_IP || normalized.includes('169.254.169.254')) {
      return {
        blocked: true,
        risk: 'CRITICAL',
        reason: 'Attempted access to Cloud Instance Metadata Service (SSRF vulnerability)'
      };
    }
  }

  // 2. User-configured blocked domains
  if (config?.blockedDomains) {
    for (const blocked of config.blockedDomains) {
      if (normalized === blocked || normalized.endsWith('.' + blocked)) {
        return {
          blocked: true,
          risk: 'HIGH',
          reason: `Outbound connection to explicitly blocked domain '${blocked}'`
        };
      }
    }
  }

  // 3. Raw IP Address blocking (prevents bypassing DNS checks with direct IPs)
  if (config?.blockRawIPs && isIpAddress(normalized)) {
    // Exclude localhost/127.0.0.1 if specifically needed, but default block external raw IPs
    if (normalized !== '127.0.0.1' && normalized !== 'localhost') {
      return {
        blocked: true,
        risk: 'HIGH',
        reason: `Direct outbound connection to raw IP address '${target}' is restricted`
      };
    }
  }

  // 4. Allowed domains whitelist (if strict whitelist is configured)
  if (config?.allowedDomains && config.allowedDomains.length > 0) {
    const isWhitelisted = config.allowedDomains.some(
      allowed => normalized === allowed || normalized.endsWith('.' + allowed)
    );
    if (!isWhitelisted) {
      return {
        blocked: true,
        risk: 'MEDIUM',
        reason: `Domain '${target}' is not in the allowed outbound network whitelist`
      };
    }
  }

  return null;
}
