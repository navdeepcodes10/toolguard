import { RiskLevel } from '../types';

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
 * Extracts target hostnames using the WHATWG URL parser and smart CLI argument parsing.
 * Eliminates SSRF bypasses via userinfo (http://x@169.254.169.254), hex/dword IPs, and option confusion.
 */
export function extractNetworkTargets(command: string): string[] {
  const targets: string[] = [];

  // 1. Capture full URL tokens: https?://..., ftp://..., git://...
  const urlTokenRegex = /\b(?:https?|ftp|git):\/\/[^\s"']+/gi;
  let match: RegExpExecArray | null;

  while ((match = urlTokenRegex.exec(command)) !== null) {
    try {
      const parsed = new URL(match[0]);
      let hostname = parsed.hostname.toLowerCase();
      // Strip trailing dot if present (e.g., example.com.)
      if (hostname.endsWith('.')) {
        hostname = hostname.slice(0, -1);
      }
      // Remove bracket enclosing for IPv6 literals
      if (hostname.startsWith('[') && hostname.endsWith(']')) {
        hostname = hostname.slice(1, -1);
      }
      if (hostname && !targets.includes(hostname)) {
        targets.push(hostname);
      }
    } catch {
      // Ignore invalid URL tokens
    }
  }

  // 2. If no URLs were found, check bare host commands (ping, nc, ncat, telnet, ssh, scp)
  // Skip options that take parameters (-o, -O, -H, -d, -X, -A, -u, -p, -i)
  if (targets.length === 0) {
    const tokens = command.trim().split(/\s+/);
    const optionsWithArgs = new Set(['-o', '-O', '-H', '-d', '-X', '-A', '-u', '-p', '-i', '-e', '-m', '--output']);

    for (let i = 1; i < tokens.length; i++) {
      const token = tokens[i];
      const prev = tokens[i - 1];

      if (optionsWithArgs.has(prev)) {
        continue;
      }
      if (token.startsWith('-')) {
        continue;
      }

      // Check if token resembles a domain or IP (excluding simple file names like file.txt)
      const isDomainOrIp = /^[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}$/.test(token) || isIpAddress(token);
      if (isDomainOrIp && !targets.includes(token.toLowerCase())) {
        targets.push(token.toLowerCase());
      }
    }
  }

  return targets;
}

/**
 * Checks if a target host is an IPv4 or IPv6 address (including dword/hex decimal forms)
 */
export function isIpAddress(host: string): boolean {
  // IPv4 standard
  const ipv4Regex = /^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Regex.test(host)) return true;

  // IPv6
  if (host.includes(':')) return true;

  // Dword integer or hex representation of IP
  if (/^\d{8,10}$/.test(host) || /^0x[0-9a-fA-F]{8}$/.test(host)) return true;

  return false;
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
  // Covers 169.254.169.254, dword (2852039166), and hex (0xa9fea9fe)
  if (config?.blockCloudMetadata !== false) {
    if (
      normalized === CLOUD_METADATA_IP ||
      normalized === '2852039166' ||
      normalized === '0xa9fea9fe' ||
      normalized.includes('169.254.169.254')
    ) {
      return {
        blocked: true,
        risk: 'CRITICAL',
        reason: 'Attempted access to Cloud Instance Metadata Service (SSRF vulnerability)'
      };
    }
  }

  // 2. User-configured blocked domains
  if (config?.blockedDomains) {
    for (const rawBlocked of config.blockedDomains) {
      const blocked = rawBlocked.toLowerCase().trim();
      if (normalized === blocked || normalized.endsWith('.' + blocked)) {
        return {
          blocked: true,
          risk: 'HIGH',
          reason: `Outbound connection to explicitly blocked domain '${rawBlocked}'`
        };
      }
    }
  }

  // 3. Raw IP Address blocking (prevents bypassing DNS checks with direct IPs)
  if (config?.blockRawIPs && isIpAddress(normalized)) {
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
    const isWhitelisted = config.allowedDomains.some(rawAllowed => {
      const allowed = rawAllowed.toLowerCase().trim();
      return normalized === allowed || normalized.endsWith('.' + allowed);
    });

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
