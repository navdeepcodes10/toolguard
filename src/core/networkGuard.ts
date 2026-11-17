import net from 'net';
import { RiskLevel } from '../types';

export interface NetworkGuardConfig {
  allowedDomains?: string[];
  blockedDomains?: string[];
  blockRawIPs?: boolean;
  blockCloudMetadata?: boolean;
}

// AWS, GCP, Azure, OpenStack instance metadata service IPs
export const CLOUD_METADATA_IP = '169.254.169.254';
export const AWS_IPV6_METADATA = 'fd00:ec2::254';

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

const KNOWN_NETWORK_BINARIES = new Set([
  'curl', 'wget', 'nc', 'ncat', 'netcat', 'ping', 'ssh', 'scp', 'telnet', 'ftp', 'rsync', 'fetch'
]);

const WRAPPER_COMMANDS = new Set([
  'sudo', 'env', 'nohup', 'command', 'exec', 'xargs', 'timeout', 'time', 'doas'
]);

const WRAPPER_OPTIONS_WITH_ARGS = new Set([
  '-u', '-g', '-C', '-D', '-h', '-p', '-t', '-k', '--user', '--group'
]);

/**
 * Checks if a target host is an IPv4 or IPv6 address using node's standard net.isIP
 */
export function isIpAddress(host: string): boolean {
  if (net.isIP(host) !== 0) return true;
  // Dword integer representation (e.g., 2852039166) or hex representation (0xa9fea9fe)
  if (/^\d{8,10}$/.test(host) || /^0x[0-9a-fA-F]{8}$/.test(host)) return true;
  return false;
}

/**
 * Normalizes IPv4-mapped IPv6 hostnames (like ::ffff:169.254.169.254 or ::ffff:a9fe:a9fe)
 */
export function normalizeIpTarget(host: string): string {
  let lower = host.toLowerCase().trim();

  // Strip trailing dot
  if (lower.endsWith('.')) {
    lower = lower.slice(0, -1);
  }

  // Handle IPv4-mapped IPv6 hex format: ::ffff:a9fe:a9fe -> 169.254.169.254
  const ipv4MappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(lower);
  if (ipv4MappedHex) {
    const p1 = parseInt(ipv4MappedHex[1], 16);
    const p2 = parseInt(ipv4MappedHex[2], 16);
    const o1 = (p1 >> 8) & 0xff;
    const o2 = p1 & 0xff;
    const o3 = (p2 >> 8) & 0xff;
    const o4 = p2 & 0xff;
    return `${o1}.${o2}.${o3}.${o4}`;
  }

  // Handle IPv4-mapped dotted decimal: ::ffff:169.254.169.254
  if (lower.startsWith('::ffff:')) {
    return lower.slice(7);
  }

  return lower;
}

/**
 * Extracts target hostnames using the WHATWG URL parser and gated CLI argument scanning.
 * Unpacks environment variable prefixes (FOO=1) and wrapper commands (sudo, env, timeout).
 */
export function extractNetworkTargets(command: string): string[] {
  const targets: string[] = [];
  const trimmed = command.trim();
  if (!trimmed) return targets;

  // 1. Capture full URL tokens: stops at whitespace, quotes, and shell redirect/pipe/control characters (<, >, ;, |, &, (, ))
  const urlTokenRegex = /\b(?:https?|ftp|git):\/\/[^\s"'<>;&|()]+/gi;
  let match: RegExpExecArray | null;

  while ((match = urlTokenRegex.exec(trimmed)) !== null) {
    try {
      const parsed = new URL(match[0]);
      let hostname = parsed.hostname.toLowerCase();
      if (hostname.endsWith('.')) {
        hostname = hostname.slice(0, -1);
      }
      if (hostname.startsWith('[') && hostname.endsWith(']')) {
        hostname = hostname.slice(1, -1);
      }
      const normalized = normalizeIpTarget(hostname);
      if (normalized && !targets.includes(normalized)) {
        targets.push(normalized);
      }
    } catch {
      // Ignore invalid URL tokens
    }
  }

  // 2. Gated argument scan: unwraps env prefixes (FOO=1) and wrapper commands (sudo, env, timeout)
  const tokens = trimmed.split(/\s+/);
  let binaryIdx = 0;

  // Skip leading env assignments
  while (binaryIdx < tokens.length && /^[a-zA-Z_][a-zA-Z0-9_]*=/.test(tokens[binaryIdx])) {
    binaryIdx++;
  }

  // Skip wrapper commands and their options (e.g. sudo -u root, timeout 10)
  while (binaryIdx < tokens.length) {
    const candidate = tokens[binaryIdx]?.replace(/^.*[\\\/]/, '').toLowerCase();
    if (WRAPPER_COMMANDS.has(candidate)) {
      binaryIdx++;
      // Skip wrapper options and their arguments
      while (binaryIdx < tokens.length && tokens[binaryIdx].startsWith('-')) {
        const opt = tokens[binaryIdx];
        binaryIdx++;
        if (WRAPPER_OPTIONS_WITH_ARGS.has(opt) && binaryIdx < tokens.length && !tokens[binaryIdx].startsWith('-')) {
          binaryIdx++;
        }
      }
      // If timeout or similar command has a duration parameter (number), skip it
      if (candidate === 'timeout' && binaryIdx < tokens.length && /^\d+[smhd]?$/i.test(tokens[binaryIdx])) {
        binaryIdx++;
      }
    } else {
      break;
    }
  }

  if (binaryIdx < tokens.length) {
    const binaryName = tokens[binaryIdx]?.replace(/^.*[\\\/]/, '').toLowerCase();

    if (KNOWN_NETWORK_BINARIES.has(binaryName)) {
      const optionsWithArgs = new Set(['-o', '-O', '-H', '-d', '-X', '-A', '-u', '-p', '-i', '-e', '-m', '--output']);

      for (let i = binaryIdx + 1; i < tokens.length; i++) {
        let token = tokens[i];
        const prev = tokens[i - 1];

        if (optionsWithArgs.has(prev)) continue;
        if (token.startsWith('-')) continue;

        // Remove surrounding or internal quotes first
        token = token.replace(/["']/g, '');

        // Extract bracketed IPv6 literals first before colon splitting (e.g. [fd00:ec2::254])
        let hostCandidate = '';
        const bracketMatch = /^\[([a-fA-F0-9:]+)\](?::\d+)?(?:\/.*)?$/.exec(token);
        if (bracketMatch) {
          hostCandidate = bracketMatch[1];
        } else {
          // Clean token of userinfo (user@...), port (:8080), path (/path), and redirects
          let cleaned = token.replace(/^[a-zA-Z0-9_\-\.]+@/, ''); // strip user@
          cleaned = cleaned.split(/[:\/?#<>;&|]/)[0].toLowerCase(); // strip port, path, redirects
          if (cleaned.endsWith('.')) cleaned = cleaned.slice(0, -1);
          hostCandidate = cleaned;
        }

        const normalized = normalizeIpTarget(hostCandidate);

        // Validate if it is a domain with TLD or valid IP
        const isDomain = /^[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}$/.test(normalized);
        const isIp = isIpAddress(normalized);

        if ((isDomain || isIp) && !targets.includes(normalized)) {
          targets.push(normalized);
        }
      }
    }
  }

  return targets;
}

/**
 * Evaluates network targets against security rules and domain policies
 */
export function evaluateNetworkTarget(
  target: string,
  config?: NetworkGuardConfig
): { blocked: boolean; risk: RiskLevel; reason: string } | null {
  const normalized = normalizeIpTarget(target.toLowerCase());

  // 1. Cloud Instance Metadata SSRF Protection (Critical)
  if (config?.blockCloudMetadata !== false) {
    if (
      normalized === CLOUD_METADATA_IP ||
      normalized === AWS_IPV6_METADATA ||
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
