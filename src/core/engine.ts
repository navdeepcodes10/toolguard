import {
  ActionVerdict,
  EvaluationResult,
  RiskLevel,
  SecurityRule,
  ToolCallPayload,
  ToolGuardConfig
} from '../types';
import { DEFAULT_RULES, SAFE_COMMAND_PATTERNS } from './defaultRules';
import { PRESET_MAP } from '../presets';
import { detectSecrets } from './secretDetector';
import { isPathProtected } from './pathChecker';
import { decomposeCommands, detectBase64Execution } from './astParser';
import { extractNetworkTargets, evaluateNetworkTarget } from './networkGuard';

export class ToolGuardEngine {
  private config: ToolGuardConfig;
  private rules: SecurityRule[];

  constructor(config?: Partial<ToolGuardConfig>) {
    this.config = {
      version: '1.0',
      mode: 'enforce',
      detectSecrets: true,
      ...config
    };

    // Collect preset rules
    const presetRules: SecurityRule[] = [];
    if (this.config.presets && Array.isArray(this.config.presets)) {
      for (const presetName of this.config.presets) {
        if (typeof presetName !== 'string') continue;
        const normalized = presetName.trim().toLowerCase();
        if (Object.prototype.hasOwnProperty.call(PRESET_MAP, normalized)) {
          presetRules.push(...PRESET_MAP[normalized]);
        }
      }
    }

    // Combine custom rules, presets, and default rules
    this.rules = [
      ...(this.config.customRules || []),
      ...presetRules,
      ...DEFAULT_RULES
    ];
  }

  /**
   * Evaluates a raw shell command string or full tool call payload
   */
  public evaluate(input: string | ToolCallPayload): EvaluationResult {
    const timestamp = new Date().toISOString();
    const payload: ToolCallPayload = typeof input === 'string'
      ? { toolName: 'shell', command: input }
      : input;

    const commandStr = (payload.command || '').trim();
    const fullPayloadStr = JSON.stringify(payload);

    // 1. Check user-defined explicit allowed commands
    if (this.config.allowedCommands && commandStr) {
      for (const allowed of this.config.allowedCommands) {
        if (commandStr === allowed || commandStr.startsWith(allowed + ' ')) {
          return {
            verdict: 'ALLOW',
            risk: 'SAFE',
            reason: `Explicitly whitelisted in configuration ('${allowed}')`,
            timestamp
          };
        }
      }
    }

    // 2. Check user-defined explicit blocked commands
    if (this.config.blockedCommands && commandStr) {
      for (const blocked of this.config.blockedCommands) {
        if (commandStr.includes(blocked)) {
          return {
            verdict: 'BLOCK',
            risk: 'CRITICAL',
            reason: `Explicitly prohibited by configuration rule ('${blocked}')`,
            timestamp
          };
        }
      }
    }

    // 3. Secret & Credential Leakage Check
    if (this.config.detectSecrets !== false) {
      const secrets = detectSecrets(commandStr || fullPayloadStr);
      if (secrets.length > 0) {
        const secretTypes = secrets.map(s => `${s.type} (${s.redactedPreview})`).join(', ');
        return {
          verdict: 'BLOCK',
          risk: 'HIGH',
          reason: `Potential credential leakage detected in payload: ${secretTypes}`,
          suggestedMitigation: 'Remove hardcoded credentials and use secured environment variables or vaults.',
          timestamp
        };
      }
    }

    // 4. Obfuscated Base64 Shell Execution Check (CWE-94)
    if (commandStr && detectBase64Execution(commandStr)) {
      return {
        verdict: 'BLOCK',
        risk: 'CRITICAL',
        reason: 'Obfuscated shell execution: base64 decode piped directly to shell interpreter',
        suggestedMitigation: 'Execute transparent, unencoded scripts only.',
        timestamp
      };
    }

    // 5. Network SSRF and Outbound Domain Guard
    if (commandStr) {
      const targets = extractNetworkTargets(commandStr);
      for (const target of targets) {
        const netCheck = evaluateNetworkTarget(target, this.config.network);
        if (netCheck && netCheck.blocked) {
          return {
            verdict: 'BLOCK',
            risk: netCheck.risk,
            reason: netCheck.reason,
            suggestedMitigation: 'Use verified outbound endpoints or add to network.allowedDomains in .toolguard.yaml.',
            timestamp
          };
        }
      }
    }

    // 6. Target Path Protection & Workspace Sandboxing Check (Evaluated before deferring to PROMPTs)
    if (payload.targetPath) {
      const wsRoot = this.config.sandboxWorkspace ? (this.config.workspaceRoot || process.cwd()) : undefined;
      const pathCheck = isPathProtected(payload.targetPath, this.config.protectedPaths, wsRoot);
      if (pathCheck.isProtected) {
        return {
          verdict: 'BLOCK',
          risk: 'HIGH',
          reason: pathCheck.reason || 'Protected file path access blocked',
          suggestedMitigation: 'Isolate operations within the project workspace.',
          timestamp
        };
      }
    }

    // 7. AST Command Chain & Subshell Decomposition (&&, ||, ;, |, $(...))
    const atomicSegments = commandStr ? decomposeCommands(commandStr) : [];
    if (atomicSegments.length > 1 || atomicSegments.some(s => s.isSubshell)) {
      let highestRiskPrompt: EvaluationResult | null = null;

      for (const seg of atomicSegments) {
        if (!seg.cleaned || seg.cleaned === commandStr) continue;

        // Evaluate sub-segment without re-decomposing
        const subResult = this.evaluateAtomic(seg.cleaned, timestamp);
        if (subResult.verdict === 'BLOCK') {
          return {
            ...subResult,
            reason: `Chained command rejected in segment '${seg.cleaned}': ${subResult.reason}`
          };
        }
        if (subResult.verdict === 'PROMPT') {
          highestRiskPrompt = {
            ...subResult,
            reason: `Chained command requires confirmation in segment '${seg.cleaned}': ${subResult.reason}`
          };
        }
      }

      if (highestRiskPrompt) {
        return highestRiskPrompt;
      }
    }

    // 5. Evaluate against Security Rules (Critical & High checked first)
    for (const rule of this.rules) {
      for (const pattern of rule.patterns) {
        let matched = false;

        if (typeof pattern === 'string') {
          matched = commandStr.includes(pattern) || fullPayloadStr.includes(pattern);
        } else if (pattern instanceof RegExp) {
          matched = pattern.test(commandStr) || pattern.test(fullPayloadStr);
        }

        if (matched) {
          return {
            verdict: rule.action,
            risk: rule.risk,
            ruleId: rule.id,
            reason: `${rule.name}: ${rule.description}`,
            matchedPattern: pattern.toString(),
            suggestedMitigation: rule.mitigation,
            timestamp
          };
        }
      }
    }

    // 6. Check Known Safe Command Patterns (e.g. read-only inspections)
    if (commandStr) {
      for (const safePattern of SAFE_COMMAND_PATTERNS) {
        if (safePattern.test(commandStr)) {
          return {
            verdict: 'ALLOW',
            risk: 'SAFE',
            reason: 'Recognized standard read-only or verification command',
            timestamp
          };
        }
      }
    }

    // 8. Default Policy fallback
    return {
      verdict: this.config.mode === 'interactive' ? 'PROMPT' : 'ALLOW',
      risk: 'LOW',
      reason: 'No policy violations found in standard command execution',
      timestamp
    };
  }

  /**
   * Evaluates an atomic sub-command segment extracted by the AST parser
   */
  private evaluateAtomic(commandStr: string, timestamp: string): EvaluationResult {
    // 1. Check user-defined explicit blocked commands
    if (this.config.blockedCommands) {
      for (const blocked of this.config.blockedCommands) {
        if (commandStr.includes(blocked)) {
          return {
            verdict: 'BLOCK',
            risk: 'CRITICAL',
            reason: `Explicitly prohibited by configuration rule ('${blocked}')`,
            timestamp
          };
        }
      }
    }

    // 2. Secret check
    if (this.config.detectSecrets !== false) {
      const secrets = detectSecrets(commandStr);
      if (secrets.length > 0) {
        return {
          verdict: 'BLOCK',
          risk: 'HIGH',
          reason: `Potential credential leakage detected: ${secrets[0].type}`,
          timestamp
        };
      }
    }

    // 3. Network check
    const targets = extractNetworkTargets(commandStr);
    for (const target of targets) {
      const netCheck = evaluateNetworkTarget(target, this.config.network);
      if (netCheck && netCheck.blocked) {
        return {
          verdict: 'BLOCK',
          risk: netCheck.risk,
          reason: netCheck.reason,
          timestamp
        };
      }
    }

    // 4. Security Rules
    for (const rule of this.rules) {
      for (const pattern of rule.patterns) {
        let matched = false;
        if (typeof pattern === 'string') {
          matched = commandStr.includes(pattern);
        } else if (pattern instanceof RegExp) {
          matched = pattern.test(commandStr);
        }

        if (matched) {
          return {
            verdict: rule.action,
            risk: rule.risk,
            ruleId: rule.id,
            reason: `${rule.name}: ${rule.description}`,
            matchedPattern: pattern.toString(),
            suggestedMitigation: rule.mitigation,
            timestamp
          };
        }
      }
    }

    // 5. Safe Patterns
    for (const safePattern of SAFE_COMMAND_PATTERNS) {
      if (safePattern.test(commandStr)) {
        return {
          verdict: 'ALLOW',
          risk: 'SAFE',
          reason: 'Recognized standard read-only or verification command',
          timestamp
        };
      }
    }

    return {
      verdict: this.config.mode === 'interactive' ? 'PROMPT' : 'ALLOW',
      risk: 'LOW',
      reason: 'Standard command execution',
      timestamp
    };
  }
}
