import {
  ActionVerdict,
  EvaluationResult,
  RiskLevel,
  SecurityRule,
  ToolCallPayload,
  ToolGuardConfig
} from '../types';
import { DEFAULT_RULES, SAFE_COMMAND_PATTERNS } from './defaultRules';
import { detectSecrets } from './secretDetector';
import { isPathProtected } from './pathChecker';

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

    // Combine custom rules with default rules
    this.rules = [
      ...(this.config.customRules || []),
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

    // 4. Target Path Protection Check
    if (payload.targetPath) {
      const pathCheck = isPathProtected(payload.targetPath, this.config.protectedPaths);
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

    // 7. Default Policy fallback
    return {
      verdict: this.config.mode === 'interactive' ? 'PROMPT' : 'ALLOW',
      risk: 'LOW',
      reason: 'No policy violations found in standard command execution',
      timestamp
    };
  }
}
