export type ActionVerdict = 'ALLOW' | 'PROMPT' | 'BLOCK';

export type RiskLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface EvaluationResult {
  verdict: ActionVerdict;
  risk: RiskLevel;
  reason: string;
  ruleId?: string;
  matchedPattern?: string;
  suggestedMitigation?: string;
  timestamp: string;
}

export interface SecurityRule {
  id: string;
  name: string;
  description: string;
  risk: RiskLevel;
  action: ActionVerdict;
  // Regex pattern matched against command or arguments
  patterns: (string | RegExp)[];
  mitigation?: string;
}

export interface ToolCallPayload {
  toolName: string;
  command?: string;
  args?: Record<string, any> | string[];
  targetPath?: string;
  content?: string;
}

export interface ToolGuardConfig {
  version: string;
  mode: 'enforce' | 'audit' | 'interactive';
  customRules?: SecurityRule[];
  allowedCommands?: string[];
  blockedCommands?: string[];
  protectedPaths?: string[];
  auditLogPath?: string;
  detectSecrets?: boolean;
}
