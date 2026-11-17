import fs from 'fs';
import path from 'path';
import { EvaluationResult, ToolCallPayload } from '../types';

export class AuditLogger {
  private logPath: string;

  constructor(customPath?: string) {
    const dir = path.join(process.cwd(), '.toolguard');
    if (!fs.existsSync(dir)) {
      try {
        fs.mkdirSync(dir, { recursive: true });
      } catch {
        // ignore in readonly envs
      }
    }
    this.logPath = customPath || path.join(dir, 'audit.jsonl');
  }

  public log(input: string | ToolCallPayload, result: EvaluationResult, executed: boolean = false): void {
    const entry = {
      timestamp: result.timestamp,
      target: typeof input === 'string' ? { command: input } : input,
      verdict: result.verdict,
      risk: result.risk,
      ruleId: result.ruleId,
      reason: result.reason,
      executed
    };

    try {
      fs.appendFileSync(this.logPath, JSON.stringify(entry) + '\n', 'utf-8');
    } catch {
      // Gracefully ignore write failures in non-writable environments
    }
  }

  public getLogPath(): string {
    return this.logPath;
  }
}
