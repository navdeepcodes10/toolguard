import readline from 'readline';
import { spawn, ChildProcess } from 'child_process';
import { ToolGuardEngine } from '../core/engine';
import { AuditLogger } from '../logger/audit';
import { EvaluationResult, ToolGuardConfig } from '../types';

/**
 * Standard MCP JSON-RPC Stdio Proxy & Firewall
 * Intercepts tool calls between an AI client (Claude Code, Cursor) and an upstream MCP server.
 */
export function startMcpProxy(config?: ToolGuardConfig, upstreamCommand?: string[]) {
  const engine = new ToolGuardEngine(config);
  const logger = new AuditLogger();

  let upstreamProcess: ChildProcess | null = null;

  if (upstreamCommand && upstreamCommand.length > 0) {
    const [bin, ...args] = upstreamCommand;
    upstreamProcess = spawn(bin, args, {
      stdio: ['pipe', 'pipe', 'inherit'],
      shell: false
    });

    upstreamProcess.on('error', (err) => {
      console.error(`[ToolGuard] Failed to start upstream MCP server '${bin}': ${err.message}`);
      process.exit(1);
    });

    // Pipe upstream responses back to agent client
    upstreamProcess.stdout?.on('data', (chunk) => {
      process.stdout.write(chunk);
    });

    upstreamProcess.on('exit', (code) => {
      process.exit(code ?? 0);
    });
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false
  });

  rl.on('close', () => {
    if (upstreamProcess && upstreamProcess.stdin) {
      upstreamProcess.stdin.end();
    }
  });

  function evaluateSingleCall(message: any): EvaluationResult | null {
    if (message && message.method === 'tools/call' && message.params) {
      const { name, arguments: args } = message.params;
      return engine.evaluate({
        toolName: name,
        args,
        command: typeof args?.command === 'string' ? args.command : undefined,
        targetPath: typeof args?.path === 'string' ? args.path : undefined
      });
    }
    return null;
  }

  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    try {
      const parsed = JSON.parse(trimmed);

      // Handle JSON-RPC batch array
      if (Array.isArray(parsed)) {
        for (const item of parsed) {
          const result = evaluateSingleCall(item);
          if (result && result.verdict === 'BLOCK') {
            logger.log({ toolName: item.params?.name, args: item.params?.arguments }, result, false);
            const errorResponse = {
              jsonrpc: '2.0',
              id: item.id ?? null,
              error: {
                code: -32000,
                message: `[ToolGuard Security Block] ${result.reason}`,
                data: {
                  risk: result.risk,
                  ruleId: result.ruleId,
                  mitigation: result.suggestedMitigation
                }
              }
            };
            process.stdout.write(JSON.stringify(errorResponse) + '\n');
            return;
          }
        }
      } else {
        // Handle single JSON-RPC call
        const result = evaluateSingleCall(parsed);
        if (result && result.verdict === 'BLOCK') {
          logger.log({ toolName: parsed.params?.name, args: parsed.params?.arguments }, result, false);
          const errorResponse = {
            jsonrpc: '2.0',
            id: parsed.id ?? null,
            error: {
              code: -32000,
              message: `[ToolGuard Security Block] ${result.reason}`,
              data: {
                risk: result.risk,
                ruleId: result.ruleId,
                mitigation: result.suggestedMitigation
              }
            }
          };
          process.stdout.write(JSON.stringify(errorResponse) + '\n');
          return;
        }
      }

      // Forward approved message to upstream process if running, or echo back
      if (upstreamProcess && upstreamProcess.stdin) {
        upstreamProcess.stdin.write(trimmed + '\n');
      } else {
        process.stdout.write(trimmed + '\n');
      }
    } catch {
      // Fail closed: reject invalid JSON without forwarding unevaluated input
      const parseError = {
        jsonrpc: '2.0',
        id: null,
        error: {
          code: -32700,
          message: '[ToolGuard] Parse error: invalid JSON input rejected'
        }
      };
      process.stdout.write(JSON.stringify(parseError) + '\n');
    }
  });
}
