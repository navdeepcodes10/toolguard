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

  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    try {
      const message = JSON.parse(trimmed);

      // Intercept MCP tool calls
      if (message.method === 'tools/call' && message.params) {
        const { name, arguments: args } = message.params;

        // Evaluate against security engine
        const result: EvaluationResult = engine.evaluate({
          toolName: name,
          args,
          command: typeof args?.command === 'string' ? args.command : undefined,
          targetPath: typeof args?.path === 'string' ? args.path : undefined
        });

        if (result.verdict === 'BLOCK') {
          logger.log({ toolName: name, args }, result, false);

          // Return JSON-RPC error response preventing tool execution
          const errorResponse = {
            jsonrpc: '2.0',
            id: message.id,
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

        logger.log({ toolName: name, args }, result, true);
      }

      // Forward approved message to upstream process if running, or echo back
      if (upstreamProcess && upstreamProcess.stdin) {
        upstreamProcess.stdin.write(trimmed + '\n');
      } else {
        process.stdout.write(trimmed + '\n');
      }
    } catch {
      if (upstreamProcess && upstreamProcess.stdin) {
        upstreamProcess.stdin.write(trimmed + '\n');
      } else {
        process.stdout.write(trimmed + '\n');
      }
    }
  });
}
