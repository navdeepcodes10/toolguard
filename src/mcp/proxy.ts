import readline from 'readline';
import { ToolGuardEngine } from '../core/engine';
import { AuditLogger } from '../logger/audit';
import { EvaluationResult, ToolGuardConfig } from '../types';

/**
 * Standard MCP JSON-RPC Stdio Proxy
 * Reads JSON-RPC requests from stdin, filters dangerous 'tools/call' payloads,
 * and passes safe requests through to the underlying MCP server.
 */
export function startMcpProxy(config?: ToolGuardConfig) {
  const engine = new ToolGuardEngine(config);
  const logger = new AuditLogger();

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

      // If safe or non-tool call, echo / forward through
      process.stdout.write(trimmed + '\n');
    } catch {
      // Pass-through raw lines if not valid JSON
      process.stdout.write(trimmed + '\n');
    }
  });
}
