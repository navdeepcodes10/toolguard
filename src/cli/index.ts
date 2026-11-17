#!/usr/bin/env node

import { Command } from 'commander';
import pc from 'picocolors';
import { spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import readline from 'readline';

import { ToolGuardEngine } from '../core/engine';
import { loadConfig } from '../config/loader';
import { DEFAULT_CONFIG_YAML } from '../config/schema';
import { AuditLogger } from '../logger/audit';
import { EvaluationResult, RiskLevel } from '../types';

import { startMcpProxy } from '../mcp/proxy';

const program = new Command();
const logger = new AuditLogger();

function formatRiskBadge(risk: RiskLevel): string {
  switch (risk) {
    case 'CRITICAL':
      return pc.bgRed(pc.white(pc.bold(' CRITICAL ')));
    case 'HIGH':
      return pc.red(pc.bold(' HIGH '));
    case 'MEDIUM':
      return pc.yellow(pc.bold(' MEDIUM '));
    case 'LOW':
      return pc.blue(' LOW ');
    case 'SAFE':
    default:
      return pc.green(pc.bold(' SAFE '));
  }
}

function promptConfirmation(question: string): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === 'y' || answer.trim().toLowerCase() === 'yes');
    });
  });
}

program
  .name('toolguard')
  .description('🛡️ The open-source security firewall & permission proxy for AI coding agents & MCP servers')
  .version('0.1.0');

// Command: eval
program
  .command('eval <command...>')
  .description('Evaluate a command string against security rules without executing it')
  .action((cmdParts: string[]) => {
    const rawCmd = cmdParts.join(' ');
    const config = loadConfig();
    const engine = new ToolGuardEngine(config);

    const result: EvaluationResult = engine.evaluate(rawCmd);
    logger.log(rawCmd, result, false);

    console.log('\n' + pc.bold(pc.cyan('🛡️  ToolGuard Security Assessment')));
    console.log(pc.dim('─'.repeat(50)));
    console.log(`${pc.bold('Command:')}   ${pc.white(rawCmd)}`);
    console.log(`${pc.bold('Verdict:')}   ${
      result.verdict === 'ALLOW' ? pc.green(pc.bold('ALLOW')) :
      result.verdict === 'PROMPT' ? pc.yellow(pc.bold('PROMPT (Requires Confirmation)')) :
      pc.red(pc.bold('BLOCK (Restricted)'))
    }`);
    console.log(`${pc.bold('Risk:')}      ${formatRiskBadge(result.risk)}`);
    console.log(`${pc.bold('Reason:')}    ${result.reason}`);

    if (result.suggestedMitigation) {
      console.log(`${pc.bold('Guidance:')}  ${pc.cyan(result.suggestedMitigation)}`);
    }
    console.log(pc.dim('─'.repeat(50)) + '\n');

    if (result.verdict === 'BLOCK') {
      process.exit(1);
    }
  });

// Command: run (exec with guard)
program
  .command('run <command...>')
  .description('Safely execute a command through the ToolGuard policy firewall')
  .action(async (cmdParts: string[]) => {
    const rawCmd = cmdParts.join(' ');
    const config = loadConfig();
    const engine = new ToolGuardEngine(config);

    const result: EvaluationResult = engine.evaluate(rawCmd);

    if (result.verdict === 'BLOCK') {
      logger.log(rawCmd, result, false);
      console.error('\n' + pc.bgRed(pc.white(pc.bold(' 🛑 [ToolGuard] EXECUTION BLOCKED '))));
      console.error(`${pc.red('Command:')}  ${rawCmd}`);
      console.error(`${pc.red('Reason:')}   ${result.reason}`);
      if (result.suggestedMitigation) {
        console.error(`${pc.cyan('Advice:')}   ${result.suggestedMitigation}`);
      }
      console.error(pc.dim('─'.repeat(50)) + '\n');
      process.exit(1);
    }

    if (result.verdict === 'PROMPT') {
      console.log('\n' + pc.yellow(pc.bold('⚠️  [ToolGuard] Sensitive Action Detected')));
      console.log(`${pc.bold('Command:')}  ${rawCmd}`);
      console.log(`${pc.bold('Risk:')}     ${formatRiskBadge(result.risk)}`);
      console.log(`${pc.bold('Reason:')}   ${result.reason}`);

      const approved = await promptConfirmation(pc.bold(pc.yellow('Allow this command to execute? [y/N]: ')));
      if (!approved) {
        logger.log(rawCmd, result, false);
        console.log(pc.red('Execution cancelled by user.'));
        process.exit(1);
      }
    }

    // Proceed to execute
    logger.log(rawCmd, result, true);
    const child = spawnSync(rawCmd, {
      shell: true,
      stdio: 'inherit'
    });

    process.exit(child.status ?? 0);
  });

// Command: init
program
  .command('init')
  .description('Initialize a starter .toolguard.yaml in the current directory')
  .action(() => {
    const targetFile = path.join(process.cwd(), '.toolguard.yaml');
    if (fs.existsSync(targetFile)) {
      console.log(pc.yellow(`[ToolGuard] Config already exists at ${targetFile}`));
      return;
    }

    fs.writeFileSync(targetFile, DEFAULT_CONFIG_YAML, 'utf-8');
    console.log(pc.green(`✨ Successfully created ${pc.bold('.toolguard.yaml')}`));
    console.log(pc.dim('You can now customize allowed commands, protected paths, and safety rules.'));
  });

// Command: audit
program
  .command('audit')
  .description('View recent tool execution audit history')
  .option('-n, --limit <number>', 'Number of recent entries to show', '10')
  .action((options) => {
    const logPath = logger.getLogPath();
    if (!fs.existsSync(logPath)) {
      console.log(pc.yellow('[ToolGuard] No audit logs recorded yet.'));
      return;
    }

    const lines = fs.readFileSync(logPath, 'utf-8').trim().split('\n').filter(Boolean);
    const limit = parseInt(options.limit, 10) || 10;
    const recent = lines.slice(-limit);

    console.log('\n' + pc.bold(pc.cyan(`📋 ToolGuard Recent Audit Events (Showing last ${recent.length})`)));
    console.log(pc.dim('─'.repeat(60)));

    for (const line of recent) {
      try {
        const item = JSON.parse(line);
        const icon = item.verdict === 'ALLOW' ? pc.green('✔ ALLOW') :
                     item.verdict === 'PROMPT' ? pc.yellow('? PROMPT') : pc.red('✖ BLOCK');
        console.log(`[${pc.dim(item.timestamp.slice(11, 19))}] ${icon}  ${item.target?.command || item.target?.toolName}`);
        if (item.reason) {
          console.log(`   ${pc.dim('↳')} ${pc.dim(item.reason)}`);
        }
      } catch {
        // skip malformed line
      }
    }
    console.log(pc.dim('─'.repeat(60)) + '\n');
  });

// Command: mcp-proxy
program
  .command('mcp-proxy')
  .description('Run as an MCP stdio firewall proxy to shield Model Context Protocol servers')
  .action(() => {
    const config = loadConfig();
    startMcpProxy(config);
  });

program.parse(process.argv);
