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
import { PRESET_MAP } from '../presets';
import { generateShellHook, installShellHook } from './hook';

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
  .passThroughOptions()
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

    // Proceed to execute preserving discrete argument list
    logger.log(rawCmd, result, true);

    // If passed as a single quoted string like "npm test", split by whitespace
    let executable: string;
    let args: string[];

    if (cmdParts.length === 1 && cmdParts[0].trim().includes(' ')) {
      const tokens = cmdParts[0].trim().match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
      const cleaned = tokens.map(t => t.replace(/^["']|["']$/g, ''));
      executable = cleaned[0] || cmdParts[0];
      args = cleaned.slice(1);
    } else {
      executable = cmdParts[0];
      args = cmdParts.slice(1);
    }

    const child = spawnSync(executable, args, {
      stdio: 'inherit',
      shell: false
    });

    if (child.error) {
      console.error(pc.red(`[ToolGuard] Failed to execute '${executable}': ${child.error.message}`));
      process.exit(1);
    }

    process.exit(child.status ?? (child.signal ? 1 : 0));
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

// Command: hook
program
  .command('hook [shell]')
  .description('Generate or install one-command shell integration (zsh, bash, fish)')
  .option('-i, --install', 'Automatically append hook to ~/.zshrc or ~/.bashrc')
  .action((shellArg, options) => {
    const envShell = process.env.SHELL || '';
    const detectedShell = shellArg || (
      envShell.includes('fish') ? 'fish' :
      envShell.includes('zsh') ? 'zsh' : 'bash'
    );

    if (options.install) {
      const res = installShellHook(detectedShell);
      if (res.success) {
        console.log(pc.green(`✔ ${res.message}`));
        console.log(pc.dim('Restart your terminal or run: source ~/.zshrc (or ~/.bashrc)'));
      } else {
        console.error(pc.red(`✖ ${res.message}`));
      }
      return;
    }

    // Output raw script for eval "$(toolguard hook)"
    const script = generateShellHook(detectedShell);
    process.stdout.write(script);
  });

// Command: presets
program
  .command('presets')
  .description('List available community security presets (docker, node, python)')
  .action(() => {
    console.log('\n' + pc.bold(pc.cyan('🛡️  ToolGuard Available Security Presets')));
    console.log(pc.dim('─'.repeat(55)));

    for (const [name, rules] of Object.entries(PRESET_MAP)) {
      console.log(`${pc.bold(pc.green(name.toUpperCase()))} ${pc.dim(`(${rules.length} rules)`)}`);
      for (const rule of rules) {
        const badge = rule.action === 'BLOCK' ? pc.red('[BLOCK]') : pc.yellow('[PROMPT]');
        console.log(`  ${badge} ${pc.white(rule.name)}: ${pc.dim(rule.description)}`);
      }
      console.log('');
    }
    console.log(pc.dim('Enable presets in your .toolguard.yaml:'));
    console.log(pc.cyan('presets:\n  - docker\n  - node\n  - python\n'));
  });

// Command: mcp-proxy
program
  .command('mcp-proxy [upstreamCommand...]')
  .description('Run as an MCP stdio firewall proxy to shield upstream Model Context Protocol servers')
  .passThroughOptions()
  .action((upstreamCommand) => {
    const config = loadConfig();
    startMcpProxy(config, upstreamCommand);
  });

program.parse(process.argv);
