import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';
import { ToolGuardConfig } from '../types';

export function loadConfig(searchDir: string = process.cwd()): ToolGuardConfig {
  const possibleFiles = [
    path.join(searchDir, '.toolguard.yaml'),
    path.join(searchDir, '.toolguard.yml'),
    path.join(searchDir, '.toolguard.json')
  ];

  for (const file of possibleFiles) {
    if (fs.existsSync(file)) {
      try {
        const rawContent = fs.readFileSync(file, 'utf-8');
        if (file.endsWith('.json')) {
          return JSON.parse(rawContent) as ToolGuardConfig;
        } else {
          return yaml.load(rawContent) as ToolGuardConfig;
        }
      } catch (err: any) {
        console.warn(`[ToolGuard] Warning: Failed to parse config file ${file}:`, err.message);
      }
    }
  }

  // Fallback to sensible defaults
  return {
    version: '1.0',
    mode: 'enforce',
    detectSecrets: true
  };
}
