import { SecurityRule } from '../types';

export const DOCKER_PRESET: SecurityRule[] = [
  {
    id: 'docker-privileged',
    name: 'Docker Privileged Mode Guard',
    description: 'Prevents running Docker containers with host root privileges (--privileged)',
    risk: 'CRITICAL',
    action: 'BLOCK',
    patterns: [
      /\bdocker\s+(run|create)\b.*--privileged\b/
    ],
    mitigation: 'Use fine-grained Linux capabilities (--cap-add) instead of full --privileged access.'
  },
  {
    id: 'docker-socket-mount',
    name: 'Docker Socket Escape Prevention',
    description: 'Prevents mounting the host Docker daemon socket into a container',
    risk: 'CRITICAL',
    action: 'BLOCK',
    patterns: [
      /\bdocker\s+(run|create)\b.*(-v\s*|--volume(\s+|=)|--mount\b.*(source=|src=))[\'\"\/a-zA-Z0-9_\-\.]*\/var\/run\/docker\.sock\b/
    ],
    mitigation: 'Do not expose the host Docker daemon socket inside guest containers.'
  },
  {
    id: 'docker-root-mount',
    name: 'Host Root Volume Mount Guard',
    description: 'Prevents mounting the host root filesystem into a container',
    risk: 'CRITICAL',
    action: 'BLOCK',
    patterns: [
      /\bdocker\s+(run|create)\b.*(-v\s*|--volume(\s+|=)|--mount\b.*(source=|src=))\/(:\/|\s|,|$)/
    ],
    mitigation: 'Mount only specific project directories, never the host root.'
  },
  {
    id: 'docker-prune-all',
    name: 'Nuclear Docker Volume Prune',
    description: 'Prompts before wiping all stopped containers and persistent database volumes',
    risk: 'MEDIUM',
    action: 'PROMPT',
    patterns: [
      /\bdocker\s+system\s+prune\b.*(--all|-a)\b.*--volumes\b/,
      /\bdocker\s+volume\s+prune\b/
    ],
    mitigation: 'Verify that no persistent database volumes will be lost before pruning.'
  }
];

export const NODE_PRESET: SecurityRule[] = [
  {
    id: 'node-pipe-exec',
    name: 'Remote Script Execution via Pipe',
    description: 'Blocks piping remote network downloads directly into node/bash',
    risk: 'HIGH',
    action: 'BLOCK',
    patterns: [
      /\b(curl|wget)\b.*\|\s*(node|sh|bash)\b/
    ],
    mitigation: 'Download and inspect scripts locally before executing them.'
  },
  {
    id: 'node-npm-publish',
    name: 'NPM Package Publish Prompt',
    description: 'Prompts before publishing a package to the public registry',
    risk: 'MEDIUM',
    action: 'PROMPT',
    patterns: [
      /\bnpm\s+publish\b/
    ],
    mitigation: 'Verify package version, changelog, and git tag before publishing to npm.'
  }
];

export const PYTHON_PRESET: SecurityRule[] = [
  {
    id: 'python-break-system',
    name: 'System Python Package Pollution',
    description: 'Blocks installing packages globally with --break-system-packages',
    risk: 'HIGH',
    action: 'BLOCK',
    patterns: [
      /\bpip(3)?\s+install\b.*--break-system-packages\b/
    ],
    mitigation: 'Create an isolated virtual environment (`python -m venv .venv`) first.'
  }
];

export const PRESET_MAP: Record<string, SecurityRule[]> = {
  docker: DOCKER_PRESET,
  node: NODE_PRESET,
  python: PYTHON_PRESET
};
