export interface SecretMatch {
  type: string;
  redactedPreview: string;
}

const SECRET_PATTERNS: { name: string; pattern: RegExp }[] = [
  { name: 'OpenAI API Key', pattern: /\bsk-[a-zA-Z0-9_-]{20,}\b/ },
  { name: 'GitHub Personal Access Token', pattern: /\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b/ },
  { name: 'GitHub Fine-Grained Token', pattern: /\bgithub_pat_[a-zA-Z0-9_]{82}\b/ },
  { name: 'AWS Access Key ID', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'Stripe Secret Key', pattern: /\b[sr]k_live_[0-9a-zA-Z]{24,}\b/ },
  { name: 'Slack Token', pattern: /\bxox[baprs]-[0-9a-zA-Z]{10,}\b/ },
  { name: 'Generic Bearer Token', pattern: /\bBearer\s+[a-zA-Z0-9_\-\.]{30,}\b/i },
  { name: 'Private Key Header', pattern: /-----BEGIN\s+([A-Z\s]+)?PRIVATE\s+KEY-----/ }
];

export function detectSecrets(text: string): SecretMatch[] {
  const matches: SecretMatch[] = [];

  for (const { name, pattern } of SECRET_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      const raw = match[0];
      const preview = raw.length > 8
        ? `${raw.substring(0, 4)}...${raw.substring(raw.length - 4)}`
        : '****';
      matches.push({
        type: name,
        redactedPreview: preview
      });
    }
  }

  return matches;
}
