const SENSITIVE_KEYS = [
  'email',
  'password',
  'password_hash',
  'token',
  'accesstoken',
  'refresh_token',
  'authorization',
  'cookie'
];

function maskEmail(value) {
  const str = String(value);
  const parts = str.split('@');
  if (parts.length !== 2) return '[REDACTED_EMAIL]';
  const local = parts[0];
  const domain = parts[1];
  const safeLocal = local.length <= 2 ? `${local[0] || '*'}*` : `${local.slice(0, 2)}***`;
  return `${safeLocal}@${domain}`;
}

function maskToken(value) {
  const str = String(value || '');
  if (!str) return '[REDACTED_TOKEN]';
  if (str.length <= 10) return '[REDACTED_TOKEN]';
  return `${str.slice(0, 4)}...[REDACTED]...${str.slice(-4)}`;
}

function sanitizeString(value) {
  const str = String(value);
  const emailMasked = str.replace(/\b([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\b/gi, (email) => maskEmail(email));
  const passwordMasked = emailMasked.replace(/(password\s*[=:]\s*)([^\s,;]+)/gi, '$1[REDACTED_PASSWORD]');
  const bearerMasked = passwordMasked.replace(/(Bearer\s+)([A-Za-z0-9\-_.]+)/gi, '$1[REDACTED_TOKEN]');
  return bearerMasked;
}

function sanitizeForLogs(input, keyHint = '') {
  if (input == null) return input;
  const normalizedKeyHint = String(keyHint || '').toLowerCase();

  if (typeof input === 'string') {
    if (SENSITIVE_KEYS.includes(normalizedKeyHint)) {
      if (normalizedKeyHint.includes('password')) return '[REDACTED_PASSWORD]';
      if (normalizedKeyHint.includes('email')) return maskEmail(input);
      if (normalizedKeyHint === 'authorization' || normalizedKeyHint === 'cookie') return '[REDACTED_SECRET]';
      return maskToken(input);
    }
    return sanitizeString(input);
  }

  if (typeof input === 'number' || typeof input === 'boolean') return input;

  if (Array.isArray(input)) {
    return input.map(item => sanitizeForLogs(item, keyHint));
  }

  if (typeof input === 'object') {
    const output = {};
    for (const [key, value] of Object.entries(input)) {
      const lower = key.toLowerCase();
      if (lower.includes('password')) {
        output[key] = '[REDACTED_PASSWORD]';
      } else if (lower === 'authorization' || lower === 'cookie') {
        output[key] = '[REDACTED_SECRET]';
      } else if (lower.includes('token')) {
        output[key] = maskToken(value);
      } else if (lower.includes('email')) {
        output[key] = maskEmail(value);
      } else {
        output[key] = sanitizeForLogs(value, lower);
      }
    }
    return output;
  }

  return String(input);
}

module.exports = {
  sanitizeForLogs
};
