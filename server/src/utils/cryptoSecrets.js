const crypto = require('crypto');

const ENCRYPTION_PREFIX = 'enc:v1:';
const IV_LENGTH = 12;

function getEncryptionKey() {
  const rawKey = process.env.SECRET_ENCRYPTION_KEY;
  if (typeof rawKey !== 'string' || rawKey.trim() === '') {
    throw new Error('SECRET_ENCRYPTION_KEY is required');
  }

  const trimmed = rawKey.trim();

  if (/^[a-fA-F0-9]{64}$/.test(trimmed)) {
    return Buffer.from(trimmed, 'hex');
  }

  try {
    const keyBuffer = Buffer.from(trimmed, 'base64');
    if (keyBuffer.length === 32) return keyBuffer;
  } catch (_) {
    // ignored: invalid base64 will be handled by final error
  }

  throw new Error('SECRET_ENCRYPTION_KEY must be 32-byte key in base64 or 64-char hex format');
}

function encryptSecretValue(plaintext) {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([
    cipher.update(String(plaintext), 'utf8'),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  return `${ENCRYPTION_PREFIX}${iv.toString('base64')}:${tag.toString('base64')}:${encrypted.toString('base64')}`;
}

function decryptSecretValue(storedValue) {
  const value = String(storedValue ?? '');

  // Backward compatibility: old plaintext rows remain readable.
  if (!value.startsWith(ENCRYPTION_PREFIX)) {
    return value;
  }

  const key = getEncryptionKey();
  const parts = value.slice(ENCRYPTION_PREFIX.length).split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted secret format');
  }

  const [ivB64, tagB64, dataB64] = parts;
  const iv = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const encrypted = Buffer.from(dataB64, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

module.exports = {
  ENCRYPTION_PREFIX,
  encryptSecretValue,
  decryptSecretValue
};
