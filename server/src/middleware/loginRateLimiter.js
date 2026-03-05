/**
 * Login rate limiter (brute-force protection)
 *
 * Blocks an IP after N failed login attempts within a time window.
 * Default: 5 failures => block 15 minutes.
 *
 * Requirement: "bloqueiem um IP após 5 logins falhados durante 15 minutos".
 */

const { writeSecurityLog } = require('../utils/securityLog');
const auditLogModel = require('../models/auditLogModel');

const MAX_FAILURES = Number(process.env.LOGIN_MAX_FAILURES || 5);
const WINDOW_MS = Number(process.env.LOGIN_FAIL_WINDOW_MS || (15 * 60 * 1000));
const BLOCK_MS = Number(process.env.LOGIN_BLOCK_MS || (15 * 60 * 1000));

function writeAudit(entry) {
  auditLogModel.createAuditLog(entry).catch(() => {});
}

// In-memory store: ip -> { failures: number[], blockedUntil?: number }
const store = new Map();

function getClientIp(req) {
  // If behind proxy, trust proxy should be enabled in app.js
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.trim()) {
    return xff.split(',')[0].trim();
  }
  return (req.ip || '').replace('::ffff:', '') || 'unknown';
}

function _getState(ip) {
  if (!store.has(ip)) store.set(ip, { failures: [], blockedUntil: 0 });
  return store.get(ip);
}

function guard(req, res, next) {
  const ip = getClientIp(req);
  const state = _getState(ip);
  const now = Date.now();

  if (state.blockedUntil && state.blockedUntil > now) {
    const retryAfterSec = Math.ceil((state.blockedUntil - now) / 1000);

    // Converter para minutos + segundos
    const minutes = Math.floor(retryAfterSec / 60);
    const seconds = retryAfterSec % 60;

    // Formatação amigável
    let timeMessage;
    if (minutes > 0) {
      timeMessage = `${minutes}m ${seconds.toString().padStart(2, '0')}s`;
    } else {
      timeMessage = `${seconds}s`;
    }

    // Header HTTP deve continuar em segundos
    res.set('Retry-After', String(retryAfterSec));

    writeSecurityLog('LOGIN_BLOCKED_ATTEMPT', {
      ip,
      retryAfterSec,
      blockedUntil: new Date(state.blockedUntil).toISOString()
    });
    writeAudit({
      action: 'AUTH_LOGIN_BLOCKED',
      result: 'FAIL',
      details: { ip, retryAfterSec }
    });

    return res.status(429).json({
      error: 'Too Many Requests',
      message: `IP bloqueado temporariamente devido a múltiplas falhas de login. Tenta novamente em ${timeMessage}.`,
      retryAfterSec,
      retryAfterFormatted: timeMessage
    });
  }

  next();
}

function recordFailure(req, meta = {}) {
  const ip = getClientIp(req);
  const state = _getState(ip);
  const now = Date.now();

  // Keep only failures within window
  state.failures = state.failures.filter((ts) => now - ts <= WINDOW_MS);
  state.failures.push(now);

  writeSecurityLog('LOGIN_FAILED', { ip, failuresInWindow: state.failures.length, ...meta });
  writeAudit({
    userId: meta.userId || null,
    action: 'AUTH_LOGIN_ATTEMPT',
    result: 'FAIL',
    details: { ip, failuresInWindow: state.failures.length, email: meta.email }
  });

  if (state.failures.length >= MAX_FAILURES) {
    state.blockedUntil = now + BLOCK_MS;
    // Reset failures list to avoid growth
    state.failures = [];

    writeSecurityLog('LOGIN_IP_BLOCKED', {
      ip,
      blockedUntil: new Date(state.blockedUntil).toISOString(),
      blockMinutes: Math.round(BLOCK_MS / 60000)
    });
    writeAudit({
      action: 'AUTH_LOGIN_IP_BLOCKED',
      result: 'FAIL',
      details: { ip, blockMinutes: Math.round(BLOCK_MS / 60000) }
    });

    return { blocked: true, blockedUntil: state.blockedUntil };
  }

  return { blocked: false, remaining: Math.max(0, MAX_FAILURES - state.failures.length) };
}

function recordSuccess(req, meta = {}) {
  const ip = getClientIp(req);
  store.delete(ip);
  writeSecurityLog('LOGIN_SUCCESS', { ip, ...meta });
  writeAudit({
    userId: meta.userId || null,
    action: 'AUTH_LOGIN_ATTEMPT',
    result: 'SUCCESS',
    details: { ip, email: meta.email }
  });
}

module.exports = {
  guard,
  recordFailure,
  recordSuccess,
  getClientIp,
  _store: store
};
