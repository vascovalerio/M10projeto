/**
 * Auth Controller
 *
 * Implements:
 * - User registration with hashed passwords (KDF + salt)
 * - Login with password verification
 * - JWT (access token) + refresh token HttpOnly cookie
 */

const { validationResult } = require('express-validator');
const userModel = require('../models/userModel');
const sessionModel = require('../models/sessionModel');
const auditLogModel = require('../models/auditLogModel');
const loginRateLimiter = require('../middleware/loginRateLimiter');
const { isStrongPassword, hashPassword, verifyPassword } = require('../utils/password');
const jwt = require('../utils/jwt');

const REFRESH_COOKIE_NAME = 'refresh_token';
const REFRESH_COOKIE_MAX_AGE_MS = Number(process.env.REFRESH_TOKEN_TTL_MS || (7 * 24 * 60 * 60 * 1000));

function getCookieValue(req, name) {
  const raw = req.headers.cookie || '';
  const parts = raw.split(';').map(s => s.trim()).filter(Boolean);
  for (const p of parts) {
    const idx = p.indexOf('=');
    if (idx <= 0) continue;
    const key = p.slice(0, idx).trim();
    const val = p.slice(idx + 1).trim();
    if (key === name) return decodeURIComponent(val);
  }
  return null;
}

function setRefreshCookie(res, token) {
  const isProd = process.env.NODE_ENV === 'production';
  res.cookie(REFRESH_COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProd,
    sameSite: 'strict',
    path: '/api/auth/refresh',
    maxAge: REFRESH_COOKIE_MAX_AGE_MS
  });
}

function clearRefreshCookie(res) {
  res.clearCookie(REFRESH_COOKIE_NAME, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/auth/refresh'
  });
}

function buildAccessToken(user) {
  return jwt.sign({
    sub: String(user.id),
    email: user.email,
    role: user.role,
    tokenVersion: user.token_version || 0
  });
}

function isAdminEmail(email) {
  const raw = process.env.ADMIN_EMAILS || '';
  const admins = raw
    .split(',')
    .map(s => s.trim().toLowerCase())
    .filter(Boolean);
  return admins.includes(email);
}

async function register(req, res, next) {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!isStrongPassword(password)) {
      await auditLogModel.createAuditLog({
        action: 'AUTH_REGISTER',
        result: 'FAIL',
        details: { email, reason: 'weak_password' }
      });
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Password fraca. Requisitos: >=8 caracteres, 1 número e 1 caracter especial.'
      });
    }

    const existing = await userModel.getUserByEmail(email);
    if (existing) {
      await auditLogModel.createAuditLog({
        userId: existing.id,
        action: 'AUTH_REGISTER',
        result: 'FAIL',
        details: { email, reason: 'email_exists' }
      });
      return res.status(409).json({ error: 'Conflict', message: 'Email já registado.' });
    }

    const passwordHash = await hashPassword(password);
    let user = await userModel.createUser({ email, passwordHash });

    // Optional: allow easy bootstrapping of admins via env var
    if (isAdminEmail(email) && user.role !== 'admin') {
      user = await userModel.setUserRole(user.id, 'admin');
    }

    await auditLogModel.createAuditLog({
      userId: user.id,
      action: 'AUTH_REGISTER',
      result: 'SUCCESS',
      details: { email }
    });

    return res.status(201).json({
      id: user.id,
      email: user.email,
      role: user.role,
      created_at: user.created_at
    });
  } catch (err) {
    return next(err);
  }
}

async function login(req, res, next) {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    // Verificar se utilizador existe
    const userRow = await userModel.getUserByEmail(email);
    if (!userRow) {
      loginRateLimiter.recordFailure(req, { email });
      await auditLogModel.createAuditLog({
        action: 'AUTH_LOGIN',
        result: 'FAIL',
        details: { email, reason: 'user_not_found' }
      });
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Credenciais inválidas.'
      });
    }

    // Verificar password
    const ok = await verifyPassword(password, userRow.password_hash);
    if (!ok) {
      loginRateLimiter.recordFailure(req, { email, userId: userRow.id });
      await auditLogModel.createAuditLog({
        userId: userRow.id,
        action: 'AUTH_LOGIN',
        result: 'FAIL',
        details: { email, reason: 'invalid_password' }
      });
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Credenciais inválidas.'
      });
    }

    // Login bem sucedido
    loginRateLimiter.recordSuccess(req, { email, userId: userRow.id });

    const ip = loginRateLimiter.getClientIp(req);
    const userAgent = req.headers['user-agent'] || null;

    const session = await sessionModel.createSession(userRow.id, { ip, userAgent });
    const accessToken = buildAccessToken(userRow);
    setRefreshCookie(res, session.token);

    await auditLogModel.createAuditLog({
      userId: userRow.id,
      action: 'AUTH_LOGIN',
      result: 'SUCCESS',
      details: { email, ip }
    });

    return res.json({
      token: accessToken,
      accessToken,
      expiresAt: session.expiresAt,
      user: { id: userRow.id, email: userRow.email, role: userRow.role }
    });

  } catch (err) {
    return next(err);
  }
}

async function me(req, res) {
  return res.json({ user: req.auth.user });
}

async function logout(req, res, next) {
  try {
    const refreshToken = getCookieValue(req, REFRESH_COOKIE_NAME);
    if (refreshToken) {
      await sessionModel.deleteSession(refreshToken);
    }
    clearRefreshCookie(res);
    await auditLogModel.createAuditLog({
      userId: req.auth.user.id,
      action: 'AUTH_LOGOUT',
      result: 'SUCCESS',
      details: { email: req.auth.user.email }
    });
    return res.json({ message: 'Logged out' });
  } catch (err) {
    return next(err);
  }
}

async function refresh(req, res, next) {
  try {
    const refreshToken = getCookieValue(req, REFRESH_COOKIE_NAME);
    if (!refreshToken) {
      await auditLogModel.createAuditLog({
        action: 'AUTH_REFRESH',
        result: 'FAIL',
        details: { reason: 'missing_refresh_token' }
      });
      return res.status(401).json({ error: 'Unauthorized', message: 'Refresh token em falta.' });
    }

    const currentSession = await sessionModel.getSessionByToken(refreshToken);
    if (!currentSession) {
      clearRefreshCookie(res);
      await auditLogModel.createAuditLog({
        action: 'AUTH_REFRESH',
        result: 'FAIL',
        details: { reason: 'invalid_session' }
      });
      return res.status(401).json({ error: 'Unauthorized', message: 'Refresh token inválido ou expirado.' });
    }

    const user = await userModel.getUserById(currentSession.user_id);
    if (!user) {
      await sessionModel.deleteSession(refreshToken);
      clearRefreshCookie(res);
      await auditLogModel.createAuditLog({
        action: 'AUTH_REFRESH',
        result: 'FAIL',
        details: { reason: 'user_not_found' }
      });
      return res.status(401).json({ error: 'Unauthorized', message: 'Utilizador inválido.' });
    }

    await sessionModel.deleteSession(refreshToken);
    const ip = loginRateLimiter.getClientIp(req);
    const userAgent = req.headers['user-agent'] || null;
    const newSession = await sessionModel.createSession(user.id, { ip, userAgent });
    setRefreshCookie(res, newSession.token);

    const accessToken = buildAccessToken(user);
    await auditLogModel.createAuditLog({
      userId: user.id,
      action: 'AUTH_REFRESH',
      result: 'SUCCESS',
      details: { email: user.email }
    });
    return res.json({
      token: accessToken,
      accessToken,
      expiresAt: newSession.expiresAt
    });
  } catch (err) {
    return next(err);
  }
}

module.exports = {
  register,
  login,
  me,
  logout,
  refresh
};
