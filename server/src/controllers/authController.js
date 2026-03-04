/**
 * Auth Controller
 *
 * Implements:
 * - User registration with hashed passwords (KDF + salt)
 * - Login with password verification
 * - Session (opaque bearer token)
 */

const { validationResult } = require('express-validator');
const userModel = require('../models/userModel');
const sessionModel = require('../models/sessionModel');
const loginRateLimiter = require('../middleware/loginRateLimiter');
const { isStrongPassword, hashPassword, verifyPassword } = require('../utils/password');

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
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Password fraca. Requisitos: >=8 caracteres, 1 número e 1 caracter especial.'
      });
    }

    const existing = await userModel.getUserByEmail(email);
    if (existing) {
      return res.status(409).json({ error: 'Conflict', message: 'Email já registado.' });
    }

    const passwordHash = await hashPassword(password);
    let user = await userModel.createUser({ email, passwordHash });

    // Optional: allow easy bootstrapping of admins via env var
    if (isAdminEmail(email) && user.role !== 'admin') {
      user = await userModel.setUserRole(user.id, 'admin');
    }

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
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Credenciais inválidas.'
      });
    }

    // Verificar password
    const ok = await verifyPassword(password, userRow.password_hash);
    if (!ok) {
      loginRateLimiter.recordFailure(req, { email, userId: userRow.id });
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

    return res.json({
      token: session.token,
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
    await sessionModel.deleteSession(req.auth.token);
    return res.json({ message: 'Logged out' });
  } catch (err) {
    return next(err);
  }
}

module.exports = {
  register,
  login,
  me,
  logout
};
