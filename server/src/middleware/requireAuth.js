/**
 * requireAuth middleware
 *
 * Uses short-lived JWT access tokens.
 */

const userModel = require('../models/userModel');
const jwt = require('../utils/jwt');

async function requireAuth(req, res, next) {
  try {
    const auth = req.headers.authorization || '';
    const match = auth.match(/^Bearer\s+(.+)$/i);
    if (!match) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Missing Bearer token' });
    }

    const token = match[1].trim();
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Missing Bearer token' });
    }

    let payload;
    try {
      payload = jwt.verify(token);
    } catch (_err) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid or expired token' });
    }

    const userId = Number(payload.sub);
    const user = await userModel.getUserById(userId);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid token' });
    }

    const tokenVersion = Number(payload.tokenVersion || 0);
    if (tokenVersion !== Number(user.token_version || 0)) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Token revoked' });
    }

    req.auth = {
      token,
      user: { id: user.id, email: user.email, role: user.role }
    };

    return next();
  } catch (err) {
    return next(err);
  }
}

module.exports = { requireAuth };
