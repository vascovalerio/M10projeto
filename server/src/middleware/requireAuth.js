/**
 * requireAuth middleware
 *
 * Uses opaque bearer tokens stored in the sessions table.
 */

const sessionModel = require('../models/sessionModel');
const userModel = require('../models/userModel');

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

    const session = await sessionModel.getSessionByToken(token);
    if (!session) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid or expired session' });
    }

    const user = await userModel.getUserById(session.user_id);
    if (!user) {
      await sessionModel.deleteSession(token);
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid session' });
    }

    req.auth = {
      token,
      session,
      user: { id: user.id, email: user.email, role: user.role }
    };

    return next();
  } catch (err) {
    return next(err);
  }
}

module.exports = { requireAuth };
