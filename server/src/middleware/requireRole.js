/**
 * requireRole middleware factory
 *
 * Usage:
 *   const { requireRole } = require('./middleware/requireRole');
 *   app.get('/system/logs', requireAuth, requireRole('admin'), handler)
 */

function requireRole(role) {
  return function requireRoleMiddleware(req, res, next) {
    const user = req.auth && req.auth.user;
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Missing authentication context' });
    }

    if (user.role !== role) {
      return res.status(403).json({ error: 'Forbidden', message: `Requires role: ${role}` });
    }

    return next();
  };
}

module.exports = { requireRole };
