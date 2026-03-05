const { getDatabase } = require('../config/database');
const { sanitizeForLogs } = require('../utils/logSanitizer');

async function createAuditLog({ userId = null, action, result, details = {} }) {
  if (!action || typeof action !== 'string') {
    throw new Error('Audit action is required');
  }

  const db = getDatabase();
  const safeResult = result === 'FAIL' ? 'FAIL' : 'SUCCESS';
  const sanitizedDetails = sanitizeForLogs(details || {});

  await db.run(
    `INSERT INTO audit_logs (user_id, action, result, details) VALUES (?, ?, ?, ?)`,
    [userId, action, safeResult, JSON.stringify(sanitizedDetails)]
  );
}

async function listAuditLogs({ limit = 100 } = {}) {
  const db = getDatabase();
  const safeLimit = Math.min(Math.max(Number(limit) || 100, 1), 500);
  const rows = await db.all(
    `SELECT id, user_id, action, result, details, created_at
     FROM audit_logs
     ORDER BY datetime(created_at) DESC, id DESC
     LIMIT ?`,
    [safeLimit]
  );

  return rows.map(row => {
    let parsedDetails = row.details;
    try {
      parsedDetails = JSON.parse(row.details || '{}');
    } catch {
      parsedDetails = { raw: row.details };
    }

    return {
      id: row.id,
      user_id: row.user_id,
      action: row.action,
      result: row.result,
      details: sanitizeForLogs(parsedDetails),
      created_at: row.created_at
    };
  });
}

module.exports = {
  createAuditLog,
  listAuditLogs
};
