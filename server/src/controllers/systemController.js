const fs = require('fs-extra');
const { LOG_FILE } = require('../utils/securityLog');
const auditLogModel = require('../models/auditLogModel');

async function getSecurityLogs(req, res, next) {
  try {
    const exists = await fs.pathExists(LOG_FILE);
    if (!exists) {
      return res.json({ logs: [] });
    }

    const raw = await fs.readFile(LOG_FILE, 'utf8');
    const lines = raw.split(/\r?\n/).filter(Boolean);

    // Parse JSON Lines; skip malformed entries
    const logs = [];
    for (const line of lines) {
      try {
        logs.push(JSON.parse(line));
      } catch {
        // ignore malformed
      }
    }

    // Most recent first
    logs.sort((a, b) => String(b.timestamp || '').localeCompare(String(a.timestamp || '')));

    return res.json({ logs });
  } catch (err) {
    return next(err);
  }
}

async function getAuditLogs(req, res, next) {
  try {
    const limit = Number(req.query.limit || 100);
    const logs = await auditLogModel.listAuditLogs({ limit });
    return res.json({ logs });
  } catch (err) {
    return next(err);
  }
}

module.exports = { getSecurityLogs, getAuditLogs };
