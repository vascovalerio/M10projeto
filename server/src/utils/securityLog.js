/**
 * Security Log Utility
 *
 * Appends security-relevant events to server/logs/security.log (JSON lines).
 */

const fs = require('fs-extra');
const path = require('path');
const { sanitizeForLogs } = require('./logSanitizer');

const LOG_FILE = path.join(__dirname, '../../logs/security.log');

async function writeSecurityLog(event, meta = {}) {
  try {
    await fs.ensureDir(path.dirname(LOG_FILE));
    const line = JSON.stringify(sanitizeForLogs({
      timestamp: new Date().toISOString(),
      event,
      ...meta
    }));
    await fs.appendFile(LOG_FILE, line + '\n', 'utf8');
  } catch {
    // Never crash the app because logging failed.
  }
}

module.exports = { writeSecurityLog, LOG_FILE };
