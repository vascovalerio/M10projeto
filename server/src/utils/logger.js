/**
 * Logger Utility
 * 
 * Simple logging utility using console with structured output.
 */

const { sanitizeForLogs } = require('./logSanitizer');

function write(level, message, meta = {}) {
  const payload = sanitizeForLogs({
    timestamp: new Date().toISOString(),
    level,
    message,
    ...meta
  });

  const line = JSON.stringify(payload);
  if (level === 'ERROR') {
    console.error(line);
    return;
  }
  if (level === 'WARN') {
    console.warn(line);
    return;
  }
  console.log(line);
}

const logger = {
  info: (message, meta = {}) => {
    write('INFO', message, meta);
  },

  error: (message, meta = {}) => {
    write('ERROR', message, meta);
  },

  warn: (message, meta = {}) => {
    write('WARN', message, meta);
  },

  debug: (message, meta = {}) => {
    if (process.env.NODE_ENV === 'development') {
      write('DEBUG', message, meta);
    }
  }
};

module.exports = logger;
