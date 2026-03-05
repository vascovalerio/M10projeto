/**
 * Database Configuration
 * 
 * Configures SQLite database connection and initializes tables.
 */

const sqlite3 = require('sqlite3').verbose();
const sqlite = require('sqlite');
const path = require('path');
const fs = require('fs-extra');
require('dotenv').config();

const dbPath = path.resolve(__dirname, '../../', process.env.DATABASE_URL || './data/tickets.db');

let db = null;
let initializingPromise = null;

/**
 * Initialize database connection and create tables
 */
async function initializeDatabase() {
  if (db) return db;
  if (initializingPromise) return initializingPromise;

  initializingPromise = (async () => {
    await fs.ensureDir(path.dirname(dbPath));

    const openedDb = await sqlite.open({
      filename: dbPath,
      driver: sqlite3.Database
    });

    db = openedDb;
    console.log(`Database connected: ${dbPath}`);

    // Tickets table
    await db.exec(`
      CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        status TEXT DEFAULT 'Open',
        priority TEXT DEFAULT '3',
        category TEXT DEFAULT 'incident',
        impact TEXT,
        urgency TEXT,
        created_at DATETIME,
        resolved_at DATETIME,
        closed_at DATETIME,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Users table (auth)
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Backwards-compatible migration: add role column if upgrading an existing DB
    const userCols = await db.all(`PRAGMA table_info(users)`);
    const hasRole = userCols.some(c => c && c.name === 'role');
    if (!hasRole) {
      await db.exec(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'`);
    }
    const hasTokenVersion = userCols.some(c => c && c.name === 'token_version');
    if (!hasTokenVersion) {
      await db.exec(`ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0`);
    }

    // Sessions table (opaque bearer token)
    await db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        ip TEXT,
        user_agent TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Audit logs (exercise 5.1)
    await db.exec(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        result TEXT NOT NULL CHECK(result IN ('SUCCESS', 'FAIL')),
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    await db.exec(`
      CREATE TRIGGER IF NOT EXISTS trg_audit_logs_no_update
      BEFORE UPDATE ON audit_logs
      BEGIN
        SELECT RAISE(ABORT, 'audit_logs are immutable');
      END;
    `);

    await db.exec(`
      CREATE TRIGGER IF NOT EXISTS trg_audit_logs_no_delete
      BEFORE DELETE ON audit_logs
      BEGIN
        SELECT RAISE(ABORT, 'audit_logs are immutable');
      END;
    `);

    // Secrets table (exercise 2.2)
    await db.exec(`
      CREATE TABLE IF NOT EXISTS secrets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        value TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    await db.exec(`
      CREATE INDEX IF NOT EXISTS idx_secrets_owner_id ON secrets(owner_id);
    `);

    // Indexes
    await db.exec(`
      CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
      CREATE INDEX IF NOT EXISTS idx_tickets_priority ON tickets(priority);
      CREATE INDEX IF NOT EXISTS idx_tickets_category ON tickets(category);
    `);

    await db.exec(`
      CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
    `);

    console.log('Database tables initialized successfully');

    return db;
  })()
    .catch(error => {
      console.error('Database initialization failed:', error);
      throw error;
    })
    .finally(() => {
      initializingPromise = null;
    });

  return initializingPromise;
}

function getDatabase() {
  if (!db) throw new Error('Database not initialized. Call initializeDatabase() first.');
  return db;
}

async function closeDatabase() {
  if (db) {
    await db.close();
    db = null;
    console.log('Database connection closed');
  }
}

module.exports = {
  initializeDatabase,
  getDatabase,
  closeDatabase
};
