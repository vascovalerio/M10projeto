/**
 * User model (SQLite)
 */

const { getDatabase } = require('../config/database');

async function createUser({ email, passwordHash }) {
  const db = getDatabase();
  const result = await db.run(
    `INSERT INTO users (email, password_hash) VALUES (?, ?)`,
    [email, passwordHash]
  );
  return getUserById(result.lastID);
}

async function getUserByEmail(email) {
  const db = getDatabase();
  return db.get(`SELECT id, email, password_hash, role, token_version, created_at FROM users WHERE email = ?`, [email]);
}

async function getUserById(id) {
  const db = getDatabase();
  return db.get(`SELECT id, email, role, token_version, created_at FROM users WHERE id = ?`, [id]);
}

async function setUserRole(userId, role) {
  const db = getDatabase();
  await db.run(`UPDATE users SET role = ? WHERE id = ?`, [role, userId]);
  return getUserById(userId);
}

async function incrementTokenVersion(userId) {
  const db = getDatabase();
  await db.run(`UPDATE users SET token_version = token_version + 1 WHERE id = ?`, [userId]);
  return getUserById(userId);
}

module.exports = {
  createUser,
  getUserByEmail,
  getUserById,
  setUserRole,
  incrementTokenVersion
};
