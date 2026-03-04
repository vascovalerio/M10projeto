/**
 * Secret model (SQLite)
 */

const { getDatabase } = require('../config/database');

async function createSecret({ ownerId, name, value }) {
  const db = getDatabase();
  const result = await db.run(
    `INSERT INTO secrets (owner_id, name, value) VALUES (?, ?, ?)`,
    [ownerId, name, value]
  );
  return getSecretById(result.lastID);
}

async function getSecretById(id) {
  const db = getDatabase();
  return db.get(
    `SELECT id, owner_id, name, value, created_at FROM secrets WHERE id = ?`,
    [id]
  );
}

async function getSecretByIdForOwner(id, ownerId) {
  const db = getDatabase();
  return db.get(
    `SELECT id, owner_id, name, value, created_at
     FROM secrets
     WHERE id = ? AND owner_id = ?`,
    [id, ownerId]
  );
}

module.exports = {
  createSecret,
  getSecretById,
  getSecretByIdForOwner
};
