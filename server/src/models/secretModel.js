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

/**
 * Lists secrets that belong to a given owner, with optional text search on name/value.
 *
 * Uses parameterized queries to avoid SQL injection.
 */
async function listSecretsForOwner({ ownerId, search }) {
  const db = getDatabase();

  const baseSql = `
    SELECT id, owner_id, name, value, created_at
    FROM secrets
    WHERE owner_id = ?
  `;

  if (!search) {
    return db.all(`${baseSql} ORDER BY created_at DESC`, [ownerId]);
  }

  const likeTerm = `%${search}%`;
  return db.all(
    `${baseSql} AND (name LIKE ? OR value LIKE ?) ORDER BY created_at DESC`,
    [ownerId, likeTerm, likeTerm]
  );
}

module.exports = {
  createSecret,
  getSecretById,
  getSecretByIdForOwner,
  listSecretsForOwner
};
