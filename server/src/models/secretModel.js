/**
 * Secret model (SQLite)
 */

const { getDatabase } = require('../config/database');
const { encryptSecretValue, decryptSecretValue } = require('../utils/cryptoSecrets');

async function createSecret({ ownerId, name, value }) {
  const db = getDatabase();
  const encryptedValue = encryptSecretValue(value);

  const result = await db.run(
    `INSERT INTO secrets (owner_id, name, value) VALUES (?, ?, ?)`,
    [ownerId, name, encryptedValue]
  );

  return getSecretById(result.lastID);
}

async function getSecretById(id) {
  const db = getDatabase();
  const row = await db.get(
    `SELECT id, owner_id, name, value, created_at FROM secrets WHERE id = ?`,
    [id]
  );

  return decryptSecretRow(row);
}

async function getSecretByIdForOwner(id, ownerId) {
  const db = getDatabase();
  const row = await db.get(
    `SELECT id, owner_id, name, value, created_at
     FROM secrets
     WHERE id = ? AND owner_id = ?`,
    [id, ownerId]
  );

  return decryptSecretRow(row);
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

  const rows = await db.all(`${baseSql} ORDER BY created_at DESC`, [ownerId]);
  const decryptedSecrets = rows.map(decryptSecretRow);

  if (!search) {
    return decryptedSecrets;
  }

  const needle = String(search).toLowerCase();
  return decryptedSecrets.filter(secret =>
    String(secret.name).toLowerCase().includes(needle) ||
    String(secret.value).toLowerCase().includes(needle)
  );
}

module.exports = {
  createSecret,
  getSecretById,
  getSecretByIdForOwner,
  listSecretsForOwner
};

function decryptSecretRow(secretRow) {
  if (!secretRow) return null;
  return {
    ...secretRow,
    value: decryptSecretValue(secretRow.value)
  };
}
