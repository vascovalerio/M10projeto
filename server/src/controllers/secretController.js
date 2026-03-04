const { validationResult } = require('express-validator');
const secretModel = require('../models/secretModel');
const { escapeHtml } = require('../utils/sanitize');

/**
 * POST /secrets
 * Create a secret for the authenticated user
 */
async function createSecret(req, res, next) {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const name = String(req.body.name || '').trim();
    const value = String(req.body.value || '').trim();
    const ownerId = req.auth.user.id;

    const secret = await secretModel.createSecret({ ownerId, name, value });
    return res.status(201).json(serializeSecret(secret));
  } catch (err) {
    return next(err);
  }
}

/**
 * GET /secrets/:id
 * Avoid IDOR: only allow access to secrets owned by the authenticated user.
 * If not owned (or doesn't exist), respond with 404.
 */
async function getSecret(req, res, next) {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const id = Number(req.params.id);
    if (!Number.isFinite(id)) {
      return res.status(400).json({ error: 'Validation Error', message: 'Invalid secret id' });
    }

    const userId = req.auth.user.id;
    const secret = await secretModel.getSecretByIdForOwner(id, userId);

    // Important: return 404 instead of 403 when resource isn't owned
    if (!secret) {
      return res.status(404).json({ error: 'Not Found', message: 'Secret not found' });
    }

    return res.json(serializeSecret(secret));
  } catch (err) {
    return next(err);
  }
}


/**
 * GET /secrets?search=foo
 * List authenticated user's secrets with optional search.
 */
async function listSecrets(req, res, next) {
  try {
    const ownerId = req.auth.user.id;
    const search = typeof req.query.search === 'string' ? req.query.search.trim() : '';

    const secrets = await secretModel.listSecretsForOwner({ ownerId, search });
    return res.json({ data: secrets.map(serializeSecret) });
  } catch (err) {
    return next(err);
  }
}

module.exports = {
  listSecrets,
  createSecret,
  getSecret
};

function serializeSecret(secret) {
  return {
    id: secret.id,
    owner_id: secret.owner_id,
    name: escapeHtml(secret.name),
    value: escapeHtml(secret.value),
    created_at: secret.created_at
  };
}
