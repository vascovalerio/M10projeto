const express = require('express');
const router = express.Router();
const { body, param } = require('express-validator');

const secretController = require('../controllers/secretController');

// GET /secrets
router.get('/', secretController.listSecrets);

// POST /secrets
router.post('/', [
  body('name').trim().notEmpty().withMessage('name is required'),
  body('value').trim().notEmpty().withMessage('value is required')
], secretController.createSecret);

// GET /secrets/:id
router.get('/:id', [
  param('id').notEmpty().withMessage('Secret ID is required')
], secretController.getSecret);

module.exports = router;
