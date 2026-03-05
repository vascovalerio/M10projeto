/**
 * Auth Routes
 */

const express = require('express');
const { body } = require('express-validator');
const authController = require('../controllers/authController');
const loginRateLimiter = require('../middleware/loginRateLimiter');
const { requireAuth } = require('../middleware/requireAuth');

const router = express.Router();

router.post(
  '/register',
  [
    body('email').trim().isEmail().withMessage('Email inválido'),
    body('password').isString().withMessage('Password é obrigatória')
  ],
  authController.register
);

router.post(
  '/login',
  loginRateLimiter.guard,
  [
    body('email').trim().isEmail().withMessage('Email inválido'),
    body('password').isString().withMessage('Password é obrigatória')
  ],
  authController.login
);

router.get('/me', requireAuth, authController.me);
router.post('/refresh', authController.refresh);
router.post('/logout', requireAuth, authController.logout);

module.exports = router;
