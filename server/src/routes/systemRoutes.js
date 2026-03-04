const express = require('express');
const router = express.Router();

const systemController = require('../controllers/systemController');

// GET /system/logs (admin only)
router.get('/logs', systemController.getSecurityLogs);

module.exports = router;
