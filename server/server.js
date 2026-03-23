#!/usr/bin/env node
const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Warmup probe do Azure (responde a /robots933456.txt)
app.get('/robots933456.txt', (req, res) => {
  res.send('OK');
});

// Warmup probe do Azure (responde à raiz)
app.get('/', (req, res) => {
  res.send('Backend a funcionar no Azure! 🎉');
});

// O teu código original (adaptado para usar express)
const yourApp = express(); // Usa o teu app original
yourApp.get('/api-docs', (req, res) => res.send('API Docs'));
yourApp.get('/health', (req, res) => res.send('Healthy'));

// Usa a mesma porta
yourApp.listen(PORT, () => {
  console.log(`Ticket Manager Server running on port ${PORT}`);
});

// Graceful shutdown
function shutdown(signal) {
  console.log(`${signal} received. Shutting down gracefully...`);
  yourApp.close(() => process.exit(0));
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
