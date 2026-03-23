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

// O teu código original (mantém a tua lógica)
app.get('/api-docs', (req, res) => res.send('API Docs'));
app.get('/health', (req, res) => res.send('Healthy'));

// Inicia o servidor
app.listen(PORT, () => {
  console.log(`Servidor a correr na porta ${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  app.close(() => process.exit(0));
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  app.close(() => process.exit(0));
});
