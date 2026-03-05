const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const YAML = require('yamljs');
const swaggerUi = require('swagger-ui-express');

require('dotenv').config();

const { initializeDatabase } = require('./config/database');
const { seedTicketsIfEmpty } = require('./services/seedTickets');

const healthRoutes = require('./routes/healthRoutes');
const authRoutes = require('./routes/authRoutes');
const ticketRoutes = require('./routes/ticketRoutes');
const statsRoutes = require('./routes/statsRoutes');
const systemRoutes = require('./routes/systemRoutes');
const secretRoutes = require('./routes/secretRoutes');

const { requireAuth } = require('./middleware/requireAuth');
const { requireRole } = require('./middleware/requireRole');

const logger = require('./utils/logger');
const swaggerDocument = YAML.load(path.join(__dirname, '../docs/openapi.yaml'));

const app = express();
const allowedOrigins = (process.env.CLIENT_ORIGINS || 'http://localhost:3000,http://localhost:5500')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

// If deployed behind a reverse proxy, this enables req.ip to be set correctly
app.set('trust proxy', true);

// Database init + seeding
initializeDatabase()
  .then(async () => {
    logger.info('Database initialized and ready');

    const seedResult = await seedTicketsIfEmpty();
    if (seedResult.seeded) {
      logger.info(`Ticket seeding completed. Inserted ${seedResult.insertedCount} tickets.`);
    } else {
      logger.info(`Ticket seeding skipped: ${seedResult.reason} (existing tickets: ${seedResult.existingCount || 0})`);
    }
  })
  .catch(error => {
    logger.error('Application initialization failed:', error);
    process.exit(1);
  });

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"]
    }
  },
  frameguard: { action: 'deny' },
  hsts: { maxAge: 15552000, includeSubDomains: true }
}));
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('CORS origin não autorizada'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined', { stream: { write: msg => logger.info(msg.trim()) } }));

// Serve frontend (webapp) as static files
app.use(express.static(path.join(__dirname, '../../webapp')));

// Routes
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// API info (kept under /api so / serves the frontend)
app.get('/api', (req, res) => res.json({ name:'Ticket Manager API', version:'2.0.0', endpoints:{ health:'/health', auth:'/api/auth', tickets:'/api/tickets', stats:'/api/stats', documentation:'/api-docs' } }));

app.use('/health', healthRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/tickets', requireAuth, ticketRoutes);
app.use('/api/stats', requireAuth, statsRoutes);

// Secrets (exercise 2.2)
app.use('/secrets', requireAuth, secretRoutes);

// System operations
app.use('/system', requireAuth, requireRole('admin'), systemRoutes);

// 404 & error handler
app.use((req,res)=>res.status(404).json({ error:'Not Found', message:`Route ${req.method} ${req.path} not found` }));
app.use((err, req, res, next)=>{
  if (err && err.message === 'CORS origin não autorizada') {
    return res.status(403).json({ error: 'Forbidden', message: err.message });
  }
  logger.error('Unhandled error:', err);
  res.status(err.status||500).json({ error:err.name||'Internal Server Error', message:err.message||'Unexpected error', ...(process.env.NODE_ENV==='development' && { stack: err.stack }) });
});

module.exports = app;
