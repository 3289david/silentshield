require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-secret-key', 'x-admin-secret', 'Authorization'],
}));
app.use(express.json({ limit: '50kb' }));

const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 500,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many requests' },
});
app.use('/api/', apiLimiter);

const verifyRouter = require('./routes/verify');
const analyticsRouter = require('./routes/analytics');
const authRouter = require('./routes/auth');
app.use('/api', verifyRouter);
app.use('/api/analytics', analyticsRouter);
app.use('/api/auth', authRouter);
app.get('/health', (_, res) => res.json({ status: 'ok', ts: Date.now() }));

const publicDir = path.join(__dirname, '..', 'public');
app.use(express.static(publicDir));
app.get('*', (_, res) => res.sendFile(path.join(publicDir, 'index.html')));

// Initialize DB first, then start server
async function start() {
  const db = require('./db');
  await db.init();

  const { startBotLearner } = require('./botLearner');

  app.listen(PORT, () => {
    console.log(`\n🛡️  SilentShield running on port ${PORT}`);
    console.log(`   Landing:   http://localhost:${PORT}`);
    console.log(`   Dashboard: http://localhost:${PORT}/dashboard`);
    console.log(`   API:       http://localhost:${PORT}/api\n`);
    startBotLearner();
  });
}

start().catch(err => { console.error('Startup failed:', err); process.exit(1); });

module.exports = app;
