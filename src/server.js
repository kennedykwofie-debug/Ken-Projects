require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const logger = require('./utils/logger');
const apiRoutes = require('./routes/api');

if (!fs.existsSync('logs')) fs.mkdirSync('logs');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(helmet());
app.use(cors({ origin: '*', methods: ['GET', 'POST'] }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));
app.use(express.json());
app.use('/api/v1', apiRoutes);

const publicDir = path.join(__dirname, '..', 'public');
app.use(express.static(publicDir));
app.get('*', (req, res) => {
  const i = path.join(publicDir, 'index.html');
  fs.existsSync(i) ? res.sendFile(i) : res.json({ message: 'DARKWATCH API' });
});

app.listen(PORT, () => {
  logger.info(`DARKWATCH started on http://localhost:${PORT}`);

  // Pre-warm MITRE ATT&CK cache in background (50MB download, takes ~30s cold)
  setTimeout(() => {
    logger.info('Pre-warming MITRE ATT&CK cache...');
    require('./feeds/actors').fetchThreatActors({ limit: 50 })
      .then(g => logger.info(`MITRE warm: ${g.length} groups cached`))
      .catch(e => logger.warn('MITRE warm-up failed: ' + e.message));

    // Also pre-warm CISA KEV
    require('./feeds/cves').fetchCISAKEV()
      .then(() => logger.info('CISA KEV warmed'))
      .catch(() => {});

    // Pre-warm OpenPhish
    require('./feeds/phishing').fetchPhishingCampaigns()
      .then(p => logger.info(`Phishing warm: ${p.length} campaigns`))
      .catch(() => {});
  }, 2000); // wait 2s after server starts
});

module.exports = app;
