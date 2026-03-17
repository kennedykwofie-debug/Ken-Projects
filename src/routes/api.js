const express = require('express');
const aggregator = require('../feeds/aggregator');
const monitor = require('../feeds/monitor');
const shodan = require('../feeds/shodan');
const creds = require('../feeds/credentials');
const cacheUtil = require('../utils/cache');
const logger = require('../utils/logger');
const router = express.Router();

// ── Existing threat intel routes ─────────────────────────────────────────────
router.get('/threats', async function(req, res) {
  try {
    var q = req.query;
    var data = await aggregator.aggregateAll({ industry: q.industry || 'all', region: q.region || 'all', severity: q.severity || 'all', limit: Math.min(parseInt(q.limit) || 50, 200) });
    res.json({ success: true, data: data });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/iocs', async function(req, res) {
  try {
    var iocs = await aggregator.aggregateIoCs({ limit: Math.min(parseInt(req.query.limit) || 100, 500) });
    res.json({ success: true, data: iocs, total: iocs.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/actors', async function(req, res) {
  try {
    var q = req.query;
    var actors = await aggregator.fetchThreatActors({ limit: 50 });
    if (q.nation) actors = actors.filter(function(a) { return a.nation && a.nation.toLowerCase() === q.nation.toLowerCase(); });
    res.json({ success: true, data: actors.slice(0, parseInt(q.limit) || 40), total: actors.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/cves', async function(req, res) {
  try {
    var q = req.query;
    var list = q.source === 'kev' ? await aggregator.fetchRecentKEV({ limit: parseInt(q.limit) || 20 }) : await aggregator.fetchRecentCVEs({ limit: parseInt(q.limit) || 20 });
    if (q.exploited === 'true') list = list.filter(function(c) { return c.exploited; });
    res.json({ success: true, data: list, total: list.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/phishing', async function(req, res) {
  try {
    var data = await aggregator.fetchPhishing();
    res.json({ success: true, data: data.slice(0, parseInt(req.query.limit) || 20), total: data.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/stats', async function(req, res) {
  try { res.json({ success: true, data: await aggregator.getStats() }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/health', function(req, res) {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), cache: cacheUtil.stats(), feeds: { otx: process.env.OTX_API_KEY && !process.env.OTX_API_KEY.startsWith('your_') ? 'configured' : 'no-key', urlhaus: 'public', bazaar: 'public', feodo: 'public', threatfox: 'public', mitre: 'public', cisa: 'public' } });
});

router.post('/cache/flush', function(req, res) {
  cacheUtil.flush((req.body || {}).prefix || null);
  res.json({ success: true, message: 'Cache flushed' });
});

// ── MONITORING: Shodan Asset Routes ──────────────────────────────────────────

// GET /api/v1/monitor/status - full monitoring state
router.get('/monitor/status', function(req, res) {
  try { res.json({ success: true, data: monitor.getState() }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// POST /api/v1/monitor/scan - trigger manual scan
router.post('/monitor/scan', async function(req, res) {
  try {
    res.json({ success: true, message: 'Scan started', data: { started: new Date().toISOString() } });
    monitor.runScanCycle().catch(function(e) { logger.error('Manual scan error: ' + e.message); });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// POST /api/v1/monitor/watchlist - add to watchlist
router.post('/monitor/watchlist', function(req, res) {
  try {
    var body = req.body || {};
    if (body.ip) monitor.addWatchedIP(body.ip);
    if (body.domain) monitor.addWatchedDomain(body.domain);
    if (body.credDomain) monitor.addCredDomain(body.credDomain);
    res.json({ success: true, message: 'Added to watchlist', state: monitor.getState() });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// DELETE /api/v1/monitor/watchlist
router.delete('/monitor/watchlist', function(req, res) {
  try {
    var body = req.body || {};
    if (body.type && body.value) monitor.removeWatched(body.type, body.value);
    res.json({ success: true, state: monitor.getState() });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/v1/monitor/assets - internet-facing assets
router.get('/monitor/assets', function(req, res) {
  try {
    var state = monitor.getState();
    var all = [];
    (state.domainAssets || []).forEach(function(d) { (d.assets || []).forEach(function(a) { all.push(Object.assign({}, a, { org: d.domain })); }); });
    all.sort(function(a, b) {
      var order = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order[a.riskLevel] || 4) - (order[b.riskLevel] || 4);
    });
    res.json({ success: true, data: all, total: all.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/v1/monitor/ip/:ip - scan single IP
router.get('/monitor/ip/:ip', async function(req, res) {
  try {
    var result = await shodan.scanIP(req.params.ip);
    res.json({ success: true, data: result });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/v1/monitor/alerts - monitoring alerts
router.get('/monitor/alerts', function(req, res) {
  try {
    var state = monitor.getState();
    res.json({ success: true, data: state.alerts, total: (state.alerts || []).length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── CREDENTIAL LEAK Routes ────────────────────────────────────────────────────

// GET /api/v1/credentials/status - all monitored domains
router.get('/credentials/status', function(req, res) {
  try {
    var state = monitor.getState();
    res.json({ success: true, data: state.credResults, domains: state.credDomains });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/v1/credentials/domain/:domain - check specific domain
router.get('/credentials/domain/:domain', async function(req, res) {
  try {
    var result = await creds.checkDomainBreaches(req.params.domain);
    res.json({ success: true, data: result });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/v1/credentials/breaches - recent major breaches from HIBP
router.get('/credentials/breaches', async function(req, res) {
  try {
    var breaches = await creds.getAllBreaches();
    res.json({ success: true, data: breaches, total: breaches.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

module.exports = router;
