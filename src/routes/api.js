const express = require('express');
const aggregator = require('../feeds/aggregator');
const cacheUtil = require('../utils/cache');
const logger = require('../utils/logger');
const router = express.Router();

router.get('/threats', async (req, res) => {
  try {
    const { industry, region, severity, limit = 50 } = req.query;
    const data = await aggregator.aggregateAll({ industry: industry || 'all', region: region || 'all', severity: severity || 'all', limit: Math.min(parseInt(limit) || 50, 200) });
    res.json({ success: true, data });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
router.get('/iocs', async (req, res) => {
  try {
    const { limit = 100 } = req.query;
    const iocs = await aggregator.aggregateIoCs({ limit: Math.min(parseInt(limit) || 100, 500) });
    res.json({ success: true, data: iocs, total: iocs.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
router.get('/actors', async (req, res) => {
  try {
    const { limit = 20, nation, type } = req.query;
    let actors = await aggregator.fetchThreatActors({ limit: 50 });
    if (nation) actors = actors.filter(a => a.nation?.toLowerCase() === nation.toLowerCase());
    if (type) actors = actors.filter(a => a.type?.toLowerCase().includes(type.toLowerCase()));
    res.json({ success: true, data: actors.slice(0, parseInt(limit)), total: actors.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
router.get('/cves', async (req, res) => {
  try {
    const { limit = 20, exploited, source } = req.query;
    let list = source === 'kev' ? await aggregator.fetchRecentKEV({ limit: parseInt(limit) || 20 }) : await aggregator.fetchRecentCVEs({ limit: parseInt(limit) || 20 });
    if (exploited === 'true') list = list.filter(c => c.exploited);
    res.json({ success: true, data: list, total: list.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
router.get('/phishing', async (req, res) => {
  try {
    const { limit = 20 } = req.query;
    const data = await aggregator.fetchPhishing();
    res.json({ success: true, data: data.slice(0, parseInt(limit)), total: data.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
router.get('/stats', async (req, res) => {
  try { res.json({ success: true, data: await aggregator.getStats() }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
router.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), cache: cacheUtil.stats(), feeds: { otx: process.env.OTX_API_KEY && !process.env.OTX_API_KEY.startsWith('your_') ? 'configured' : 'no-key', urlhaus: 'public', bazaar: 'public', feodo: 'public', threatfox: 'public', mitre: 'public', cisa: 'public' } });
});
router.post('/cache/flush', (req, res) => {
  cacheUtil.flush((req.body || {}).prefix || null);
  res.json({ success: true, message: 'Cache flushed' });
});
module.exports = router;
