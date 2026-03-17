const express = require('express');
const aggregator = require('../feeds/aggregator');
const monitor = require('../feeds/monitor');
const shodan = require('../feeds/shodan');
const creds = require('../feeds/credentials');
const cacheUtil = require('../utils/cache');
const logger = require('../utils/logger');
const https = require('https');
const router = express.Router();

// ── Threat Intel ──────────────────────────────────────────────────────────────
router.get('/threats', async function(req, res) {
  try {
    var q = req.query;
    var data = await aggregator.aggregateAll({ industry: q.industry||'all', region: q.region||'all', severity: q.severity||'all', limit: Math.min(parseInt(q.limit)||50,200) });
    res.json({ success: true, data: data });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/iocs', async function(req, res) {
  try {
    var iocs = await aggregator.aggregateIoCs({ limit: Math.min(parseInt(req.query.limit)||100,500) });
    res.json({ success: true, data: iocs, total: iocs.length });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/actors', async function(req, res) {
  try {
    var q = req.query;
    var actors = await aggregator.fetchThreatActors({ limit: 50 });
    if (q.nation) actors = actors.filter(function(a){ return a.nation && a.nation.toLowerCase()===q.nation.toLowerCase(); });
    res.json({ success: true, data: actors.slice(0,parseInt(q.limit)||40), total: actors.length });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/cves', async function(req, res) {
  try {
    var q = req.query;
    var list = q.source==='kev' ? await aggregator.fetchRecentKEV({limit:parseInt(q.limit)||20}) : await aggregator.fetchRecentCVEs({limit:parseInt(q.limit)||20});
    if (q.exploited==='true') list = list.filter(function(c){ return c.exploited; });
    res.json({ success: true, data: list, total: list.length });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/phishing', async function(req, res) {
  try {
    var data = await aggregator.fetchPhishing();
    res.json({ success: true, data: data.slice(0,parseInt(req.query.limit)||20), total: data.length });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/stats', async function(req, res) {
  try { res.json({ success: true, data: await aggregator.getStats() }); }
  catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/health', function(req, res) {
  var hibp = process.env.HIBP_API_KEY;
  var shod = process.env.SHODAN_API_KEY;
  res.json({ status:'ok', timestamp: new Date().toISOString(), cache: cacheUtil.stats(), feeds: {
    otx: process.env.OTX_API_KEY && !process.env.OTX_API_KEY.startsWith('your_') ? 'configured' : 'no-key',
    urlhaus:'public', bazaar:'public', feodo:'public', threatfox:'public', mitre:'public', cisa:'public',
    hibp: (!hibp||hibp.startsWith('your_')) ? 'no-key' : 'configured',
    shodan: (!shod||shod.startsWith('your_')) ? 'no-key' : 'configured'
  }});
});

router.post('/cache/flush', function(req, res) {
  cacheUtil.flush((req.body||{}).prefix||null);
  res.json({ success: true, message: 'Cache flushed' });
});

// ── DNS Resolution ─────────────────────────────────────────────────────────────
// GET /api/v1/monitor/resolve?domain=example.com
router.get('/monitor/resolve', function(req, res) {
  var domain = (req.query.domain||'').trim();
  if (!domain) return res.status(400).json({ success: false, error: 'domain required' });
  var url = 'https://dns.google/resolve?name=' + encodeURIComponent(domain) + '&type=A';
  https.get(url, { headers: { 'Accept': 'application/json' } }, function(resp) {
    var body = '';
    resp.on('data', function(chunk){ body += chunk; });
    resp.on('end', function() {
      try {
        var data = JSON.parse(body);
        var ips = (data.Answer||[]).filter(function(r){ return r.type===1; }).map(function(r){ return r.data; });
        var cnames = (data.Answer||[]).filter(function(r){ return r.type===5; }).map(function(r){ return r.data; });
        res.json({ success: true, domain: domain, ips: ips, cnames: cnames, status: data.Status });
      } catch(e) { res.status(500).json({ success: false, error: 'DNS parse error' }); }
    });
  }).on('error', function(e){ res.status(500).json({ success: false, error: e.message }); });
});

// ── Asset Monitor ─────────────────────────────────────────────────────────────
router.get('/monitor/status', function(req, res) {
  try { res.json({ success: true, data: monitor.getState() }); }
  catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/monitor/scan', async function(req, res) {
  try {
    res.json({ success: true, message: 'Scan started', data: { started: new Date().toISOString() } });
    monitor.runScanCycle().catch(function(e){ logger.error('Scan error: ' + e.message); });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/monitor/watchlist', function(req, res) {
  try {
    var body = req.body || {};
    if (body.ip) monitor.addWatchedIP(body.ip);
    if (body.domain) monitor.addWatchedDomain(body.domain);
    if (body.credDomain) monitor.addCredDomain(body.credDomain);
    if (body.email) monitor.addWatchedEmail(body.email);
    res.json({ success: true, state: monitor.getState() });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

router.delete('/monitor/watchlist', function(req, res) {
  try {
    var body = req.body || {};
    if (body.type && body.value) monitor.removeWatched(body.type, body.value);
    res.json({ success: true, state: monitor.getState() });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/v1/monitor/assets — returns BOTH IP scan results AND domain discovery results
router.get('/monitor/assets', function(req, res) {
  try {
    var state = monitor.getState();
    var all = [];

    // 1. IP-level Shodan results (from watched IPs)
    (state.assetResults||[]).forEach(function(asset) {
      if (!asset || !asset.ip) return;
      // IP scan returns one entry per IP with multiple ports/services
      var ports = asset.ports || [];
      if (ports.length === 0) {
        // Add one row even if no ports found
        all.push({
          ip: asset.ip, hostnames: asset.hostnames||[], org: asset.org||'Unknown',
          port: null, transport: null, product: asset.services&&asset.services[0]&&asset.services[0].product||'Unknown',
          version: asset.services&&asset.services[0]&&asset.services[0].version||'',
          country: asset.country||'Unknown', vulns: asset.vulns||{},
          vulnCount: asset.vulnCount||0, riskLevel: asset.riskLevel||'low',
          lastScan: asset.lastScan, source: 'Shodan', ports: ports
        });
      } else {
        // One row per service/port for detailed view
        var services = asset.services && asset.services.length ? asset.services : ports.map(function(p){ return {port:p,transport:'tcp',product:'',version:''}; });
        services.forEach(function(svc) {
          all.push({
            ip: asset.ip, hostnames: asset.hostnames||[], org: asset.org||'Unknown',
            port: svc.port, transport: svc.transport||'tcp',
            product: svc.product||'Unknown', version: svc.version||'',
            country: asset.country||'Unknown', vulns: asset.vulns||{},
            vulnCount: asset.vulnCount||0, riskLevel: asset.riskLevel||'low',
            lastScan: asset.lastScan, source: 'Shodan', allPorts: ports
          });
        });
      }
    });

    // 2. Domain discovery results (from watched domains)
    (state.domainAssets||[]).forEach(function(d) {
      (d.assets||[]).forEach(function(a) { all.push(Object.assign({}, a, { org: a.org||d.domain })); });
    });

    // Sort by risk level
    var order = { critical:0, high:1, medium:2, low:3 };
    all.sort(function(a, b){ return (order[a.riskLevel]||4) - (order[b.riskLevel]||4); });

    res.json({ success: true, data: all, total: all.length });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/monitor/ip/:ip', async function(req, res) {
  try { res.json({ success: true, data: await shodan.scanIP(req.params.ip) }); }
  catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/monitor/alerts', function(req, res) {
  try {
    var state = monitor.getState();
    res.json({ success: true, data: state.alerts||[], total: (state.alerts||[]).length });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── Credentials ───────────────────────────────────────────────────────────────
router.get('/credentials/status', function(req, res) {
  try {
    var state = monitor.getState();
    var summary = state.emailResults && state.emailResults.length ? creds.summarise(state.emailResults) : null;
    res.json({ success: true, data: state.emailResults||[], emails: state.watchedEmails||[], summary: summary });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/credentials/check', async function(req, res) {
  try {
    var email = (req.body||{}).email;
    if (!email) return res.status(400).json({ success: false, error: 'email required' });
    res.json({ success: true, data: await creds.checkEmail(email) });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/credentials/email/:email', async function(req, res) {
  try { res.json({ success: true, data: await creds.checkEmail(decodeURIComponent(req.params.email)) }); }
  catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/credentials/breaches', async function(req, res) {
  try {
    var breaches = await creds.getAllBreaches();
    res.json({ success: true, data: breaches, total: breaches.length });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

module.exports = router;
