const shodan = require('./shodan');
const creds = require('./credentials');
const logger = require('../utils/logger');

var state = {
  watchedIPs: [],
  watchedDomains: [],
  watchedEmails: [],
  assetResults: [],
  domainAssets: [],
  emailResults: [],
  alerts: [],
  lastScan: null
};

function addWatchedIP(ip) {
  if (!state.watchedIPs.includes(ip)) {
    state.watchedIPs.push(ip);
    logger.info('Watchlist: added IP ' + ip);
  }
}

function addWatchedDomain(domain) {
  if (!state.watchedDomains.includes(domain)) {
    state.watchedDomains.push(domain);
    logger.info('Watchlist: added domain ' + domain);
  }
}

function addWatchedEmail(em) {
  if (!state.watchedEmails.includes(em)) {
    state.watchedEmails.push(em);
    logger.info('Watchlist: added email ' + em);
  }
}

function addCredDomain(domain) { addWatchedDomain(domain); }

function removeWatched(type, value) {
  if (type === 'ip') state.watchedIPs = state.watchedIPs.filter(function(x) { return x !== value; });
  if (type === 'domain') state.watchedDomains = state.watchedDomains.filter(function(x) { return x !== value; });
  if (type === 'email') state.watchedEmails = state.watchedEmails.filter(function(x) { return x !== value; });
}

async function runScanCycle() {
  logger.info('Monitor: starting scan cycle...');
  var newAlerts = [];

  // Only scan if user has actually added something — no demo defaults
  var ips = state.watchedIPs;
  var domains = state.watchedDomains;
  var emails = state.watchedEmails;

  if (ips.length === 0 && domains.length === 0 && emails.length === 0) {
    logger.info('Monitor: nothing in watchlist, skipping scan');
    state.lastScan = new Date().toISOString();
    return { alerts: [], assetsScanned: 0 };
  }

  // Scan watched IPs via Shodan
  if (ips.length > 0) {
    try {
      var ipResults = await shodan.scanWatchlist(ips);
      var prevAssets = {};
      state.assetResults.forEach(function(a) { if (a && a.ip) prevAssets[a.ip] = a; });
      ipResults.forEach(function(asset) {
        if (!asset || !asset.ip) return;
        var prev = prevAssets[asset.ip];
        if (prev) {
          var newPorts = (asset.ports || []).filter(function(p) { return !(prev.ports || []).includes(p); });
          if (newPorts.length) {
            newAlerts.push({ type: 'new_port', severity: 'high', message: 'New port(s) open on ' + asset.ip + ': ' + newPorts.join(', '), asset: asset.ip, timestamp: new Date().toISOString() });
          }
          var newVulns = Object.keys(asset.vulns || {}).filter(function(v) { return !prev.vulns || !prev.vulns[v]; });
          if (newVulns.length) {
            newAlerts.push({ type: 'new_vuln', severity: 'critical', message: 'New CVE on ' + asset.ip + ': ' + newVulns.join(', '), asset: asset.ip, timestamp: new Date().toISOString() });
          }
        }
      });
      state.assetResults = ipResults.filter(function(r) { return r && r.ip; });
    } catch(e) { logger.error('IP scan error: ' + e.message); }
  } else {
    state.assetResults = [];
  }

  // Discover domain assets via Shodan
  if (domains.length > 0) {
    try {
      var domainAssets = [];
      for (var i = 0; i < domains.length; i++) {
        var assets = await shodan.discoverOrgAssets(domains[i]);
        domainAssets.push({ domain: domains[i], assets: assets, scannedAt: new Date().toISOString() });
        assets.forEach(function(a) {
          if (a.riskLevel === 'critical') {
            newAlerts.push({ type: 'critical_asset', severity: 'critical', message: 'Critical asset: ' + a.ip + ':' + a.port + ' (' + a.product + ') for ' + domains[i], asset: a.ip, timestamp: new Date().toISOString() });
          }
        });
      }
      state.domainAssets = domainAssets;
    } catch(e) { logger.error('Domain discovery error: ' + e.message); }
  } else {
    state.domainAssets = [];
  }

  // Check emails via HIBP
  if (emails.length > 0) {
    try {
      var emailResults = await creds.checkEmails(emails);
      var prevResults = {};
      state.emailResults.forEach(function(r) { if (r && r.email) prevResults[r.email] = r; });
      emailResults.forEach(function(r) {
        if (!r || !r.email) return;
        var prev = prevResults[r.email];
        var prevCount = prev ? (prev.breachCount || 0) : 0;
        if (r.breachCount > prevCount) {
          var newBreaches = (r.breachNames || []).filter(function(n) { return !prev || !(prev.breachNames || []).includes(n); });
          newAlerts.push({ type: 'credential_leak', severity: r.breachCount >= 5 ? 'critical' : 'high', message: r.email + ' found in ' + r.breachCount + ' breach(es)' + (newBreaches.length ? ' including ' + newBreaches.slice(0, 3).join(', ') : ''), email: r.email, timestamp: new Date().toISOString() });
        }
      });
      state.emailResults = emailResults;
    } catch(e) { logger.error('Email check error: ' + e.message); }
  } else {
    state.emailResults = [];
  }

  if (newAlerts.length > 0) {
    state.alerts = newAlerts.concat(state.alerts).slice(0, 100);
    logger.info('Monitor: ' + newAlerts.length + ' new alerts');
  }
  state.lastScan = new Date().toISOString();
  logger.info('Monitor: scan cycle complete');
  return { alerts: newAlerts, assetsScanned: state.assetResults.length + (state.domainAssets.reduce(function(acc, d) { return acc + d.assets.length; }, 0)) };
}

function getState() {
  return {
    watchedIPs: state.watchedIPs,
    watchedDomains: state.watchedDomains,
    watchedEmails: state.watchedEmails,
    assetResults: state.assetResults,
    domainAssets: state.domainAssets,
    emailResults: state.emailResults,
    alerts: state.alerts.slice(0, 50),
    lastScan: state.lastScan
  };
}

module.exports = { addWatchedIP, addWatchedDomain, addWatchedEmail, addCredDomain, removeWatched, runScanCycle, getState };
