// In-memory watchlist store for monitored assets and domains
// In production this would be backed by a database (Postgres, MongoDB)

const shodan = require('./shodan');
const creds = require('./credentials');
const logger = require('../utils/logger');

// Watchlists stored in memory (persist across requests via module cache)
const state = {
  watchedIPs: [],
  watchedDomains: [],
  credDomains: [],
  assetResults: [],
  credResults: [],
  alerts: [],
  lastScan: null
};

// Add IP to watchlist
function addWatchedIP(ip) {
  if (!state.watchedIPs.includes(ip)) {
    state.watchedIPs.push(ip);
    logger.info('Watchlist: added IP ' + ip);
  }
}

// Add domain for asset discovery
function addWatchedDomain(domain) {
  if (!state.watchedDomains.includes(domain)) {
    state.watchedDomains.push(domain);
    logger.info('Watchlist: added domain ' + domain);
  }
}

// Add domain for credential monitoring
function addCredDomain(domain) {
  if (!state.credDomains.includes(domain)) {
    state.credDomains.push(domain);
    logger.info('Cred monitor: added domain ' + domain);
  }
}

// Remove from watchlist
function removeWatched(type, value) {
  if (type === 'ip') state.watchedIPs = state.watchedIPs.filter(function(x) { return x !== value; });
  if (type === 'domain') state.watchedDomains = state.watchedDomains.filter(function(x) { return x !== value; });
  if (type === 'cred') state.credDomains = state.credDomains.filter(function(x) { return x !== value; });
}

// Run a full monitoring scan cycle
async function runScanCycle() {
  logger.info('Monitor: starting scan cycle...');
  const newAlerts = [];

  // Use defaults if watchlists are empty (demo mode)
  const ips = state.watchedIPs.length ? state.watchedIPs : ['185.220.101.47', '8.8.8.8'];
  const domains = state.watchedDomains.length ? state.watchedDomains : ['example.com'];
  const credDomains = state.credDomains.length ? state.credDomains : ['example.com'];

  // Scan IPs
  try {
    const ipResults = await shodan.scanWatchlist(ips);
    const prevAssets = {};
    state.assetResults.forEach(function(a) { prevAssets[a.ip] = a; });

    ipResults.forEach(function(asset) {
      if (asset && asset.ip) {
        // Check for new open ports vs previous scan
        const prev = prevAssets[asset.ip];
        if (prev) {
          const newPorts = (asset.ports || []).filter(function(p) { return !(prev.ports || []).includes(p); });
          if (newPorts.length > 0) {
            newAlerts.push({ type: 'new_port', severity: 'high', message: 'New port(s) open on ' + asset.ip + ': ' + newPorts.join(', '), asset: asset.ip, timestamp: new Date().toISOString() });
          }
          const newVulns = Object.keys(asset.vulns || {}).filter(function(v) { return !prev.vulns || !prev.vulns[v]; });
          if (newVulns.length > 0) {
            newAlerts.push({ type: 'new_vuln', severity: 'critical', message: 'New CVE detected on ' + asset.ip + ': ' + newVulns.join(', '), asset: asset.ip, timestamp: new Date().toISOString() });
          }
        }
      }
    });
    state.assetResults = ipResults.filter(function(r) { return r && r.ip; });
  } catch (e) { logger.error('IP scan cycle error: ' + e.message); }

  // Discover domain assets
  try {
    const domainAssets = [];
    for (let i = 0; i < domains.length; i++) {
      const assets = await shodan.discoverOrgAssets('org:"' + domains[i] + '"');
      domainAssets.push({ domain: domains[i], assets: assets, scannedAt: new Date().toISOString() });
    }
    state.domainAssets = domainAssets;
    // Alert on critical assets
    domainAssets.forEach(function(d) {
      (d.assets || []).forEach(function(a) {
        if (a.riskLevel === 'critical') {
          newAlerts.push({ type: 'critical_asset', severity: 'critical', message: 'Critical internet-facing asset: ' + a.ip + ':' + a.port + ' (' + a.product + ') for ' + d.domain, asset: a.ip, timestamp: new Date().toISOString() });
        }
      });
    });
  } catch (e) { logger.error('Domain discovery error: ' + e.message); }

  // Check credential leaks
  try {
    const credResults = await creds.monitorDomains(credDomains);
    credResults.forEach(function(r) {
      if (r && r.totalExposedAccounts > 0) {
        newAlerts.push({ type: 'credential_leak', severity: r.totalExposedAccounts > 100 ? 'critical' : 'high', message: r.totalExposedAccounts + ' exposed accounts found for ' + r.domain + ' across ' + (r.breaches || []).length + ' breach(es)', domain: r.domain, timestamp: new Date().toISOString() });
      }
    });
    state.credResults = credResults;
  } catch (e) { logger.error('Credential check error: ' + e.message); }

  // Prepend new alerts
  if (newAlerts.length > 0) {
    state.alerts = newAlerts.concat(state.alerts).slice(0, 100);
    logger.info('Monitor: ' + newAlerts.length + ' new alerts generated');
  }

  state.lastScan = new Date().toISOString();
  logger.info('Monitor: scan cycle complete');
  return { alerts: newAlerts, assetsScanned: state.assetResults.length };
}

// Get current state
function getState() {
  return {
    watchedIPs: state.watchedIPs,
    watchedDomains: state.watchedDomains,
    credDomains: state.credDomains,
    assetResults: state.assetResults,
    domainAssets: state.domainAssets || [],
    credResults: state.credResults,
    alerts: state.alerts.slice(0, 50),
    lastScan: state.lastScan
  };
}

module.exports = { addWatchedIP, addWatchedDomain, addCredDomain, removeWatched, runScanCycle, getState };
