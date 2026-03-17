const shodan = require('./shodan');
const creds = require('./credentials');
const logger = require('../utils/logger');

var state = {
  watchedIPs: [], watchedDomains: [], watchedEmails: [],
  assetResults: [], domainAssets: [], emailResults: [], alerts: [], lastScan: null
};

function addWatchedIP(ip) { if (!state.watchedIPs.includes(ip)) { state.watchedIPs.push(ip); logger.info('Watchlist: added IP ' + ip); } }
function addWatchedDomain(domain) { if (!state.watchedDomains.includes(domain)) { state.watchedDomains.push(domain); logger.info('Watchlist: added domain ' + domain); } }
function addWatchedEmail(email) { if (!state.watchedEmails.includes(email)) { state.watchedEmails.push(email); logger.info('Watchlist: added email ' + email); } }
function addCredDomain(domain) { addWatchedDomain(domain); } // legacy compat

function removeWatched(type, value) {
  if (type === 'ip') state.watchedIPs = state.watchedIPs.filter(function(x) { return x !== value; });
  if (type === 'domain') state.watchedDomains = state.watchedDomains.filter(function(x) { return x !== value; });
  if (type === 'email') state.watchedEmails = state.watchedEmails.filter(function(x) { return x !== value; });
}

async function runScanCycle() {
  logger.info('Monitor: starting scan cycle...');
  var newAlerts = [];
  var ips = state.watchedIPs.length ? state.watchedIPs : ['185.220.101.47', '8.8.8.8'];
  var domains = state.watchedDomains.length ? state.watchedDomains : ['example.com'];
  var emails = state.watchedEmails.length ? state.watchedEmails : [];

  // Scan IPs via Shodan
  try {
    var ipResults = await shodan.scanWatchlist(ips);
    var prevAssets = {};
    state.assetResults.forEach(function(a) { if (a && a.ip) prevAssets[a.ip] = a; });
    ipResults.forEach(function(asset) {
      if (!asset || !asset.ip) return;
      var prev = prevAssets[asset.ip];
      if (prev) {
        var newPorts = (asset.ports||[]).filter(function(p) { return !(prev.ports||[]).includes(p); });
        if (newPorts.length) newAlerts.push({ type:'new_port', severity:'high', message:'New port(s) open on '+asset.ip+': '+newPorts.join(', '), asset:asset.ip, timestamp:new Date().toISOString() });
        var newVulns = Object.keys(asset.vulns||{}).filter(function(v) { return !prev.vulns||!prev.vulns[v]; });
        if (newVulns.length) newAlerts.push({ type:'new_vuln', severity:'critical', message:'New CVE on '+asset.ip+': '+newVulns.join(', '), asset:asset.ip, timestamp:new Date().toISOString() });
      }
    });
    state.assetResults = ipResults.filter(function(r) { return r && r.ip; });
  } catch(e) { logger.error('IP scan error: '+e.message); }

  // Discover domain assets
  try {
    var domainAssets = [];
    for (var i=0; i<domains.length; i++) {
      var assets = await shodan.discoverOrgAssets('org:"'+domains[i]+'"');
      domainAssets.push({ domain: domains[i], assets: assets, scannedAt: new Date().toISOString() });
      assets.forEach(function(a) {
        if (a.riskLevel === 'critical') newAlerts.push({ type:'critical_asset', severity:'critical', message:'Critical internet-facing asset: '+a.ip+':'+a.port+' ('+a.product+') for '+domains[i], asset:a.ip, timestamp:new Date().toISOString() });
      });
    }
    state.domainAssets = domainAssets;
  } catch(e) { logger.error('Domain discovery error: '+e.message); }

  // Check emails via HIBP
  if (emails.length > 0) {
    try {
      var emailResults = await creds.checkEmails(emails);
      var prevResults = {};
      state.emailResults.forEach(function(r) { if(r && r.email) prevResults[r.email] = r; });
      emailResults.forEach(function(r) {
        if (!r || !r.email) return;
        var prev = prevResults[r.email];
        var prevCount = prev ? (prev.breachCount||0) : 0;
        if (r.breachCount > prevCount) {
          var newBreaches = (r.breachNames||[]).filter(function(n) { return !prev||!(prev.breachNames||[]).includes(n); });
          newAlerts.push({ type:'credential_leak', severity: r.breachCount>=5?'critical':'high', message: r.email+' found in '+r.breachCount+' breach(es)'+(newBreaches.length?' including '+newBreaches.slice(0,3).join(', '):''), email: r.email, timestamp: new Date().toISOString() });
        }
      });
      state.emailResults = emailResults;
    } catch(e) { logger.error('Email check error: '+e.message); }
  }

  if (newAlerts.length > 0) {
    state.alerts = newAlerts.concat(state.alerts).slice(0, 100);
    logger.info('Monitor: '+newAlerts.length+' new alerts');
  }
  state.lastScan = new Date().toISOString();
  logger.info('Monitor: scan cycle complete');
  return { alerts: newAlerts, assetsScanned: state.assetResults.length };
}

function getState() {
  return { watchedIPs: state.watchedIPs, watchedDomains: state.watchedDomains, watchedEmails: state.watchedEmails, assetResults: state.assetResults, domainAssets: state.domainAssets||[], emailResults: state.emailResults, alerts: state.alerts.slice(0,50), lastScan: state.lastScan };
}

module.exports = { addWatchedIP, addWatchedDomain, addWatchedEmail, addCredDomain, removeWatched, runScanCycle, getState };
