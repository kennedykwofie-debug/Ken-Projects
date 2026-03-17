const axios = require('axios');
const cache = require('../utils/cache');
const logger = require('../utils/logger');
const crypto = require('crypto');

const HIBP_KEY = process.env.HIBP_API_KEY;
const HIBP_BASE = 'https://haveibeenpwned.com/api/v3';

// In-memory verified domains store
var verifiedDomains = {};

// Generate a deterministic verification token for a domain
function getVerificationToken(domain) {
  var hash = crypto.createHash('sha256').update(domain + (HIBP_KEY || 'darkwatch')).digest('hex').substring(0, 16);
  return 'hibp-verify=' + hash;
}

// Check if a domain's DNS TXT record contains the verification token
async function checkDomainVerification(domain) {
  var token = getVerificationToken(domain);
  try {
    var res = await axios.get('https://dns.google/resolve', {
      params: { name: domain, type: 'TXT' },
      timeout: 8000
    });
    var answers = res.data.Answer || [];
    var found = answers.some(function(a) {
      return a.type === 16 && (a.data || '').indexOf(token) > -1;
    });
    if (found) {
      verifiedDomains[domain] = { verifiedAt: new Date().toISOString(), token: token };
      logger.info('Domain verified: ' + domain);
    }
    return { domain: domain, verified: found, token: token, txtRecord: token, answers: answers.map(function(a){ return a.data; }) };
  } catch(err) {
    logger.error('DNS check failed for ' + domain + ': ' + err.message);
    return { domain: domain, verified: false, token: token, txtRecord: token, error: err.message };
  }
}

// Get all breached emails for a verified domain via HIBP domain search
async function checkDomainBreaches(domain) {
  var cacheKey = 'creds:domain:' + domain;
  var cached = cache.get(cacheKey);
  if (cached) return cached;

  if (!HIBP_KEY || HIBP_KEY === 'your_hibp_api_key_here') {
    return getMockDomainBreaches(domain);
  }

  try {
    var res = await axios.get(HIBP_BASE + '/breacheddomain/' + encodeURIComponent(domain), {
      headers: { 'hibp-api-key': HIBP_KEY, 'User-Agent': 'DARKWATCH-ThreatIntel/1.0' },
      timeout: 20000
    });
    // HIBP returns { alias: [breach1, breach2, ...] }
    var data = res.data || {};
    var emails = Object.keys(data).map(function(alias) {
      return {
        email: alias + '@' + domain,
        alias: alias,
        breachNames: data[alias],
        breachCount: data[alias].length,
        riskLevel: data[alias].length >= 5 ? 'critical' : data[alias].length >= 2 ? 'high' : 'medium',
        source: 'HaveIBeenPwned'
      };
    });
    var result = {
      domain: domain,
      totalExposedAccounts: emails.length,
      emails: emails,
      source: 'HaveIBeenPwned',
      checkedAt: new Date().toISOString()
    };
    cache.set(cacheKey, result, 43200);
    logger.info('HIBP domain: ' + emails.length + ' exposed accounts for ' + domain);
    return result;
  } catch(err) {
    if (err.response && err.response.status === 403) {
      return { domain: domain, error: 'Domain not verified with HIBP. Complete DNS verification first.', needsVerification: true };
    }
    if (err.response && err.response.status === 404) {
      var empty = { domain: domain, totalExposedAccounts: 0, emails: [], source: 'HaveIBeenPwned', checkedAt: new Date().toISOString() };
      cache.set(cacheKey, empty, 43200);
      return empty;
    }
    logger.error('HIBP domain check failed: ' + err.message);
    return { domain: domain, error: err.message };
  }
}

// Check a single email address
async function checkEmail(email) {
  var cacheKey = 'creds:email:' + email;
  var cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!HIBP_KEY || HIBP_KEY === 'your_hibp_api_key_here') return getMockEmail(email);
  try {
    var encoded = encodeURIComponent(email);
    var res = await axios.get(HIBP_BASE + '/breachedaccount/' + encoded + '?truncateResponse=false', {
      headers: { 'hibp-api-key': HIBP_KEY, 'User-Agent': 'DARKWATCH-ThreatIntel/1.0' },
      timeout: 15000
    });
    var breaches = (res.data || []).map(function(b) {
      return { name: b.Name, domain: b.Domain, breachDate: b.BreachDate, pwnCount: b.PwnCount, dataClasses: b.DataClasses, isSensitive: b.IsSensitive };
    });
    var result = {
      email: email, breachCount: breaches.length, breaches: breaches,
      breachNames: breaches.map(function(b){ return b.name; }),
      riskLevel: breaches.length >= 5 ? 'critical' : breaches.length >= 2 ? 'high' : breaches.length >= 1 ? 'medium' : 'clean',
      lastChecked: new Date().toISOString(), source: 'HaveIBeenPwned'
    };
    cache.set(cacheKey, result, 43200);
    return result;
  } catch(err) {
    if (err.response && err.response.status === 404) {
      var clean = { email: email, breachCount: 0, breaches: [], breachNames: [], riskLevel: 'clean', lastChecked: new Date().toISOString(), source: 'HaveIBeenPwned' };
      cache.set(cacheKey, clean, 43200);
      return clean;
    }
    if (err.response && err.response.status === 429) {
      await new Promise(function(res) { setTimeout(res, 1500); });
      return checkEmail(email);
    }
    logger.error('HIBP email check failed: ' + err.message);
    return getMockEmail(email);
  }
}

async function checkEmails(emails) {
  var results = [];
  for (var i = 0; i < emails.length; i++) {
    var r = await checkEmail(emails[i]);
    results.push(r);
    if (i < emails.length - 1) await new Promise(function(res){ setTimeout(res, 1600); });
  }
  return results;
}

function summarise(results) {
  var totalBreaches = 0, uniqueBreachNames = new Set(), criticalEmails = 0;
  results.forEach(function(r) {
    totalBreaches += (r.breachCount || 0);
    (r.breachNames || []).forEach(function(n){ uniqueBreachNames.add(n); });
    if (r.riskLevel === 'critical' || r.riskLevel === 'high') criticalEmails++;
  });
  return { totalEmails: results.length, exposedEmails: results.filter(function(r){ return r.breachCount > 0; }).length, totalBreachInstances: totalBreaches, uniqueBreaches: Array.from(uniqueBreachNames), criticalEmails: criticalEmails };
}

async function getAllBreaches() {
  var cacheKey = 'creds:allbreaches';
  var cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!HIBP_KEY || HIBP_KEY === 'your_hibp_api_key_here') return getMockBreachList();
  try {
    var res = await axios.get(HIBP_BASE + '/breaches', { headers: { 'hibp-api-key': HIBP_KEY, 'User-Agent': 'DARKWATCH-ThreatIntel/1.0' }, timeout: 15000 });
    var breaches = (res.data || []).sort(function(a,b){ return new Date(b.AddedDate)-new Date(a.AddedDate); }).slice(0,20).map(function(b){
      return { name: b.Name, domain: b.Domain, breachDate: b.BreachDate, addedDate: b.AddedDate, pwnCount: b.PwnCount, dataClasses: b.DataClasses, isSensitive: b.IsSensitive, isVerified: b.IsVerified, description: (b.Description||'').replace(/<[^>]+>/g,'').substring(0,200), source: 'HaveIBeenPwned' };
    });
    cache.set(cacheKey, breaches, 3600);
    return breaches;
  } catch(err) {
    logger.error('HIBP all breaches failed: ' + err.message);
    return getMockBreachList();
  }
}

function getVerifiedDomains() { return verifiedDomains; }

function getMockEmail(email) {
  return { email: email, breachCount: 2, breaches: [{name:'LinkedIn',breachDate:'2016-05-05',pwnCount:164611595,dataClasses:['Email addresses','Passwords']},{name:'Adobe',breachDate:'2013-10-04',pwnCount:152445165,dataClasses:['Email addresses','Password hints']}], breachNames: ['LinkedIn','Adobe'], riskLevel: 'medium', lastChecked: new Date().toISOString(), source: 'HaveIBeenPwned (mock)' };
}
function getMockDomainBreaches(domain) {
  return { domain: domain, totalExposedAccounts: 3, emails: [{email:'admin@'+domain,alias:'admin',breachNames:['LinkedIn','Adobe'],breachCount:2,riskLevel:'high',source:'mock'},{email:'ceo@'+domain,alias:'ceo',breachNames:['Dropbox'],breachCount:1,riskLevel:'medium',source:'mock'},{email:'it@'+domain,alias:'it',breachNames:['LinkedIn','Adobe','Dropbox'],breachCount:3,riskLevel:'high',source:'mock'}], source: 'HaveIBeenPwned (mock)', checkedAt: new Date().toISOString() };
}
function getMockBreachList() {
  return [
    { name: 'RockYou2024', domain: 'rockyou.net', breachDate: '2024-06-04', addedDate: '2024-07-05', pwnCount: 9948575739, dataClasses: ['Passwords'], isVerified: true, source: 'HaveIBeenPwned' },
    { name: 'Trello', domain: 'trello.com', breachDate: '2024-01-22', addedDate: '2024-01-24', pwnCount: 15115516, dataClasses: ['Email addresses','Usernames','Names'], isVerified: true, source: 'HaveIBeenPwned' },
    { name: 'Infosys McCamish', domain: 'infosysbpm.com', breachDate: '2023-11-03', addedDate: '2024-05-07', pwnCount: 6078263, dataClasses: ['SSNs','Bank account numbers'], isSensitive: true, isVerified: true, source: 'HaveIBeenPwned' }
  ];
}

module.exports = { checkEmail, checkEmails, summarise, getAllBreaches, checkDomainBreaches, checkDomainVerification, getVerificationToken, getVerifiedDomains };
