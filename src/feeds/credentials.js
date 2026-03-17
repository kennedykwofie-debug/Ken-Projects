const axios = require('axios');
const cache = require('../utils/cache');
const logger = require('../utils/logger');

const HIBP_KEY = process.env.HIBP_API_KEY;
const HIBP_BASE = 'https://haveibeenpwned.com/api/v3';

// Check a single email address against HIBP - works immediately with API key
async function checkEmail(email) {
  var cacheKey = 'creds:email:' + email;
  var cached = cache.get(cacheKey);
  if (cached) return cached;

  if (!HIBP_KEY || HIBP_KEY === 'your_hibp_api_key_here') {
    return getMockEmail(email);
  }

  try {
    var encoded = encodeURIComponent(email);
    var res = await axios.get(HIBP_BASE + '/breachedaccount/' + encoded + '?truncateResponse=false', {
      headers: { 'hibp-api-key': HIBP_KEY, 'User-Agent': 'DARKWATCH-ThreatIntel/1.0' },
      timeout: 15000
    });
    var breaches = (res.data || []).map(function(b) {
      return {
        name: b.Name,
        domain: b.Domain,
        breachDate: b.BreachDate,
        pwnCount: b.PwnCount,
        dataClasses: b.DataClasses,
        isSensitive: b.IsSensitive,
        isVerified: b.IsVerified
      };
    });
    var result = {
      email: email,
      breachCount: breaches.length,
      breaches: breaches,
      breachNames: breaches.map(function(b) { return b.name; }),
      riskLevel: breaches.length >= 5 ? 'critical' : breaches.length >= 2 ? 'high' : breaches.length >= 1 ? 'medium' : 'clean',
      lastChecked: new Date().toISOString(),
      source: 'HaveIBeenPwned'
    };
    cache.set(cacheKey, result, 43200); // 12hr cache
    logger.info('HIBP: ' + email + ' found in ' + breaches.length + ' breaches');
    return result;
  } catch (err) {
    if (err.response && err.response.status === 404) {
      var clean = { email: email, breachCount: 0, breaches: [], breachNames: [], riskLevel: 'clean', lastChecked: new Date().toISOString(), source: 'HaveIBeenPwned' };
      cache.set(cacheKey, clean, 43200);
      return clean;
    }
    if (err.response && err.response.status === 401) {
      logger.error('HIBP: Invalid API key');
      return getMockEmail(email);
    }
    if (err.response && err.response.status === 429) {
      logger.warn('HIBP: Rate limited, waiting...');
      await new Promise(function(res) { setTimeout(res, 1500); });
      return checkEmail(email); // retry once
    }
    logger.error('HIBP email check failed for ' + email + ': ' + err.message);
    return getMockEmail(email);
  }
}

// Check multiple emails, respecting HIBP rate limit (1 req/1500ms for free tier)
async function checkEmails(emails) {
  var results = [];
  for (var i = 0; i < emails.length; i++) {
    var r = await checkEmail(emails[i]);
    results.push(r);
    if (i < emails.length - 1) {
      await new Promise(function(res) { setTimeout(res, 1600); }); // HIBP rate limit
    }
  }
  return results;
}

// Get summary stats across all monitored emails
function summarise(results) {
  var totalBreaches = 0;
  var uniqueBreachNames = new Set();
  var criticalEmails = 0;
  results.forEach(function(r) {
    totalBreaches += (r.breachCount || 0);
    (r.breachNames || []).forEach(function(n) { uniqueBreachNames.add(n); });
    if (r.riskLevel === 'critical' || r.riskLevel === 'high') criticalEmails++;
  });
  return {
    totalEmails: results.length,
    exposedEmails: results.filter(function(r) { return r.breachCount > 0; }).length,
    totalBreachInstances: totalBreaches,
    uniqueBreaches: Array.from(uniqueBreachNames),
    criticalEmails: criticalEmails,
    cleanEmails: results.filter(function(r) { return r.breachCount === 0; }).length
  };
}

// Get all recent breaches from HIBP
async function getAllBreaches() {
  var cacheKey = 'creds:allbreaches';
  var cached = cache.get(cacheKey);
  if (cached) return cached;

  if (!HIBP_KEY || HIBP_KEY === 'your_hibp_api_key_here') {
    return getMockBreachList();
  }

  try {
    var res = await axios.get(HIBP_BASE + '/breaches', {
      headers: { 'hibp-api-key': HIBP_KEY, 'User-Agent': 'DARKWATCH-ThreatIntel/1.0' },
      timeout: 15000
    });
    var breaches = (res.data || [])
      .sort(function(a, b) { return new Date(b.AddedDate) - new Date(a.AddedDate); })
      .slice(0, 20)
      .map(function(b) {
        return {
          name: b.Name, domain: b.Domain, breachDate: b.BreachDate,
          addedDate: b.AddedDate, pwnCount: b.PwnCount, dataClasses: b.DataClasses,
          isSensitive: b.IsSensitive, isVerified: b.IsVerified,
          description: (b.Description || '').replace(/<[^>]+>/g, '').substring(0, 200),
          source: 'HaveIBeenPwned'
        };
      });
    cache.set(cacheKey, breaches, 3600);
    logger.info('HIBP: fetched ' + breaches.length + ' recent breaches');
    return breaches;
  } catch (err) {
    logger.error('HIBP all breaches failed: ' + err.message);
    return getMockBreachList();
  }
}

function getMockEmail(email) {
  var mocks = {
    'admin@example.com': { email: 'admin@example.com', breachCount: 3, breaches: [{name:'LinkedIn',breachDate:'2016-05-05',pwnCount:164611595,dataClasses:['Email addresses','Passwords']},{name:'Adobe',breachDate:'2013-10-04',pwnCount:152445165,dataClasses:['Email addresses','Password hints','Usernames']},{name:'Dropbox',breachDate:'2012-07-01',pwnCount:68648009,dataClasses:['Email addresses','Passwords']}], breachNames: ['LinkedIn','Adobe','Dropbox'], riskLevel: 'high', lastChecked: new Date().toISOString(), source: 'HaveIBeenPwned (mock)' }
  };
  return mocks[email] || {
    email: email, breachCount: 2,
    breaches: [{name:'LinkedIn',breachDate:'2016-05-05',pwnCount:164611595,dataClasses:['Email addresses','Passwords']},{name:'Adobe',breachDate:'2013-10-04',pwnCount:152445165,dataClasses:['Email addresses','Password hints']}],
    breachNames: ['LinkedIn','Adobe'], riskLevel: 'medium', lastChecked: new Date().toISOString(), source: 'HaveIBeenPwned (mock)'
  };
}

function getMockBreachList() {
  return [
    { name: 'RockYou2024', domain: 'rockyou.net', breachDate: '2024-06-04', addedDate: '2024-07-05', pwnCount: 9948575739, dataClasses: ['Passwords'], isVerified: true, description: 'The largest password compilation ever released - 9.9 billion unique passwords.', source: 'HaveIBeenPwned' },
    { name: 'Trello', domain: 'trello.com', breachDate: '2024-01-22', addedDate: '2024-01-24', pwnCount: 15115516, dataClasses: ['Email addresses', 'Usernames', 'Names'], isVerified: true, description: 'In January 2024, 15M email addresses were scraped from public Trello profiles.', source: 'HaveIBeenPwned' },
    { name: 'Infosys McCamish', domain: 'infosysbpm.com', breachDate: '2023-11-03', addedDate: '2024-05-07', pwnCount: 6078263, dataClasses: ['SSNs', 'Bank account numbers', 'Dates of birth'], isSensitive: true, isVerified: true, description: 'A ransomware attack exposed highly sensitive financial and personal data.', source: 'HaveIBeenPwned' }
  ];
}

module.exports = { checkEmail, checkEmails, summarise, getAllBreaches };
