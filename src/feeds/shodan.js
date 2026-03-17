const axios = require('axios');
const cache = require('../utils/cache');
const logger = require('../utils/logger');

const KEY = process.env.SHODAN_API_KEY;
const BASE = 'https://api.shodan.io';

// Risk-score an asset based on what's exposed
function scoreAsset(data) {
  let score = 0;
  const ports = data.ports || [];
  const vulns = Object.keys(data.vulns || {});
  // Critical exposures
  if (ports.includes(3306) || ports.includes(5432) || ports.includes(27017)) score += 40; // DB
  if (ports.includes(3389)) score += 35; // RDP
  if (ports.includes(445) || ports.includes(139)) score += 30; // SMB
  if (ports.includes(23)) score += 30; // Telnet
  if (vulns.length > 0) score += Math.min(vulns.length * 10, 40);
  if (ports.includes(22)) score += 10; // SSH
  if (ports.includes(21)) score += 15; // FTP
  if (ports.includes(80) || ports.includes(443)) score += 5;
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 20) return 'medium';
  return 'low';
}

// Scan a single IP via Shodan
async function scanIP(ip) {
  const cacheKey = 'shodan:ip:' + ip;
  const cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!KEY || KEY === 'your_shodan_api_key_here') return getMockAsset(ip);
  try {
    const res = await axios.get(BASE + '/shodan/host/' + ip, {
      params: { key: KEY }, timeout: 15000
    });
    const d = res.data;
    const result = {
      ip: d.ip_str,
      hostnames: d.hostnames || [],
      org: d.org || 'Unknown',
      isp: d.isp || 'Unknown',
      country: d.country_name || 'Unknown',
      city: d.city || 'Unknown',
      os: d.os || null,
      ports: d.ports || [],
      services: (d.data || []).map(function(s) {
        return { port: s.port, transport: s.transport, product: s.product, version: s.version, banner: (s.data || '').substring(0, 100) };
      }),
      vulns: d.vulns || {},
      vulnCount: Object.keys(d.vulns || {}).length,
      riskLevel: scoreAsset(d),
      lastScan: d.last_update || new Date().toISOString(),
      source: 'Shodan'
    };
    cache.set(cacheKey, result, 21600); // 6hr cache
    return result;
  } catch (err) {
    logger.error('Shodan IP scan failed: ' + ip + ' - ' + err.message);
    return getMockAsset(ip);
  }
}

// Search Shodan for all assets belonging to an org/domain
async function discoverOrgAssets(query) {
  const cacheKey = 'shodan:search:' + query;
  const cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!KEY || KEY === 'your_shodan_api_key_here') return getMockDiscovery(query);
  try {
    const res = await axios.get(BASE + '/shodan/host/search', {
      params: { key: KEY, query: query, minify: false }, timeout: 15000
    });
    const assets = (res.data.matches || []).slice(0, 50).map(function(d) {
      return {
        ip: d.ip_str,
        hostnames: d.hostnames || [],
        org: d.org || 'Unknown',
        port: d.port,
        transport: d.transport,
        product: d.product || 'Unknown',
        version: d.version || '',
        country: d.location && d.location.country_name || 'Unknown',
        vulns: d.vulns || {},
        vulnCount: Object.keys(d.vulns || {}).length,
        riskLevel: scoreAsset({ ports: [d.port], vulns: d.vulns || {} }),
        lastScan: d.timestamp || new Date().toISOString(),
        source: 'Shodan'
      };
    });
    cache.set(cacheKey, assets, 21600);
    logger.info('Shodan: discovered ' + assets.length + ' assets for: ' + query);
    return assets;
  } catch (err) {
    logger.error('Shodan discovery failed: ' + err.message);
    return getMockDiscovery(query);
  }
}

// Scan multiple watched IPs (for continuous monitoring)
async function scanWatchlist(ips) {
  const results = [];
  for (let i = 0; i < ips.length; i++) {
    const r = await scanIP(ips[i]);
    results.push(r);
    await new Promise(function(res) { setTimeout(res, 1000); }); // rate limit
  }
  return results;
}

function getMockAsset(ip) {
  const mocks = {
    '185.220.101.47': { ip: '185.220.101.47', hostnames: ['tor-exit-node.example.com'], org: 'Tor Network', isp: 'Frantech Solutions', country: 'Netherlands', city: 'Amsterdam', os: 'Linux', ports: [22, 80, 443, 9001, 9030], services: [{ port: 22, transport: 'tcp', product: 'OpenSSH', version: '8.4' }, { port: 9001, transport: 'tcp', product: 'Tor', version: '' }], vulns: { 'CVE-2023-38408': { cvss: 9.8, summary: 'OpenSSH pre-auth RCE' } }, vulnCount: 1, riskLevel: 'critical', lastScan: new Date().toISOString(), source: 'Shodan' },
    '8.8.8.8': { ip: '8.8.8.8', hostnames: ['dns.google'], org: 'Google LLC', isp: 'Google LLC', country: 'United States', city: 'Mountain View', os: null, ports: [53, 443], services: [{ port: 53, transport: 'udp', product: 'DNS', version: '' }, { port: 443, transport: 'tcp', product: 'HTTPS', version: '' }], vulns: {}, vulnCount: 0, riskLevel: 'low', lastScan: new Date().toISOString(), source: 'Shodan' }
  };
  return mocks[ip] || {
    ip: ip, hostnames: [], org: 'Unknown Org', isp: 'Unknown ISP', country: 'Unknown', city: 'Unknown', os: 'Linux',
    ports: [22, 80, 443, 3306], services: [{ port: 22, transport: 'tcp', product: 'OpenSSH', version: '7.9' }, { port: 3306, transport: 'tcp', product: 'MySQL', version: '5.7.44' }],
    vulns: { 'CVE-2022-21824': { cvss: 7.5, summary: 'MySQL improper access control' } }, vulnCount: 1, riskLevel: 'high', lastScan: new Date().toISOString(), source: 'Shodan'
  };
}

function getMockDiscovery(query) {
  return [
    { ip: '203.0.113.10', hostnames: ['web01.' + query], org: query, port: 443, transport: 'tcp', product: 'nginx', version: '1.18.0', country: 'Singapore', vulns: {}, vulnCount: 0, riskLevel: 'low', lastScan: new Date().toISOString(), source: 'Shodan' },
    { ip: '203.0.113.11', hostnames: ['db01.' + query], org: query, port: 3306, transport: 'tcp', product: 'MySQL', version: '5.7.44', country: 'Singapore', vulns: { 'CVE-2022-21824': { cvss: 7.5 } }, vulnCount: 1, riskLevel: 'critical', lastScan: new Date().toISOString(), source: 'Shodan' },
    { ip: '203.0.113.12', hostnames: ['rdp01.' + query], org: query, port: 3389, transport: 'tcp', product: 'Microsoft RDS', version: '', country: 'United States', vulns: { 'CVE-2019-0708': { cvss: 9.8, summary: 'BlueKeep' } }, vulnCount: 1, riskLevel: 'critical', lastScan: new Date().toISOString(), source: 'Shodan' },
    { ip: '203.0.113.13', hostnames: ['mail.' + query], org: query, port: 25, transport: 'tcp', product: 'Postfix', version: '3.6.4', country: 'United Kingdom', vulns: {}, vulnCount: 0, riskLevel: 'medium', lastScan: new Date().toISOString(), source: 'Shodan' },
    { ip: '203.0.113.14', hostnames: ['vpn.' + query], org: query, port: 1194, transport: 'udp', product: 'OpenVPN', version: '2.5.1', country: 'Singapore', vulns: {}, vulnCount: 0, riskLevel: 'medium', lastScan: new Date().toISOString(), source: 'Shodan' },
  ];
}

module.exports = { scanIP, discoverOrgAssets, scanWatchlist };
