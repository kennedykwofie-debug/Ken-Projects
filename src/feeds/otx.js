/**
 * AlienVault OTX Feed
 * Docs: https://otx.alienvault.com/api
 * Free tier: 10,000 requests/month
 */

const axios = require('axios');
const cache = require('../utils/cache');
const logger = require('../utils/logger');

const BASE = 'https://otx.alienvault.com/api/v1';
const KEY  = process.env.OTX_API_KEY;
const headers = () => ({ 'X-OTX-API-KEY': KEY });

function normalizePulse(pulse) {
  const sevMap = (tlp) => tlp === 'red' ? 'critical' : tlp === 'amber' ? 'high' : tlp === 'green' ? 'medium' : 'low';
  return {
    id: `OTX-${pulse.id}`, source: 'AlienVault OTX',
    type: pulse.tags?.[0]?.toUpperCase() || 'THREAT INTEL',
    title: pulse.name, description: pulse.description || 'No description.',
    severity: sevMap(pulse.tlp),
    industry: (pulse.industries || []).map(i => i.toLowerCase()),
    region: (pulse.targeted_countries || []).map(r => r.toLowerCase()),
    tags: pulse.tags || [],
    iocs: (pulse.indicators || []).slice(0,20).map(ind => ({ type: ind.type, value: ind.indicator, confidence: 75, source: 'OTX', firstSeen: ind.created })),
    createdAt: pulse.created, url: `https://otx.alienvault.com/pulse/${pulse.id}`,
  };
}

acync function fetchPulses({ limit = 20 } = {}) {
  const cacheKey = `otx:pulses:${limit}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!KEY || KEY === 'your_otx_api_key_here') { logger.warn('OTX: no key - mock data'); return getMockPulses(); }
  const res = await axios.get(`${BASE}/pulses/subscribed`, { headers: headers(), params: { limit }, timeout: 10000 });
  const pulses = (res.data.results || []).map(normalizePulse);
  cache.set(cacheKey, pulses, cache.TTL.SHORT);
  return pulses;
}

async function fetchIndicators({ type = 'IPv4', limit = 50 } = {}) {
  const cacheKey = `otx:indicators:${type}:${limit}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!KEY || KEY === 'your_otx_api_key_here') return getMockIoCs();
  const res = await axios.get(`${BASE}/indicators/export`, { headers: headers(), params: { type, limit }, timeout: 10000 });
  const indicators = (res.data.results || []).map(ind => ({ type: ind.type, value: ind.indicator, confidence: 75, source: 'OTX', firstSeen: ind.created, tags: ind.tags || [] }));
  cache.set(cacheKey, indicators, cache.TTL.SHORT);
  return indicators;
}

function getMockPulses() {
  return [
    { id:'OTX-MOCK-001', source:'AlienVault OTX', type:'RANSOMWARE', title:'LockBit 3.0 Campaign', description:'Active LockBit 3.0 campaign targeting financial institutions.', severity:'critical', industry:['finance'], region:['apac'], tags:['lockbit','ransomware'], iocs:[], createdAt: new Date().toISOString() },
    { id:'OTX-MOCK-002', source:'AlienVault OTX', type:'APT', title:'APT41 Infrastructure Reactivation', description:'APT41 spinning up new C2 infrastructure.', severity:'critical', industry:['energy'], region:['eu','na'], tags:['apt41'], iocs:[], createdAt: new Date().toISOString() },
  ];
}
function getMockIoCs() {
  return [ { type:'IPv4', value:'185.220.101.47', confidence:95, source:'OTX', firstSeen: new Date().toISOString(), tags:['c2'] } ];
}
module.exports = { fetchPulses, fetchIndicators };