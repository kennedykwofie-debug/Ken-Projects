var API = '/api/v1';
var RC = {na:'#4d9eff',eu:'#a78bfa',apac:'#00d4aa',mena:'#f5c518',latam:'#ff8c42'};
var RN = {na:'N.Am',eu:'Europe',apac:'Asia',mena:'MENA',latam:'LatAm'};

function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function cvClass(s) {
  return !s ? 'medium' : s >= 9 ? 'critical' : s >= 7 ? 'high' : 'medium';
}
function g(id) { return document.getElementById(id); }

function go() {
  var fi = g('fi').value;
  var fr = g('fr').value;
  var fs = g('fs').value;
  var qs = '?industry=' + fi + '&region=' + fr + '&severity=' + fs + '&limit=50';

  fetch(API + '/threats' + qs)
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (!d.success) return;
      var ev = d.data.events || [];
      var crit = ev.filter(function(t) { return t.severity === 'critical'; }).length;
      g('fb').textContent = crit + ' CRITICAL';
      g('c0').textContent = ev.length;
      var html = '';
      for (var i = 0; i < ev.length; i++) {
        var t = ev[i];
        var sev = esc(t.severity || 'low');
        html += '<div class="fi">';
        html += '<div class="svb ' + sev + '"></div>';
        html += '<div style="flex:1;min-width:0">';
        html += '<div class="fm"><span class="bx ' + sev + '">' + sev.toUpperCase() + '</span>';
        html += '<span style="background:#161b22;padding:1px 5px;border-radius:3px">' + esc(t.source) + '</span></div>';
        html += '<div class="ftl">' + esc(t.title) + '</div>';
        html += '<div class="fd">' + esc((t.description || '').substring(0, 100)) + '</div>';
        html += '</div></div>';
      }
      g('fa').innerHTML = html || '<div class="lt">No threats</div>';
      var cnt = {};
      for (var i = 0; i < ev.length; i++) {
        var rg = ev[i].region || [];
        for (var j = 0; j < rg.length; j++) { cnt[rg[j]] = (cnt[rg[j]] || 0) + 1; }
      }
      var sr = Object.entries(cnt).sort(function(a,b){ return b[1]-a[1]; }).slice(0,5);
      var mx = sr.length ? sr[0][1] : 1;
      var rbh = '';
      for (var i = 0; i < sr.length; i++) {
        var k = sr[i][0], v = sr[i][1];
        rbh += '<div class="br"><span class="bl">' + esc(RN[k] || k) + '</span>';
        rbh += '<div class="bt"><div class="bf" style="width:' + Math.round(v/mx*100) + '%;background:' + (RC[k] || '#4d9eff') + '"></div></div>';
        rbh += '<span class="bc">' + v + '</span></div>';
      }
      g('rb').innerHTML = rbh || '<div class="lt">No data</div>';
      var ind = {};
      for (var i = 0; i < ev.length; i++) {
        var ig = ev[i].industry || [];
        for (var j = 0; j < ig.length; j++) { ind[ig[j]] = (ind[ig[j]] || 0) + 1; }
      }
      var si = Object.entries(ind).sort(function(a,b){ return b[1]-a[1]; }).slice(0,7);
      var mi = si.length ? si[0][1] : 1;
      var ibh = '';
      for (var i = 0; i < si.length; i++) {
        var k = si[i][0], v = si[i][1];
        ibh += '<div class="br"><span class="bl" style="text-transform:capitalize">' + esc(k) + '</span>';
        ibh += '<div class="bt"><div class="bf" style="width:' + Math.round(v/mi*100) + '%;background:linear-gradient(90deg,#4d9eff,#a78bfa)"></div></div>';
        ibh += '<span class="bc">' + Math.round(v / (ev.length || 1) * 100) + '%</span></div>';
      }
      g('ib2').innerHTML = ibh || '<div class="lt">No data</div>';
    }).catch(function() {});

  fetch(API + '/stats')
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (!d.success) return;
      var s = d.data;
      g('s0').textContent = s.criticalThreats || '-';
      g('s1').textContent = (s.activeIoCs || 0).toLocaleString();
      g('s2').textContent = s.threatActors || '-';
      g('s3').textContent = s.zeroDayCVEs || '-';
      g('s4').textContent = s.phishingKits || '-';
    }).catch(function() {});

  fetch(API + '/health')
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (!d.feeds) return;
      var fc = {configured:'#00d4aa',active:'#00d4aa',public:'#4d9eff','no-key':'#f5c518'};
      var fl = {configured:'active',active:'active',public:'public','no-key':'no key'};
      var h = '<h3 style="font-size:10px;color:#64748b;text-transform:uppercase;margin-bottom:8px">Health</h3>';
      Object.entries(d.feeds).forEach(function(e) {
        h += '<div style="display:flex;justify-content:space-between;padding:3px 0;font-size:11px">';
        h += '<span>' + e[0] + '</span>';
        h += '<span style="color:' + (fc[e[1]] || '#64748b') + '">' + (fl[e[1]] || e[1]) + '</span></div>';
      });
      g('fh').innerHTML = h;
    }).catch(function() {});

  fetch(API + '/iocs?limit=100')
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (!d.success) return;
      var ic = d.data || [];
      g('c1').textContent = ic.filter(function(i){ return i.source==='OTX'; }).length;
      g('c2').textContent = ic.filter(function(i){ return i.source==='URLhaus'; }).length;
      g('c3').textContent = ic.filter(function(i){ return i.source==='MalwareBazaar'; }).length;
      g('c4').textContent = ic.filter(function(i){ return i.source==='ThreatFox'; }).length;
      g('c5').textContent = ic.filter(function(i){ return i.source==='Feodo Tracker'; }).length;
      var kc = function(c) { return c>=90?'#00d4aa':c>=75?'#f5c518':'#ff3b5c'; };
      var h = '';
      for (var i = 0; i < ic.length; i++) {
        var v = ic[i];
        h += '<tr><td><span style="background:#2e2300;color:#f5c518;border:1px solid #f5c518;padding:1px 4px;border-radius:3px;font-size:9px">' + esc(v.type || '-') + '</span></td>';
        h += '<td style="color:#f5c518;word-break:break-all">' + esc((v.value || '').substring(0, 48)) + '</td>';
        h += '<td style="color:' + kc(v.confidence || 0) + '">' + (v.confidence || '?') + '%</td>';
        h += '<td style="color:#64748b">' + esc(v.first || '-') + '</td>';
        h += '<td style="color:#64748b">' + esc(v.source || '-') + '</td></tr>';
      }
      g('ib').innerHTML = h || '<tr><td colspan="5" class="lt">No IoCs</td></tr>';
    }).catch(function() {});

  fetch(API + '/actors?limit=40')
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (!d.success) return;
      var ac = d.data || [];
      g('c7').textContent = ac.length;
      var h = '';
      for (var i = 0; i < ac.length; i++) {
        var a = ac[i];
        h += '<div class="ac"><div class="an">' + esc(a.name || '?') + '</div>';
        h += '<div class="asu">' + esc(a.nation || '?') + ' - ' + esc(a.type || 'APT') + '</div></div>';
      }
      g('ag').innerHTML = h || '<div class="lt">No actors</div>';
    }).catch(function() {});

  fetch(API + '/cves?limit=20')
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (!d.success) return;
      var cv = d.data || [];
      g('c8').textContent = cv.length;
      var h = '';
      for (var i = 0; i < cv.length; i++) {
        var c = cv[i];
        h += '<div class="ci"><div class="cvs ' + cvClass(c.cvss) + '">' + (c.cvss || 'N/A') + '</div>';
        h += '<div><div style="font-family:monospace;font-size:11px">';
        h += '<a href="' + (c.url || '#') + '" target="_blank" rel="noopener" style="color:#4d9eff;text-decoration:none">' + esc(c.id) + '</a>';
        if (c.exploited) h += '<span style="color:#ff3b5c;font-size:10px;margin-left:6px">EXPLOITED</span>';
        h += '</div><div class="ftl">' + esc((c.title || '').substring(0, 90)) + '</div></div></div>';
      }
      g('cl').innerHTML = h || '<div class="lt">No CVEs</div>';
    }).catch(function() {});

  fetch(API + '/phishing?limit=20')
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (!d.success) return;
      var ph = d.data || [];
      g('c6').textContent = ph.length;
      g('s4').textContent = ph.length;
      var h = '';
      for (var i = 0; i < ph.length; i++) {
        var p = ph[i];
        h += '<div class="pi"><div style="margin-top:2px;font-size:14px">!</div>';
        h += '<div><div class="ftl">' + esc(p.subject || ('Phishing: ' + p.target)) + '</div>';
        h += '<div style="font-size:10px;color:#ff3b5c;font-family:monospace">' + esc(p.target || '-') + '</div>';
        h += '<div style="font-size:11px;color:#64748b">' + (p.domains || 1) + ' domain(s)</div></div></div>';
      }
      g('pl').innerHTML = h || '<div class="lt">No phishing data</div>';
    }).catch(function() {});

  clearTimeout(window._rt);
  window._rt = setTimeout(function() {
    fetch(API + '/cache/flush', {method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
      .catch(function(){}).then(go);
  }, 300000);
}

function rf() {
  fetch(API + '/cache/flush', {method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .catch(function(){}).then(go);
}

function sw(id, el) {
  document.querySelectorAll('.tc').forEach(function(t) { t.classList.remove('on'); });
  document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('on'); });
  g(id).classList.add('on');
  el.classList.add('on');
}

function uc() {
  var n = new Date();
  var p = function(x) { return String(x).padStart(2,'0'); };
  g('ck').textContent = p(n.getUTCHours()) + ':' + p(n.getUTCMinutes()) + ':' + p(n.getUTCSeconds()) + ' UTC';
}

// Wire up events
document.getElementById('fi').addEventListener('change', go);
document.getElementById('fr').addEventListener('change', go);
document.getElementById('fs').addEventListener('change', go);
document.getElementById('rfbtn').addEventListener('click', rf);
document.querySelectorAll('.tab').forEach(function(btn) {
  btn.addEventListener('click', function() { sw(btn.dataset.tab, btn); });
});

setInterval(uc, 1000);
uc();
go();