(function() {
  'use strict';

  var API = '/api/v1';
  var RC = {na:'#4d9eff',eu:'#a78bfa',apac:'#00d4aa',mena:'#f5c518',latam:'#ff8c42'};
  var RN = {na:'N.Am',eu:'Europe',apac:'Asia',mena:'MENA',latam:'LatAm'};

  function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function cvClass(v) { return !v?'medium':v>=9?'critical':v>=7?'high':'medium'; }
  function g(id) { return document.getElementById(id); }
  function rel(iso) {
    if (!iso) return 'never';
    var d = Date.now() - new Date(iso).getTime();
    var m = Math.floor(d/60000), h = Math.floor(d/3600000), dy = Math.floor(d/86400000);
    return m < 60 ? m+'m ago' : h < 24 ? h+'h ago' : dy+'d ago';
  }

  // ── Page Navigation ────────────────────────────────────────────────────────
  function showPage(name) {
    document.querySelectorAll('.page').forEach(function(p) { p.classList.remove('active'); });
    document.querySelectorAll('.nvb').forEach(function(b) { b.classList.remove('active'); });
    var pg = g('page-' + name);
    if (pg) pg.classList.add('active');
    document.querySelectorAll('[data-page="' + name + '"]').forEach(function(b) { b.classList.add('active'); });
    if (name === 'assets') loadAssets();
    if (name === 'creds') loadCreds();
    if (name === 'alerts') loadAlerts();
  }

  document.querySelectorAll('.nvb').forEach(function(btn) {
    btn.addEventListener('click', function() { showPage(btn.dataset.page); });
  });

  // ── Tab switching ──────────────────────────────────────────────────────────
  function sw(id, el) {
    document.querySelectorAll('.tc').forEach(function(t) { t.classList.remove('on'); });
    document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('on'); });
    g(id).classList.add('on');
    el.classList.add('on');
  }
  document.querySelectorAll('.tab').forEach(function(btn) {
    btn.addEventListener('click', function() { sw(btn.dataset.tab, btn); });
  });

  // ── Clock ──────────────────────────────────────────────────────────────────
  function uc() {
    var n = new Date(), p = function(x) { return String(x).padStart(2,'0'); };
    g('ck').textContent = p(n.getUTCHours())+':'+p(n.getUTCMinutes())+':'+p(n.getUTCSeconds())+' UTC';
  }
  setInterval(uc, 1000); uc();

  // ── INTEL FEED ─────────────────────────────────────────────────────────────
  function go() {
    var fi = g('fi').value, fr = g('fr').value, fs = g('fs').value;
    var qs = '?industry='+fi+'&region='+fr+'&severity='+fs+'&limit=50';

    fetch(API+'/threats'+qs)
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (!d.success) return;
        var ev = d.data.events || [];
        var crit = ev.filter(function(t) { return t.severity==='critical'; }).length;
        g('fb').textContent = crit + ' CRITICAL';
        g('c0').textContent = ev.length;
        var h = '';
        for (var i = 0; i < ev.length; i++) {
          var t = ev[i], sev = esc(t.severity||'low');
          h += '<div class="fi">';
          h += '<div class="svb '+sev+'"></div>';
          h += '<div style="flex:1;min-width:0">';
          h += '<div class="fm"><span class="bx '+sev+'">'+sev.toUpperCase()+'</span>';
          h += '<span style="background:#161b22;padding:1px 5px;border-radius:3px">'+esc(t.source)+'</span></div>';
          h += '<div class="ftl">'+esc(t.title)+'</div>';
          h += '<div class="fd">'+esc((t.description||'').substring(0,100))+'</div>';
          h += '</div></div>';
        }
        g('fa').innerHTML = h || '<div class="lt">No threats match filters</div>';
        // Region bars
        var cnt = {};
        for (var i = 0; i < ev.length; i++) { var rg = ev[i].region||[]; for (var j=0;j<rg.length;j++) { cnt[rg[j]]=(cnt[rg[j]]||0)+1; } }
        var sr = Object.entries(cnt).sort(function(a,b){return b[1]-a[1];}).slice(0,5); var mx = sr.length?sr[0][1]:1;
        var rbh = '';
        for (var i=0;i<sr.length;i++) { var k=sr[i][0],v=sr[i][1]; rbh+='<div class="br"><span class="bl">'+esc(RN[k]||k)+'</span><div class="bt"><div class="bf" style="width:'+Math.round(v/mx*100)+'%;background:'+(RC[k]||'#4d9eff')+'"></div></div><span class="bc">'+v+'</span></div>'; }
        g('rb').innerHTML = rbh || '<div class="lt">No data</div>';
        // Industry bars
        var ind = {};
        for (var i=0;i<ev.length;i++) { var ig=ev[i].industry||[]; for (var j=0;j<ig.length;j++) { ind[ig[j]]=(ind[ig[j]]||0)+1; } }
        var si = Object.entries(ind).sort(function(a,b){return b[1]-a[1];}).slice(0,7); var mi = si.length?si[0][1]:1;
        var ibh = '';
        for (var i=0;i<si.length;i++) { var k=si[i][0],v=si[i][1]; ibh+='<div class="br"><span class="bl" style="text-transform:capitalize">'+esc(k)+'</span><div class="bt"><div class="bf" style="width:'+Math.round(v/mi*100)+'%;background:linear-gradient(90deg,#4d9eff,#a78bfa)"></div></div><span class="bc">'+Math.round(v/(ev.length||1)*100)+'%</span></div>'; }
        g('ib2').innerHTML = ibh || '<div class="lt">No data</div>';
      }).catch(function(){});

    fetch(API+'/stats')
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (!d.success) return; var s = d.data;
        g('s0').textContent = s.criticalThreats||'-'; g('s1').textContent = (s.activeIoCs||0).toLocaleString();
        g('s2').textContent = s.threatActors||'-'; g('s3').textContent = s.zeroDayCVEs||'-'; g('s4').textContent = s.phishingKits||'-';
      }).catch(function(){});

    fetch(API+'/health')
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (!d.feeds) return;
        var fc = {configured:'#00d4aa',active:'#00d4aa',public:'#4d9eff','no-key':'#f5c518'};
        var h = '<h3 style="font-size:10px;color:#64748b;text-transform:uppercase;margin-bottom:8px">Health</h3>';
        Object.entries(d.feeds).forEach(function(e) { h+='<div style="display:flex;justify-content:space-between;padding:3px 0;font-size:11px"><span>'+e[0]+'</span><span style="color:'+(fc[e[1]]||'#64748b')+'">'+e[1]+'</span></div>'; });
        g('fh').innerHTML = h;
      }).catch(function(){});

    fetch(API+'/iocs?limit=100')
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (!d.success) return; var ic = d.data||[];
        g('c1').textContent = ic.filter(function(i){return i.source==='OTX';}).length;
        g('c2').textContent = ic.filter(function(i){return i.source==='URLhaus';}).length;
        g('c3').textContent = ic.filter(function(i){return i.source==='MalwareBazaar';}).length;
        g('c4').textContent = ic.filter(function(i){return i.source==='ThreatFox';}).length;
        g('c5').textContent = ic.filter(function(i){return i.source==='Feodo Tracker';}).length;
        var kc = function(c){return c>=90?'#00d4aa':c>=75?'#f5c518':'#ff3b5c';};
        var h = '';
        for (var i=0;i<ic.length;i++) { var v=ic[i]; h+='<tr><td><span style="background:#2e2300;color:#f5c518;border:1px solid #f5c518;padding:1px 4px;border-radius:3px;font-size:9px">'+esc(v.type||'-')+'</span></td><td style="color:#f5c518;word-break:break-all">'+esc((v.value||'').substring(0,48))+'</td><td style="color:'+kc(v.confidence||0)+'">'+(v.confidence||'?')+'%</td><td style="color:#64748b">'+esc(v.first||'-')+'</td><td style="color:#64748b">'+esc(v.source||'-')+'</td></tr>'; }
        g('ib').innerHTML = h || '<tr><td colspan="5" class="lt">No IoCs</td></tr>';
      }).catch(function(){});

    fetch(API+'/actors?limit=40')
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (!d.success) return; var ac = d.data||[];
        g('c7').textContent = ac.length;
        var h = '';
        for (var i=0;i<ac.length;i++) { var a=ac[i]; h+='<div class="ac"><div class="an">'+esc(a.name||'?')+'</div><div class="asu">'+esc(a.nation||'?')+' - '+esc(a.type||'APT')+'</div></div>'; }
        g('ag').innerHTML = h || '<div class="lt">No actors</div>';
      }).catch(function(){});

    fetch(API+'/cves?limit=20')
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (!d.success) return; var cv = d.data||[];
        g('c8').textContent = cv.length;
        var h = '';
        for (var i=0;i<cv.length;i++) { var c=cv[i]; h+='<div class="ci"><div class="cvs '+cvClass(c.cvss)+'">'+(c.cvss||'N/A')+'</div><div><div style="font-family:monospace;font-size:11px"><a href="'+(c.url||'#')+'" target="_blank" rel="noopener" style="color:#4d9eff;text-decoration:none">'+esc(c.id)+'</a>'+(c.exploited?'<span style="color:#ff3b5c;font-size:10px;margin-left:6px">EXPLOITED</span>':'')+'</div><div class="ftl">'+esc((c.title||'').substring(0,90))+'</div></div></div>'; }
        g('cl').innerHTML = h || '<div class="lt">No CVEs</div>';
      }).catch(function(){});

    fetch(API+'/phishing?limit=20')
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (!d.success) return; var ph = d.data||[];
        g('c6').textContent = ph.length; g('s4').textContent = ph.length;
        var h = '';
        for (var i=0;i<ph.length;i++) { var p=ph[i]; h+='<div class="pi"><div style="margin-top:2px;font-size:14px">!</div><div><div class="ftl">'+esc(p.subject||('Phishing: '+p.target))+'</div><div style="font-size:10px;color:#ff3b5c">'+esc(p.target||'-')+'</div><div style="font-size:11px;color:#64748b">'+(p.domains||1)+' domain(s)</div></div></div>'; }
        g('pl').innerHTML = h || '<div class="lt">No phishing data</div>';
      }).catch(function(){});

    clearTimeout(window._rt);
    window._rt = setTimeout(function() {
      fetch(API+'/cache/flush',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).catch(function(){}).then(go);
    }, 300000);
  }

  function rf() {
    fetch(API+'/cache/flush',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).catch(function(){}).then(go);
  }

  // ── ASSET MONITOR ──────────────────────────────────────────────────────────
  function loadAssets() {
    fetch(API+'/monitor/status')
      .then(function(r){return r.json();})
      .then(function(d) {
        if (!d.success) return; var st = d.data;
        var ipH = ''; (st.watchedIPs||[]).forEach(function(ip){ ipH+='<span class="watched-chip">'+esc(ip)+'<button onclick="window._removeWatch('ip',''+esc(ip)+'')">x</button></span>'; });
        g('watched-ips').innerHTML = ipH || '<div class="lt">No IPs watched</div>';
        var dmH = ''; (st.watchedDomains||[]).forEach(function(dm){ dmH+='<span class="watched-chip">'+esc(dm)+'<button onclick="window._removeWatch('domain',''+esc(dm)+'')">x</button></span>'; });
        g('watched-domains').innerHTML = dmH || '<div class="lt">No domains watched</div>';
        if (st.lastScan) g('as-scan').textContent = rel(st.lastScan);
      }).catch(function(){});

    fetch(API+'/monitor/assets')
      .then(function(r){return r.json();})
      .then(function(d) {
        if (!d.success) return; var assets = d.data||[];
        var crit = assets.filter(function(a){return a.riskLevel==='critical';}).length;
        var high = assets.filter(function(a){return a.riskLevel==='high';}).length;
        g('as-crit').textContent = crit; g('as-high').textContent = high;
        g('as-total').textContent = assets.length; g('as-ports').textContent = assets.length;
        g('asset-badge').textContent = crit + ' CRITICAL';
        var h = '';
        for (var i=0;i<assets.length;i++) {
          var a = assets[i];
          var vulnStr = Object.keys(a.vulns||{}).length ? '<span style="color:#ff3b5c">'+Object.keys(a.vulns).length+' CVE(s)</span>' : '<span style="color:#00d4aa">Clean</span>';
          h += '<tr><td style="font-family:monospace;color:#4d9eff">'+esc(a.ip)+'</td>';
          h += '<td style="color:#64748b">'+esc((a.hostnames||[])[0]||a.org||'-')+'</td>';
          h += '<td style="font-family:monospace">'+esc(String(a.port||'-'))+'</td>';
          h += '<td>'+esc(a.product||'Unknown')+(a.version?' <span style="color:#64748b">'+esc(a.version)+'</span>':'')+'</td>';
          h += '<td style="color:#64748b">'+esc(a.country||'-')+'</td>';
          h += '<td>'+vulnStr+'</td>';
          h += '<td><span class="risk-badge '+esc(a.riskLevel||'low')+'">'+esc((a.riskLevel||'low').toUpperCase())+'</span></td></tr>';
        }
        g('asset-tbody').innerHTML = h || '<tr><td colspan="7" class="lt">No assets — add domains/IPs and run a scan</td></tr>';
      }).catch(function(){});
  }

  window._removeWatch = function(type, value) {
    fetch(API+'/monitor/watchlist',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:type,value:value})})
      .then(function(){loadAssets();}).catch(function(){});
  };

  g('add-asset-btn').addEventListener('click', function() {
    var ip = g('add-ip').value.trim(), dm = g('add-domain').value.trim();
    if (!ip && !dm) { alert('Enter an IP or domain'); return; }
    var body = {};
    if (ip) body.ip = ip;
    if (dm) { body.domain = dm; body.credDomain = dm; }
    fetch(API+'/monitor/watchlist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
      .then(function(){ g('add-ip').value=''; g('add-domain').value=''; loadAssets(); })
      .catch(function(){});
  });

  g('scan-btn').addEventListener('click', function() {
    var btn = g('scan-btn'); btn.textContent = 'Scanning...';
    g('asset-badge').textContent = 'SCANNING';
    fetch(API+'/monitor/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
      .then(function() {
        setTimeout(function(){ btn.textContent = 'Run Scan Now'; loadAssets(); loadAlerts(); }, 15000);
      }).catch(function(){ btn.textContent = 'Run Scan Now'; });
  });

  // ── CREDENTIAL LEAKS ───────────────────────────────────────────────────────
  function loadCreds() {
    fetch(API+'/credentials/status')
      .then(function(r){return r.json();})
      .then(function(d) {
        if (!d.success) return; var results = d.data||[], domains = d.domains||[];
        g('cr-domains').textContent = domains.length || '-';
        var totalAcc=0, breachSet=new Set(), critCount=0;
        results.forEach(function(r){ totalAcc+=(r.totalExposedAccounts||0); (r.breaches||[]).forEach(function(b){breachSet.add(b);}); if((r.totalExposedAccounts||0)>100)critCount++; });
        g('cr-accounts').textContent = totalAcc.toLocaleString();
        g('cr-breaches').textContent = breachSet.size;
        g('cr-critical').textContent = critCount;
        if (results.length && results[0].lastChecked) g('cr-last').textContent = rel(results[0].lastChecked);
        // Summary cards
        var sumH = '';
        if (!results.length) { sumH = '<div class="lt">Add a domain to monitor for credential leaks</div>'; }
        else {
          results.forEach(function(r) {
            var sev = r.totalExposedAccounts>100?'critical':r.totalExposedAccounts>10?'high':'medium';
            sumH += '<div style="padding:10px 0;border-bottom:1px solid #1e2630">';
            sumH += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">';
            sumH += '<span style="font-family:monospace;font-size:13px;font-weight:700">'+esc(r.domain)+'</span>';
            sumH += '<span class="risk-badge '+sev+'">'+r.totalExposedAccounts+' EXPOSED</span></div>';
            sumH += '<div style="font-size:11px;color:#64748b;margin-bottom:5px">Breaches: ';
            (r.breaches||[]).forEach(function(b){ sumH+='<span class="tag">'+esc(b)+'</span>'; });
            sumH += '</div></div>';
          });
        }
        g('cred-summary').innerHTML = sumH;
        // Exposed emails table
        var emailH = '';
        results.forEach(function(r) {
          (r.exposedEmails||[]).forEach(function(e) {
            emailH += '<tr><td style="font-family:monospace;color:#f5c518">'+esc(e.email||'-')+'</td>';
            emailH += '<td>'+(e.breaches||[]).map(function(b){return '<span class="tag">'+esc(b)+'</span>';}).join('')+'</td>';
            emailH += '<td style="color:#64748b">'+esc(r.domain||'-')+'</td></tr>';
          });
        });
        g('exposed-emails').innerHTML = emailH || '<tr><td colspan="3" class="lt">No exposed emails</td></tr>';
      }).catch(function(){});

    fetch(API+'/credentials/breaches')
      .then(function(r){return r.json();})
      .then(function(d) {
        if (!d.success) return; var breaches = d.data||[], h = '';
        for (var i=0;i<breaches.length;i++) {
          var b = breaches[i];
          h += '<div class="breach-item">';
          h += '<div class="breach-name">'+esc(b.name)+'</div>';
          h += '<div class="breach-meta">'+esc(b.domain||'-')+' &bull; '+esc(b.breachDate||'-')+' &bull; <span style="color:#ff8c42">'+(b.pwnCount||0).toLocaleString()+' accounts</span></div>';
          h += '<div style="margin-top:4px">'+(b.dataClasses||[]).map(function(c){return '<span class="tag">'+esc(c)+'</span>';}).join('')+'</div>';
          h += '</div>';
        }
        g('global-breaches').innerHTML = h || '<div class="lt">No breach data</div>';
      }).catch(function(){});
  }

  g('add-cred-btn').addEventListener('click', function() {
    var dm = g('add-cred-domain').value.trim();
    if (!dm) { alert('Enter a domain'); return; }
    fetch(API+'/monitor/watchlist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({credDomain:dm})})
      .then(function(){ g('add-cred-domain').value=''; loadCreds(); })
      .catch(function(){});
  });

  g('check-btn').addEventListener('click', function() {
    var btn = g('check-btn'); btn.textContent = 'Checking...';
    fetch(API+'/monitor/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
      .then(function(){ setTimeout(function(){ btn.textContent='Check Now'; loadCreds(); }, 8000); })
      .catch(function(){ btn.textContent='Check Now'; });
  });

  // ── ALERTS ─────────────────────────────────────────────────────────────────
  function loadAlerts() {
    fetch(API+'/monitor/alerts')
      .then(function(r){return r.json();})
      .then(function(d) {
        if (!d.success) return; var alerts = d.data||[];
        var cnt = alerts.length; var dot = g('alert-count');
        if (cnt > 0) { dot.textContent = cnt; dot.style.display = 'inline-block'; }
        else { dot.style.display = 'none'; }
        g('alerts-badge').textContent = cnt + ' ALERTS';
        if (!alerts.length) {
          g('alerts-list').innerHTML = '<div class="lt">No alerts yet. Monitoring runs every 6h. Use Asset Monitor to trigger a manual scan now.</div>';
          return;
        }
        var icons = {new_port:'[PORT]',new_vuln:'[CVE]',credential_leak:'[CRED]',critical_asset:'[ASSET]'};
        var sevColor = {critical:'#ff3b5c',high:'#ff8c42',medium:'#f5c518',low:'#00d4aa'};
        var h = '';
        for (var i=0;i<alerts.length;i++) {
          var a = alerts[i];
          var sc = sevColor[a.severity]||'#64748b';
          h += '<div class="alert-item">';
          h += '<div style="font-family:monospace;font-size:11px;color:'+sc+';flex-shrink:0;padding-top:2px">'+(icons[a.type]||'[!]')+'</div>';
          h += '<div style="flex:1"><div class="alert-msg">'+esc(a.message)+'</div>';
          h += '<div class="alert-time"><span style="color:'+sc+'">'+esc((a.severity||'').toUpperCase())+'</span> &bull; '+esc(rel(a.timestamp))+'</div></div>';
          h += '</div>';
        }
        g('alerts-list').innerHTML = h;
      }).catch(function(){});
  }

  g('clear-alerts-btn').addEventListener('click', loadAlerts);

  // ── Filters + refresh wiring ───────────────────────────────────────────────
  g('fi').addEventListener('change', go);
  g('fr').addEventListener('change', go);
  g('fs').addEventListener('change', go);
  g('rfbtn').addEventListener('click', rf);

  // ── Auto-refresh monitoring pages every 30s ────────────────────────────────
  setInterval(function() {
    var activePage = document.querySelector('.page.active');
    if (!activePage) return;
    var id = activePage.id;
    if (id === 'page-assets') loadAssets();
    if (id === 'page-creds') loadCreds();
    if (id === 'page-alerts') loadAlerts();
  }, 30000);

  // ── Boot ───────────────────────────────────────────────────────────────────
  go();

})();