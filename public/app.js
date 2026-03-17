var API = '/api/v1';
var RC = {na:'#4d9eff',eu:'#a78bfa',apac:'#00d4aa',mena:'#f5c518',latam:'#ff8c42'};
var RN = {na:'N.Am',eu:'Europe',apac:'Asia',mena:'MENA',latam:'LatAm'};

function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function cvClass(s) { return !s?'medium':s>=9?'critical':s>=7?'high':'medium'; }
function g(id) { return document.getElementById(id); }
function relTime(iso) {
  if (!iso) return 'never';
  var d = Date.now() - new Date(iso).getTime();
  var m = Math.floor(d/60000), h = Math.floor(d/3600000), dy = Math.floor(d/86400000);
  return m < 60 ? m+'m ago' : h < 24 ? h+'h ago' : dy+'d ago';
}

// ── Page Navigation ──────────────────────────────────────────────────────────
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

// ── Tab Switching ────────────────────────────────────────────────────────────
function sw(id, el) {
  document.querySelectorAll('.tc').forEach(function(t) { t.classList.remove('on'); });
  document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('on'); });
  g(id).classList.add('on');
  el.classList.add('on');
}
document.querySelectorAll('.tab').forEach(function(btn) {
  btn.addEventListener('click', function() { sw(btn.dataset.tab, btn); });
});

// ── INTEL FEED ───────────────────────────────────────────────────────────────
function go() {
  var fi = g('fi').value, fr = g('fr').value, fs = g('fs').value;
  var qs = '?industry='+fi+'&region='+fr+'&severity='+fs+'&limit=50';

  fetch(API+'/threats'+qs).then(function(r){return r.json();}).then(function(d){
    if(!d.success) return;
    var ev = d.data.events||[];
    g('fb').textContent = ev.filter(function(t){return t.severity==='critical';}).length+' CRITICAL';
    g('c0').textContent = ev.length;
    var html = '';
    for (var i=0;i<ev.length;i++) {
      var t=ev[i], sev=esc(t.severity||'low');
      html += '<div class="fi"><div class="svb '+sev+'"></div><div style="flex:1;min-width:0">';
      html += '<div class="fm"><span class="bx '+sev+'">'+sev.toUpperCase()+'</span><span style="background:#161b22;padding:1px 5px;border-radius:3px">'+esc(t.source)+'</span></div>';
      html += '<div class="ftl">'+esc(t.title)+'</div>';
      html += '<div class="fd">'+esc((t.description||'').substring(0,100))+'</div></div></div>';
    }
    g('fa').innerHTML = html||'<div class="lt">No threats match filters</div>';
    var cnt={};
    for(var i=0;i<ev.length;i++){var rg=ev[i].region||[];for(var j=0;j<rg.length;j++){cnt[rg[j]]=(cnt[rg[j]]||0)+1;}}
    var sr=Object.entries(cnt).sort(function(a,b){return b[1]-a[1];}).slice(0,5); var mx=sr.length?sr[0][1]:1;
    var rbh='';
    for(var i=0;i<sr.length;i++){var k=sr[i][0],v=sr[i][1];rbh+='<div class="br"><span class="bl">'+esc(RN[k]||k)+'</span><div class="bt"><div class="bf" style="width:'+Math.round(v/mx*100)+'%;background:'+(RC[k]||'#4d9eff')+'"></div></div><span class="bc">'+v+'</span></div>';}
    g('rb').innerHTML=rbh||'<div class="lt">No data</div>';
    var ind={};
    for(var i=0;i<ev.length;i++){var ig=ev[i].industry||[];for(var j=0;j<ig.length;j++){ind[ig[j]]=(ind[ig[j]]||0)+1;}}
    var si=Object.entries(ind).sort(function(a,b){return b[1]-a[1];}).slice(0,7); var mi=si.length?si[0][1]:1;
    var ibh='';
    for(var i=0;i<si.length;i++){var k=si[i][0],v=si[i][1];ibh+='<div class="br"><span class="bl" style="text-transform:capitalize">'+esc(k)+'</span><div class="bt"><div class="bf" style="width:'+Math.round(v/mi*100)+'%;background:linear-gradient(90deg,#4d9eff,#a78bfa)"></div></div><span class="bc">'+Math.round(v/(ev.length||1)*100)+'%</span></div>';}
    g('ib2').innerHTML=ibh||'<div class="lt">No data</div>';
  }).catch(function(){});

  fetch(API+'/stats').then(function(r){return r.json();}).then(function(d){
    if(!d.success)return; var s=d.data;
    g('s0').textContent=s.criticalThreats||'-'; g('s1').textContent=(s.activeIoCs||0).toLocaleString();
    g('s2').textContent=s.threatActors||'-'; g('s3').textContent=s.zeroDayCVEs||'-'; g('s4').textContent=s.phishingKits||'-';
  }).catch(function(){});

  fetch(API+'/health').then(function(r){return r.json();}).then(function(d){
    if(!d.feeds)return;
    var fc={configured:'#00d4aa',active:'#00d4aa',public:'#4d9eff','no-key':'#f5c518'};
    var h='<h3 style="font-size:10px;color:#64748b;text-transform:uppercase;margin-bottom:8px">Health</h3>';
    Object.entries(d.feeds).forEach(function(e){h+='<div style="display:flex;justify-content:space-between;padding:3px 0;font-size:11px"><span>'+e[0]+'</span><span style="color:'+(fc[e[1]]||'#64748b')+'">'+e[1]+'</span></div>';});
    g('fh').innerHTML=h;
  }).catch(function(){});

  fetch(API+'/iocs?limit=100').then(function(r){return r.json();}).then(function(d){
    if(!d.success)return; var ic=d.data||[];
    g('c1').textContent=ic.filter(function(i){return i.source==='OTX';}).length;
    g('c2').textContent=ic.filter(function(i){return i.source==='URLhaus';}).length;
    g('c3').textContent=ic.filter(function(i){return i.source==='MalwareBazaar';}).length;
    g('c4').textContent=ic.filter(function(i){return i.source==='ThreatFox';}).length;
    g('c5').textContent=ic.filter(function(i){return i.source==='Feodo Tracker';}).length;
    var kc=function(c){return c>=90?'#00d4aa':c>=75?'#f5c518':'#ff3b5c';};
    var h='';
    for(var i=0;i<ic.length;i++){var v=ic[i];h+='<tr><td><span style="background:#2e2300;color:#f5c518;border:1px solid #f5c518;padding:1px 4px;border-radius:3px;font-size:9px">'+esc(v.type||'-')+'</span></td><td style="color:#f5c518;word-break:break-all">'+esc((v.value||'').substring(0,48))+'</td><td style="color:'+kc(v.confidence||0)+'">'+(v.confidence||'?')+'%</td><td style="color:#64748b">'+esc(v.first||'-')+'</td><td style="color:#64748b">'+esc(v.source||'-')+'</td></tr>';}
    g('ib').innerHTML=h||'<tr><td colspan="5" class="lt">No IoCs</td></tr>';
  }).catch(function(){});

  fetch(API+'/actors?limit=40').then(function(r){return r.json();}).then(function(d){
    if(!d.success)return; var ac=d.data||[];
    g('c7').textContent=ac.length;
    var h='';
    for(var i=0;i<ac.length;i++){var a=ac[i];h+='<div class="ac"><div class="an">'+esc(a.name||'?')+'</div><div class="asu">'+esc(a.nation||'?')+' - '+esc(a.type||'APT')+'</div></div>';}
    g('ag').innerHTML=h||'<div class="lt">No actors</div>';
  }).catch(function(){});

  fetch(API+'/cves?limit=20').then(function(r){return r.json();}).then(function(d){
    if(!d.success)return; var cv=d.data||[];
    g('c8').textContent=cv.length;
    var h='';
    for(var i=0;i<cv.length;i++){var c=cv[i];h+='<div class="ci"><div class="cvs '+cvClass(c.cvss)+'">'+(c.cvss||'N/A')+'</div><div><div style="font-family:monospace;font-size:11px"><a href="'+(c.url||'#')+'" target="_blank" rel="noopener" style="color:#4d9eff;text-decoration:none">'+esc(c.id)+'</a>'+(c.exploited?'<span style="color:#ff3b5c;font-size:10px;margin-left:6px">EXPLOITED</span>':'')+'</div><div class="ftl">'+esc((c.title||'').substring(0,90))+'</div></div></div>';}
    g('cl').innerHTML=h||'<div class="lt">No CVEs</div>';
  }).catch(function(){});

  fetch(API+'/phishing?limit=20').then(function(r){return r.json();}).then(function(d){
    if(!d.success)return; var ph=d.data||[];
    g('c6').textContent=ph.length; g('s4').textContent=ph.length;
    var h='';
    for(var i=0;i<ph.length;i++){var p=ph[i];h+='<div class="pi"><div style="margin-top:2px;font-size:14px">!</div><div><div class="ftl">'+esc(p.subject||('Phishing: '+p.target))+'</div><div style="font-size:10px;color:#ff3b5c">'+esc(p.target||'-')+'</div><div style="font-size:11px;color:#64748b">'+(p.domains||1)+' domain(s)</div></div></div>';}
    g('pl').innerHTML=h||'<div class="lt">No phishing data</div>';
  }).catch(function(){});

  clearTimeout(window._rt);
  window._rt=setTimeout(function(){fetch(API+'/cache/flush',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).catch(function(){}).then(go);},300000);
}

function rf(){fetch(API+'/cache/flush',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).catch(function(){}).then(go);}

// ── ASSET MONITOR ────────────────────────────────────────────────────────────
function loadAssets() {
  fetch(API+'/monitor/status').then(function(r){return r.json();}).then(function(d){
    if(!d.success)return;
    var st=d.data;
    // Update watchlists display
    var ipHtml='';
    (st.watchedIPs||[]).forEach(function(ip){ipHtml+='<span class="watched-chip">'+esc(ip)+'<button onclick="removeWatch('ip',''+esc(ip)+'')">x</button></span>';});
    g('watched-ips').innerHTML=ipHtml||'<div class="lt">No IPs watched</div>';
    var dmHtml='';
    (st.watchedDomains||[]).forEach(function(d){dmHtml+='<span class="watched-chip">'+esc(d)+'<button onclick="removeWatch('domain',''+esc(d)+'')">x</button></span>';});
    g('watched-domains').innerHTML=dmHtml||'<div class="lt">No domains watched</div>';
    if(st.lastScan) g('as-scan').textContent=relTime(st.lastScan);
  }).catch(function(){});

  fetch(API+'/monitor/assets').then(function(r){return r.json();}).then(function(d){
    if(!d.success)return;
    var assets=d.data||[];
    var crit=assets.filter(function(a){return a.riskLevel==='critical';}).length;
    var high=assets.filter(function(a){return a.riskLevel==='high';}).length;
    var totalPorts=0; assets.forEach(function(a){totalPorts+=(a.port?1:0);});
    g('as-crit').textContent=crit; g('as-high').textContent=high;
    g('as-total').textContent=assets.length; g('as-ports').textContent=totalPorts;
    g('asset-badge').textContent=crit+' CRITICAL';
    var h='';
    for(var i=0;i<assets.length;i++){
      var a=assets[i];
      var vulnStr=Object.keys(a.vulns||{}).length?'<span style="color:#ff3b5c">'+Object.keys(a.vulns).length+' CVE(s)</span>':'<span style="color:#00d4aa">Clean</span>';
      h+='<tr><td style="font-family:monospace;color:#4d9eff">'+esc(a.ip)+'</td>';
      h+='<td style="color:#64748b">'+esc((a.hostnames||[a.org||''])[0]||'-')+'</td>';
      h+='<td style="font-family:monospace">'+esc(String(a.port||'-'))+'</td>';
      h+='<td>'+esc(a.product||'Unknown')+(a.version?' <span style="color:#64748b">'+esc(a.version)+'</span>':'')+'</td>';
      h+='<td style="color:#64748b">'+esc(a.country||'-')+'</td>';
      h+='<td>'+vulnStr+'</td>';
      h+='<td><span class="risk-badge '+esc(a.riskLevel||'low')+'">'+esc((a.riskLevel||'low').toUpperCase())+'</span></td></tr>';
    }
    g('asset-tbody').innerHTML=h||'<tr><td colspan="7" class="lt">No assets found - add domains/IPs and run a scan</td></tr>';
  }).catch(function(){});
}

function removeWatch(type, value) {
  fetch(API+'/monitor/watchlist',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:type,value:value})})
    .then(function(){loadAssets();}).catch(function(){});
}

g('add-asset-btn').addEventListener('click', function() {
  var ip=g('add-ip').value.trim(), dm=g('add-domain').value.trim();
  if(!ip&&!dm){alert('Enter an IP address or domain name');return;}
  var body={};
  if(ip) body.ip=ip;
  if(dm){body.domain=dm; body.credDomain=dm;}
  fetch(API+'/monitor/watchlist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})
    .then(function(){g('add-ip').value='';g('add-domain').value='';loadAssets();})
    .catch(function(){});
});

g('scan-btn').addEventListener('click', function() {
  g('scan-btn').textContent='Scanning...';
  g('asset-badge').textContent='SCANNING';
  fetch(API+'/monitor/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .then(function(){
      setTimeout(function(){
        g('scan-btn').textContent='Run Scan Now';
        loadAssets();
        loadAlerts();
      }, 15000); // wait 15s for scan to complete
    }).catch(function(){g('scan-btn').textContent='Run Scan Now';});
});

// ── CREDENTIAL LEAK MONITOR ──────────────────────────────────────────────────
function loadCreds() {
  fetch(API+'/credentials/status').then(function(r){return r.json();}).then(function(d){
    if(!d.success)return;
    var results=d.data||[], domains=d.domains||[];
    g('cr-domains').textContent=domains.length||'-';
    var totalAccounts=0, totalBreaches=new Set(), critCount=0;
    results.forEach(function(r){
      totalAccounts+=(r.totalExposedAccounts||0);
      (r.breaches||[]).forEach(function(b){totalBreaches.add(b);});
      if((r.totalExposedAccounts||0)>100) critCount++;
    });
    g('cr-accounts').textContent=totalAccounts.toLocaleString();
    g('cr-breaches').textContent=totalBreaches.size;
    g('cr-critical').textContent=critCount;
    if(results.length>0&&results[0].lastChecked) g('cr-last').textContent=relTime(results[0].lastChecked);

    // Domain breach summary cards
    var sumHtml='';
    if(results.length===0){
      sumHtml='<div class="lt">Add a domain to start monitoring for credential leaks</div>';
    } else {
      results.forEach(function(r){
        var sev=r.totalExposedAccounts>100?'critical':r.totalExposedAccounts>10?'high':'medium';
        sumHtml+='<div style="padding:10px 0;border-bottom:1px solid #1e2630">';
        sumHtml+='<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">';
        sumHtml+='<span style="font-family:monospace;font-size:13px;font-weight:700">'+esc(r.domain)+'</span>';
        sumHtml+='<span class="risk-badge '+sev+'">'+r.totalExposedAccounts+' EXPOSED</span></div>';
        sumHtml+='<div style="font-size:11px;color:#64748b;margin-bottom:5px">Breaches: ';
        (r.breaches||[]).forEach(function(b){sumHtml+='<span class="tag">'+esc(b)+'</span>';});
        sumHtml+='</div></div>';
      });
    }
    g('cred-summary').innerHTML=sumHtml;

    // Exposed emails table
    var emailHtml='';
    results.forEach(function(r){
      (r.exposedEmails||[]).forEach(function(e){
        emailHtml+='<tr><td style="font-family:monospace;color:#f5c518">'+esc(e.email||'-')+'</td>';
        emailHtml+='<td>'+( e.breaches||[]).map(function(b){return '<span class="tag">'+esc(b)+'</span>';}).join('')+'</td>';
        emailHtml+='<td style="color:#64748b">'+esc(r.domain||'-')+'</td></tr>';
      });
    });
    g('exposed-emails').innerHTML=emailHtml||'<tr><td colspan="3" class="lt">No exposed emails detected</td></tr>';
  }).catch(function(){});

  // Global breach feed
  fetch(API+'/credentials/breaches').then(function(r){return r.json();}).then(function(d){
    if(!d.success)return;
    var breaches=d.data||[], h='';
    for(var i=0;i<breaches.length;i++){
      var b=breaches[i];
      h+='<div class="breach-item">';
      h+='<div class="breach-name">'+esc(b.name)+'</div>';
      h+='<div class="breach-meta">'+esc(b.domain||'-')+' &bull; '+esc(b.breachDate||'-')+' &bull; <span style="color:#ff8c42">'+(b.pwnCount||0).toLocaleString()+' accounts</span></div>';
      h+='<div style="margin-top:4px">'+(b.dataClasses||[]).map(function(c){return '<span class="tag">'+esc(c)+'</span>';}).join('')+'</div>';
      h+='</div>';
    }
    g('global-breaches').innerHTML=h||'<div class="lt">No breach data</div>';
  }).catch(function(){});
}

g('add-cred-btn').addEventListener('click', function() {
  var dm=g('add-cred-domain').value.trim();
  if(!dm){alert('Enter an organisation domain (e.g. company.com)');return;}
  fetch(API+'/monitor/watchlist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({credDomain:dm})})
    .then(function(){
      g('add-cred-domain').value='';
      // Immediately check the domain
      return fetch(API+'/credentials/domain/'+encodeURIComponent(dm));
    }).then(function(){loadCreds();}).catch(function(){});
});

g('check-btn').addEventListener('click', function() {
  g('check-btn').textContent='Checking...';
  fetch(API+'/monitor/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .then(function(){setTimeout(function(){g('check-btn').textContent='Check Now';loadCreds();},8000);})
    .catch(function(){g('check-btn').textContent='Check Now';});
});

// ── ALERTS ───────────────────────────────────────────────────────────────────
function loadAlerts() {
  fetch(API+'/monitor/alerts').then(function(r){return r.json();}).then(function(d){
    if(!d.success)return;
    var alerts=d.data||[];
    // Update alert count badge in nav
    var cnt=alerts.length;
    var dot=g('alert-count');
    if(cnt>0){dot.textContent=cnt;dot.style.display='inline-block';}
    else{dot.style.display='none';}
    g('alerts-badge').textContent=cnt+' ALERTS';
    if(alerts.length===0){
      g('alerts-list').innerHTML='<div class="lt">No alerts yet - monitoring runs every 6 hours. Click scan on the Asset Monitor to trigger now.</div>';
      return;
    }
    var icons={critical:'&#128680;',high:'&#9888;',medium:'&#8505;',new_port:'&#128268;',new_vuln:'&#128161;',credential_leak:'&#128274;',critical_asset:'&#128683;'};
    var h='';
    for(var i=0;i<alerts.length;i++){
      var a=alerts[i];
      var icon=icons[a.type]||icons[a.severity]||'&#9888;';
      var sevColor=a.severity==='critical'?'#ff3b5c':a.severity==='high'?'#ff8c42':'#f5c518';
      h+='<div class="alert-item">';
      h+='<div class="alert-icon">'+icon+'</div>';
      h+='<div style="flex:1">';
      h+='<div class="alert-msg">'+esc(a.message)+'</div>';
      h+='<div class="alert-time"><span style="color:'+sevColor+'">'+esc((a.severity||'').toUpperCase())+'</span> &bull; '+esc(relTime(a.timestamp))+'</div>';
      h+='</div></div>';
    }
    g('alerts-list').innerHTML=h;
  }).catch(function(){});
}

g('clear-alerts-btn').addEventListener('click', function() {
  // Just reload to get fresh state
  loadAlerts();
});

// ── Misc ─────────────────────────────────────────────────────────────────────
g('fi').addEventListener('change', go);
g('fr').addEventListener('change', go);
g('fs').addEventListener('change', go);
g('rfbtn').addEventListener('click', rf);

function uc() {
  var n=new Date(), p=function(x){return String(x).padStart(2,'0');};
  g('ck').textContent=p(n.getUTCHours())+':'+p(n.getUTCMinutes())+':'+p(n.getUTCSeconds())+' UTC';
}
setInterval(uc,1000); uc();

// Auto-refresh monitoring pages every 30s
setInterval(function() {
  var activePage = document.querySelector('.page.active');
  if (!activePage) return;
  var id = activePage.id;
  if (id === 'page-assets') loadAssets();
  if (id === 'page-creds') loadCreds();
  if (id === 'page-alerts') loadAlerts();
}, 30000);

// Start intel feed
go();