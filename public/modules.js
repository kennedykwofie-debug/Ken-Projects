/**
 * DARKWATCH Pro v2.2 - Intelligence Modules
 * Dark Web | Investigation | Posture | CVE Intel | News Feed
 */
(function(){
  var PROAPI='https://spectacular-wisdom-production.up.railway.app';
  // Warm up the API on page load to avoid cold-start failures
  fetch(PROAPI+'/health').catch(function(){});
  function authH(){var t=localStorage.getItem('dw_access_token');return t?{'Content-Type':'application/json','Authorization':'Bearer '+t}:{'Content-Type':'application/json'};}
  function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
  function stat(label,val,color){return '<div style="background:#0f1117;border:1px solid #1e293b;border-radius:8px;padding:12px 16px;"><div style="color:#64748b;font-size:10px;letter-spacing:1px;margin-bottom:6px;">'+label+'</div><div style="color:'+(color||'#e2e8f0')+';font-size:22px;font-weight:700;">'+val+'</div></div>';}

  // ── DARK WEB ──────────────────────────────────────────────────────────────
  window.loadDarkWeb = async function(){
    var el=document.getElementById('dw-stats');
    if(el) el.innerHTML='<div style="color:#64748b;grid-column:1/-1;text-align:center;padding:20px;">Loading...</div>';
    try{
      var r=await fetch(PROAPI+'/darkweb/summary',{headers:authH()});
      var d=await r.json();
      if(!r.ok){if(el) el.innerHTML='<div style="color:#ff3b5c;grid-column:1/-1;">'+esc(d.detail||'Auth required')+'</div>';return;}
      el.innerHTML=stat('RECENT VICTIMS',d.total_recent_victims,'#ff3b5c')+stat('ACTIVE GROUPS',d.active_groups,'#f97316')+stat('TOP GROUP',(d.top_groups||[['-']])[0][0]||'-','#f5c518')+stat('TOP SECTOR',(d.top_sectors||[['-']])[0][0]||'-','#a855f7');
      var vr=await fetch(PROAPI+'/darkweb/ransomware?limit=15',{headers:authH()});
      var vd=await vr.json();
      var vh='<table style="width:100%;border-collapse:collapse;font-size:11px;"><tr style="color:#64748b;border-bottom:1px solid #1e293b;"><td style="padding:5px 8px;font-size:10px;">VICTIM</td><td style="font-size:10px;">GROUP</td><td style="font-size:10px;">COUNTRY</td><td style="font-size:10px;">DATE</td></tr>';
      (vd.victims||[]).slice(0,12).forEach(function(v){vh+='<tr style="border-bottom:1px solid #0f1117;"><td style="padding:5px 8px;color:#e2e8f0;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">'+esc(v.victim||'-')+'</td><td style="color:#ff3b5c;white-space:nowrap;">'+esc(v.group||'-')+'</td><td style="color:#64748b;">'+esc(v.country||'-')+'</td><td style="color:#64748b;white-space:nowrap;">'+esc((v.published||'').substring(0,10))+'</td></tr>';});
      vh+='</table>';
      document.getElementById('dw-victims').innerHTML=vh;
      var gh='';
      (d.top_groups||[]).forEach(function(g){var pct=Math.round((g[1]/(d.total_recent_victims||1))*100);gh+='<div style="margin-bottom:8px;"><div style="display:flex;justify-content:space-between;margin-bottom:3px;font-size:12px;"><span style="color:#f97316;">'+esc(g[0])+'</span><span style="color:#64748b;">'+g[1]+'</span></div><div style="background:#1e293b;border-radius:2px;height:3px;"><div style="background:linear-gradient(90deg,#f97316,#ff3b5c);height:3px;width:'+pct+'%;border-radius:2px;"></div></div></div>';});
      document.getElementById('dw-groups').innerHTML=gh||'<div style="color:#64748b;font-size:12px;">No data</div>';
      var sh='';
      (d.top_sectors||[]).slice(0,6).forEach(function(s){sh+='<div style="display:flex;justify-content:space-between;margin-bottom:6px;font-size:12px;"><span style="color:#94a3b8;">'+esc(s[0])+'</span><span style="color:#a855f7;font-weight:700;">'+s[1]+'</span></div>';});
      document.getElementById('dw-sectors').innerHTML=sh||'<div style="color:#64748b;font-size:12px;">No data</div>';
    }catch(e){if(el) el.innerHTML='<div style="color:#ff3b5c;grid-column:1/-1;">'+esc(e.message)+'</div>';}
  };

  window.checkDomainBreaches = async function(){
    var domain=document.getElementById('dw-domain-input').value.trim();
    if(!domain)return;
    var el=document.getElementById('dw-breach-result');
    el.innerHTML='<span style="color:#64748b;font-size:12px;">Checking '+esc(domain)+'...</span>';
    try{
      var r=await fetch(PROAPI+'/darkweb/breaches/'+encodeURIComponent(domain),{headers:authH()});
      var d=await r.json();
      if(!r.ok){el.innerHTML='<span style="color:#ff3b5c;font-size:12px;">'+esc(d.detail||'Error')+'</span>';return;}
      var total=d.total_exposed||0;
      var col=total>1000?'#ff3b5c':total>0?'#f5c518':'#22c55e';
      el.innerHTML='<div style="color:'+col+';font-weight:700;font-size:13px;margin-bottom:4px;">'+total.toLocaleString()+' credentials exposed</div>';
    }catch(e){el.innerHTML='<span style="color:#ff3b5c;font-size:12px;">'+esc(e.message)+'</span>';}
  };

  // ── INVESTIGATION ─────────────────────────────────────────────────────────
  window.runInvestigation = async function(){
    var indicator=document.getElementById('inv-input').value.trim();
    if(!indicator)return;
    var el=document.getElementById('inv-result');
    el.innerHTML='<div style="color:#64748b;text-align:center;padding:40px;font-size:13px;">Enriching <strong style="color:#f5c518;">'+esc(indicator)+'</strong>...</div>';
    try{
      var r=await fetch(PROAPI+'/investigate/enrich/'+encodeURIComponent(indicator),{headers:authH()});
      var d=await r.json();
      if(!r.ok){el.innerHTML='<div style="color:#ff3b5c;padding:16px;">'+esc(d.detail||JSON.stringify(d))+'</div>';return;}
      var type=(d.type||'unknown').toUpperCase();
      var tc={'IP':'#00d4aa','DOMAIN':'#f5c518','HASH':'#a855f7'}[type]||'#64748b';
      var h='<div style="background:#0f1117;border:1px solid #1e293b;border-radius:10px;padding:20px;">';
      h+='<div style="display:flex;align-items:center;gap:12px;margin-bottom:18px;padding-bottom:14px;border-bottom:1px solid #1e293b;">';
      h+='<span style="background:'+tc+'22;color:'+tc+';border:1px solid '+tc+'44;padding:3px 10px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:1px;">'+type+'</span>';
      h+='<span style="color:#e2e8f0;font-size:15px;font-weight:700;font-family:monospace;">'+esc(indicator)+'</span></div>';
      var vt=d.virustotal||{};
      if(vt.status==='key_not_configured'){
        h+='<div style="background:#1e293b;border-radius:6px;padding:10px 14px;margin-bottom:10px;font-size:11px;color:#64748b;">VirusTotal: VIRUSTOTAL_KEY not configured</div>';
      } else if(vt.malicious!==undefined){
        var mal=vt.malicious||0;var col=mal>5?'#ff3b5c':mal>0?'#f5c518':'#22c55e';
        h+='<div style="margin-bottom:14px;"><div style="color:#64748b;font-size:10px;letter-spacing:1px;margin-bottom:8px;">VIRUSTOTAL DETECTIONS</div>';
        h+='<div style="display:flex;align-items:baseline;gap:8px;"><span style="color:'+col+';font-size:32px;font-weight:700;">'+mal+'</span><span style="color:#64748b;font-size:12px;">/ 80+ engines</span></div></div>';
      }
      if(d.greynoise&&d.greynoise.noise!==undefined){
        var gn=d.greynoise;var gnc=gn.noise?'#f97316':'#22c55e';
        h+='<div style="margin-bottom:14px;"><div style="color:#64748b;font-size:10px;letter-spacing:1px;margin-bottom:8px;">GREYNOISE</div>';
        h+='<span style="color:'+gnc+';font-weight:700;">'+esc(gn.noise?'INTERNET NOISE':'NOT IN NOISE')+'</span>';
        if(gn.name) h+=' <span style="color:#f5c518;font-size:12px;">'+esc(gn.name)+'</span>';
        h+='</div>';
      }
      if(d.ipinfo&&(d.ipinfo.city||d.ipinfo.org)){
        var ii=d.ipinfo;
        h+='<div style="margin-bottom:14px;"><div style="color:#64748b;font-size:10px;letter-spacing:1px;margin-bottom:8px;">GEOLOCATION</div>';
        h+='<div style="font-size:12px;color:#e2e8f0;">'+esc([ii.city,ii.region,ii.country].filter(Boolean).join(', '))+'</div>';
        if(ii.org) h+='<div style="font-size:11px;color:#64748b;margin-top:2px;">'+esc(ii.org)+'</div>';
        h+='</div>';
      }
      if(d.shodan&&d.shodan.ports&&d.shodan.ports.length){
        h+='<div style="margin-bottom:14px;"><div style="color:#64748b;font-size:10px;letter-spacing:1px;margin-bottom:8px;">SHODAN</div>';
        h+='<div style="font-size:12px;color:#f5c518;">Ports: '+d.shodan.ports.slice(0,10).join(', ')+'</div>';
        if(d.shodan.vulns&&d.shodan.vulns.length) h+='<div style="font-size:12px;color:#ff3b5c;margin-top:4px;">CVEs: '+d.shodan.vulns.slice(0,4).join(', ')+'</div>';
        h+='</div>';
      }
      if(d.malwarebazaar&&d.malwarebazaar.file_name){
        var mb=d.malwarebazaar;
        h+='<div style="background:#1a0a0a;border:1px solid #ff3b5c33;border-radius:6px;padding:12px 14px;margin-bottom:10px;">';
        h+='<div style="color:#ff3b5c;font-weight:700;font-size:12px;margin-bottom:6px;">KNOWN MALWARE - MalwareBazaar</div>';
        if(mb.file_name) h+='<div style="color:#94a3b8;font-size:11px;">File: <span style="color:#e2e8f0;">'+esc(mb.file_name)+'</span></div>';
        if(mb.signature) h+='<div style="color:#94a3b8;font-size:11px;">Signature: <span style="color:#f5c518;">'+esc(mb.signature)+'</span></div>';
        h+='</div>';
      }
      h+='</div>';
      el.innerHTML=h;
    }catch(e){el.innerHTML='<div style="color:#ff3b5c;padding:16px;">'+esc(e.message)+'</div>';}
  };

  var invInput=document.getElementById('inv-input');
  if(invInput) invInput.addEventListener('keydown',function(e){if(e.key==='Enter') window.runInvestigation();});

  // ── POSTURE ───────────────────────────────────────────────────────────────
  window.runPostureScan = async function(){
    var domain=document.getElementById('pos-domain').value.trim();
    if(!domain)return;
    var el=document.getElementById('pos-result');
    el.innerHTML='<div style="color:#64748b;text-align:center;padding:40px;font-size:13px;">Scanning '+esc(domain)+'...</div>';
    try{
      var r=await fetch(PROAPI+'/posture/scan/'+encodeURIComponent(domain),{headers:authH()});
      var d=await r.json();
      if(!r.ok){el.innerHTML='<div style="color:#ff3b5c;padding:16px;">'+esc(d.detail||JSON.stringify(d))+'</div>';return;}
      var score=d.score||0;var rl=d.risk_level||'UNKNOWN';
      var rc={'CRITICAL':'#ff3b5c','HIGH':'#f97316','MEDIUM':'#f5c518','LOW':'#22c55e'}[rl]||'#64748b';
      var sc=score<40?'#ff3b5c':score<60?'#f97316':score<80?'#f5c518':'#22c55e';
      var h='<div style="display:grid;grid-template-columns:auto 1fr;gap:20px;align-items:start;">';
      h+='<div style="background:#0f1117;border:2px solid '+rc+';border-radius:12px;padding:24px 20px;text-align:center;min-width:130px;">';
      h+='<div style="color:'+sc+';font-size:48px;font-weight:700;line-height:1;">'+score+'</div>';
      h+='<div style="color:#64748b;font-size:9px;letter-spacing:1px;margin-top:4px;">POSTURE SCORE</div>';
      h+='<div style="color:'+rc+';font-size:12px;font-weight:700;margin-top:6px;padding:2px 8px;background:'+rc+'22;border-radius:4px;">'+rl+'</div></div>';
      h+='<div>';
      if(d.findings&&d.findings.length){
        h+='<div style="color:#64748b;font-size:10px;letter-spacing:1px;margin-bottom:8px;">FINDINGS</div>';
        d.findings.forEach(function(f){h+='<div style="display:flex;align-items:flex-start;gap:8px;margin-bottom:7px;font-size:12px;"><span style="color:#f97316;">!</span><span style="color:#e2e8f0;">'+esc(f)+'</span></div>';});
      } else {
        h+='<div style="color:#22c55e;font-size:12px;">No critical findings detected</div>';
      }
      if(d.shodan&&d.shodan.ports&&d.shodan.ports.length){
        h+='<div style="margin-top:14px;"><div style="color:#64748b;font-size:10px;letter-spacing:1px;margin-bottom:6px;">SHODAN EXPOSURE</div>';
        h+='<div style="font-size:12px;color:#94a3b8;">'+esc(d.shodan.org||'')+'</div>';
        h+='<div style="font-size:12px;color:#f5c518;margin-top:3px;">Ports: '+d.shodan.ports.slice(0,10).join(', ')+'</div>';
        if(d.shodan.vulns&&d.shodan.vulns.length) h+='<div style="font-size:12px;color:#ff3b5c;margin-top:3px;">'+d.shodan.vulns.length+' CVE(s): '+d.shodan.vulns.slice(0,4).join(', ')+'</div>';
        h+='</div>';
      }
      if(d.hibp&&d.hibp.exposed_emails!==undefined){
        h+='<div style="margin-top:14px;"><div style="color:#64748b;font-size:10px;letter-spacing:1px;margin-bottom:6px;">CREDENTIAL EXPOSURE</div>';
        var ec=(d.hibp.exposed_emails||0)>0?'#ff3b5c':'#22c55e';
        h+='<div style="font-size:13px;color:'+ec+';font-weight:700;">'+(d.hibp.exposed_emails||0).toLocaleString()+' emails exposed</div></div>';
      }
      h+='</div></div>';
      el.innerHTML=h;
    }catch(e){el.innerHTML='<div style="color:#ff3b5c;padding:16px;">'+esc(e.message)+'</div>';}
  };

  var posInput=document.getElementById('pos-domain');
  if(posInput) posInput.addEventListener('keydown',function(e){if(e.key==='Enter') window.runPostureScan();});

  // ── CVE INTEL ─────────────────────────────────────────────────────────────
  window.loadVulns = async function(){
    var cEl=document.getElementById('vuln-critical');
    var kEl=document.getElementById('vuln-kev');
    if(cEl) cEl.innerHTML='<div style="color:#64748b;font-size:12px;">Loading...</div>';
    if(kEl) kEl.innerHTML='<div style="color:#64748b;font-size:12px;">Loading...</div>';
    try{
      var r=await fetch(PROAPI+'/vuln/critical',{headers:authH()});
      var d=await r.json();
      if(!r.ok){if(cEl) cEl.innerHTML='<div style="color:#ff3b5c;">'+esc(d.detail||'Auth required')+'</div>';return;}
      var ch='';
      (d.recent_critical_cves||[]).slice(0,8).forEach(function(c){
        ch+='<div style="background:#0f1117;border-left:3px solid #ff3b5c;padding:9px 12px;margin-bottom:7px;border-radius:0 4px 4px 0;">';
        ch+='<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">';
        ch+='<span style="color:#ff3b5c;font-weight:700;font-size:11px;font-family:monospace;">'+esc(c.id)+'</span>';
        ch+='<span style="background:#ff3b5c22;color:#ff3b5c;padding:1px 7px;border-radius:3px;font-size:11px;font-weight:700;">'+c.cvss_score+'</span></div>';
        ch+='<div style="color:#94a3b8;font-size:10px;">'+esc((c.description||'').substring(0,130))+'</div></div>';
      });
      if(cEl) cEl.innerHTML=ch||'<div style="color:#22c55e;font-size:12px;">No critical CVEs in last 14 days</div>';
      var kh='';
      (d.actively_exploited_kev||[]).slice(0,8).forEach(function(k){
        var isR=(k.ransomware_use||'').toLowerCase().includes('known');
        kh+='<div style="background:#0f1117;border-left:3px solid #a855f7;padding:9px 12px;margin-bottom:7px;border-radius:0 4px 4px 0;">';
        kh+='<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">';
        kh+='<span style="color:#a855f7;font-weight:700;font-size:11px;font-family:monospace;">'+esc(k.cve_id)+'</span>';
        if(isR) kh+='<span style="background:#ff3b5c22;color:#ff3b5c;padding:1px 7px;border-radius:3px;font-size:10px;">RANSOMWARE</span>';
        kh+='</div><div style="color:#e2e8f0;font-size:11px;margin-bottom:2px;">'+esc(k.vendor+' '+k.product)+'</div>';
        kh+='<div style="color:#64748b;font-size:10px;">'+esc((k.description||'').substring(0,100))+'</div></div>';
      });
      if(kEl) kEl.innerHTML=kh||'<div style="color:#64748b;font-size:12px;">No KEV data</div>';
    }catch(e){if(cEl) cEl.innerHTML='<div style="color:#ff3b5c;">'+esc(e.message)+'</div>';}
  };

  window.searchVulns = async function(){
    var q=document.getElementById('vuln-search').value.trim();
    if(!q)return;
    var el=document.getElementById('vuln-search-result');
    el.innerHTML='<div style="color:#64748b;font-size:12px;">Searching...</div>';
    try{
      var r=await fetch(PROAPI+'/vuln/search?q='+encodeURIComponent(q)+'&limit=10',{headers:authH()});
      var d=await r.json();
      if(!r.ok){el.innerHTML='<div style="color:#ff3b5c;">'+esc(d.detail||'Error')+'</div>';return;}
      var h='<div style="border-top:1px solid #1e293b;padding-top:14px;margin-top:4px;">';
      h+='<div style="color:#64748b;font-size:10px;letter-spacing:1px;margin-bottom:10px;">'+d.total+' RESULTS FOR "'+esc(q.toUpperCase())+'"</div>';
      (d.cves||[]).forEach(function(c){
        h+='<div style="background:#0f1117;border:1px solid #1e293b;padding:10px 14px;margin-bottom:7px;border-radius:6px;">';
        h+='<div style="color:#a855f7;font-weight:700;font-size:11px;font-family:monospace;margin-bottom:4px;">'+esc(c.id)+'</div>';
        h+='<div style="color:#94a3b8;font-size:11px;">'+esc((c.description||'').substring(0,200))+'</div></div>';
      });
      if(!d.cves||!d.cves.length) h+='<div style="color:#64748b;">No results</div>';
      h+='</div>';
      el.innerHTML=h;
    }catch(e){el.innerHTML='<div style="color:#ff3b5c;">'+esc(e.message)+'</div>';}
  };

  var vulnInput=document.getElementById('vuln-search');
  if(vulnInput) vulnInput.addEventListener('keydown',function(e){if(e.key==='Enter') window.searchVulns();});
  // Wire search button directly (override any onclick)
  var vulnBtn=document.querySelector('#page-vuln button[onclick*="searchVulns"], #page-vuln button[onclick*="loadVulns"][onclick*="search"]');
  if(!vulnBtn){
    // find the purple Search button next to the input
    vulnBtn = vulnInput && vulnInput.nextElementSibling;
  }
  if(vulnBtn) vulnBtn.onclick=function(e){e.stopImmediatePropagation();window.searchVulns&&window.searchVulns();};
  // Also wire investigate and posture buttons directly
  var invBtn=document.querySelector('#page-investigate button');
  if(invBtn) invBtn.onclick=function(e){e.stopImmediatePropagation();window.runInvestigation&&window.runInvestigation();};
  var posBtn=document.querySelector('#page-posture button');
  if(posBtn) posBtn.onclick=function(e){e.stopImmediatePropagation();window.runPostureScan&&window.runPostureScan();};

  // ── NEWS FEED ─────────────────────────────────────────────────────────────
  window.loadNews = async function(category){
    category = category || 'headlines';
    var el=document.getElementById('news-feed');
    if(el) el.innerHTML='<div style="color:#64748b;font-size:12px;text-align:center;padding:30px;">Loading...</div>';
    document.querySelectorAll('.news-tab').forEach(function(b){
      var active=b.dataset.cat===category;
      b.style.background=active?'#0ea5e9':'#1e293b';
      b.style.color=active?'#fff':'#64748b';
    });
    try{
      var r=await fetch(PROAPI+'/news/'+category,{headers:authH()});
      var d=await r.json();
      if(d.status==='key_not_configured'){
        if(el) el.innerHTML='<div style="color:#f97316;padding:16px;">NEWS_API_KEY not configured in Railway</div>';return;
      }
      if(!r.ok){if(el) el.innerHTML='<div style="color:#ff3b5c;padding:16px;">'+esc(d.detail||'Error')+'</div>';return;}
      var articles=d.articles||[];
      if(!articles.length){if(el) el.innerHTML='<div style="color:#64748b;padding:16px;">No articles found</div>';return;}
      var h='';
      articles.forEach(function(a){
        var pub=a.published?new Date(a.published).toLocaleDateString('en-GB',{day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'}):'';;
        h+='<a href="'+esc(a.url)+'" target="_blank" rel="noopener" style="display:block;border-bottom:1px solid #1e293b;padding:12px 0;text-decoration:none;">';
        h+='<div style="color:#e2e8f0;font-size:13px;font-weight:600;line-height:1.4;margin-bottom:5px;">'+esc(a.title||'')+'</div>';
        h+='<div style="display:flex;align-items:center;gap:10px;">';
        h+='<span style="color:#0ea5e9;font-size:10px;font-weight:700;background:#0ea5e922;padding:1px 8px;border-radius:3px;">'+esc(a.source||'')+'</span>';
        h+='<span style="color:#475569;font-size:10px;">'+esc(pub)+'</span></div>';
        if(a.description) h+='<div style="color:#64748b;font-size:11px;margin-top:4px;line-height:1.4;">'+esc((a.description||'').substring(0,130))+'</div>';
        h+='</a>';
      });
      if(el) el.innerHTML=h;
    }catch(e){if(el) el.innerHTML='<div style="color:#ff3b5c;padding:16px;">'+esc(e.message)+'</div>';}
  };

  window.searchNews = async function(){
    var q=document.getElementById('news-search-input').value.trim();
    if(!q)return;
    var el=document.getElementById('news-search-result');
    el.innerHTML='<div style="color:#64748b;font-size:12px;">Searching...</div>';
    try{
      var r=await fetch(PROAPI+'/news/search?q='+encodeURIComponent(q)+'&limit=10',{headers:authH()});
      var d=await r.json();
      if(!r.ok){el.innerHTML='<div style="color:#ff3b5c;">'+esc(d.detail||'Error')+'</div>';return;}
      var h='<div style="border-top:1px solid #1e293b;padding-top:12px;"><div style="color:#64748b;font-size:10px;margin-bottom:8px;">'+d.total+' results for "'+esc(q)+'"</div>';
      (d.articles||[]).forEach(function(a){
        h+='<a href="'+esc(a.url)+'" target="_blank" style="display:block;background:#0f1117;border:1px solid #1e293b;border-radius:5px;padding:9px 12px;margin-bottom:7px;text-decoration:none;">';
        h+='<div style="color:#e2e8f0;font-size:12px;font-weight:600;margin-bottom:3px;">'+esc(a.title||'')+'</div>';
        h+='<div style="color:#0ea5e9;font-size:10px;">'+esc(a.source||'')+'</div></a>';
      });
      h+='</div>';
      el.innerHTML=h;
    }catch(e){el.innerHTML='<div style="color:#ff3b5c;">'+esc(e.message)+'</div>';}
  };

  // ── NAV WIRING ────────────────────────────────────────────────────────────
  // Use document-level capture to intercept ALL nav clicks reliably
  document.addEventListener('click', function(e){
    var btn = e.target.closest('[data-page]');
    if(!btn) return;
    // Only fire for nav buttons — ignore data-page elements inside .page content areas
    if(btn.closest('.page')) return;
    var name = btn.dataset.page;
    var newPages = ['darkweb','investigate','posture','vuln','news'];
    if(newPages.indexOf(name) === -1) return;
    e.stopImmediatePropagation();
    e.preventDefault();
    // Switch page
    document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active');});
    document.querySelectorAll('.nvb,[data-page]').forEach(function(b){b.classList.remove('active');});
    var pg = document.getElementById('page-'+name);
    if(pg) pg.classList.add('active');
    btn.classList.add('active');
    // Load data
    var tok = localStorage.getItem('dw_access_token');
    function go(){
      if(name==='darkweb')    window.loadDarkWeb();
      if(name==='vuln')       window.loadVulns();
      if(name==='news'){      window.loadNews(); }
      if(name==='investigate'){
        var inp=document.getElementById('inv-input');
        if(inp && !inp.value){ inp.value='45.33.32.156'; }
        window.runInvestigation();
      }
      if(name==='posture'){
        var pd=document.getElementById('pos-domain');
        if(pd && !pd.value){ pd.value='github.com'; }
        window.runPostureScan();
      }
    }
    tok ? go() : (window.dwShowLoginModal && window.dwShowLoginModal(go));
  }, true);

  // News tab buttons
  document.addEventListener('click', function(e){
    var tb = e.target.closest('.news-tab');
    if(tb) window.loadNews(tb.dataset.cat);
  });

})();
