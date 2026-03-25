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

  // ÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ DARK WEB ÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ
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

  // ÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ INVESTIGATION ÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ
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

  // ÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ POSTURE ÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ
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

  // ÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ CVE INTEL ÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ
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

  // ÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ NEWS FEED ÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ
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

  // ÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ NAV WIRING ÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ¢ÃÂÃÂÃÂÃÂÃÂÃÂÃÂÃÂ
  // Use document-level capture to intercept ALL nav clicks reliably
  document.addEventListener('click', function(e){
    var btn = e.target.closest('[data-page]');
    if(!btn) return;
    if(btn.closest('.page')) return;
    var name = btn.dataset.page;
    var newPages = ['darkweb','investigate','posture','vuln','news'];
    if(newPages.indexOf(name) === -1) return;
    e.stopImmediatePropagation();
    e.preventDefault();
    document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active');});
    document.querySelectorAll('.nvb,[data-page]').forEach(function(b){b.classList.remove('active');});
    var pg = document.getElementById('page-'+name);
    if(pg) pg.classList.add('active');
    btn.classList.add('active');
    var tok = localStorage.getItem('dw_access_token');
    function go(){
      if(name==='darkweb') window.loadDarkWeb && window.loadDarkWeb();
      if(name==='vuln')    window.loadVulns && window.loadVulns();
      if(name==='news')    window.loadNews && window.loadNews();
      if(name==='investigate') window.runInvestigation && window.runInvestigation();
      if(name==='posture') window.runPostureScan && window.runPostureScan();
    }
    tok ? go() : (window.dwShowLoginModal && window.dwShowLoginModal(go));
  }, true);

  // Handle Pro Intel sidebar section clicks for new modules
  document.addEventListener('click', function(e){
    var btn = e.target.closest('.pi-nav-btn[data-section]');
    if(!btn) return;
    var section = btn.dataset.section;
    var tok = localStorage.getItem('dw_access_token');
    function go(){
      if(section==='darkweb')     window.loadDarkWeb && window.loadDarkWeb();
      if(section==='cve')         window.loadVulns && window.loadVulns();
      if(section==='news')        window.loadNews && window.loadNews('headlines');
      if(section==='investigate') { /* user types and clicks */ }
      if(section==='posture')     { /* user types and clicks */ }
    }
    // Small delay to let piNav() render the section first
    setTimeout(function(){
      if(!tok) return;
      go();
      // geo/cyber/econ/ai sections are loaded by loadPro from app.js
      var proSections = ['geo','cyber','econ','ai'];
      if(proSections.indexOf(section) !== -1 && window.loadPro) window.loadPro();
    }, 150);
  });

  // News tab buttons
  document.addEventListener('click', function(e){
    var tb = e.target.closest('.news-tab');
    if(tb) window.loadNews(tb.dataset.cat);
  });


  // ââ IntelX dark web search ââââââââââââââââââââââââââââââââââââââââââââ
  window.searchIntelX = async function(query){
    if(!query) return;
    var resEl = document.getElementById('intelx-results');
    if(resEl) resEl.innerHTML = '<div style="color:#64748b;font-size:12px;padding:12px;">Searching Intelligence X...</div>';
    var data = await fetch(PROAPI+'/darkweb/intelx/search?q='+encodeURIComponent(query)+'&limit=10', {headers:authH()}).then(function(r){return r.json();}).catch(function(){return null;});
    if(!resEl) return;
    if(!data){ resEl.innerHTML='<div style="color:#ff3b5c;font-size:12px;padding:12px;">Search failed â check your IntelX key</div>'; return; }
    var recs = data.results||[];
    if(recs.length===0){ resEl.innerHTML='<div style="color:#64748b;font-size:12px;padding:12px;">No results found in Intelligence X</div>'; return; }
    var h = '<div style="color:#a78bfa;font-size:10px;letter-spacing:1px;font-weight:700;margin-bottom:10px;">'+recs.length+' RESULTS ('+data.count+' total in corpus)</div>';
    recs.forEach(function(r){
      var bc = {'pastes':'#f5c518','leaks':'#ff3b5c','darkweb':'#ff3b5c'}[r.bucket]||'#64748b';
      h += '<div style="background:#0f1117;border:1px solid #1e293b;border-radius:6px;padding:8px 12px;margin-bottom:4px;display:flex;align-items:center;gap:8px;">';
      h += '<span style="color:#e2e8f0;font-size:12px;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">'+(r.name||'').substring(0,70)+'</span>';
      h += '<span style="background:'+bc+'22;color:'+bc+';font-size:9px;padding:2px 6px;border-radius:3px;white-space:nowrap;">'+(r.bucket||'unknown')+'</span>';
      h += '<span style="color:#475569;font-size:10px;white-space:nowrap;">'+(r.date||'').substring(0,10)+'</span>';
      h += '</div>';
    });
    resEl.innerHTML = h;
  };

  // ââ Credentials breach search âââââââââââââââââââââââââââââââââââââââââ
  window.searchCredentials = async function(domain){
    if(!domain){ domain = document.getElementById('cred-domain-input')?.value; }
    if(!domain) return;
    var resEl = document.getElementById('cred-results');
    if(resEl) resEl.innerHTML = '<div style="color:#64748b;font-size:12px;padding:12px;">Searching DeHashed and Leak-Lookup...</div>';
    var data = await fetch(PROAPI+'/credentials/search/'+encodeURIComponent(domain), {headers:authH()}).then(function(r){return r.json();}).catch(function(){return null;});
    if(!resEl) return;
    if(!data){ resEl.innerHTML='<div style="color:#ff3b5c;font-size:12px;padding:12px;">Search failed</div>'; return; }
    var total = data.total_exposed||0;
    if(total===0){
      resEl.innerHTML='<div style="color:#22c55e;padding:14px;font-size:13px;display:flex;align-items:center;gap:8px;"><span style="font-size:18px;">&#10003;</span> No exposed credentials found for <strong>'+esc(domain)+'</strong></div>';
      return;
    }
    var dh = data.dehashed||{entries:[],total:0};
    var ll = data.leaklookup||{breaches:[],total:0};
    var h = '<div style="background:#ff3b5c11;border:1px solid #ff3b5c33;border-radius:8px;padding:14px;margin-bottom:16px;">';
    h += '<div style="color:#ff3b5c;font-weight:700;font-size:16px;">&#9888; '+total+' Exposed Records Found</div>';
    h += '<div style="color:#94a3b8;font-size:12px;margin-top:4px;">Domain: <strong>'+esc(domain)+'</strong></div></div>';
    if(dh.total>0){
      h += '<div style="color:#64748b;font-size:10px;letter-spacing:1px;font-weight:700;margin-bottom:8px;">DEHASHED â '+dh.total+' RECORDS</div>';
      (dh.entries||[]).slice(0,10).forEach(function(e){
        h += '<div style="background:#ff3b5c06;border:1px solid #ff3b5c1a;border-radius:6px;padding:8px 12px;margin-bottom:4px;display:flex;gap:12px;font-size:11px;align-items:center;">';
        h += '<span style="color:#e2e8f0;flex:1;">'+esc(e.email||e.username||'(redacted)')+'</span>';
        h += '<span style="color:#64748b;">'+esc(e.database_name||'')+'</span>';
        if(e.password||e.hashed_password) h += '<span style="color:#f5c518;font-size:13px;" title="Password hash exposed">&#128274;</span>';
        h += '</div>';
      });
      if(dh.total>10) h += '<div style="color:#64748b;font-size:11px;padding:6px 12px;">...and '+(dh.total-10)+' more records</div>';
    }
    if(ll.total>0){
      h += '<div style="color:#64748b;font-size:10px;letter-spacing:1px;font-weight:700;margin:16px 0 8px;">LEAK-LOOKUP â '+ll.total+' BREACH SOURCES</div>';
      (ll.breaches||[]).slice(0,10).forEach(function(b){
        h += '<div style="background:#f5c51806;border:1px solid #f5c5181a;border-radius:4px;padding:6px 12px;margin-bottom:3px;display:flex;justify-content:space-between;font-size:11px;">';
        h += '<span style="color:#e2e8f0;">'+esc(b.source||String(b))+'</span>';
        if(b.count) h += '<span style="color:#f5c518;">'+b.count+' records</span>';
        h += '</div>';
      });
    }
    resEl.innerHTML = h;
  };

  // ââ VulnCheck exploited feed ââââââââââââââââââââââââââââââââââââââââââ
  window.loadVulncheckExploited = async function(){
    var el = document.getElementById('vuln-exploited');
    if(!el) return;
    el.innerHTML = '<div style="color:#64748b;font-size:12px;">Loading active exploitation data...</div>';
    var data = await fetch(PROAPI+'/vuln/exploited?limit=15', {headers:authH()}).then(function(r){return r.json();}).catch(function(){return null;});
    if(!data){ el.innerHTML='<div style="color:#ff3b5c;font-size:12px;">VulnCheck unavailable</div>'; return; }
    var cves = data.cves||[];
    if(cves.length===0){ el.innerHTML='<div style="color:#64748b;font-size:12px;">No active exploitation data</div>'; return; }
    var h = '<div style="color:#ff3b5c;font-size:10px;letter-spacing:1px;font-weight:700;margin-bottom:8px;">'+cves.length+' CVEs ACTIVELY EXPLOITED IN THE WILD</div>';
    cves.forEach(function(c){
      var rang = c.ransomware ? '<span style="background:#ff3b5c22;color:#ff3b5c;font-size:9px;padding:1px 6px;border-radius:3px;margin-left:6px;">RANSOMWARE</span>' : '';
      var epss = c.epss ? '<span style="color:#f5c518;font-size:10px;margin-left:8px;">EPSS '+(parseFloat(c.epss)*100).toFixed(1)+'%</span>' : '';
      h += '<div style="background:#ff3b5c08;border:1px solid #ff3b5c22;border-radius:6px;padding:10px 12px;margin-bottom:6px;">';
      h += '<div style="display:flex;align-items:center;flex-wrap:wrap;gap:4px;margin-bottom:4px;">';
      h += '<span style="color:#ff3b5c;font-weight:700;font-size:12px;font-family:monospace;">'+(c.id||c.name||'Unknown')+'</span>'+rang+epss;
      h += '</div>';
      if(c.description) h += '<div style="color:#94a3b8;font-size:11px;line-height:1.4;">'+(c.description||'').substring(0,150)+'...</div>';
      h += '</div>';
    });
    el.innerHTML = h;
  };

  // Auto-trigger on CVE section click
  document.addEventListener('click', function(e){
    var btn = e.target.closest('.pi-nav-btn[data-section="cve"]');
    if(btn) setTimeout(function(){ window.loadVulncheckExploited&&window.loadVulncheckExploited(); }, 300);
  });


})();
