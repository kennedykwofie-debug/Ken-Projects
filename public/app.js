(function() {
'use strict';
var API='/api/v1';
var RC={na:'#4d9eff',eu:'#a78bfa',apac:'#00d4aa',mena:'#f5c518',latam:'#ff8c42'};
var RN={na:'N.Am',eu:'Europe',apac:'Asia',mena:'MENA',latam:'LatAm'};
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function cvCls(v){return !v?'medium':v>=9?'critical':v>=7?'high':'medium';}
function g(id){return document.getElementById(id);}
function rel(iso){if(!iso)return'never';var diff=Date.now()-new Date(iso).getTime();var mm=Math.floor(diff/60000),hh=Math.floor(diff/3600000),dd=Math.floor(diff/86400000);return mm<60?mm+'m ago':hh<24?hh+'h ago':dd+'d ago';}
function showPage(name){document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active');});document.querySelectorAll('.nvb').forEach(function(b){b.classList.remove('active');});var pg=g('page-'+name);if(pg)pg.classList.add('active');document.querySelectorAll('[data-page="'+name+'"]').forEach(function(b){b.classList.add('active');});if(name==='assets')loadAssets();if(name==='creds')loadCreds();if(name==='alerts')loadAlerts();}
document.querySelectorAll('.nvb').forEach(function(btn){btn.addEventListener('click',function(){showPage(btn.dataset.page);});});
function sw(tid,el){document.querySelectorAll('.tc').forEach(function(t){t.classList.remove('on');});document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('on');});g(tid).classList.add('on');el.classList.add('on');}
document.querySelectorAll('.tab').forEach(function(btn){btn.addEventListener('click',function(){sw(btn.dataset.tab,btn);});});
function uc(){var n=new Date(),pd=function(x){return String(x).padStart(2,'0');};g('ck').textContent=pd(n.getUTCHours())+':'+pd(n.getUTCMinutes())+':'+pd(n.getUTCSeconds())+' UTC';}
setInterval(uc,1000);uc();
function go(){
var fi=g('fi').value,fr=g('fr').value,fs=g('fs').value;
var qs='?industry='+fi+'&region='+fr+'&severity='+fs+'&limit=50';
fetch(API+'/threats'+qs).then(function(r){return r.json();}).then(function(d){if(!d.success)return;var ev=d.data.events||[];var crit=ev.filter(function(t){return t.severity==='critical';}).length;g('fb').textContent=crit+' CRITICAL';g('c0').textContent=ev.length;var th='';for(var ti=0;ti<ev.length;ti++){var te=ev[ti],tsev=esc(te.severity||'low');th+='<div class="fi"><div class="svb '+tsev+'"></div><div style="flex:1;min-width:0"><div class="fm"><span class="bx '+tsev+'">'+tsev.toUpperCase()+'</span><span style="background:#161b22;padding:1px 5px;border-radius:3px">'+esc(te.source)+'</span></div><div class="ftl">'+esc(te.title)+'</div><div class="fd">'+esc((te.description||'').substring(0,100))+'</div></div></div>';}g('fa').innerHTML=th||'<div class="lt">No threats</div>';var rcnt={};for(var ri=0;ri<ev.length;ri++){var rg=ev[ri].region||[];for(var rj=0;rj<rg.length;rj++){rcnt[rg[rj]]=(rcnt[rg[rj]]||0)+1;}}var rsr=Object.entries(rcnt).sort(function(a,b){return b[1]-a[1];}).slice(0,5);var rmx=rsr.length?rsr[0][1]:1;var rbh='';for(var ri2=0;ri2<rsr.length;ri2++){var rk=rsr[ri2][0],rv=rsr[ri2][1];rbh+='<div class="br"><span class="bl">'+esc(RN[rk]||rk)+'</span><div class="bt"><div class="bf" style="width:'+Math.round(rv/rmx*100)+'%;background:'+(RC[rk]||'#4d9eff')+'}"></div></div><span class="bc">'+rv+'</span></div>';}g('rb').innerHTML=rbh||'<div class="lt">No data</div>';var icnt={};for(var ii=0;ii<ev.length;ii++){var ig=ev[ii].industry||[];for(var ij=0;ij<ig.length;ij++){icnt[ig[ij]]=(icnt[ig[ij]]||0)+1;}}var isr=Object.entries(icnt).sort(function(a,b){return b[1]-a[1];}).slice(0,7);var imx=isr.length?isr[0][1]:1;var ibh='';for(var ii2=0;ii2<isr.length;ii2++){var ik=isr[ii2][0],iv=isr[ii2][1];ibh+='<div class="br"><span class="bl" style="text-transform:capitalize">'+esc(ik)+'</span><div class="bt"><div class="bf" style="width:'+Math.round(iv/imx*100)+'%;background:linear-gradient(90deg,#4d9eff,#a78bfa)"></div></div><span class="bc">'+Math.round(iv/(ev.length||1)*100)+'%</span></div>';}g('ib2').innerHTML=ibh||'<div class="lt">No data</div>';}).catch(function(){});
fetch(API+'/stats').then(function(r){return r.json();}).then(function(d){if(!d.success)return;var sd=d.data;g('s0').textContent=sd.criticalThreats||'-';g('s1').textContent=(sd.activeIoCs||0).toLocaleString();g('s2').textContent=sd.threatActors||'-';g('s3').textContent=sd.zeroDayCVEs||'-';g('s4').textContent=sd.phishingKits||'-';}).catch(function(){});
fetch(API+'/health').then(function(r){return r.json();}).then(function(d){if(!d.feeds)return;var hfc={configured:'#00d4aa',active:'#00d4aa',public:'#4d9eff','no-key':'#f5c518'};var hh='<h3 style="font-size:10px;color:#64748b;text-transform:uppercase;margin-bottom:8px">Health</h3>';Object.entries(d.feeds).forEach(function(fe){hh+='<div style="display:flex;justify-content:space-between;padding:3px 0;font-size:11px"><span>'+fe[0]+'</span><span style="color:'+(hfc[fe[1]]||'#64748b')+'">'+fe[1]+'</span></div>';});g('fh').innerHTML=hh;}).catch(function(){});
fetch(API+'/iocs?limit=100').then(function(r){return r.json();}).then(function(d){if(!d.success)return;var ic=d.data||[];g('c1').textContent=ic.filter(function(x){return x.source==='OTX';}).length;g('c2').textContent=ic.filter(function(x){return x.source==='URLhaus';}).length;g('c3').textContent=ic.filter(function(x){return x.source==='MalwareBazaar';}).length;g('c4').textContent=ic.filter(function(x){return x.source==='ThreatFox';}).length;g('c5').textContent=ic.filter(function(x){return x.source==='Feodo Tracker';}).length;var kc=function(c){return c>=90?'#00d4aa':c>=75?'#f5c518':'#ff3b5c';};var ih='';for(var ici=0;ici<ic.length;ici++){var icv=ic[ici];ih+='<tr><td><span style="background:#2e2300;color:#f5c518;border:1px solid #f5c518;padding:1px 4px;border-radius:3px;font-size:9px">'+esc(icv.type||'-')+'</span></td><td style="color:#f5c518;word-break:break-all">'+esc((icv.value||'').substring(0,48))+'</td><td style="color:'+kc(icv.confidence||0)+'">'+(icv.confidence||'?')+'%</td><td style="color:#64748b">'+esc(icv.first||'-')+'</td><td style="color:#64748b">'+esc(icv.source||'-')+'</td></tr>';}g('ib').innerHTML=ih||'<tr><td colspan="5" class="lt">No IoCs</td></tr>';}).catch(function(){});
fetch(API+'/actors?limit=40').then(function(r){return r.json();}).then(function(d){if(!d.success)return;var ac=d.data||[];g('c7').textContent=ac.length;var ah='';for(var aci=0;aci<ac.length;aci++){var aa=ac[aci];ah+='<div class="ac"><div class="an">'+esc(aa.name||'?')+'</div><div class="asu">'+esc(aa.nation||'?')+' - '+esc(aa.type||'APT')+'</div></div>';}g('ag').innerHTML=ah||'<div class="lt">No actors</div>';}).catch(function(){});
fetch(API+'/cves?limit=20').then(function(r){return r.json();}).then(function(d){if(!d.success)return;var cv=d.data||[];g('c8').textContent=cv.length;var ch='';for(var cvi=0;cvi<cv.length;cvi++){var cc=cv[cvi];ch+='<div class="ci"><div class="cvs '+cvCls(cc.cvss)+'">'+(cc.cvss||'N/A')+'</div><div><div style="font-family:monospace;font-size:11px"><a href="'+(cc.url||'#')+'" target="_blank" rel="noopener" style="color:#4d9eff;text-decoration:none">'+esc(cc.id)+'</a>'+(cc.exploited?'<span style="color:#ff3b5c;font-size:10px;margin-left:6px">EXPLOITED</span>':'')+'</div><div class="ftl">'+esc((cc.title||'').substring(0,90))+'</div></div></div>';}g('cl').innerHTML=ch||'<div class="lt">No CVEs</div>';}).catch(function(){});
fetch(API+'/phishing?limit=20').then(function(r){return r.json();}).then(function(d){if(!d.success)return;var ph=d.data||[];g('c6').textContent=ph.length;g('s4').textContent=ph.length;var pph='';for(var phi=0;phi<ph.length;phi++){var pp=ph[phi];pph+='<div class="pi"><div style="margin-top:2px;font-size:14px">!</div><div><div class="ftl">'+esc(pp.subject||('Phishing: '+pp.target))+'</div><div style="font-size:10px;color:#ff3b5c">'+esc(pp.target||'-')+'</div><div style="font-size:11px;color:#64748b">'+(pp.domains||1)+' domain(s)</div></div></div>';}g('pl').innerHTML=pph||'<div class="lt">No phishing</div>';}).catch(function(){});
clearTimeout(window._rt);window._rt=setTimeout(function(){fetch(API+'/cache/flush',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).catch(function(){}).then(go);},300000);
}
function rf(){fetch(API+'/cache/flush',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).catch(function(){}).then(go);}
document.addEventListener('click',function(ev){var btn=ev.target.closest('.rm-btn');if(!btn)return;var wt=btn.getAttribute('data-type');var wv=btn.getAttribute('data-val');if(wt&&wv)window._rmW(wt,wv);});
window._rmW=function(wt,wv){fetch(API+'/monitor/watchlist',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:wt,value:wv})}).then(function(){loadAssets();}).catch(function(){});};
function loadAssets(){
fetch(API+'/monitor/status').then(function(r){return r.json();}).then(function(d){if(!d.success)return;var st=d.data;var ipH='';(st.watchedIPs||[]).forEach(function(wip){ipH+='<span class="watched-chip">'+esc(wip)+'<button class="rm-btn" data-type="ip" data-val="'+esc(wip)+'">x</button></span>';});g('watched-ips').innerHTML=ipH||'<div class="lt">No IPs watched</div>';var dmH='';(st.watchedDomains||[]).forEach(function(wdm){dmH+='<span class="watched-chip">'+esc(wdm)+'<button class="rm-btn" data-type="domain" data-val="'+esc(wdm)+'">x</button></span>';});g('watched-domains').innerHTML=dmH||'<div class="lt">No domains watched</div>';if(st.lastScan)g('as-scan').textContent=rel(st.lastScan);}).catch(function(){});
fetch(API+'/monitor/assets').then(function(r){return r.json();}).then(function(d){if(!d.success)return;var assets=d.data||[];var acrit=assets.filter(function(a){return a.riskLevel==='critical';}).length;var ahigh=assets.filter(function(a){return a.riskLevel==='high';}).length;var aports=assets.filter(function(a){return a.port;}).length;g('as-crit').textContent=acrit;g('as-high').textContent=ahigh;g('as-total').textContent=assets.length;g('as-ports').textContent=aports;g('asset-badge').textContent=acrit+' CRITICAL';var at='';for(var asi=0;asi<assets.length;asi++){var aa2=assets[asi];var vs=aa2.vulnCount>0?'<span style="color:#ff3b5c">'+aa2.vulnCount+' CVE(s)</span>':'<span style="color:#00d4aa">Clean</span>';var nt=aa2.note?'<span style="color:#64748b;font-size:10px"> ('+esc(aa2.note)+')</span>':'';at+='<tr><td style="font-family:monospace;color:#4d9eff">'+esc(aa2.ip)+'</td><td style="color:#64748b">'+esc((aa2.hostnames||[])[0]||aa2.org||'-')+'</td><td style="font-family:monospace">'+esc(aa2.port?String(aa2.port):'-')+'</td><td>'+esc(aa2.product||'Unknown')+(aa2.version?' <span style="color:#64748b">'+esc(aa2.version)+'</span>':'')+nt+'</td><td style="color:#64748b">'+esc(aa2.country||'-')+'</td><td>'+vs+'</td><td><span class="risk-badge '+esc(aa2.riskLevel||'low')+'">'+esc((aa2.riskLevel||'low').toUpperCase())+'</span></td></tr>';}g('asset-tbody').innerHTML=at||'<tr><td colspan="7" class="lt">No assets - add a domain or IP then run a scan</td></tr>';}).catch(function(){});
}
g('add-asset-btn').addEventListener('click',function(){
var aiv=g('add-ip').value.trim(),adv=g('add-domain').value.trim();
if(!aiv&&!adv){alert('Enter an IP address or domain name');return;}
var abn=g('add-asset-btn');abn.textContent=adv?'Resolving DNS...':'Adding...';
var ab={};if(aiv)ab.ip=aiv;if(adv)ab.domain=adv;
fetch(API+'/monitor/watchlist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(ab)})
.then(function(r){return r.json();})
.then(function(resp){
g('add-ip').value='';g('add-domain').value='';abn.textContent='+ Add to Watchlist';
if(adv&&resp.resolvedIPs&&resp.resolvedIPs.length>0){
var dn=g('dns-note');
if(!dn){dn=document.createElement('div');dn.id='dns-note';dn.style.cssText='font-size:11px;color:#00d4aa;padding:6px 16px;background:#002e26;border-top:1px solid #1e2630;font-family:monospace';
var pgAssets=g('page-assets');if(pgAssets)pgAssets.insertBefore(dn,pgAssets.firstChild);}
dn.textContent='DNS: '+adv+' resolved to '+resp.resolvedIPs.join(', ')+' - IPs added. Click Run Scan Now.';
setTimeout(function(){if(dn&&dn.parentNode)dn.parentNode.removeChild(dn);},10000);}
loadAssets();
}).catch(function(){abn.textContent='+ Add to Watchlist';});
});
g('scan-btn').addEventListener('click',function(){var sb=g('scan-btn');sb.textContent='Scanning...';g('asset-badge').textContent='SCANNING';fetch(API+'/monitor/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(function(){setTimeout(function(){sb.textContent='Run Scan Now';loadAssets();loadAlerts();},15000);}).catch(function(){sb.textContent='Run Scan Now';});});


});


// \u2500\u2500 Domain Verification Wizard (dv- prefix) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
(function() {
  var dvDomain = '', dvToken = '';
  var header = document.getElementById('dv-header');
  if (header) {
    header.addEventListener('click', function() {
      var body = document.getElementById('dv-body');
      if (!body) return;
      var open = body.style.display !== 'none';
      body.style.display = open ? 'none' : 'block';
      header.querySelector('div:last-child').textContent = open ? 'Click to expand' : 'Click to collapse';
    });
  }
  function dvShow(step) {
    ['dv-s1','dv-s2','dv-s3'].forEach(function(id) {
      var el = document.getElementById(id);
      if (el) el.style.display = id === step ? 'block' : 'none';
    });
  }
  var btn1 = document.getElementById('dv-btn1');
  if (btn1) {
    btn1.addEventListener('click', function() {
      var inp = document.getElementById('dv-input');
      if (!inp) return;
      dvDomain = inp.value.trim();
      if (!dvDomain || dvDomain.indexOf('.') < 0) { alert('Enter a valid domain (e.g. yourcompany.com)'); return; }
      btn1.textContent = 'Requesting...'; btn1.disabled = true;
      fetch('/api/v1/credentials/domain/verify/request/' + encodeURIComponent(dvDomain))
        .then(function(r) { return r.json(); })
        .then(function(d) {
          btn1.textContent = 'Get DNS Verification Token'; btn1.disabled = false;
          if (!d.success) {
            alert('Could not get token. Make sure you first add your domain at haveibeenpwned.com/DomainSearch, then try again.  Details: ' + (d.error || 'Unknown error'));
            return;
          }
          dvToken = d.token;
          document.getElementById('dv-domname').textContent = dvDomain;
          document.getElementById('dv-token').textContent = 'have-i-been-pwned-verification=' + dvToken;
          document.getElementById('dv-body').style.display = 'block';
          dvShow('dv-s2');
        })
        .catch(function(e) { btn1.textContent = 'Get DNS Verification Token'; btn1.disabled = false; alert('Request failed: ' + e.message); });
    });
  }
  var back = document.getElementById('dv-back');
  if (back) { back.addEventListener('click', function() { dvShow('dv-s1'); }); }
  var btn2 = document.getElementById('dv-btn2');
  if (btn2) {
    btn2.addEventListener('click', function() {
      var statusEl = document.getElementById('dv-status');
      btn2.textContent = 'Checking...'; btn2.disabled = true;
      statusEl.textContent = 'Checking HIBP for your DNS TXT record...';
      statusEl.style.color = '#64748b';
      fetch('/api/v1/credentials/domain/verify/check/' + encodeURIComponent(dvDomain))
        .then(function(r) { return r.json(); })
        .then(function(d) {
          btn2.textContent = 'Check Verification Status'; btn2.disabled = false;
          if (d.success && d.data && d.data.verified) {
            document.getElementById('dv-verified-name').textContent = dvDomain;
            dvShow('dv-s3');
            statusEl.textContent = '';
          } else {
            var reason = (d.data && d.data.reason) || 'TXT record not yet detected.';
            statusEl.textContent = reason + ' DNS propagation can take up to 24h -- try again later.';
            statusEl.style.color = '#f5c518';
          }
        })
        .catch(function(e) { btn2.textContent = 'Check Verification Status'; btn2.disabled = false; statusEl.textContent = 'Check failed: ' + e.message; statusEl.style.color = '#ff3b5c'; });
    });
  }
  var btn3 = document.getElementById('dv-btn3');
  if (btn3) {
    btn3.addEventListener('click', function() {
      var resultEl = document.getElementById('dv-scan-result');
      btn3.textContent = 'Scanning all emails...'; btn3.disabled = true;
      resultEl.textContent = 'Querying HIBP for all breached accounts on ' + dvDomain + '...';
      resultEl.style.color = '#64748b';
      fetch('/api/v1/credentials/domain/scan/' + encodeURIComponent(dvDomain))
        .then(function(r) { return r.json(); })
        .then(function(d) {
          btn3.textContent = 'Scan All Emails on Domain Now'; btn3.disabled = false;
          if (d.success && d.data && d.data.verified) {
            var count = d.data.totalBreached || 0;
            resultEl.textContent = 'Found ' + count + ' breached email account(s) on ' + dvDomain + '. Refreshing display...';
            resultEl.style.color = '#00d4aa';
            setTimeout(function() { loadCreds(); }, 1500);
          } else {
            resultEl.textContent = 'Domain not yet verified by HIBP. Add the DNS TXT record and try again.';
            resultEl.style.color = '#f5c518';
          }
        })
        .catch(function(e) { btn3.textContent = 'Scan All Emails on Domain Now'; btn3.disabled = false; resultEl.textContent = 'Scan failed: ' + e.message; resultEl.style.color = '#ff3b5c'; });
    });
  }
})();

function loadCreds(){
fetch(API+'/credentials/status').then(function(r){return r.json();}).then(function(d){if(!d.success)return;var er=d.data||[],me=d.emails||[],sm=d.summary||{};g('cr-domains').textContent=me.length||'-';g('cr-accounts').textContent=(sm.exposedEmails||0).toLocaleString();g('cr-breaches').textContent=(sm.uniqueBreaches||[]).length||0;g('cr-critical').textContent=sm.criticalEmails||0;if(er.length&&er[0].lastChecked)g('cr-last').textContent=rel(er[0].lastChecked);var sh='';if(!er.length){sh='<div style="padding:20px;color:#64748b;font-size:12px;line-height:1.6">Enter any email above to check against 700+ known breaches.<br><span style="color:#4d9eff">Powered by HaveIBeenPwned</span></div>';}else{er.forEach(function(em){var erc=em.riskLevel==='clean'?'low':em.riskLevel||'low';var ecol=erc==='critical'?'#ff3b5c':erc==='high'?'#ff8c42':erc==='medium'?'#f5c518':'#00d4aa';sh+='<div style="padding:12px 0;border-bottom:1px solid #1e2630;display:flex;justify-content:space-between;align-items:flex-start"><div style="flex:1;min-width:0"><div style="font-family:monospace;font-size:12px;font-weight:700;color:'+ecol+';margin-bottom:5px">'+esc(em.email)+'</div>';if(em.breachCount>0){sh+='<div style="font-size:11px;color:#64748b;margin-bottom:4px">Found in: ';(em.breachNames||[]).slice(0,6).forEach(function(bn){sh+='<span class="tag">'+esc(bn)+'</span>';});if((em.breachNames||[]).length>6)sh+='<span class="tag">+'+(em.breachNames.length-6)+' more</span>';sh+='</div>';}else{sh+='<div style="font-size:11px;color:#00d4aa">No breaches - clean!</div>';}sh+='</div><div style="text-align:right;flex-shrink:0;margin-left:16px"><span class="risk-badge '+erc+'">'+(em.breachCount||0)+' breach'+(em.breachCount!==1?'es':'')+'</span><br><button class="rm-btn" data-type="email" data-val="'+esc(em.email)+'" style="margin-top:6px;padding:2px 8px;font-size:10px">Remove</button></div></div>';});}g('cred-summary').innerHTML=sh;var emH='';er.filter(function(e2){return e2.breachCount>0;}).forEach(function(em3){(em3.breaches||[]).forEach(function(br){var erc2=em3.riskLevel==='clean'?'low':em3.riskLevel||'low';var ec2=erc2==='critical'?'#ff3b5c':erc2==='high'?'#ff8c42':'#f5c518';emH+='<tr><td style="font-family:monospace;color:'+ec2+'">'+esc(em3.email)+'</td><td style="text-align:center;font-family:monospace;color:#64748b">'+em3.breachCount+'</td><td><span style="font-weight:700;color:#e2e8f0">'+esc(br.name||'-')+'</span> <span style="color:#64748b;font-size:10px">'+esc(br.breachDate||'-')+'</span><br><span style="font-size:10px;color:#64748b">'+(br.dataClasses||[]).slice(0,3).join(', ')+'</span></td><td><span class="risk-badge '+erc2+'">'+erc2.toUpperCase()+'</span></td></tr>';});});g('exposed-emails').innerHTML=emH||'<tr><td colspan="4" class="lt">No breaches found</td></tr>';}).catch(function(){});
fetch(API+'/credentials/breaches').then(function(r){return r.json();}).then(function(d){if(!d.success)return;var brs=d.data||[],gbh='';for(var gbi=0;gbi<brs.length;gbi++){var gbr=brs[gbi];gbh+='<div class="breach-item"><div class="breach-name">'+esc(gbr.name)+'</div><div class="breach-meta">'+esc(gbr.domain||'-')+' &bull; '+esc(gbr.breachDate||'-')+' &bull; <span style="color:#ff8c42">'+(gbr.pwnCount||0).toLocaleString()+' accounts</span></div><div style="margin-top:4px">'+(gbr.dataClasses||[]).map(function(dc){return'<span class="tag">'+esc(dc)+'</span>';}).join('')+'</div></div>';}g('global-breaches').innerHTML=gbh||'<div class="lt">No breach data</div>';}).catch(function(){});
}
g('add-cred-btn').addEventListener('click',function(){var cev=g('add-cred-email').value.trim();if(!cev||cev.indexOf('@')<0){alert('Enter a valid email');return;}var cb=g('add-cred-btn');cb.textContent='Checking...';fetch(API+'/monitor/watchlist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:cev})}).then(function(){return fetch(API+'/credentials/email/'+encodeURIComponent(cev));}).then(function(r){return r.json();}).then(function(){g('add-cred-email').value='';cb.textContent='+ Monitor Email';loadCreds();}).catch(function(){cb.textContent='+ Monitor Email';});});
g('check-btn').addEventListener('click',function(){var cb2=g('check-btn');cb2.textContent='Checking...';fetch(API+'/monitor/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(function(){setTimeout(function(){cb2.textContent='Check All Now';loadCreds();},8000);}).catch(function(){cb2.textContent='Check All Now';});});
function loadAlerts(){fetch(API+'/monitor/alerts').then(function(r){return r.json();}).then(function(d){if(!d.success)return;var alts=d.data||[];var acnt=alts.length,adot=g('alert-count');if(acnt>0){adot.textContent=acnt;adot.style.display='inline-block';}else{adot.style.display='none';}g('alerts-badge').textContent=acnt+' ALERTS';if(!alts.length){g('alerts-list').innerHTML='<div class="lt">No alerts yet. Monitoring runs every 6h.</div>';return;}var ai={new_port:'[PORT]',new_vuln:'[CVE]',credential_leak:'[CRED]',critical_asset:'[ASSET]'};var ac2={critical:'#ff3b5c',high:'#ff8c42',medium:'#f5c518',low:'#00d4aa'};var alh='';for(var ali=0;ali<alts.length;ali++){var alt=alts[ali],asc=ac2[alt.severity]||'#64748b';alh+='<div class="alert-item"><div style="font-family:monospace;font-size:11px;color:'+asc+';flex-shrink:0;padding-top:2px">'+(ai[alt.type]||'[!]')+'</div><div style="flex:1"><div class="alert-msg">'+esc(alt.message)+'</div><div class="alert-time"><span style="color:'+asc+'">'+esc((alt.severity||'').toUpperCase())+'</span> &bull; '+esc(rel(alt.timestamp))+'</div></div></div>';}g('alerts-list').innerHTML=alh;}).catch(function(){});}
g('clear-alerts-btn').addEventListener('click',loadAlerts);
g('fi').addEventListener('change',go);g('fr').addEventListener('change',go);g('fs').addEventListener('change',go);g('rfbtn').addEventListener('click',rf);
setInterval(function(){var ap=document.querySelector('.page.active');if(!ap)return;if(ap.id==='page-assets')loadAssets();if(ap.id==='page-creds')loadCreds();if(ap.id==='page-alerts')loadAlerts();},30000);
go();

// Domain Verification
var _vd="";
if(g("get-token-btn")){
g("get-token-btn").addEventListener("click",function(){
var dom=g("verify-domain-input").value.trim();
if(!dom||dom.indexOf(".")<0){alert("Enter a valid domain e.g. doh.gov.ph");return;}
_vd=dom;var vb=g("get-token-btn");vb.textContent="Fetching...";
fetch(API+"/credentials/token/"+encodeURIComponent(dom)).then(function(r){return r.json();}).then(function(d){
vb.textContent="Get Verification Token";
if(!d.success)return;
g("token-display").textContent=d.token;
g("verify-panel").style.display="block";
g("verified-success").style.display="none";
g("verify-status").textContent="";
}).catch(function(){vb.textContent="Get Verification Token";});
});
g("copy-token-btn").addEventListener("click",function(){
var tok=g("token-display").textContent;if(!tok)return;
var cb=g("copy-token-btn");
navigator.clipboard.writeText(tok).then(function(){cb.textContent="Copied!";setTimeout(function(){cb.textContent="Copy";},2000);}).catch(function(){var ta=document.createElement("textarea");ta.value=tok;document.body.appendChild(ta);ta.select();document.execCommand("copy");document.body.removeChild(ta);cb.textContent="Copied!";setTimeout(function(){cb.textContent="Copy";},2000);});
});
g("check-verify-btn").addEventListener("click",function(){
var d2=_vd||g("verify-domain-input").value.trim();
if(!d2){alert("Enter your domain first");return;}
var cvb=g("check-verify-btn"),vs=g("verify-status");
cvb.textContent="Checking DNS...";vs.textContent="Querying...";vs.style.color="#64748b";
fetch(API+"/credentials/verify/"+encodeURIComponent(d2)).then(function(r){return r.json();}).then(function(d){
cvb.textContent="Check Verification Status";
if(!d.success){vs.textContent="Error: "+(d.error||"?");vs.style.color="#ff3b5c";return;}
var vr=d.data;
if(vr.verified){
vs.textContent="Verified!";vs.style.color="#00d4aa";
g("verified-success").style.display="block";
fetch(API+"/monitor/watchlist",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domain:d2})}).catch(function(){});
}else{
vs.style.color="#ff8c42";
vs.textContent="Not verified yet. Found TXT: "+(vr.answers&&vr.answers.length?vr.answers.join(" | ").substring(0,80):"none")+". DNS can take up to 48h.";
}
}).catch(function(){cvb.textContent="Check Verification Status";vs.textContent="Check failed";vs.style.color="#ff3b5c";});
});
g("bulk-scan-btn").addEventListener("click",function(){
var bd=_vd||g("verify-domain-input").value.trim();if(!bd)return;
var bb=g("bulk-scan-btn");bb.textContent="Scanning all emails...";
fetch(API+"/credentials/domain/"+encodeURIComponent(bd)).then(function(r){return r.json();}).then(function(d){
bb.textContent="Scan All Breached Emails Now";
if(!d.success){alert("Scan failed: "+(d.error||"?"));return;}
var br=d.data;
if(br.needsVerification){alert("HIBP rejected - verify DNS first.");return;}
var be=br.emails||[];
var bh="<div style=\"padding:10px 0;border-bottom:1px solid #2a3440;margin-bottom:8px\"><div style=\"color:#00d4aa;font-weight:700\">"+be.length+" exposed accounts found on "+esc(bd)+"</div><div style=\"color:#64748b;font-size:11px\">Source: HaveIBeenPwned bulk domain scan</div></div>";
be.forEach(function(em){var erc=em.riskLevel==="clean"?"low":em.riskLevel||"low";var ec=erc==="critical"?"#ff3b5c":erc==="high"?"#ff8c42":"#f5c518";bh+="<div style=\"padding:8px 0;border-bottom:1px solid #1e2630;display:flex;justify-content:space-between;align-items:center\"><div><div style=\"font-family:monospace;font-size:12px;color:"+ec+"\">"+esc(em.email)+"</div><div style=\"font-size:11px;color:#64748b;margin-top:3px\">";(em.breachNames||[]).slice(0,5).forEach(function(bn){bh+="<span class=\"tag\">"+esc(bn)+"</span>";});bh+="</div></div><span class=\"risk-badge "+erc+"\">"+em.breachCount+" breach"+(em.breachCount!==1?"es":"")+"</span></div>";});
if(!be.length)bh+="<div style=\"color:#00d4aa;padding:12px\">No breached accounts found.</div>";
g("cred-summary").innerHTML=bh;
g("cr-accounts").textContent=be.length;
g("cr-domains").textContent="1 verified domain";
g("cr-critical").textContent=be.filter(function(e){return e.riskLevel==="critical";}).length;
}).catch(function(){bb.textContent="Scan All Breached Emails Now";});
});
}
})();