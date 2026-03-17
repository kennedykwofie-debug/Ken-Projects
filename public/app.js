(function() {
"use strict";
var API = "/api/v1";
var RC = {na:"#4d9eff",eu:"#a78bfa",apac:"#00d4aa",mena:"#f5c518",latam:"#ff8c42"};
var RN = {na:"N.Am",eu:"Europe",apac:"Asia",mena:"MENA",latam:"LatAm"};
function esc(s){return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
function cvCls(v){return !v?"medium":v>=9?"critical":v>=7?"high":"medium";}
function g(id){return document.getElementById(id);}
function rel(iso){if(!iso)return "never";var diff=Date.now()-new Date(iso).getTime();var mm=Math.floor(diff/60000),hh=Math.floor(diff/3600000),dd=Math.floor(diff/86400000);return mm<60?mm+"m ago":hh<24?hh+"h ago":dd+"d ago";}

// Page navigation
function showPage(name){
  document.querySelectorAll(".page").forEach(function(p){p.classList.remove("active");});
  document.querySelectorAll(".nvb").forEach(function(b){b.classList.remove("active");});
  var pg=g("page-"+name); if(pg)pg.classList.add("active");
  document.querySelectorAll("[data-page=\""+name+"\"]").forEach(function(b){b.classList.add("active");});
  if(name==="assets")loadAssets();
  if(name==="creds")loadCreds();
  if(name==="alerts")loadAlerts();
}
document.querySelectorAll(".nvb").forEach(function(btn){btn.addEventListener("click",function(){showPage(btn.dataset.page);});});

// Tab switching
function sw(tid,el){
  document.querySelectorAll(".tc").forEach(function(t){t.classList.remove("on");});
  document.querySelectorAll(".tab").forEach(function(t){t.classList.remove("on");});
  g(tid).classList.add("on"); el.classList.add("on");
}
document.querySelectorAll(".tab").forEach(function(btn){btn.addEventListener("click",function(){sw(btn.dataset.tab,btn);});});

// Clock
function uc(){var n=new Date(),pd=function(x){return String(x).padStart(2,"0");};g("ck").textContent=pd(n.getUTCHours())+":"+pd(n.getUTCMinutes())+":"+pd(n.getUTCSeconds())+" UTC";}
setInterval(uc,1000); uc();

// Intel Feed
function go(){
  var fi=g("fi").value,fr=g("fr").value,fs=g("fs").value;
  var qs="?industry="+fi+"&region="+fr+"&severity="+fs+"&limit=50";
  fetch(API+"/threats"+qs).then(function(r){return r.json();}).then(function(d){
    if(!d.success)return; var ev=d.data.events||[];
    var crit=ev.filter(function(t){return t.severity==="critical";}).length;
    g("fb").textContent=crit+" CRITICAL"; g("c0").textContent=ev.length;
    var th="";
    for(var ti=0;ti<ev.length;ti++){var te=ev[ti],tsev=esc(te.severity||"low");
      th+="<div class=\"fi\"><div class=\"svb "+tsev+"\"></div><div style=\"flex:1;min-width:0\"><div class=\"fm\"><span class=\"bx "+tsev+"\">"+tsev.toUpperCase()+"</span>";
      th+="<span style=\"background:#161b22;padding:1px 5px;border-radius:3px\">"+esc(te.source)+"</span></div>";
      th+="<div class=\"ftl\">"+esc(te.title)+"</div><div class=\"fd\">"+esc((te.description||"").substring(0,100))+"</div></div></div>";}
    g("fa").innerHTML=th||"<div class=\"lt\">No threats match filters</div>";
    var rcnt={}; for(var ri=0;ri<ev.length;ri++){var rg=ev[ri].region||[];for(var rj=0;rj<rg.length;rj++){rcnt[rg[rj]]=(rcnt[rg[rj]]||0)+1;}}
    var rsr=Object.entries(rcnt).sort(function(a,b){return b[1]-a[1];}).slice(0,5); var rmx=rsr.length?rsr[0][1]:1;
    var rbh=""; for(var ri2=0;ri2<rsr.length;ri2++){var rk=rsr[ri2][0],rv=rsr[ri2][1]; rbh+="<div class=\"br\"><span class=\"bl\">"+esc(RN[rk]||rk)+"</span><div class=\"bt\"><div class=\"bf\" style=\"width:"+Math.round(rv/rmx*100)+"%;background:"+(RC[rk]||"#4d9eff")+"\"></div></div><span class=\"bc\">"+rv+"</span></div>";}
    g("rb").innerHTML=rbh||"<div class=\"lt\">No data</div>";
    var icnt={}; for(var ii=0;ii<ev.length;ii++){var ig=ev[ii].industry||[];for(var ij=0;ij<ig.length;ij++){icnt[ig[ij]]=(icnt[ig[ij]]||0)+1;}}
    var isr=Object.entries(icnt).sort(function(a,b){return b[1]-a[1];}).slice(0,7); var imx=isr.length?isr[0][1]:1;
    var ibh2=""; for(var ii2=0;ii2<isr.length;ii2++){var ik=isr[ii2][0],iv=isr[ii2][1]; ibh2+="<div class=\"br\"><span class=\"bl\" style=\"text-transform:capitalize\">"+esc(ik)+"</span><div class=\"bt\"><div class=\"bf\" style=\"width:"+Math.round(iv/imx*100)+"%;background:linear-gradient(90deg,#4d9eff,#a78bfa)\"></div></div><span class=\"bc\">"+Math.round(iv/(ev.length||1)*100)+"%</span></div>";}
    g("ib2").innerHTML=ibh2||"<div class=\"lt\">No data</div>";
  }).catch(function(){});
  fetch(API+"/stats").then(function(r){return r.json();}).then(function(d){
    if(!d.success)return; var sd=d.data;
    g("s0").textContent=sd.criticalThreats||"-"; g("s1").textContent=(sd.activeIoCs||0).toLocaleString();
    g("s2").textContent=sd.threatActors||"-"; g("s3").textContent=sd.zeroDayCVEs||"-"; g("s4").textContent=sd.phishingKits||"-";
  }).catch(function(){});
  fetch(API+"/health").then(function(r){return r.json();}).then(function(d){
    if(!d.feeds)return;
    var hfc={configured:"#00d4aa",active:"#00d4aa",public:"#4d9eff","no-key":"#f5c518"};
    var hh="<h3 style=\"font-size:10px;color:#64748b;text-transform:uppercase;margin-bottom:8px\">Health</h3>";
    Object.entries(d.feeds).forEach(function(fe){hh+="<div style=\"display:flex;justify-content:space-between;padding:3px 0;font-size:11px\"><span>"+fe[0]+"</span><span style=\"color:"+(hfc[fe[1]]||"#64748b")+"\">"+ fe[1]+"</span></div>";});
    g("fh").innerHTML=hh;
  }).catch(function(){});
  fetch(API+"/iocs?limit=100").then(function(r){return r.json();}).then(function(d){
    if(!d.success)return; var ic=d.data||[];
    g("c1").textContent=ic.filter(function(x){return x.source==="OTX";}).length;
    g("c2").textContent=ic.filter(function(x){return x.source==="URLhaus";}).length;
    g("c3").textContent=ic.filter(function(x){return x.source==="MalwareBazaar";}).length;
    g("c4").textContent=ic.filter(function(x){return x.source==="ThreatFox";}).length;
    g("c5").textContent=ic.filter(function(x){return x.source==="Feodo Tracker";}).length;
    var kc=function(c){return c>=90?"#00d4aa":c>=75?"#f5c518":"#ff3b5c";};
    var ih=""; for(var ici=0;ici<ic.length;ici++){var icv=ic[ici]; ih+="<tr><td><span style=\"background:#2e2300;color:#f5c518;border:1px solid #f5c518;padding:1px 4px;border-radius:3px;font-size:9px\">"+esc(icv.type||"-")+"</span></td><td style=\"color:#f5c518;word-break:break-all\">"+esc((icv.value||"").substring(0,48))+"</td><td style=\"color:"+kc(icv.confidence||0)+"\">"+(icv.confidence||"?")+"</td><td style=\"color:#64748b\">"+esc(icv.first||"-")+"</td><td style=\"color:#64748b\">"+esc(icv.source||"-")+"</td></tr>";}
    g("ib").innerHTML=ih||"<tr><td colspan=\"5\" class=\"lt\">No IoCs</td></tr>";
  }).catch(function(){});
  fetch(API+"/actors?limit=40").then(function(r){return r.json();}).then(function(d){
    if(!d.success)return; var ac=d.data||[];
    g("c7").textContent=ac.length;
    var ah=""; for(var aci=0;aci<ac.length;aci++){var aa=ac[aci]; ah+="<div class=\"ac\"><div class=\"an\">"+esc(aa.name||"?")+"</div><div class=\"asu\">"+esc(aa.nation||"?")+" - "+esc(aa.type||"APT")+"</div></div>";}
    g("ag").innerHTML=ah||"<div class=\"lt\">No actors</div>";
  }).catch(function(){});
  fetch(API+"/cves?limit=20").then(function(r){return r.json();}).then(function(d){
    if(!d.success)return; var cv=d.data||[];
    g("c8").textContent=cv.length;
    var ch=""; for(var cvi=0;cvi<cv.length;cvi++){var cc=cv[cvi]; ch+="<div class=\"ci\"><div class=\"cvs "+cvCls(cc.cvss)+"\">"+(cc.cvss||"N/A")+"</div><div><div style=\"font-family:monospace;font-size:11px\"><a href=\""+( cc.url||"#")+"\" target=\"_blank\" rel=\"noopener\" style=\"color:#4d9eff;text-decoration:none\">"+esc(cc.id)+"</a>"+(cc.exploited?"<span style=\"color:#ff3b5c;font-size:10px;margin-left:6px\">EXPLOITED</span>":"")+"</div><div class=\"ftl\">"+esc((cc.title||"").substring(0,90))+"</div></div></div>";}
    g("cl").innerHTML=ch||"<div class=\"lt\">No CVEs</div>";
  }).catch(function(){});
  fetch(API+"/phishing?limit=20").then(function(r){return r.json();}).then(function(d){
    if(!d.success)return; var ph=d.data||[];
    g("c6").textContent=ph.length; g("s4").textContent=ph.length;
    var pph=""; for(var phi=0;phi<ph.length;phi++){var pp=ph[phi]; pph+="<div class=\"pi\"><div style=\"margin-top:2px;font-size:14px\">!</div><div><div class=\"ftl\">"+esc(pp.subject||("Phishing: "+pp.target))+"</div><div style=\"font-size:10px;color:#ff3b5c\">"+esc(pp.target||"-")+"</div><div style=\"font-size:11px;color:#64748b\">"+(pp.domains||1)+" domain(s)</div></div></div>";}
    g("pl").innerHTML=pph||"<div class=\"lt\">No phishing data</div>";
  }).catch(function(){});
  clearTimeout(window._rt);
  window._rt=setTimeout(function(){fetch(API+"/cache/flush",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}).catch(function(){}).then(go);},300000);
}
function rf(){fetch(API+"/cache/flush",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}).catch(function(){}).then(go);}

// Asset Monitor
function loadAssets(){
  fetch(API+"/monitor/status").then(function(r){return r.json();}).then(function(d){
    if(!d.success)return; var st=d.data;
    var ipH=""; (st.watchedIPs||[]).forEach(function(wip){ipH+="<span class=\"watched-chip\">"+esc(wip)+"<button onclick=\"window._rmW('ip','"+esc(wip)+"')\">x</button></span>";});
    g("watched-ips").innerHTML=ipH||"<div class=\"lt\">No IPs watched</div>";
    var dmH=""; (st.watchedDomains||[]).forEach(function(wdm){dmH+="<span class=\"watched-chip\">"+esc(wdm)+"<button onclick=\"window._rmW('domain','"+esc(wdm)+"')\">x</button></span>";});
    g("watched-domains").innerHTML=dmH||"<div class=\"lt\">No domains watched</div>";
    if(st.lastScan)g("as-scan").textContent=rel(st.lastScan);
  }).catch(function(){});
  fetch(API+"/monitor/assets").then(function(r){return r.json();}).then(function(d){
    if(!d.success)return; var assets=d.data||[];
    var ac2=assets.filter(function(a){return a.riskLevel==="critical";}).length;
    var ah2=assets.filter(function(a){return a.riskLevel==="high";}).length;
    g("as-crit").textContent=ac2; g("as-high").textContent=ah2;
    g("as-total").textContent=assets.length; g("as-ports").textContent=assets.length;
    g("asset-badge").textContent=ac2+" CRITICAL";
    var at=""; for(var asi=0;asi<assets.length;asi++){var aa2=assets[asi];
      var vs=Object.keys(aa2.vulns||{}).length?"<span style=\"color:#ff3b5c\">"+Object.keys(aa2.vulns).length+" CVE(s)</span>":"<span style=\"color:#00d4aa\">Clean</span>";
      at+="<tr><td style=\"font-family:monospace;color:#4d9eff\">"+esc(aa2.ip)+"</td><td style=\"color:#64748b\">"+esc((aa2.hostnames||[])[0]||aa2.org||"-")+"</td><td style=\"font-family:monospace\">"+esc(String(aa2.port||"-"))+"</td><td>"+esc(aa2.product||"Unknown")+(aa2.version?" <span style=\"color:#64748b\">"+esc(aa2.version)+"</span>":"")+"</td><td style=\"color:#64748b\">"+esc(aa2.country||"-")+"</td><td>"+vs+"</td><td><span class=\"risk-badge "+esc(aa2.riskLevel||"low")+"\">"+ esc((aa2.riskLevel||"low").toUpperCase())+"</span></td></tr>";}
    g("asset-tbody").innerHTML=at||"<tr><td colspan=\"7\" class=\"lt\">No assets - add domains/IPs and scan</td></tr>";
  }).catch(function(){});
}
window._rmW=function(type,val){fetch(API+"/monitor/watchlist",{method:"DELETE",headers:{"Content-Type":"application/json"},body:JSON.stringify({type:type,value:val})}).then(function(){loadAssets();}).catch(function(){});};
g("add-asset-btn").addEventListener("click",function(){
  var addIp=g("add-ip").value.trim(), addDm=g("add-domain").value.trim();
  if(!addIp&&!addDm){alert("Enter an IP or domain");return;}
  var ab={};
  if(addIp)ab.ip=addIp;
  if(addDm){ab.domain=addDm;ab.credDomain=addDm;}
  fetch(API+"/monitor/watchlist",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(ab)})
    .then(function(){g("add-ip").value="";g("add-domain").value="";loadAssets();}).catch(function(){});
});
g("scan-btn").addEventListener("click",function(){
  var sb=g("scan-btn"); sb.textContent="Scanning...";
  g("asset-badge").textContent="SCANNING";
  fetch(API+"/monitor/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"})
    .then(function(){setTimeout(function(){sb.textContent="Run Scan Now";loadAssets();loadAlerts();},15000);})
    .catch(function(){sb.textContent="Run Scan Now";});
});

// Credential Leaks
function loadCreds(){
  fetch(API+"/credentials/status").then(function(r){return r.json();}).then(function(d){
    if(!d.success)return; var cres=d.data||[],doms=d.domains||[];
    g("cr-domains").textContent=doms.length||"-";
    var totAcc=0,bSet=new Set(),crit2=0;
    cres.forEach(function(cr){totAcc+=(cr.totalExposedAccounts||0);(cr.breaches||[]).forEach(function(b){bSet.add(b);});if((cr.totalExposedAccounts||0)>100)crit2++;});
    g("cr-accounts").textContent=totAcc.toLocaleString(); g("cr-breaches").textContent=bSet.size; g("cr-critical").textContent=crit2;
    if(cres.length&&cres[0].lastChecked)g("cr-last").textContent=rel(cres[0].lastChecked);
    var sumH="";
    if(!cres.length){sumH="<div class=\"lt\">Add a domain to monitor for credential leaks</div>";}
    else{cres.forEach(function(cr2){var csev=cr2.totalExposedAccounts>100?"critical":cr2.totalExposedAccounts>10?"high":"medium";
      sumH+="<div style=\"padding:10px 0;border-bottom:1px solid #1e2630\"><div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:6px\"><span style=\"font-family:monospace;font-size:13px;font-weight:700\">"+esc(cr2.domain)+"</span><span class=\"risk-badge "+csev+"\">"+cr2.totalExposedAccounts+" EXPOSED</span></div><div style=\"font-size:11px;color:#64748b;margin-bottom:5px\">Breaches: ";
      (cr2.breaches||[]).forEach(function(b2){sumH+="<span class=\"tag\">"+esc(b2)+"</span>";});
      sumH+="</div></div>";});}
    g("cred-summary").innerHTML=sumH;
    var emH="";
    cres.forEach(function(cr3){(cr3.exposedEmails||[]).forEach(function(em){
      emH+="<tr><td style=\"font-family:monospace;color:#f5c518\">"+esc(em.email||"-")+"</td><td>"+(em.breaches||[]).map(function(b3){return "<span class=\"tag\">"+esc(b3)+"</span>";}).join("")+"</td><td style=\"color:#64748b\">"+esc(cr3.domain||"-")+"</td></tr>";});});
    g("exposed-emails").innerHTML=emH||"<tr><td colspan=\"3\" class=\"lt\">No exposed emails</td></tr>";
  }).catch(function(){});
  fetch(API+"/credentials/breaches").then(function(r){return r.json();}).then(function(d){
    if(!d.success)return; var brs=d.data||[],bh="";
    for(var bi=0;bi<brs.length;bi++){var br2=brs[bi];
      bh+="<div class=\"breach-item\"><div class=\"breach-name\">"+esc(br2.name)+"</div>";
      bh+="<div class=\"breach-meta\">"+esc(br2.domain||"-")+" &bull; "+esc(br2.breachDate||"-")+" &bull; <span style=\"color:#ff8c42\">"+(br2.pwnCount||0).toLocaleString()+" accounts</span></div>";
      bh+="<div style=\"margin-top:4px\">"+(br2.dataClasses||[]).map(function(dc){return "<span class=\"tag\">"+esc(dc)+"</span>";}).join("")+"</div></div>";}
    g("global-breaches").innerHTML=bh||"<div class=\"lt\">No breach data</div>";
  }).catch(function(){});
}
g("add-cred-btn").addEventListener("click",function(){
  var cdm=g("add-cred-domain").value.trim();
  if(!cdm){alert("Enter a domain");return;}
  fetch(API+"/monitor/watchlist",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({credDomain:cdm})})
    .then(function(){g("add-cred-domain").value="";loadCreds();}).catch(function(){});
});
g("check-btn").addEventListener("click",function(){
  var cb=g("check-btn"); cb.textContent="Checking...";
  fetch(API+"/monitor/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"})
    .then(function(){setTimeout(function(){cb.textContent="Check Now";loadCreds();},8000);})
    .catch(function(){cb.textContent="Check Now";});
});

// Alerts
function loadAlerts(){
  fetch(API+"/monitor/alerts").then(function(r){return r.json();}).then(function(d){
    if(!d.success)return; var alts=d.data||[];
    var acnt=alts.length; var adot=g("alert-count");
    if(acnt>0){adot.textContent=acnt;adot.style.display="inline-block";}else{adot.style.display="none";}
    g("alerts-badge").textContent=acnt+" ALERTS";
    if(!alts.length){g("alerts-list").innerHTML="<div class=\"lt\">No alerts yet. Monitoring runs every 6h. Use Asset Monitor to trigger a manual scan.</div>";return;}
    var aicons={new_port:"[PORT]",new_vuln:"[CVE]",credential_leak:"[CRED]",critical_asset:"[ASSET]"};
    var asevC={critical:"#ff3b5c",high:"#ff8c42",medium:"#f5c518",low:"#00d4aa"};
    var alh=""; for(var ali=0;ali<alts.length;ali++){var alt=alts[ali];
      var asc=asevC[alt.severity]||"#64748b";
      alh+="<div class=\"alert-item\"><div style=\"font-family:monospace;font-size:11px;color:"+asc+";flex-shrink:0;padding-top:2px\">"+(aicons[alt.type]||"[!]")+"</div>";
      alh+="<div style=\"flex:1\"><div class=\"alert-msg\">"+esc(alt.message)+"</div><div class=\"alert-time\"><span style=\"color:"+asc+"\">"+esc((alt.severity||"").toUpperCase())+"</span> &bull; "+esc(rel(alt.timestamp))+"</div></div></div>";}
    g("alerts-list").innerHTML=alh;
  }).catch(function(){});
}
g("clear-alerts-btn").addEventListener("click",loadAlerts);

// Wire up filters
g("fi").addEventListener("change",go);
g("fr").addEventListener("change",go);
g("fs").addEventListener("change",go);
g("rfbtn").addEventListener("click",rf);

// Auto-refresh monitoring pages every 30s
setInterval(function(){
  var ap=document.querySelector(".page.active"); if(!ap)return;
  if(ap.id==="page-assets")loadAssets();
  if(ap.id==="page-creds")loadCreds();
  if(ap.id==="page-alerts")loadAlerts();
},30000);

// Boot
go();

})();