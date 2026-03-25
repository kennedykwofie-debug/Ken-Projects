(function() {
"use strict";
var API="/api/v1";
var RC={na:"#4d9eff",eu:"#a78bfa",apac:"#00d4aa",mena:"#f5c518",latam:"#ff8c42"};
var RN={na:"N.Am",eu:"Europe",apac:"Asia",mena:"MENA",latam:"LatAm"};
function esc(s){return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
function cvCls(v){return !v?"medium":v>=9?"critical":v>=7?"high":"medium";}
function g(id){return document.getElementById(id);}
function rel(iso){if(!iso)return"never";var diff=Date.now()-new Date(iso).getTime();var mm=Math.floor(diff/60000),hh=Math.floor(diff/3600000),dd=Math.floor(diff/86400000);return mm<60?mm+"m ago":hh<24?hh+"h ago":dd+"d ago";}
function showPage(name){document.querySelectorAll(".page").forEach(function(p){p.classList.remove("active");});document.querySelectorAll(".nvb").forEach(function(b){b.classList.remove("active");});var pg=g("page-"+name);if(pg)pg.classList.add("active");document.querySelectorAll("[data-page=\""+name+"\"]").forEach(function(b){b.classList.add("active");});if(name==="assets")loadAssets();if(name==="creds")loadCreds();if(name==="alerts")loadAlerts();if(name==="pro")loadPro();}
document.querySelectorAll(".nvb").forEach(function(btn){btn.addEventListener("click",function(){showPage(btn.dataset.page);});});
function sw(tid,el){document.querySelectorAll(".tc").forEach(function(t){t.classList.remove("on");});document.querySelectorAll(".tab").forEach(function(t){t.classList.remove("on");});g(tid).classList.add("on");el.classList.add("on");}
document.querySelectorAll(".tab").forEach(function(btn){btn.addEventListener("click",function(){sw(btn.dataset.tab,btn);});});
function uc(){var n=new Date(),pd=function(x){return String(x).padStart(2,"0");};g("ck").textContent=pd(n.getUTCHours())+":"+pd(n.getUTCMinutes())+":"+pd(n.getUTCSeconds())+" UTC";}
setInterval(uc,1000);uc();
function go(){
var fi=g("fi").value,fr=g("fr").value,fs=g("fs").value;
var qs="?industry="+fi+"&region="+fr+"&severity="+fs+"&limit=50";
fetch(API+"/threats"+qs).then(function(r){return r.json();}).then(function(d){
if(!d.success)return;var ev=d.data.events||[];
var crit=ev.filter(function(t){return t.severity==="critical";}).length;
g("fb").textContent=crit+" CRITICAL";g("c0").textContent=ev.length;
var th="";for(var ti=0;ti<ev.length;ti++){var te=ev[ti],tsev=esc(te.severity||"low");
th+="<div class=\"fi\"><div class=\"svb "+tsev+"\"></div><div style=\"flex:1;min-width:0\"><div class=\"fm\"><span class=\"bx "+tsev+"\">"+tsev.toUpperCase()+"</span><span style=\"background:#161b22;padding:1px 5px;border-radius:3px\">"+esc(te.source)+"</span></div><div class=\"ftl\">"+esc(te.title)+"</div><div class=\"fd\">"+esc((te.description||"").substring(0,100))+"</div></div></div>";}
g("fa").innerHTML=th||"<div class=\"lt\">No threats</div>";
var rcnt={};for(var ri=0;ri<ev.length;ri++){var rg=ev[ri].region||[];for(var rj=0;rj<rg.length;rj++){rcnt[rg[rj]]=(rcnt[rg[rj]]||0)+1;}}
var rsr=Object.entries(rcnt).sort(function(a,b){return b[1]-a[1];}).slice(0,5);var rmx=rsr.length?rsr[0][1]:1;
var rbh="";for(var ri2=0;ri2<rsr.length;ri2++){var rk=rsr[ri2][0],rv=rsr[ri2][1];rbh+="<div class=\"br\"><span class=\"bl\">"+esc(RN[rk]||rk)+"</span><div class=\"bt\"><div class=\"bf\" style=\"width:"+Math.round(rv/rmx*100)+"%;background:"+(RC[rk]||"#4d9eff")+"\"></div></div><span class=\"bc\">"+rv+"</span></div>";}
g("rb").innerHTML=rbh||"<div class=\"lt\">No data</div>";
var icnt={};for(var ii=0;ii<ev.length;ii++){var ig=ev[ii].industry||[];for(var ij=0;ij<ig.length;ij++){icnt[ig[ij]]=(icnt[ig[ij]]||0)+1;}}
var isr=Object.entries(icnt).sort(function(a,b){return b[1]-a[1];}).slice(0,7);var imx=isr.length?isr[0][1]:1;
var ibh="";for(var ii2=0;ii2<isr.length;ii2++){var ik=isr[ii2][0],iv=isr[ii2][1];ibh+="<div class=\"br\"><span class=\"bl\" style=\"text-transform:capitalize\">"+esc(ik)+"</span><div class=\"bt\"><div class=\"bf\" style=\"width:"+Math.round(iv/imx*100)+"%;background:linear-gradient(90deg,#4d9eff,#a78bfa)\"></div></div><span class=\"bc\">"+Math.round(iv/(ev.length||1)*100)+"%</span></div>";}
g("ib2").innerHTML=ibh||"<div class=\"lt\">No data</div>";
}).catch(function(){});
fetch(API+"/stats").then(function(r){return r.json();}).then(function(d){if(!d.success)return;var sd=d.data;g("s0").textContent=sd.criticalThreats||"-";g("s1").textContent=(sd.activeIoCs||0).toLocaleString();g("s2").textContent=sd.threatActors||"-";g("s3").textContent=sd.zeroDayCVEs||"-";g("s4").textContent=sd.phishingKits||"-";}).catch(function(){});
fetch(API+"/health").then(function(r){return r.json();}).then(function(d){if(!d.feeds)return;var hfc={configured:"#00d4aa",active:"#00d4aa",public:"#4d9eff","no-key":"#f5c518"};var hh="<h3 style=\"font-size:10px;color:#64748b;text-transform:uppercase;margin-bottom:8px\">Health</h3>";Object.entries(d.feeds).forEach(function(fe){hh+="<div style=\"display:flex;justify-content:space-between;padding:3px 0;font-size:11px\"><span>"+fe[0]+"</span><span style=\"color:"+(hfc[fe[1]]||"#64748b")+"\">" +fe[1]+"</span></div>";});g("fh").innerHTML=hh;}).catch(function(){});
fetch(API+"/iocs?limit=100").then(function(r){return r.json();}).then(function(d){if(!d.success)return;var ic=d.data||[];g("c1").textContent=ic.filter(function(x){return x.source==="OTX";}).length;g("c2").textContent=ic.filter(function(x){return x.source==="URLhaus";}).length;g("c3").textContent=ic.filter(function(x){return x.source==="MalwareBazaar";}).length;g("c4").textContent=ic.filter(function(x){return x.source==="ThreatFox";}).length;g("c5").textContent=ic.filter(function(x){return x.source==="Feodo Tracker";}).length;var kc=function(c){return c>=90?"#00d4aa":c>=75?"#f5c518":"#ff3b5c";};var ih="";for(var ici=0;ici<ic.length;ici++){var icv=ic[ici];ih+="<tr><td><span style=\"background:#2e2300;color:#f5c518;border:1px solid #f5c518;padding:1px 4px;border-radius:3px;font-size:9px\">"+esc(icv.type||"-")+"</span></td><td style=\"color:#f5c518;word-break:break-all\">"+esc((icv.value||"").substring(0,48))+"</td><td style=\"color:"+kc(icv.confidence||0)+"\">"+(icv.confidence||"?")+"%</td><td style=\"color:#64748b\">"+esc(icv.first||"-")+"</td><td style=\"color:#64748b\">"+esc(icv.source||"-")+"</td></tr>";}g("ib").innerHTML=ih||"<tr><td colspan=\"5\" class=\"lt\">No IoCs</td></tr>";}).catch(function(){});
fetch(API+"/actors?limit=40").then(function(r){return r.json();}).then(function(d){if(!d.success)return;var ac=d.data||[];g("c7").textContent=ac.length;var ah="";for(var aci=0;aci<ac.length;aci++){var aa=ac[aci];ah+="<div class=\"ac\"><div class=\"an\">"+esc(aa.name||"?")+"</div><div class=\"asu\">"+esc(aa.nation||"?")+" - "+esc(aa.type||"APT")+"</div></div>";}g("ag").innerHTML=ah||"<div class=\"lt\">No actors</div>";}).catch(function(){});
fetch(API+"/cves?limit=20").then(function(r){return r.json();}).then(function(d){if(!d.success)return;var cv=d.data||[];g("c8").textContent=cv.length;var ch="";for(var cvi=0;cvi<cv.length;cvi++){var cc=cv[cvi];ch+="<div class=\"ci\"><div class=\"cvs "+cvCls(cc.cvss)+"\">"+(cc.cvss||"N/A")+"</div><div><div style=\"font-family:monospace;font-size:11px\"><a href=\""+( cc.url||"#")+"\" target=\"_blank\" rel=\"noopener\" style=\"color:#4d9eff;text-decoration:none\">"+esc(cc.id)+"</a>"+(cc.exploited?"<span style=\"color:#ff3b5c;font-size:10px;margin-left:6px\">EXPLOITED</span>":"")+"</div><div class=\"ftl\">"+esc((cc.title||"").substring(0,90))+"</div></div></div>";}g("cl").innerHTML=ch||"<div class=\"lt\">No CVEs</div>";}).catch(function(){});
fetch(API+"/phishing?limit=20").then(function(r){return r.json();}).then(function(d){if(!d.success)return;var ph=d.data||[];g("c6").textContent=ph.length;g("s4").textContent=ph.length;var pph="";for(var phi=0;phi<ph.length;phi++){var pp=ph[phi];pph+="<div class=\"pi\"><div style=\"margin-top:2px;font-size:14px\">!</div><div><div class=\"ftl\">"+esc(pp.subject||("Phishing: "+pp.target))+"</div><div style=\"font-size:10px;color:#ff3b5c\">"+esc(pp.target||"-")+"</div><div style=\"font-size:11px;color:#64748b\">"+(pp.domains||1)+" domain(s)</div></div></div>";}g("pl").innerHTML=pph||"<div class=\"lt\">No phishing</div>";}).catch(function(){});
clearTimeout(window._rt);window._rt=setTimeout(function(){fetch(API+"/cache/flush",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}).catch(function(){}).then(go);},300000);
}
function rf(){fetch(API+"/cache/flush",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}).catch(function(){}).then(go);}
function loadAssets(){
fetch(API+"/monitor/status").then(function(r){return r.json();}).then(function(d){if(!d.success)return;var st=d.data;var ipH="";(st.watchedIPs||[]).forEach(function(wip){ipH+="<span class=\"watched-chip\">"+esc(wip)+"<button onclick=\"window._rmW('ip','"+esc(wip)+"')\">x</button></span>";});g("watched-ips").innerHTML=ipH||"<div class=\"lt\">No IPs watched</div>";var dmH="";(st.watchedDomains||[]).forEach(function(wdm){dmH+="<span class=\"watched-chip\">"+esc(wdm)+"<button onclick=\"window._rmW('domain','"+esc(wdm)+"')\">x</button></span>";});g("watched-domains").innerHTML=dmH||"<div class=\"lt\">No domains watched</div>";if(st.lastScan)g("as-scan").textContent=rel(st.lastScan);}).catch(function(){});
fetch(API+"/monitor/assets").then(function(r){return r.json();}).then(function(d){if(!d.success)return;var assets=d.data||[];var acrit=assets.filter(function(a){return a.riskLevel==="critical";}).length;var ahigh=assets.filter(function(a){return a.riskLevel==="high";}).length;g("as-crit").textContent=acrit;g("as-high").textContent=ahigh;g("as-total").textContent=assets.length;g("as-ports").textContent=assets.length;g("asset-badge").textContent=acrit+" CRITICAL";var at="";for(var asi=0;asi<assets.length;asi++){var aa2=assets[asi];var vs=Object.keys(aa2.vulns||{}).length?"<span style=\"color:#ff3b5c\">"+Object.keys(aa2.vulns).length+" CVE(s)</span>":"<span style=\"color:#00d4aa\">Clean</span>";at+="<tr><td style=\"font-family:monospace;color:#4d9eff\">"+esc(aa2.ip)+"</td><td style=\"color:#64748b\">"+esc((aa2.hostnames||[])[0]||aa2.org||"-")+"</td><td style=\"font-family:monospace\">"+esc(String(aa2.port||"-"))+"</td><td>"+esc(aa2.product||"Unknown")+(aa2.version?" <span style=\"color:#64748b\">"+esc(aa2.version)+"</span>":"")+"</td><td style=\"color:#64748b\">"+esc(aa2.country||"-")+"</td><td>"+vs+"</td><td><span class=\"risk-badge "+esc(aa2.riskLevel||"low")+"\">"+esc((aa2.riskLevel||"low").toUpperCase())+"</span></td></tr>";}g("asset-tbody").innerHTML=at||"<tr><td colspan=\"7\" class=\"lt\">No assets</td></tr>";}).catch(function(){});
}
window._rmW=function(wtype,wval){fetch(API+"/monitor/watchlist",{method:"DELETE",headers:{"Content-Type":"application/json"},body:JSON.stringify({type:wtype,value:wval})}).then(function(){if(wtype==="email"){if(typeof loadCreds==="function")loadCreds();}else{if(typeof loadAssets==="function")loadAssets();}}).catch(function(){});};
g("add-asset-btn").addEventListener("click",function(){var addIpVal=g("add-ip").value.trim(),addDmVal=g("add-domain").value.trim();if(!addIpVal&&!addDmVal){alert("Enter an IP or domain");return;}var abody={};if(addIpVal)abody.ip=addIpVal;if(addDmVal){abody.domain=addDmVal;abody.credDomain=addDmVal;}fetch(API+"/monitor/watchlist",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(abody)}).then(function(){g("add-ip").value="";g("add-domain").value="";loadAssets();}).catch(function(){});});
g("scan-btn").addEventListener("click",function(){var scanBtn=g("scan-btn");scanBtn.textContent="Scanning...";g("asset-badge").textContent="SCANNING";fetch(API+"/monitor/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}).then(function(){setTimeout(function(){scanBtn.textContent="Run Scan Now";loadAssets();loadAlerts();},15000);}).catch(function(){scanBtn.textContent="Run Scan Now";});});

// Ã¢ÂÂÃ¢ÂÂ Bulk Import Panel Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ
(function(){
var PREFIXES=[
"admin","administrator","webmaster","hostmaster","postmaster","abuse","noc","security",
"info","contact","hello","support","help","helpdesk","servicedesk","it","itsupport",
"hr","humanresources","recruitment","careers","jobs","payroll","training",
"ceo","cfo","cto","coo","ciso","president","director","manager","vp",
"finance","accounting","billing","accounts","treasury","audit",
"legal","compliance","privacy","dpo","risk","governance",
"sales","marketing","press","media","communications","pr","partnerships",
"procurement","purchasing","supply","vendors","facilities",
"operations","ops","devops","dev","engineering","tech","infrastructure",
"data","analytics","research","innovation",
"customerservice","customers","clients","feedback","complaints"
];
var bHdr=document.getElementById("bulk-header");
if(!bHdr)return;
bHdr.addEventListener("click",function(){
  var bd=document.getElementById("bulk-body");
  var bt=document.getElementById("bulk-toggle");
  if(!bd)return;
  var open=bd.style.display!=="none";
  bd.style.display=open?"none":"block";
  if(bt)bt.textContent=open?"Click to expand":"Click to collapse";
});
var tabPattern=document.getElementById("bulk-tab-pattern");
var tabCsv=document.getElementById("bulk-tab-csv");
var panePattern=document.getElementById("bulk-pane-pattern");
var paneCsv=document.getElementById("bulk-pane-csv");
function switchBulkTab(t){
  var isP=t==="pattern";
  if(tabPattern)tabPattern.className=isP?"btn btn-primary":"btn";tabPattern.style.cssText=isP?"font-size:11px":"font-size:11px;background:#1e2630;border:1px solid #2a3440";
  if(tabCsv)tabCsv.style.cssText=isP?"font-size:11px;background:#1e2630;border:1px solid #2a3440":"font-size:11px";tabCsv.className=isP?"btn":"btn btn-primary";
  if(panePattern)panePattern.style.display=isP?"block":"none";
  if(paneCsv)paneCsv.style.display=isP?"none":"block";
}
if(tabPattern)tabPattern.addEventListener("click",function(){switchBulkTab("pattern");});
if(tabCsv)tabCsv.addEventListener("click",function(){switchBulkTab("csv");});
var selectedEmails={};
function updateSelCount(){
  var n=Object.keys(selectedEmails).filter(function(k){return selectedEmails[k];}).length;
  var el=document.getElementById("bulk-sel-count");
  if(el)el.textContent="("+n+" selected)";
}
var previewBtn=document.getElementById("bulk-preview-btn");
if(previewBtn){previewBtn.addEventListener("click",function(){
  var dom=document.getElementById("bulk-domain");
  if(!dom)return;
  var domain=dom.value.trim().toLowerCase().replace(/^@/,"");
  if(!domain||domain.indexOf(".")<0){dom.style.borderColor="#ff3b5c";return;}
  dom.style.borderColor="";
  selectedEmails={};
  var listEl=document.getElementById("bulk-email-list");
  var previewArea=document.getElementById("bulk-preview-area");
  if(!listEl||!previewArea)return;
  listEl.innerHTML="";
  PREFIXES.forEach(function(p){
    var em=p+"@"+domain;
    selectedEmails[em]=true;
    var chip=document.createElement("label");
    chip.style.cssText="display:inline-flex;align-items:center;gap:4px;background:#0d1117;border:1px solid #2a3440;border-radius:4px;padding:3px 7px;cursor:pointer;font-size:11px;font-family:monospace;color:#e2e8f0;user-select:none";
    var cb=document.createElement("input");
    cb.type="checkbox";cb.checked=true;cb.style.accentColor="#a78bfa";
    (function(email,lbl,checkbox){
      checkbox.addEventListener("change",function(){
        selectedEmails[email]=checkbox.checked;
        lbl.style.borderColor=checkbox.checked?"#2a3440":"#1e2630";
        lbl.style.opacity=checkbox.checked?"1":"0.4";
        updateSelCount();
      });
    })(em,chip,cb);
    chip.appendChild(cb);
    chip.appendChild(document.createTextNode(em));
    listEl.appendChild(chip);
  });
  previewArea.style.display="block";
  updateSelCount();
});}
var selAll=document.getElementById("bulk-select-all");
var deselAll=document.getElementById("bulk-deselect-all");
if(selAll){selAll.addEventListener("click",function(){
  document.querySelectorAll("#bulk-email-list input[type=checkbox]").forEach(function(cb){cb.checked=true;var em=cb.parentElement.textContent.trim();selectedEmails[em]=true;cb.parentElement.style.opacity="1";cb.parentElement.style.borderColor="#2a3440";});
  updateSelCount();
});}
if(deselAll){deselAll.addEventListener("click",function(){
  document.querySelectorAll("#bulk-email-list input[type=checkbox]").forEach(function(cb){cb.checked=false;var em=cb.parentElement.textContent.trim();selectedEmails[em]=false;cb.parentElement.style.opacity="0.4";cb.parentElement.style.borderColor="#1e2630";});
  updateSelCount();
});}
var addSelBtn=document.getElementById("bulk-add-selected");
if(addSelBtn){addSelBtn.addEventListener("click",function(){
  var toAdd=Object.keys(selectedEmails).filter(function(k){return selectedEmails[k];});
  if(!toAdd.length){return;}
  var statusEl=document.getElementById("bulk-add-status");
  addSelBtn.disabled=true;addSelBtn.textContent="Adding "+toAdd.length+" emails...";
  var added=0,errors=0;
  function addNext(i){
    if(i>=toAdd.length){
      addSelBtn.disabled=false;addSelBtn.textContent="Add Selected to Monitor";
      if(statusEl)statusEl.textContent="Done: "+added+" added, "+errors+" errors.";
      setTimeout(function(){if(typeof loadCreds==="function")loadCreds();},500);
      return;
    }
    fetch(API+"/monitor/watchlist",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:toAdd[i]})})
    .then(function(){added++;if(statusEl)statusEl.textContent="Adding... "+added+"/"+toAdd.length;addNext(i+1);})
    .catch(function(){errors++;addNext(i+1);});
  }
  addNext(0);
});}
function parseEmails(raw){
  var lines=raw.replace(/,/g,"\n").split("\n");
  var emails=[];
  lines.forEach(function(l){
    var e=l.trim().toLowerCase();
    if(e&&e.indexOf("@")>0&&e.indexOf(".")>0)emails.push(e);
  });
  return emails;
}
var csvAddBtn=document.getElementById("bulk-csv-add");
if(csvAddBtn){csvAddBtn.addEventListener("click",function(){
  var ta=document.getElementById("bulk-paste");
  if(!ta)return;
  var emails=parseEmails(ta.value);
  var statusEl=document.getElementById("bulk-csv-status");
  if(!emails.length){if(statusEl)statusEl.textContent="No valid email addresses found.";return;}
  csvAddBtn.disabled=true;csvAddBtn.textContent="Adding "+emails.length+" emails...";
  var added=0,errors=0;
  function addNext(i){
    if(i>=emails.length){
      csvAddBtn.disabled=false;csvAddBtn.textContent="Add All Emails";
      if(statusEl)statusEl.textContent="Done: "+added+" added, "+errors+" skipped/errors.";
      ta.value="";
      setTimeout(function(){if(typeof loadCreds==="function")loadCreds();},500);
      return;
    }
    fetch(API+"/monitor/watchlist",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:emails[i]})})
    .then(function(){added++;if(statusEl)statusEl.textContent="Adding... "+added+"/"+emails.length;addNext(i+1);})
    .catch(function(){errors++;addNext(i+1);});
  }
  addNext(0);
});}
var fileInput=document.getElementById("bulk-file-input");
if(fileInput){fileInput.addEventListener("change",function(e){
  var file=e.target.files[0];
  if(!file)return;
  var reader=new FileReader();
  reader.onload=function(ev){
    var ta=document.getElementById("bulk-paste");
    if(ta)ta.value=ev.target.result;
    var statusEl=document.getElementById("bulk-csv-status");
    var count=parseEmails(ev.target.result).length;
    if(statusEl)statusEl.textContent="Loaded "+file.name+" -- "+count+" valid emails found. Click Add All Emails to import.";
  };
  reader.readAsText(file);
  fileInput.value="";
});}
})();
function loadCreds(){
fetch(API+"/credentials/status").then(function(r){return r.json();}).then(function(d){
if(!d.success)return;
var ems=d.emails||[];
var res=d.data||[];
var summ=d.summary||{};
g("cr-domains").textContent=ems.length||"-";
g("cr-accounts").textContent=(summ.exposedEmails||0).toLocaleString();
g("cr-breaches").textContent=(summ.uniqueBreaches||[]).length||0;
g("cr-critical").textContent=summ.criticalEmails||0;
if(res.length&&res[0].lastChecked)g("cr-last").textContent=rel(res[0].lastChecked);
var monList=document.getElementById("monitored-email-list");
var monCount=document.getElementById("mon-email-count");
if(monList){
  monList.innerHTML="";
  if(!ems.length){
    var noEm=document.createElement("div");
    noEm.style.cssText="color:#64748b;font-size:12px";
    noEm.textContent="No emails monitored yet -- add one above";
    monList.appendChild(noEm);
  }else{
    ems.forEach(function(em){
      var r4=res.filter(function(x){return x.email===em;})[0];
      var rl=r4?(r4.riskLevel==="clean"?"low":r4.riskLevel||"low"):"pending";
      var co=rl==="critical"?"#ff3b5c":rl==="high"?"#ff8c42":rl==="medium"?"#f5c518":rl==="low"?"#00d4aa":"#64748b";
      var chip=document.createElement("span");
      chip.className="watched-chip";
      var lbl=document.createElement("span");
      lbl.style.cssText="font-family:monospace;font-size:11px;color:"+co;
      lbl.textContent=em;
      chip.appendChild(lbl);
      var st=document.createElement("span");
      st.style.cssText="font-size:10px;margin-left:4px";
      if(r4&&r4.breachCount>0){st.style.color=co;st.textContent=r4.breachCount+" breach"+(r4.breachCount!==1?"es":"");}
      else if(r4&&r4.breachCount===0){st.style.color="#00d4aa";st.textContent="clean";}
      else{st.style.color="#64748b";st.textContent="checking...";}
      chip.appendChild(st);
      var xbtn=document.createElement("button");
      xbtn.className="rm-btn";
      xbtn.textContent="x";
      xbtn.style.marginLeft="6px";
      (function(email){
        xbtn.addEventListener("click",function(e){
          e.stopPropagation();
          xbtn.disabled=true;xbtn.textContent="...";
          fetch(API+"/monitor/watchlist",{method:"DELETE",headers:{"Content-Type":"application/json"},body:JSON.stringify({type:"email",value:email})})
          .then(function(){loadCreds();})
          .catch(function(){xbtn.disabled=false;xbtn.textContent="x";});
        });
      })(em);
      chip.appendChild(xbtn);
      monList.appendChild(chip);
    });
  }
  if(monCount)monCount.textContent=ems.length+(ems.length===1?" email":" emails");
}
var emH="";
var exposed=res.filter(function(em3){return em3.breachCount>0&&ems.indexOf(em3.email)>-1;});
var badge=document.getElementById("exposed-badge");
if(badge){badge.textContent=exposed.length+" EXPOSED";badge.style.display=exposed.length?"inline":"none";}
exposed.forEach(function(em3){
  (em3.breaches||[]).forEach(function(br){
    var erc2=em3.riskLevel==="clean"?"low":em3.riskLevel||"low";
    var ec2=erc2==="critical"?"#ff3b5c":erc2==="high"?"#ff8c42":erc2==="medium"?"#f5c518":"#00d4aa";
    emH+="<tr>";
    emH+="<td style=\"font-family:monospace;color:"+ec2+";font-size:11px\">"+esc(em3.email)+"</td>";
    emH+="<td style=\"text-align:center\">"+em3.breachCount+"</td>";
    emH+="<td><div style=\"font-weight:700;color:#e2e8f0\">"+esc(br.name||"-")+"</div>";
    emH+="<div style=\"font-size:10px;color:#64748b;margin-top:2px\">"+esc(br.domain||"-")+" | "+esc(br.breachDate||"-")+"</div>";
    emH+="<div style=\"font-size:10px;color:#ff8c42;margin-top:1px\">"+(br.pwnCount||0).toLocaleString()+" accounts exposed</div></td>";
    emH+="<td>";
    (br.dataClasses||[]).forEach(function(dc){
      var dcC=dc.toLowerCase().indexOf("password")>-1||dc.toLowerCase().indexOf("ssn")>-1||dc.toLowerCase().indexOf("financial")>-1?"#ff3b5c":dc.toLowerCase().indexOf("phone")>-1||dc.toLowerCase().indexOf("address")>-1?"#f5c518":"#64748b";
      emH+="<span style=\"display:inline-block;margin:1px 2px;padding:1px 5px;border-radius:3px;font-size:10px;border:1px solid "+dcC+";color:"+dcC+"\">"+esc(dc)+"</span>";
    });
    if(br.isSensitive)emH+="<br><span style=\"font-size:10px;color:#ff3b5c\">SENSITIVE</span>";
    emH+="</td>";
    emH+="<td><span class=\"risk-badge "+erc2+"\">"+erc2.toUpperCase()+"</span></td>";
    emH+="</tr>";
  });
});
g("exposed-emails").innerHTML=emH||"<tr><td colspan=\"5\" class=\"lt\">No breaches found for monitored emails</td></tr>";
var sumH="";
if(!res.length){
  sumH="<div style=\"padding:16px;color:#64748b;font-size:12px\">Add any email above to check against 700+ known breaches.<br><span style=\"color:#4d9eff\">Powered by HaveIBeenPwned</span></div>";
}else{
  res.forEach(function(em2){
    var erc=em2.riskLevel==="clean"?"low":em2.riskLevel||"low";
    var ecol=erc==="critical"?"#ff3b5c":erc==="high"?"#ff8c42":erc==="medium"?"#f5c518":"#00d4aa";
    sumH+="<div style=\"padding:10px 13px;border-bottom:1px solid #1e2630;display:flex;justify-content:space-between;align-items:flex-start\">";
    sumH+="<div><div style=\"font-family:monospace;font-size:12px;font-weight:700;color:"+ecol+";margin-bottom:4px\">"+esc(em2.email)+"</div>";
    if(em2.breachCount>0){sumH+="<div style=\"font-size:11px;color:#64748b\">Found in: ";(em2.breachNames||[]).slice(0,6).forEach(function(bn){sumH+="<span class=\"tag\">"+esc(bn)+"</span>";});if((em2.breachNames||[]).length>6)sumH+="<span class=\"tag\">+"+(em2.breachNames.length-6)+" more</span>";sumH+="</div>";}
    else{sumH+="<div style=\"font-size:11px;color:#00d4aa\">No breaches found</div>";}
    sumH+="</div><span class=\"risk-badge "+erc+"\">"+(em2.breachCount||0)+" breach"+(em2.breachCount!==1?"es":"")+"</span></div>";
  });
}
var cs=document.getElementById("cred-summary");if(cs)cs.innerHTML=sumH;
}).catch(function(){});
fetch(API+"/credentials/breaches").then(function(r){return r.json();}).then(function(d){
if(!d.success)return;var brs=d.data||[],gbh="";
brs.forEach(function(gbr){
  gbh+="<div class=\"breach-item\"><div class=\"breach-name\">"+esc(gbr.name)+"</div>";
  gbh+="<div class=\"breach-meta\">"+esc(gbr.domain||"-")+" - "+esc(gbr.breachDate||"-")+" - <span style=\"color:#ff8c42\">"+(gbr.pwnCount||0).toLocaleString()+" accounts</span></div>";
  gbh+="<div style=\"margin-top:4px\">"+(gbr.dataClasses||[]).map(function(dc){return "<span class=\"tag\">"+esc(dc)+"</span>";}).join("")+"</div></div>";
});
var gb=document.getElementById("global-breaches");if(gb)gb.innerHTML=gbh||"<div class=\"lt\">No data</div>";
}).catch(function(){});
}

// Collapsible sections on creds page
(function(){
  function makeToggle(headerId,bodyId,toggleId){
    var h=document.getElementById(headerId);
    if(!h)return;
    h.addEventListener("click",function(){
      var b=document.getElementById(bodyId);
      var t=document.getElementById(toggleId);
      if(!b)return;
      var open=b.style.display!=="none";
      b.style.display=open?"none":"block";
      if(t)t.textContent=open?"Click to expand":"Click to collapse";
    });
  }
  makeToggle("summary-header","summary-body","summary-toggle");
  makeToggle("breaches-header","breaches-body","breaches-toggle");
})();

g("add-cred-btn").addEventListener("click",function(){var credEmailVal=g("add-cred-email").value.trim();if(!credEmailVal||credEmailVal.indexOf("@")<0){alert("Enter a valid email");return;}var credBtn=g("add-cred-btn");credBtn.textContent="Checking...";fetch(API+"/monitor/watchlist",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:credEmailVal})}).then(function(){return fetch(API+"/credentials/email/"+encodeURIComponent(credEmailVal));}).then(function(r){return r.json();}).then(function(){g("add-cred-email").value="";credBtn.textContent="+ Monitor Email";loadCreds();}).catch(function(){credBtn.textContent="+ Monitor Email";});});
g("check-btn").addEventListener("click",function(){var checkBtn=g("check-btn");checkBtn.textContent="Checking...";fetch(API+"/monitor/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}).then(function(){setTimeout(function(){checkBtn.textContent="Check All Now";loadCreds();},8000);}).catch(function(){checkBtn.textContent="Check All Now";});});
function loadAlerts(){fetch(API+"/monitor/alerts").then(function(r){return r.json();}).then(function(d){if(!d.success)return;var alts=d.data||[];var acnt=alts.length,adot=g("alert-count");if(acnt>0){adot.textContent=acnt;adot.style.display="inline-block";}else{adot.style.display="none";}g("alerts-badge").textContent=acnt+" ALERTS";if(!alts.length){g("alerts-list").innerHTML="<div class=\"lt\">No alerts yet.</div>";return;}var aicons={new_port:"[PORT]",new_vuln:"[CVE]",credential_leak:"[CRED]",critical_asset:"[ASSET]"};var asevC={critical:"#ff3b5c",high:"#ff8c42",medium:"#f5c518",low:"#00d4aa"};var alh="";for(var ali=0;ali<alts.length;ali++){var alt=alts[ali],asc=asevC[alt.severity]||"#64748b";alh+="<div class=\"alert-item\"><div style=\"font-family:monospace;font-size:11px;color:"+asc+";flex-shrink:0;padding-top:2px\">"+(aicons[alt.type]||"[!]")+"</div><div style=\"flex:1\"><div class=\"alert-msg\">"+esc(alt.message)+"</div><div class=\"alert-time\"><span style=\"color:"+asc+"\">"+esc((alt.severity||"").toUpperCase())+"</span> &bull; "+esc(rel(alt.timestamp))+"</div></div></div>";}g("alerts-list").innerHTML=alh;}).catch(function(){});}
g("clear-alerts-btn").addEventListener("click",loadAlerts);
g("fi").addEventListener("change",go);g("fr").addEventListener("change",go);g("fs").addEventListener("change",go);g("rfbtn").addEventListener("click",rf);
setInterval(function(){var ap=document.querySelector(".page.active");if(!ap)return;if(ap.id==="page-assets")loadAssets();if(ap.id==="page-creds")loadCreds();if(ap.id==="page-alerts")loadAlerts();},30000);
go()

// Ã¢ÂÂÃ¢ÂÂ PRO INTEL MODULE Ã¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂÃ¢ÂÂ
var PROAPI='https://spectacular-wisdom-production.up.railway.app';
var _CN={AF:{n:'Afghanistan',lon:67.7,lat:33.9},AL:{n:'Albania',lon:20.2,lat:41.2},DZ:{n:'Algeria',lon:2.6,lat:28.0},AO:{n:'Angola',lon:17.9,lat:-11.2},AR:{n:'Argentina',lon:-64.0,lat:-34.0},AM:{n:'Armenia',lon:45.0,lat:40.1},AZ:{n:'Azerbaijan',lon:47.6,lat:40.1},BD:{n:'Bangladesh',lon:90.4,lat:23.7},BY:{n:'Belarus',lon:28.0,lat:53.7},BJ:{n:'Benin',lon:2.3,lat:9.3},BO:{n:'Bolivia',lon:-65.0,lat:-17.0},BA:{n:'Bosnia',lon:17.7,lat:44.2},BR:{n:'Brazil',lon:-51.9,lat:-14.2},BF:{n:'Burkina Faso',lon:-1.6,lat:12.4},BI:{n:'Burundi',lon:29.9,lat:-3.4},KH:{n:'Cambodia',lon:104.9,lat:12.6},CM:{n:'Cameroon',lon:12.4,lat:3.8},CF:{n:'C.African Rep.',lon:20.9,lat:6.6},TD:{n:'Chad',lon:18.7,lat:15.5},CN:{n:'China',lon:104.2,lat:35.9},CO:{n:'Colombia',lon:-74.3,lat:4.6},CD:{n:'DR Congo',lon:24.0,lat:-4.0},CI:{n:'Cote dIvoire',lon:-5.6,lat:7.5},CU:{n:'Cuba',lon:-79.5,lat:21.5},EC:{n:'Ecuador',lon:-77.9,lat:-1.8},EG:{n:'Egypt',lon:30.8,lat:26.8},SV:{n:'El Salvador',lon:-88.9,lat:13.8},ET:{n:'Ethiopia',lon:40.5,lat:9.1},GE:{n:'Georgia',lon:43.4,lat:42.3},GH:{n:'Ghana',lon:-1.0,lat:7.9},GT:{n:'Guatemala',lon:-90.2,lat:15.8},GN:{n:'Guinea',lon:-11.4,lat:11.0},HT:{n:'Haiti',lon:-72.3,lat:19.0},HN:{n:'Honduras',lon:-86.2,lat:15.2},IN:{n:'India',lon:78.9,lat:20.6},ID:{n:'Indonesia',lon:113.9,lat:-0.8},IR:{n:'Iran',lon:53.7,lat:32.4},IQ:{n:'Iraq',lon:43.7,lat:33.2},JO:{n:'Jordan',lon:36.2,lat:31.2},KZ:{n:'Kazakhstan',lon:66.9,lat:48.0},KE:{n:'Kenya',lon:37.9,lat:0.0},KP:{n:'North Korea',lon:127.5,lat:40.3},LB:{n:'Lebanon',lon:35.9,lat:33.9},LR:{n:'Liberia',lon:-9.4,lat:6.4},LY:{n:'Libya',lon:17.2,lat:26.3},MG:{n:'Madagascar',lon:46.9,lat:-19.0},ML:{n:'Mali',lon:-1.3,lat:17.6},MR:{n:'Mauritania',lon:-10.9,lat:20.3},MX:{n:'Mexico',lon:-102.5,lat:23.6},MM:{n:'Myanmar',lon:95.9,lat:16.9},NP:{n:'Nepal',lon:84.1,lat:28.4},NI:{n:'Nicaragua',lon:-85.2,lat:12.9},NE:{n:'Niger',lon:8.1,lat:17.6},NG:{n:'Nigeria',lon:8.7,lat:9.1},PK:{n:'Pakistan',lon:69.3,lat:30.4},PS:{n:'Palestine',lon:35.3,lat:31.9},PE:{n:'Peru',lon:-75.0,lat:-9.2},PH:{n:'Philippines',lon:122.9,lat:12.9},RU:{n:'Russia',lon:96.7,lat:61.5},RW:{n:'Rwanda',lon:29.9,lat:-2.0},SN:{n:'Senegal',lon:-14.5,lat:14.5},SO:{n:'Somalia',lon:46.2,lat:6.0},SD:{n:'Sudan',lon:30.2,lat:15.6},SS:{n:'South Sudan',lon:31.3,lat:6.9},SY:{n:'Syria',lon:38.0,lat:35.0},TJ:{n:'Tajikistan',lon:71.3,lat:38.9},TH:{n:'Thailand',lon:100.9,lat:15.9},TG:{n:'Togo',lon:0.8,lat:8.6},TN:{n:'Tunisia',lon:9.5,lat:33.9},TM:{n:'Turkmenistan',lon:59.6,lat:40.5},UG:{n:'Uganda',lon:32.3,lat:1.4},UA:{n:'Ukraine',lon:31.2,lat:49.0},UZ:{n:'Uzbekistan',lon:63.9,lat:41.4},VE:{n:'Venezuela',lon:-66.6,lat:6.4},VN:{n:'Vietnam',lon:108.3,lat:14.1},YE:{n:'Yemen',lon:47.6,lat:15.6},ZM:{n:'Zambia',lon:27.8,lat:-13.1},ZW:{n:'Zimbabwe',lon:29.9,lat:-19.0}};
function _xe(s){return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
function _lc(l){return l==="CRITICAL"?"#ff3b5c":l==="HIGH"?"#ff8c42":l==="ELEVATED"?"#f5c518":l==="MODERATE"?"#4d9eff":"#00d4aa";}
function _chgH(v){if(v==null)return"";var s=v>0?"+":"";var c=v>0?"#ff3b5c":v<0?"#00d4aa":"#64748b";return"<span style=\"color:"+c+";\">" +s+(v*1).toFixed(2)+"</span>";}
function piNav(btn){document.querySelectorAll(".pi-nav-btn").forEach(function(b){b.classList.remove("active");});document.querySelectorAll(".pi-section").forEach(function(s){s.classList.remove("active");});btn.classList.add("active");var sec=document.getElementById("pi-sec-"+btn.dataset.section);if(sec)sec.classList.add("active");}
var _econD=null;
function piEconTab(btn){document.querySelectorAll(".pi-etab").forEach(function(b){b.classList.remove("active");});btn.classList.add("active");if(_econD)_renderEcon(_econD,btn.dataset.etab);}
var _geoRiskMap={};
function _buildSVGMap(data){
  data.forEach(function(c){_geoRiskMap[c.country]=c;});
  var container=document.getElementById("pi-map-container");if(!container)return;
  var svg=document.getElementById("pi-world-svg");svg.innerHTML="";
  function _rwD3(){
    var d3=window.d3;var tj=window.topojson;if(!d3||!tj){setTimeout(_rwD3,300);return;}
    var W=container.offsetWidth||900,H=420;
    svg.setAttribute("width",W);svg.setAttribute("height",H);
    var proj=d3.geoNaturalEarth1().scale(W/6.2).translate([W/2,H/2]);
    var path=d3.geoPath().projection(proj);
    // Create ONE group for everything that should pan/zoom together
    var mapG=d3.select(svg).append("g").attr("class","map-root");
    d3.json("https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json").then(function(world){
      var countries=tj.feature(world,world.objects.countries);
      var borders=tj.mesh(world,world.objects.countries,function(a,b){return a!==b;});
      var grat=d3.geoGraticule();
      mapG.append("rect").attr("width",W).attr("height",H).attr("fill","#060c15");
      mapG.append("path").datum(grat()).attr("d",path).attr("fill","none").attr("stroke","#111d2a").attr("stroke-width","0.4");
      var ISO_NUM={"004":"AF","008":"AL","012":"DZ","024":"AO","032":"AR","051":"AM","031":"AZ","050":"BD","112":"BY","204":"BJ","068":"BO","070":"BA","076":"BR","854":"BF","108":"BI","116":"KH","120":"CM","140":"CF","148":"TD","156":"CN","170":"CO","180":"CD","384":"CI","192":"CU","218":"EC","818":"EG","222":"SV","231":"ET","268":"GE","288":"GH","320":"GT","324":"GN","332":"HT","340":"HN","356":"IN","360":"ID","364":"IR","368":"IQ","400":"JO","398":"KZ","404":"KE","408":"KP","422":"LB","430":"LR","434":"LY","450":"MG","466":"ML","478":"MR","484":"MX","104":"MM","524":"NP","558":"NI","562":"NE","566":"NG","586":"PK","275":"PS","604":"PE","608":"PH","643":"RU","646":"RW","686":"SN","706":"SO","729":"SD","728":"SS","760":"SY","762":"TJ","764":"TH","768":"TG","788":"TN","795":"TM","800":"UG","804":"UA","860":"UZ","862":"VE","704":"VN","887":"YE","894":"ZM","716":"ZW"};
      var tooltip=document.getElementById("pro-map-tooltip");
      var detail=document.getElementById("pro-map-detail");
      mapG.selectAll(".country").data(countries.features).enter().append("path")
        .attr("class","country").attr("d",path)
        .attr("fill",function(f){var code=ISO_NUM[String(f.id).padStart(3,"0")];var c=code&&_geoRiskMap[code];return c?_lc(c.level)+"33":"#1a2535";})
        .attr("stroke",function(f){var code=ISO_NUM[String(f.id).padStart(3,"0")];var c=code&&_geoRiskMap[code];return c?_lc(c.level):"#243044";})
        .attr("stroke-width",function(f){var code=ISO_NUM[String(f.id).padStart(3,"0")];var c=code&&_geoRiskMap[code];return c&&(c.level==="CRITICAL"||c.level==="HIGH")?"1":"0.3";})
        .on("mouseover",function(event,f){
          var code=ISO_NUM[String(f.id).padStart(3,"0")];var c=code&&_geoRiskMap[code];if(!c)return;
          var col=_lc(c.level);var nm=(_CN[code]&&_CN[code].n)||code;
          var drv=(c.drivers||[]).map(function(d){return"<span class=\"pi-ttip-drv\">"+_xe(d)+"</span>";}).join("");
          tooltip.innerHTML="<div class=\"pi-ttip-name\" style=\"color:"+col+"\">"+_xe(nm)+" <span class=\"pi-ttip-code\">"+code+"</span></div>";
          tooltip.innerHTML+="<div class=\"pi-ttip-score\"><span style=\"color:"+col+";font-size:26px;font-weight:900\">"+c.score+"</span><span style=\"color:"+col+";font-size:11px;margin-left:5px\">"+c.level+"</span></div>";
          tooltip.innerHTML+="<div class=\"pi-ttip-trend\">Trend: "+c.trend+"</div>";
          if(drv)tooltip.innerHTML+="<div class=\"pi-ttip-drvs\">"+drv+"</div>";
          tooltip.style.display="block";tooltip.style.left=(event.offsetX+14)+"px";tooltip.style.top=Math.max(0,event.offsetY-20)+"px";
          d3.select(this).attr("fill",col+"99");
        })
        .on("mousemove",function(event){tooltip.style.left=(event.offsetX+14)+"px";tooltip.style.top=Math.max(0,event.offsetY-20)+"px";})
        .on("mouseout",function(event,f){tooltip.style.display="none";var code=ISO_NUM[String(f.id).padStart(3,"0")];var c=code&&_geoRiskMap[code];d3.select(this).attr("fill",c?_lc(c.level)+"33":"#1a2535");})
        .on("click",function(event,f){
          var code=ISO_NUM[String(f.id).padStart(3,"0")];var c=code&&_geoRiskMap[code];if(!c||!detail)return;
          var col=_lc(c.level);var nm=(_CN[code]&&_CN[code].n)||code;
          var drvH=(c.drivers||[]).map(function(d){return"<span class=\"pi-det-drv\" style=\"border-color:"+col+";color:"+col+"\">"+_xe(d)+"</span>";}).join("");
          detail.style.display="block";
          detail.innerHTML="<div class=\"pi-det-inner\"><div><div class=\"pi-det-name\">"+_xe(nm)+" <span class=\"pi-det-code\">["+code+"]</span></div><div class=\"pi-det-score-row\"><span class=\"pi-det-score\" style=\"color:"+col+"\">"+c.score+"</span><span class=\"pi-det-lvl\" style=\"color:"+col+"\">"+c.level+"</span></div><div class=\"pi-det-trend\">Trend: <span>"+c.trend+"</span></div>"+(drvH?"<div class=\"pi-det-drvs-hdr\">Risk Drivers</div><div class=\"pi-det-drvs\">"+drvH+"</div>":"")+"</div><button class=\"pi-det-close\" id=\"pi-det-cls\">&#10005;</button></div>";
          document.getElementById("pi-det-cls").onclick=function(){detail.style.display="none";};
        });
      mapG.append("path").datum(borders).attr("d",path).attr("fill","none").attr("stroke","#1e2d3d").attr("stroke-width","0.5");
      // Pan + zoom Ã¢ÂÂ svg zooms the mapG group
      var zoom=d3.zoom().scaleExtent([0.5,8]).on("zoom",function(event){
        mapG.attr("transform",event.transform);
      });
      d3.select(svg).call(zoom).on("dblclick.zoom",null);
      // Reset zoom button hint
      var resetHint=document.createElement("div");
      resetHint.style.cssText="position:absolute;bottom:8px;right:8px;font-size:10px;color:#64748b;background:#0a0e14;border:1px solid #1e2630;padding:3px 8px;border-radius:3px;cursor:pointer;user-select:none";
      resetHint.textContent="Scroll to zoom ÃÂ· Drag to pan ÃÂ· Dbl-click reset";
      resetHint.title="Double-click to reset zoom";
      resetHint.ondblclick=function(){d3.select(svg).transition().duration(500).call(zoom.transform,d3.zoomIdentity);};
      container.appendChild(resetHint);
      d3.select(svg).on("dblclick.zoom",function(){d3.select(svg).transition().duration(500).call(zoom.transform,d3.zoomIdentity);});

      data.filter(function(c){return c.level==="CRITICAL"||c.level==="HIGH";}).forEach(function(c){
        var info=_CN[c.country];if(!info)return;var xy=proj([info.lon,info.lat]);if(!xy)return;var col=_lc(c.level);
        mapG.append("circle").attr("cx",xy[0]).attr("cy",xy[1]).attr("r",c.level==="CRITICAL"?7:5).attr("fill",col).attr("opacity","0.9").attr("pointer-events","none");
        if(c.level==="CRITICAL"){mapG.append("circle").attr("cx",xy[0]).attr("cy",xy[1]).attr("r",12).attr("fill","none").attr("stroke",col).attr("stroke-width","1.2").attr("opacity","0.45").attr("pointer-events","none");}
        mapG.append("text").attr("x",xy[0]).attr("y",xy[1]-11).attr("text-anchor","middle").attr("font-size","9").attr("fill",col).attr("font-family","monospace").attr("font-weight","700").attr("pointer-events","none").text(c.country);
      });
      var leg=document.getElementById("pi-map-legend");if(leg)leg.innerHTML=[["CRITICAL","#ff3b5c"],["HIGH","#ff8c42"],["ELEVATED","#f5c518"],["MODERATE","#4d9eff"],["LOW","#00d4aa"]].map(function(lv){return"<span class=\"pi-legend-item\"><span class=\"pi-legend-dot\" style=\"background:"+lv[1]+"\"></span>"+lv[0]+"</span>";}).join("");
    }).catch(function(e){console.error("Map load failed",e);});
  }
  if(!window.d3||!window.topojson){var s1=document.createElement("script");s1.src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js";s1.onload=function(){var s2=document.createElement("script");s2.src="https://cdnjs.cloudflare.com/ajax/libs/topojson/3.0.2/topojson.min.js";s2.onload=_rwD3;document.head.appendChild(s2);};document.head.appendChild(s1);}else _rwD3();
}
function _renderEcon(d,tab){
  _econD=d;var macro=d.macro_signals||[],risks=d.risk_assessments||[],overall=d.overall_risk||"MEDIUM",concern=d.primary_concern||"";
  var mr=g("pro-macro-risk");if(mr){var mc=overall==="HIGH"||overall==="CRITICAL"?"#ff3b5c":overall==="MEDIUM"?"#f5c518":"#00d4aa";mr.style.color=mc;mr.style.fontWeight="700";mr.textContent=overall+(concern?" - "+concern.replace(/_/g," ").toUpperCase():"");}
  var el2=g("pro-econ-list");if(!el2)return;
  if(!tab||tab==="overview"){
    var h="<div class=\"pi-risk-cards\">";risks.forEach(function(r2){var rc=r2.risk==="HIGH"||r2.risk==="CRITICAL"?"#ff3b5c":r2.risk==="MEDIUM"?"#f5c518":"#00d4aa";h+="<div class=\"pi-risk-card\" style=\"border-color:"+rc+"40\"><div class=\"pi-risk-card-lbl\">"+_xe((r2.signal||"").replace(/_/g," "))+"</div><div class=\"pi-risk-card-val\" style=\"color:"+rc+"\">"+_xe(r2.risk||"?")+"</div>"+(r2.status&&r2.status!=="unknown"?"<div class=\"pi-risk-card-sub\">"+_xe(r2.status)+"</div>":"")+(r2.spread!=null?"<div class=\"pi-risk-card-sub\">Spread: "+r2.spread.toFixed(2)+"</div>":"")+"</div>";});h+="</div><div class=\"pi-indicator-table\">";
    macro.forEach(function(m){var vc=m.series_id==="VIXCLS"||m.series_id==="GVZCLS"?(m.value>30?"#ff3b5c":m.value>20?"#f5c518":"#00d4aa"):m.series_id==="T10Y2Y"?(m.value<0?"#ff3b5c":m.value<0.5?"#f5c518":"#00d4aa"):m.series_id==="STLFSI4"?(m.value>1?"#ff3b5c":m.value>0?"#f5c518":"#00d4aa"):"#e2e8f0";h+="<div class=\"pi-ind-row\"><div class=\"pi-ind-info\"><div class=\"pi-ind-name\">"+_xe(m.name)+"</div><div class=\"pi-ind-meta\">"+_xe(m.series_id)+" &bull; "+_xe(m.date||"")+"</div></div><div class=\"pi-ind-val\" style=\"color:"+vc+"\">"+_xe(m.value!=null?(m.value*1).toFixed(2):"--")+"</div><div class=\"pi-ind-chg\">"+_chgH(m.change)+"</div></div>";});h+="</div>";
    el2.innerHTML=h;
  } else {
    var ids=tab==="rates"?["DFF","T10Y2Y","BAMLH0A0HYM2"]:tab==="volatility"?["VIXCLS","GVZCLS","STLFSI4"]:["DCOILWTICO","DTWEXBGS"];
    var filtered=macro.filter(function(m){return ids.indexOf(m.series_id)>=0;});
    var titles2={"rates":"Interest Rates & Credit Spreads","volatility":"Market Volatility & Stress","commodities":"Commodities & Currency"};
    var h2="<div class=\"pi-ind-sec-title\">"+( titles2[tab]||"")+"</div><div class=\"pi-signal-cards\">";
    filtered.forEach(function(m){var vc=m.series_id==="VIXCLS"||m.series_id==="GVZCLS"?(m.value>30?"#ff3b5c":m.value>20?"#f5c518":"#00d4aa"):m.series_id==="T10Y2Y"?(m.value<0?"#ff3b5c":m.value<0.5?"#f5c518":"#00d4aa"):m.series_id==="STLFSI4"?(m.value>1?"#ff3b5c":m.value>0?"#f5c518":"#00d4aa"):"#4d9eff";var base=m.value!=null?m.value*1:0;var chg=m.change!=null?m.change*1:0;var bars=[base-chg*3.5,base-chg*2.8,base-chg*2.1,base-chg*1.5,base-chg*0.9,base-chg*0.4,base-chg*0.1,base];var bmin=Math.min.apply(null,bars),bmax=Math.max.apply(null,bars),br=bmax-bmin||1;var bh=bars.map(function(bv,bi){return"<div style=\"flex:1;height:"+Math.max(3,Math.round((bv-bmin)/br*52))+"px;background:"+(bi===7?vc:"#1e2d3d")+";border-radius:1px 1px 0 0;align-self:flex-end\"></div>";}).join("");h2+="<div class=\"pi-sig-card\"><div class=\"pi-sig-header\"><div><div class=\"pi-sig-name\">"+_xe(m.name)+"</div><div class=\"pi-sig-id\">"+_xe(m.series_id)+" &bull; "+_xe(m.date||"")+"</div></div><div class=\"pi-sig-val-block\"><div class=\"pi-sig-val\" style=\"color:"+vc+"\">"+_xe(m.value!=null?(m.value*1).toFixed(2):"--")+"</div><div class=\"pi-sig-chg\">"+_chgH(m.change)+" vs prev</div></div></div><div class=\"pi-sig-chart\">"+bh+"</div></div>";});
    h2+="</div>";
    el2.innerHTML=h2;
  }
}
function loadPro(){
  var gb=g("pi-geo-badge"),cb=g("pi-cyber-badge"),eb=g("pi-econ-badge");
  if(gb)gb.textContent="...";if(cb)cb.textContent="...";if(eb)eb.textContent="...";
  fetch(PROAPI+"/geo/cii").then(function(r){return r.json();}).then(function(d){
    var data=d.data||[];if(gb)gb.textContent=data.length;var cc=g("pro-crit-countries");if(cc)cc.textContent=data.filter(function(c){return c.level==="CRITICAL";}).length;var geoBadge=g("pro-geo-badge");if(geoBadge)geoBadge.textContent=data.length+" COUNTRIES";
    var gh=g("pro-geo-hotspots");if(gh){var hh="";data.filter(function(c){return c.level==="CRITICAL";}).slice(0,7).forEach(function(c){var nm=(_CN[c.country]&&_CN[c.country].n)||c.country;hh+="<span class=\"pi-hotspot\" title=\""+nm+"\">"+_xe(c.country)+" "+c.score+"</span>";});gh.innerHTML=hh?"<div class=\"pi-hotspot-lbl\">&#9888; Critical Hotspots</div>"+hh:"";}
    _buildSVGMap(data);
    var lh="";data.slice(0,20).forEach(function(c){var col=_lc(c.level);var nm=(_CN[c.country]&&_CN[c.country].n)||c.country;var drvs=c.drivers||[];var drvH=drvs.map(function(dr){return"<span class=\"pi-drv-tag\">"+_xe(dr)+"</span>";}).join("");var trend=c.trend==="improving"?"&#8679;":c.trend==="deteriorating"?"&#8681;":"&#8596;";var tc=c.trend==="improving"?"#00d4aa":c.trend==="deteriorating"?"#ff3b5c":"#64748b";lh+="<div class=\"pi-crow\"><div class=\"pi-crow-hdr\"><span class=\"pi-ccode\" style=\"color:"+col+";border-color:"+col+"\">"+_xe(c.country)+"</span><span class=\"pi-cname\">"+_xe(nm)+"</span><div class=\"pi-cbar-wrap\"><div class=\"pi-cbar\" style=\"width:"+c.score+"%;background:"+col+"\"></div></div><span class=\"pi-cscore\" style=\"color:"+col+"\">"+c.score+"</span><span class=\"pi-clvl\" style=\"color:"+col+"\">"+c.level+"</span><span class=\"pi-ctrend\" style=\"color:"+tc+"\">"+trend+"</span></div>"+(drvH?"<div class=\"pi-drv-row\">"+drvH+"</div>":"")+"</div>";});
    var gl=g("pro-geo-list");if(gl){gl.innerHTML=lh||"<div class=\"lt\">No data</div>";gl.querySelectorAll(".pi-crow-hdr").forEach(function(h){h.addEventListener("click",function(){var r=h.nextElementSibling;if(r&&r.classList.contains("pi-drv-row")){r.style.display=r.style.display==="flex"?"none":"flex";}});});}
  }).catch(function(){if(gb)gb.textContent="!"});
  fetch(PROAPI+"/cyber/threats").then(function(r){return r.json();}).then(function(d){
    var c2=d.c2_servers||[],mal=d.malware_domains||[],pul=d.threat_pulses||[],sum=d.summary||{};
    var tot=c2.length+mal.length+pul.length;if(cb)cb.textContent=tot;var pc=g("pro-c2-count");if(pc)pc.textContent=c2.length;
    var cyberBadge=g("pro-cyber-badge");if(cyberBadge)cyberBadge.textContent=c2.length+" C2 ÃÂ· "+mal.length+" URLs ÃÂ· "+pul.length+" PULSES";
    var h="";
    // Summary stats row
    h+="<div class=\"ct-stats\">";
    h+="<div class=\"ct-stat\"><div class=\"ct-stat-val ct-crit\">"+( sum.critical||0)+"</div><div class=\"ct-stat-lbl\">CRITICAL</div></div>";
    h+="<div class=\"ct-stat\"><div class=\"ct-stat-val ct-high\">"+( sum.high||0)+"</div><div class=\"ct-stat-lbl\">HIGH</div></div>";
    h+="<div class=\"ct-stat\"><div class=\"ct-stat-val\">"+c2.length+"</div><div class=\"ct-stat-lbl\">C2 SERVERS</div></div>";
    h+="<div class=\"ct-stat\"><div class=\"ct-stat-val\">"+mal.length+"</div><div class=\"ct-stat-lbl\">MALWARE URLs</div></div>";
    if(sum.malware_families&&sum.malware_families.length){h+="<div class=\"ct-stat ct-stat-wide\"><div class=\"ct-stat-lbl\" style=\"margin-bottom:4px\">ACTIVE FAMILIES</div><div class=\"ct-families\">";sum.malware_families.forEach(function(f){h+="<span class=\"ct-fam-tag\">"+_xe(f)+"</span>";});h+="</div></div>";}
    h+="</div>";
    // C2 server cards
    if(c2.length){
      h+="<div class=\"ct-section-hdr\">&#9888; Active C2 Servers <span class=\"ct-count\">"+c2.length+"</span></div>";
      c2.slice(0,20).forEach(function(s){
        var sc=s.severity==="CRITICAL"?"#ff3b5c":s.severity==="HIGH"?"#ff8c42":s.severity==="MEDIUM"?"#f5c518":"#4d9eff";
        var flag=s.country_code?String.fromCodePoint(...s.country_code.split("").map(function(c){return c.charCodeAt(0)+127397;})):"";
        var geo="";
        if(s.city&&s.country)geo=_xe(s.city)+", "+_xe(s.country);
        else if(s.country)geo=_xe(s.country);
        var last=s.last_seen?s.last_seen.substring(0,10):"";
        h+="<div class=\"ct-c2-card\">";
        h+="<div class=\"ct-c2-top\">";
        h+="<div class=\"ct-c2-left\">";
        h+="<div class=\"ct-sev-pill\" style=\"background:"+sc+"22;color:"+sc+";border-color:"+sc+"44\">"+_xe(s.severity||"HIGH")+"</div>";
        h+="<div class=\"ct-ip-row\">";
        h+="<span class=\"ct-ip\">"+_xe(s.ip_address||s.ip||"-")+"</span>";
        h+="<span class=\"ct-port\">:"+_xe(String(s.port||443))+"</span>";
        h+="<button class=\"ct-copy\" onclick=\"navigator.clipboard.writeText('"+_xe(s.ip_address||s.ip||"")+"')\">&#128203;</button>";
        h+="</div>";
        h+="<div class=\"ct-fam-row\">";
        h+="<span class=\"ct-fam-badge\" style=\"color:"+sc+"\">"+_xe(s.malware_family||"Unknown")+"</span>";
        h+="<span class=\"ct-fam-cat\">"+_xe(s.malware_cat||"Malware")+"</span>";
        h+="</div>";
        if(s.malware_desc)h+="<div class=\"ct-fam-desc\">"+_xe(s.malware_desc)+"</div>";
        h+="</div>";
        h+="<div class=\"ct-c2-right\">";
        if(geo)h+="<div class=\"ct-geo\">"+( flag?" "+flag+" ":"")+geo+"</div>";
        if(s.isp)h+="<div class=\"ct-isp\">"+_xe(s.isp.substring(0,40))+"</div>";
        if(s.asn)h+="<div class=\"ct-asn\">"+_xe(s.asn.substring(0,30))+"</div>";
        var badges="";
        if(s.is_proxy)badges+="<span class=\"ct-badge ct-badge-warn\">PROXY</span>";
        if(s.is_hosting)badges+="<span class=\"ct-badge ct-badge-info\">HOSTING</span>";
        if(badges)h+="<div class=\"ct-badges\">"+badges+"</div>";
        h+="<div class=\"ct-meta-row\">";
        h+="<span class=\"ct-src-tag\">"+_xe(s.source||"feodo")+"</span>";
        if(last)h+="<span class=\"ct-last-seen\">Last: "+_xe(last)+"</span>";
        h+="<span class=\"ct-conf\">"+_xe(s.confidence||"high")+"</span>";
        h+="</div>";
        h+="</div></div></div>";
      });
    }
    // Malware domains section
    if(mal.length){
      h+="<div class=\"ct-section-hdr\">&#127760; Malware URLs <span class=\"ct-count\">"+mal.length+"</span></div>";
      mal.slice(0,15).forEach(function(m){
        var tags=(m.tags||[]).map(function(t){return"<span class=\"ct-tag\">"+_xe(t)+"</span>";}).join("");
        h+="<div class=\"ct-url-row\">";
        h+="<div class=\"ct-url-top\">";
        h+="<span class=\"ct-threat-type\">"+_xe((m.threat||"malware").replace(/_/g," ").toUpperCase())+"</span>";
        h+="<span class=\"ct-domain\">"+_xe((m.domain||"").substring(0,60))+"</span>";
        h+="<button class=\"ct-copy\" onclick=\"navigator.clipboard.writeText('"+_xe(m.url||"")+"')\">&#128203;</button>";
        h+="</div>";
        h+="<div class=\"ct-url-full\">"+_xe((m.url||"").substring(0,100))+"</div>";
        if(tags)h+="<div class=\"ct-tag-row\">"+tags+"</div>";
        if(m.date_added)h+="<div class=\"ct-url-date\">Added: "+_xe(m.date_added.substring(0,10))+"</div>";
        h+="</div>";
      });
    }
    // Pulses
    if(pul.length){
      h+="<div class=\"ct-section-hdr\">&#128268; Threat Pulses <span class=\"ct-count\">"+pul.length+"</span></div>";
      pul.slice(0,8).forEach(function(p){
        h+="<div class=\"ct-pulse-card\">";
        h+="<div class=\"ct-pulse-name\">"+_xe((p.name||"").substring(0,80))+"</div>";
        h+="<div class=\"ct-pulse-meta\">";
        if(p.author)h+="<span class=\"ct-pulse-author\">by "+_xe(p.author)+"</span>";
        if(p.indicators)h+="<span class=\"ct-pulse-ioc\">"+p.indicators+" IOCs</span>";
        h+="</div>";
        h+="</div>";
      });
    }
    if(!c2.length&&!mal.length&&!pul.length)h="<div class=\"pi-no-data\">&#128274; No active threats in live feeds</div>";
    var cl=g("pro-cyber-list");if(cl)cl.innerHTML=h;
  }).catch(function(){if(cb)cb.textContent="!"});
  fetch(PROAPI+"/economic/signals").then(function(r){return r.json();}).then(function(d){
    var econBadge=g("pro-econ-badge");if(econBadge)econBadge.textContent=(d.macro_signals||[]).length+" INDICATORS";if(eb)eb.textContent=(d.macro_signals||[]).length;_renderEcon(d,"overview");
  }).catch(function(){if(eb)eb.textContent="!"});
  fetch(PROAPI+"/ai/status").then(function(r){return r.json();}).then(function(d){
    var as=g("pro-ai-status");if(as){as.textContent=d.available?"READY":"OFFLINE";as.style.color=d.available?"#00d4aa":"#ff3b5c";}
    var aib=g("pi-ai-badge");if(aib)aib.textContent=d.available?"READY":"OFF";
    var ab=g("pro-ai-btn");if(ab){if(!d.available){ab.disabled=true;ab.style.opacity="0.4";var ar=g("pro-ai-result");if(ar)ar.innerHTML="<div class=\"pi-ai-note\">GROQ_KEY required.</div>";}else{ab.disabled=false;ab.style.opacity="1";ab.onclick=function(){var inp=g("pro-ai-input");if(!inp||!inp.value.trim())return;var ar2=g("pro-ai-result");if(ar2)ar2.innerHTML="<div class=\"pi-ai-thinking\">&#129504; Analysing...</div>";ab.disabled=true;fetch(PROAPI+"/ai/deduct",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({query:inp.value.trim(),context:"DARKWATCH threat intelligence platform"})}).then(function(r2){return r2.json();}).then(function(res){ab.disabled=false;if(!ar2)return;var _rl=res.risk_level||res.risk||res.threat_level||"";var _mt=res.deduction||res.analysis||res.summary||res.result||res.content||"";if(!_mt&&typeof res==="object"){var _keys=["deduction","analysis","summary","result","content","text","response","assessment","findings"];for(var _ki=0;_ki<_keys.length;_ki++){if(res[_keys[_ki]]){_mt=res[_keys[_ki]];break;}}}if(!_mt)_mt=JSON.stringify(res,null,2);var html="<div class=\"pi-ai-response\">";if(_rl)html+="<div class=\"pi-ai-risk-level\" style=\"color:"+(_rl==="HIGH"||_rl==="CRITICAL"?"#ff3b5c":_rl==="MEDIUM"?"#f5c518":"#00d4aa")+"\">&#9888; Risk Level: "+_xe(_rl)+"</div>";html+="<div class=\"pi-ai-text\">"+_xe(String(_mt))+"</div>";if(res.recommendations&&res.recommendations.length){html+="<div class=\"pi-ai-recs-hdr\">Recommendations</div><ul class=\"pi-ai-recs\">";res.recommendations.forEach(function(rec){html+="<li>"+_xe(rec)+"</li>";});html+="</ul>";}html+="</div>";ar2.innerHTML=html;}).catch(function(err){ab.disabled=false;if(ar2)ar2.innerHTML="<div class=\"pi-ai-note\">Error: "+_xe(err.message)+"</div>";});};}}
  }).catch(function(){});
}
// Wire nav buttons - use closest() so clicks on child spans still work
document.querySelectorAll(".pi-nav-btn").forEach(function(btn){
  btn.addEventListener("click",function(e){
    var b=e.target.closest(".pi-nav-btn");if(b)piNav(b);
  });
});
// Wire econ tabs
document.querySelectorAll(".pi-etab").forEach(function(btn){
  btn.addEventListener("click",function(e){
    var b=e.target.closest(".pi-etab");if(b)piEconTab(b);
  });
});
// Wire refresh
var _prf=document.getElementById("pro-refresh-btn");
if(_prf)_prf.addEventListener("click",loadPro);
var _prb=g('pro-refresh-btn');if(_prb)_prb.addEventListener('click',loadPro);

window.loadPro=typeof loadPro!=="undefined"?loadPro:function(){};
window.piNav=typeof piNav!=="undefined"?piNav:function(){};

  // ── Credentials + IntelX button wiring (capture phase to beat global listeners) ──
  (function(){
    function wireSearchBtn(sectionId, inputId, fnName){
      var sec = document.getElementById(sectionId);
      if(!sec) return;
      var btn = sec.querySelector('button');
      if(!btn) return;
      btn.addEventListener('click', function(e){
        e.stopPropagation();
        e.preventDefault();
        var val = document.getElementById(inputId)&&document.getElementById(inputId).value;
        if(val && window[fnName]) window[fnName](val);
      }, true); // capture phase
      var inp = document.getElementById(inputId);
      if(inp) inp.addEventListener('keydown', function(e){
        if(e.key==='Enter'){ e.stopPropagation(); if(window[fnName]) window[fnName](e.target.value); }
      }, true);
    }
    setTimeout(function(){
      wireSearchBtn('pi-sec-credentials','cred-domain-input','searchCredentials');
      wireSearchBtn('pi-sec-intelx','intelx-input','searchIntelX');
    }, 800);
  })();


})();
