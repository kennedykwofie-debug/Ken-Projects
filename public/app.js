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

// ── Bulk Import Panel ────────────────────────────────────────────────────────
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

// ── PRO INTEL MODULE ──────────────────────────────────────────────────────────
var PROAPI='https://spectacular-wisdom-production.up.railway.app';
var _CN={AF:{n:'Afghanistan',lon:67.7,lat:33.9},AL:{n:'Albania',lon:20.2,lat:41.2},DZ:{n:'Algeria',lon:2.6,lat:28.0},AO:{n:'Angola',lon:17.9,lat:-11.2},AR:{n:'Argentina',lon:-64.0,lat:-34.0},AM:{n:'Armenia',lon:45.0,lat:40.1},AZ:{n:'Azerbaijan',lon:47.6,lat:40.1},BD:{n:'Bangladesh',lon:90.4,lat:23.7},BY:{n:'Belarus',lon:28.0,lat:53.7},BJ:{n:'Benin',lon:2.3,lat:9.3},BO:{n:'Bolivia',lon:-65.0,lat:-17.0},BA:{n:'Bosnia',lon:17.7,lat:44.2},BR:{n:'Brazil',lon:-51.9,lat:-14.2},BF:{n:'Burkina Faso',lon:-1.6,lat:12.4},BI:{n:'Burundi',lon:29.9,lat:-3.4},KH:{n:'Cambodia',lon:104.9,lat:12.6},CM:{n:'Cameroon',lon:12.4,lat:3.8},CF:{n:'C.African Rep.',lon:20.9,lat:6.6},TD:{n:'Chad',lon:18.7,lat:15.5},CN:{n:'China',lon:104.2,lat:35.9},CO:{n:'Colombia',lon:-74.3,lat:4.6},CD:{n:'DR Congo',lon:24.0,lat:-4.0},CI:{n:"Cote d'Ivoire",lon:-5.6,lat:7.5},CU:{n:'Cuba',lon:-79.5,lat:21.5},EC:{n:'Ecuador',lon:-77.9,lat:-1.8},EG:{n:'Egypt',lon:30.8,lat:26.8},SV:{n:'El Salvador',lon:-88.9,lat:13.8},ET:{n:'Ethiopia',lon:40.5,lat:9.1},GE:{n:'Georgia',lon:43.4,lat:42.3},GH:{n:'Ghana',lon:-1.0,lat:7.9},GT:{n:'Guatemala',lon:-90.2,lat:15.8},GN:{n:'Guinea',lon:-11.4,lat:11.0},GW:{n:'Guinea-Bissau',lon:-15.2,lat:12.0},HT:{n:'Haiti',lon:-72.3,lat:19.0},HN:{n:'Honduras',lon:-86.2,lat:15.2},IN:{n:'India',lon:78.9,lat:20.6},ID:{n:'Indonesia',lon:113.9,lat:-0.8},IR:{n:'Iran',lon:53.7,lat:32.4},IQ:{n:'Iraq',lon:43.7,lat:33.2},JM:{n:'Jamaica',lon:-77.3,lat:18.1},JO:{n:'Jordan',lon:36.2,lat:31.2},KZ:{n:'Kazakhstan',lon:66.9,lat:48.0},KE:{n:'Kenya',lon:37.9,lat:0.0},KP:{n:'North Korea',lon:127.5,lat:40.3},LB:{n:'Lebanon',lon:35.9,lat:33.9},LR:{n:'Liberia',lon:-9.4,lat:6.4},LY:{n:'Libya',lon:17.2,lat:26.3},MG:{n:'Madagascar',lon:46.9,lat:-19.0},MW:{n:'Malawi',lon:34.3,lat:-13.3},ML:{n:'Mali',lon:-1.3,lat:17.6},MR:{n:'Mauritania',lon:-10.9,lat:20.3},MX:{n:'Mexico',lon:-102.5,lat:23.6},MD:{n:'Moldova',lon:28.4,lat:47.4},MZ:{n:'Mozambique',lon:35.5,lat:-18.7},MM:{n:'Myanmar',lon:95.9,lat:16.9},NP:{n:'Nepal',lon:84.1,lat:28.4},NI:{n:'Nicaragua',lon:-85.2,lat:12.9},NE:{n:'Niger',lon:8.1,lat:17.6},NG:{n:'Nigeria',lon:8.7,lat:9.1},PK:{n:'Pakistan',lon:69.3,lat:30.4},PS:{n:'Palestine',lon:35.3,lat:31.9},PA:{n:'Panama',lon:-80.8,lat:8.5},PY:{n:'Paraguay',lon:-58.5,lat:-23.4},PE:{n:'Peru',lon:-75.0,lat:-9.2},PH:{n:'Philippines',lon:122.9,lat:12.9},RU:{n:'Russia',lon:96.7,lat:61.5},RW:{n:'Rwanda',lon:29.9,lat:-2.0},SN:{n:'Senegal',lon:-14.5,lat:14.5},SO:{n:'Somalia',lon:46.2,lat:6.0},SD:{n:'Sudan',lon:30.2,lat:15.6},SS:{n:'South Sudan',lon:31.3,lat:6.9},SY:{n:'Syria',lon:38.0,lat:35.0},TJ:{n:'Tajikistan',lon:71.3,lat:38.9},TH:{n:'Thailand',lon:100.9,lat:15.9},TL:{n:'Timor-Leste',lon:125.7,lat:-8.9},TG:{n:'Togo',lon:0.8,lat:8.6},TN:{n:'Tunisia',lon:9.5,lat:33.9},TM:{n:'Turkmenistan',lon:59.6,lat:40.5},UG:{n:'Uganda',lon:32.3,lat:1.4},UA:{n:'Ukraine',lon:31.2,lat:49.0},UZ:{n:'Uzbekistan',lon:63.9,lat:41.4},VE:{n:'Venezuela',lon:-66.6,lat:6.4},VN:{n:'Vietnam',lon:108.3,lat:14.1},YE:{n:'Yemen',lon:47.6,lat:15.6},ZM:{n:'Zambia',lon:27.8,lat:-13.1},ZW:{n:'Zimbabwe',lon:29.9,lat:-19.0}};
function _xe(s){return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
function _lvlCol(l){return l==="CRITICAL"?"#ff3b5c":l==="HIGH"?"#ff8c42":l==="ELEVATED"?"#f5c518":l==="MODERATE"?"#4d9eff":"#00d4aa";}
function _chgHtml(v){if(v==null)return"";var s=v>0?"+":"";var c=v>0?"#ff3b5c":v<0?"#00d4aa":"#64748b";return'<span style="color:'+c+';font-size:11px;margin-left:4px">'+s+(v*1).toFixed(2)+'</span>';}
var _mapData=null,_mapSelected=null;
function _lonLatToXY(lon,lat,W,H){
  var x=(lon+180)/360*W;
  var latR=lat*Math.PI/180;
  var y=H/2-W*Math.log(Math.tan(Math.PI/4+latR/2))/(2*Math.PI);
  return [x,y];
}
function _drawMap(data,W,H,ctx){
  ctx.fillStyle="#0a0e14";ctx.fillRect(0,0,W,H);
  // Draw graticule grid
  ctx.strokeStyle="#111820";ctx.lineWidth=0.5;
  for(var lon=-180;lon<=180;lon+=30){var xy1=_lonLatToXY(lon,-85,W,H);var xy2=_lonLatToXY(lon,85,W,H);ctx.beginPath();ctx.moveTo(xy1[0],xy1[1]);ctx.lineTo(xy2[0],xy2[1]);ctx.stroke();}
  for(var lat2=-60;lat2<=60;lat2+=30){ctx.beginPath();for(var lo=-180;lo<=180;lo+=1){var p=_lonLatToXY(lo,lat2,W,H);if(lo===-180)ctx.moveTo(p[0],p[1]);else ctx.lineTo(p[0],p[1]);}ctx.stroke();}
  // Draw country dots sized by risk
  var byCode={};
  data.forEach(function(c){byCode[c.country]=c;});
  Object.keys(_CN).forEach(function(code){
    var info=_CN[code];var xy=_lonLatToXY(info.lon,info.lat,W,H);
    var c=byCode[code];
    if(c){
      var col=_lvlCol(c.level);var r=c.score>=85?7:c.score>=70?5:c.score>=50?4:3;
      ctx.beginPath();ctx.arc(xy[0],xy[1],r+2,0,2*Math.PI);ctx.fillStyle="rgba(0,0,0,0.3)";ctx.fill();
      ctx.beginPath();ctx.arc(xy[0],xy[1],r,0,2*Math.PI);ctx.fillStyle=col;ctx.fill();
      if(c.score>=80){ctx.beginPath();ctx.arc(xy[0],xy[1],r+4,0,2*Math.PI);ctx.strokeStyle=col;ctx.lineWidth=1;ctx.globalAlpha=0.3;ctx.stroke();ctx.globalAlpha=1;}
    } else {
      ctx.beginPath();ctx.arc(xy[0],xy[1],2,0,2*Math.PI);ctx.fillStyle="#1e2630";ctx.fill();
    }
  });
  // Legend
  var lx=12,ly=H-60;var levels=[["CRITICAL","#ff3b5c"],["HIGH","#ff8c42"],["ELEVATED","#f5c518"],["MODERATE","#4d9eff"],["LOW","#00d4aa"]];
  ctx.font="9px monospace";
  levels.forEach(function(lv,i){ctx.beginPath();ctx.arc(lx+6,ly+i*14,4,0,2*Math.PI);ctx.fillStyle=lv[1];ctx.fill();ctx.fillStyle="#94a3b8";ctx.fillText(lv[0],lx+14,ly+i*14+4);});
}
function _initMap(data,W,H){
  _mapData=data;
  var canvas=document.getElementById("pro-map-canvas");
  if(!canvas)return;
  canvas.width=W;canvas.height=H;
  var ctx=canvas.getContext("2d");
  _drawMap(data,W,H,ctx);
  var byCode={};data.forEach(function(c){byCode[c.country]=c;});
  function getHit(ex,ey){
    var best=null,bestD=99;
    Object.keys(_CN).forEach(function(code){
      var info=_CN[code];var xy=_lonLatToXY(info.lon,info.lat,W,H);
      var d=Math.sqrt(Math.pow(ex-xy[0],2)+Math.pow(ey-xy[1],2));
      if(d<12&&d<bestD){bestD=d;best=code;}
    });
    return best;
  }
  var tt=document.getElementById("pro-map-tooltip");
  canvas.addEventListener("mousemove",function(e){
    var r=canvas.getBoundingClientRect();var sx=W/r.width,sy=H/r.height;
    var ex=(e.clientX-r.left)*sx,ey=(e.clientY-r.top)*sy;
    var code=getHit(ex,ey);
    if(code&&byCode[code]){
      var c=byCode[code];var col=_lvlCol(c.level);
      var drivers=(c.drivers||[]).map(function(d){return'<span style="display:inline-block;margin:1px 2px 0;padding:1px 6px;border-radius:8px;font-size:10px;background:#161b22;border:1px solid #2a3440;color:#94a3b8">'+_xe(d)+'</span>';}).join("");
      tt.innerHTML='<div style="font-size:13px;font-weight:700;color:'+col+'">'+_xe(_CN[code].n)+' <span style="font-size:10px;color:#64748b">'+code+'</span></div>';
      tt.innerHTML+='<div style="margin-top:4px"><span style="font-size:22px;font-weight:900;color:'+col+'">'+c.score+'</span><span style="font-size:11px;color:'+col+';margin-left:4px;vertical-align:top;margin-top:5px;display:inline-block">'+c.level+'</span></div>';
      tt.innerHTML+='<div style="font-size:10px;color:#64748b;margin-top:2px">Trend: '+_xe(c.trend)+'</div>';
      if(drivers)tt.innerHTML+='<div style="margin-top:5px">'+drivers+'</div>';
      var px=(e.clientX-r.left+canvas.offsetLeft);var py=(e.clientY-r.top+canvas.offsetTop);
      tt.style.display="block";
      tt.style.left=(e.offsetX+16)+"px";
      tt.style.top=(e.offsetY-10)+"px";
      canvas.style.cursor="pointer";
    } else {tt.style.display="none";canvas.style.cursor="crosshair";}
  });
  canvas.addEventListener("mouseleave",function(){if(tt)tt.style.display="none";});
  canvas.addEventListener("click",function(e){
    var r=canvas.getBoundingClientRect();var sx=W/r.width,sy=H/r.height;
    var ex=(e.clientX-r.left)*sx,ey=(e.clientY-r.top)*sy;
    var code=getHit(ex,ey);
    var det=document.getElementById("pro-map-detail");
    if(code&&byCode[code]&&det){
      var c=byCode[code];var col=_lvlCol(c.level);
      var drivers=(c.drivers||[]).map(function(d){return'<span style="display:inline-block;margin:2px 3px 0 0;padding:2px 8px;border-radius:10px;font-size:11px;background:#161b22;border:1px solid '+col+';color:'+col+'">'+_xe(d)+'</span>';}).join("");
      det.style.display="block";
      det.innerHTML='<div style="display:flex;align-items:flex-start;justify-content:space-between">';
      det.innerHTML+='<div><div style="font-size:16px;font-weight:700;color:#e2e8f0">'+_xe(_CN[code].n)+' <span style="font-size:11px;color:#64748b;font-weight:400">'+_xe(code)+'</span></div>';
      det.innerHTML+='<div style="margin-top:8px"><span style="font-size:36px;font-weight:900;color:'+col+'">'+c.score+'</span><span style="font-size:12px;color:'+col+';margin-left:6px;vertical-align:top;margin-top:10px;display:inline-block">'+c.level+'</span></div>';
      det.innerHTML+='<div style="font-size:11px;color:#64748b;margin-top:4px">Trend: <span style="color:#94a3b8">'+_xe(c.trend)+'</span></div>';
      if(drivers)det.innerHTML+='<div style="margin-top:8px"><div style="font-size:10px;color:#64748b;margin-bottom:4px;text-transform:uppercase;letter-spacing:1px">Risk Drivers</div>'+drivers+'</div>';
      det.innerHTML+='</div>';
      det.innerHTML+='<button onclick="document.getElementById(\'pro-map-detail\').style.display=\'none\'" style="background:none;border:1px solid #2a3440;color:#64748b;padding:4px 8px;border-radius:3px;cursor:pointer;font-size:11px">&#10005;</button></div>';
    } else if(det){det.style.display="none";}
  });
}
var _econCache=null;
function switchEconTab(btn){
  document.querySelectorAll(".econ-tab").forEach(function(b){b.classList.remove("active");});
  btn.classList.add("active");
  if(_econCache)_renderEcon(_econCache,btn.dataset.tab);
}
function _renderEcon(d,tab){
  _econCache=d;
  var macro=d.macro_signals||[],risks=d.risk_assessments||[],overall=d.overall_risk||"MEDIUM",concern=d.primary_concern||"";
  var mr=g("pro-macro-risk");if(mr){var mc=overall==="HIGH"||overall==="CRITICAL"?"#ff3b5c":overall==="MEDIUM"?"#f5c518":"#00d4aa";mr.style.color=mc;mr.style.fontSize="11px";mr.textContent=overall+(concern?" - "+concern.replace(/_/g," ").toUpperCase():"");}
  var el2=g("pro-econ-list");if(!el2)return;
  if(!tab||tab==="overview"){
    var h='<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px;margin-bottom:16px">';
    risks.forEach(function(r2){var rc=r2.risk==="HIGH"||r2.risk==="CRITICAL"?"#ff3b5c":r2.risk==="MEDIUM"?"#f5c518":"#00d4aa";h+='<div style="background:#0d1117;border:1px solid #1e2630;border-radius:4px;padding:12px;text-align:center"><div style="font-size:10px;color:#64748b;text-transform:capitalize;margin-bottom:4px">'+_xe((r2.signal||"").replace(/_/g," "))+'</div><div style="font-size:20px;font-weight:700;color:'+rc+'">'+_xe(r2.risk||"?")+'</div>'+((r2.status&&r2.status!=="unknown")?('<div style="font-size:10px;color:#94a3b8;margin-top:2px;text-transform:capitalize">'+_xe(r2.status)+'</div>'):"")+(r2.spread!=null?'<div style="font-size:10px;color:#64748b;margin-top:2px">Spread: '+r2.spread.toFixed(2)+'</div>':"")+ '</div>';});
    h+='</div><div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">All Indicators</div>';
    macro.forEach(function(m){var vc=m.series_id==="VIXCLS"||m.series_id==="GVZCLS"?(m.value>30?"#ff3b5c":m.value>20?"#f5c518":"#00d4aa"):m.series_id==="T10Y2Y"?(m.value<0?"#ff3b5c":m.value<0.5?"#f5c518":"#00d4aa"):m.series_id==="STLFSI4"?(m.value>1?"#ff3b5c":m.value>0?"#f5c518":"#00d4aa"):"#e2e8f0";h+='<div style="display:flex;align-items:center;justify-content:space-between;padding:7px 0;border-bottom:1px solid #1e2630"><div style="flex:1"><div style="font-size:12px;color:#e2e8f0;font-weight:600">'+_xe(m.name)+'</div><div style="font-size:10px;color:#64748b">'+_xe(m.series_id)+' &bull; '+_xe(m.date||"")+'</div></div><div style="text-align:right;margin-left:12px"><div style="font-size:14px;font-weight:700;color:'+vc+'">'+_xe(m.value!=null?(m.value*1).toFixed(2):"--")+'</div><div>'+_chgHtml(m.change)+'</div></div></div>';
    });
    el2.innerHTML=h;
  }
  else if(tab==="rates"){
    var ids=["DFF","T10Y2Y","BAMLH0A0HYM2"];var filtered=macro.filter(function(m){return ids.indexOf(m.series_id)>=0;});
    el2.innerHTML=_buildChartCards(filtered,"Interest Rates & Spreads");
  }
  else if(tab==="volatility"){
    var ids2=["VIXCLS","GVZCLS","STLFSI4"];var filtered2=macro.filter(function(m){return ids2.indexOf(m.series_id)>=0;});
    el2.innerHTML=_buildChartCards(filtered2,"Volatility & Stress Indicators");
  }
  else if(tab==="commodities"){
    var ids3=["DCOILWTICO","DTWEXBGS"];var filtered3=macro.filter(function(m){return ids3.indexOf(m.series_id)>=0;});
    el2.innerHTML=_buildChartCards(filtered3,"Commodities & FX");
  }
}
function _buildChartCards(signals,title){
  if(!signals.length)return'<div class="lt">No data for this category</div>';
  var h='<div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px">'+title+'</div>';
  signals.forEach(function(m,i){
    var vc=m.series_id==="VIXCLS"||m.series_id==="GVZCLS"?(m.value>30?"#ff3b5c":m.value>20?"#f5c518":"#00d4aa"):m.series_id==="T10Y2Y"?(m.value<0?"#ff3b5c":m.value<0.5?"#f5c518":"#00d4aa"):m.series_id==="STLFSI4"?(m.value>1?"#ff3b5c":m.value>0?"#f5c518":"#00d4aa"):"#4d9eff";
    h+='<div style="background:#0d1117;border:1px solid #1e2630;border-radius:6px;padding:14px;margin-bottom:10px">';
    h+='<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">';
    h+='<div><div style="font-size:13px;font-weight:700;color:#e2e8f0">'+_xe(m.name)+'</div><div style="font-size:10px;color:#64748b;margin-top:2px">'+_xe(m.series_id)+' &bull; Last: '+_xe(m.date||"")+'</div></div>';
    h+='<div style="text-align:right"><div style="font-size:28px;font-weight:900;color:'+vc+'">'+_xe(m.value!=null?(m.value*1).toFixed(2):"--")+'</div><div>'+_chgHtml(m.change)+'<span style="font-size:10px;color:#64748b"> vs prev</span></div></div>';
    h+='</div>';
    h+='<div style="position:relative;height:50px;background:#080b10;border-radius:3px;overflow:hidden">';
    var pct=Math.min(100,Math.max(5,m.value!=null?Math.abs(m.value)/50*100:50));
    h+='<div style="position:absolute;bottom:0;left:0;right:0;height:100%;display:flex;align-items:flex-end;gap:2px;padding:0 4px">';
    var base=m.value!=null?m.value*1:0;var chg=m.change!=null?m.change*1:0;
    var bars=[base-chg*4,base-chg*3.2,base-chg*2.5,base-chg*1.8,base-chg*1.2,base-chg*0.6,base-chg*0.2,base];
    var bmin=Math.min.apply(null,bars),bmax=Math.max.apply(null,bars);
    var brange=bmax-bmin||1;
    bars.forEach(function(bv,bi){
      var bh=Math.max(4,Math.round((bv-bmin)/brange*46));
      var bc=bi===7?vc:"#1e2d3d";
      h+='<div style="flex:1;height:'+bh+'px;background:'+bc+';border-radius:1px 1px 0 0;transition:all 0.3s"></div>';
    });
    h+='</div></div>';
    h+='</div>';
  });
  return h;
}
function loadPro(){
  var geoB=g("pro-geo-badge"),cyberB=g("pro-cyber-badge"),econB=g("pro-econ-badge");
  if(geoB)geoB.textContent="LOADING";if(cyberB)cyberB.textContent="LOADING";if(econB)econB.textContent="LOADING";
  fetch(PROAPI+"/geo/cii").then(function(r){return r.json();}).then(function(d){
    var data=d.data||[];
    if(geoB)geoB.textContent=data.length+" COUNTRIES";
    var cc=g("pro-crit-countries");if(cc)cc.textContent=data.filter(function(c){return c.level==="CRITICAL";}).length;
    var hotH="";data.filter(function(c){return c.level==="CRITICAL";}).slice(0,6).forEach(function(c){var nm=(_CN[c.country]&&_CN[c.country].n)||c.country;hotH+='<span title="'+nm+'" style="display:inline-block;margin:0 4px 4px 0;padding:3px 8px;border-radius:3px;font-size:11px;font-weight:700;background:#2d0a0a;border:1px solid #ff3b5c;color:#ff3b5c">'+_xe(c.country)+' '+c.score+'</span>';});
    var gh=g("pro-geo-hotspots");if(gh)gh.innerHTML=hotH?'<div style="font-size:10px;color:#ff3b5c;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;padding:8px 12px 0">Critical Hotspots</div><div style="padding:4px 12px 0">'+hotH+"</div>":"";
    var mc=document.getElementById("pro-map-canvas");if(mc){var W=mc.parentElement.offsetWidth||700;var H=320;_initMap(data,W,H);}
    var listH="";data.slice(0,15).forEach(function(c){
      var col=_lvlCol(c.level);var nm=(_CN[c.country]&&_CN[c.country].n)||c.country;var drivers=(c.drivers||[]);
      var drvH=drivers.map(function(dr){return '<span style="display:inline-block;margin:2px 3px 0 0;padding:1px 7px;border-radius:10px;font-size:10px;background:#161b22;border:1px solid #2a3440;color:#94a3b8">'+_xe(dr)+'</span>';}).join("");
      var trend=c.trend==="improving"?"&#8679; Improving":c.trend==="deteriorating"?"&#8681; Worsening":"&#8596; Stable";
      var tCol=c.trend==="improving"?"#00d4aa":c.trend==="deteriorating"?"#ff3b5c":"#64748b";
      listH+='<div class="_geo-row" style="border-bottom:1px solid #1e2630">';
      listH+='<div class="_geo-hdr" style="display:flex;align-items:center;gap:8px;padding:7px 0;cursor:pointer">';
      listH+='<div style="width:34px;text-align:center;font-size:10px;font-weight:700;color:'+col+';background:#0d1117;border:1px solid '+col+';border-radius:3px;padding:2px 3px">'+_xe(c.country)+'</div>';
      listH+='<div style="flex:1;min-width:0"><div style="font-size:12px;color:#e2e8f0;font-weight:600">'+_xe(nm)+'</div><div style="background:#1e2630;border-radius:2px;height:4px;margin-top:3px"><div style="width:'+c.score+'%;height:4px;border-radius:2px;background:'+col+'"></div></div></div>';
      listH+='<div style="text-align:right;min-width:70px"><div style="font-size:14px;font-weight:700;color:'+col+'">'+c.score+'</div><div style="font-size:10px;color:'+col+'">'+_xe(c.level)+'</div></div>';
      listH+='<div style="font-size:10px;color:'+tCol+';min-width:72px;text-align:right">'+trend+'</div></div>';
      listH+='<div class="_geo-drivers" style="display:none;padding:4px 0 8px 42px">'+( drivers.length?'<div style="font-size:10px;color:#64748b;margin-bottom:4px">Risk drivers:</div>'+drvH:'<div style="font-size:10px;color:#64748b">No drivers listed</div>')+'</div></div>';
    });
    var gl=g("pro-geo-list");if(gl){gl.innerHTML=listH||'<div class="lt">No data</div>';
    gl.querySelectorAll("._geo-hdr").forEach(function(hdr){hdr.addEventListener("click",function(){var d=hdr.parentElement.querySelector("._geo-drivers");if(d)d.style.display=d.style.display==="block"?"none":"block";});});}
  }).catch(function(){if(geoB)geoB.textContent="ERROR";});
  fetch(PROAPI+"/cyber/threats").then(function(r){return r.json();}).then(function(d){
    var c2=d.c2_servers||[],mal=d.malware_domains||[],pul=d.threat_pulses||[];
    if(cyberB)cyberB.textContent=(c2.length+mal.length+pul.length)+" FEEDS";
    var pc=g("pro-c2-count");if(pc)pc.textContent=c2.length;
    var h="";
    if(c2.length){h+='<div style="font-size:10px;color:#ff3b5c;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">C2 Servers ('+c2.length+')</div>';c2.slice(0,8).forEach(function(s){h+='<div style="padding:4px 0;border-bottom:1px solid #1e2630;font-size:11px;font-family:monospace"><span style="color:#ff3b5c">'+_xe(s.ip_address||s.ip||"-")+'</span><span style="color:#64748b;margin-left:8px">'+_xe(s.malware||s.malware_family||"-")+'</span></div>';});}
    if(mal.length){h+='<div style="font-size:10px;color:#ff8c42;text-transform:uppercase;letter-spacing:1px;margin:10px 0 6px">Malware Domains ('+mal.length+')</div>';mal.slice(0,6).forEach(function(m){h+='<div style="padding:4px 0;border-bottom:1px solid #1e2630;font-size:11px;font-family:monospace;color:#ff8c42;word-break:break-all">'+_xe(m.url||m.domain||"-")+'</div>';});}
    if(pul.length){h+='<div style="font-size:10px;color:#a78bfa;text-transform:uppercase;letter-spacing:1px;margin:10px 0 6px">Threat Pulses ('+pul.length+')</div>';pul.slice(0,5).forEach(function(p){h+='<div style="padding:5px 0;border-bottom:1px solid #1e2630"><div style="font-size:11px;color:#e2e8f0">'+_xe((p.name||"").substring(0,70))+'</div><div style="font-size:10px;color:#64748b">'+_xe(p.author||"")+'</div></div>';});}
    if(!h)h='<div class="lt" style="padding:12px">No active threats in live feeds</div>';
    var cl=g("pro-cyber-list");if(cl)cl.innerHTML=h;
  }).catch(function(){if(cyberB)cyberB.textContent="ERROR";});
  fetch(PROAPI+"/economic/signals").then(function(r){return r.json();}).then(function(d){
    var econB2=g("pro-econ-badge");if(econB2)econB2.textContent=(d.macro_signals||[]).length+" INDICATORS";
    _renderEcon(d,"overview");
  }).catch(function(){if(econB)econB.textContent="ERROR";});
  fetch(PROAPI+"/ai/status").then(function(r){return r.json();}).then(function(d){
    var as=g("pro-ai-status");if(as)as.textContent=d.available?"READY":"OFFLINE";
    var ab=g("pro-ai-btn");if(ab&&!d.available){ab.disabled=true;ab.style.opacity="0.5";var ar=g("pro-ai-result");if(ar)ar.innerHTML='<span style="color:#64748b">AI requires GROQ_KEY in Railway variables.</span>';}
  }).catch(function(){});
}
var _prb=g('pro-refresh-btn');if(_prb)_prb.addEventListener('click',loadPro);
})();
