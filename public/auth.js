/**
 * DARKWATCH Pro - Auth module
 * Loaded after app.js — wires login/register modal and Pro Intel gating
 */
(function () {
  var PROAPI = 'https://spectacular-wisdom-production.up.railway.app';
  var TOKEN_KEY = 'dw_access_token';
  var REFRESH_KEY = 'dw_refresh_token';
  var USER_KEY = 'dw_user';
  var ORG_KEY = 'dw_org';

  function getToken() { return localStorage.getItem(TOKEN_KEY); }

  function setSession(d) {
    localStorage.setItem(TOKEN_KEY, d.access_token);
    localStorage.setItem(REFRESH_KEY, d.refresh_token);
    localStorage.setItem(USER_KEY, JSON.stringify(d.user || {}));
    localStorage.setItem(ORG_KEY, JSON.stringify(d.org || {}));
  }

  function clearSession() {
    [TOKEN_KEY, REFRESH_KEY, USER_KEY, ORG_KEY].forEach(function (k) { localStorage.removeItem(k); });
  }

  function esc(s) { return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

  function showLoginModal(onSuccess) {
    var old = document.getElementById('dw-login-modal');
    if (old) old.remove();
    var m = document.createElement('div');
    m.id = 'dw-login-modal';
    m.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.88);z-index:9999;display:flex;align-items:center;justify-content:center;';
    m.innerHTML = '<div style="position:relative;background:#0f1117;border:1px solid #1e293b;border-radius:12px;padding:32px;width:380px;max-width:92vw;">' +
      '<div style="color:#00d4aa;font-size:18px;font-weight:700;margin-bottom:4px;">DARKWATCH Pro</div>' +
      '<div style="color:#64748b;font-size:12px;margin-bottom:24px;">Sign in to access Pro Intelligence</div>' +
      '<div id="dw-err" style="display:none;background:#1a0a0a;border:1px solid #ff3b5c;border-radius:6px;padding:10px;color:#ff3b5c;font-size:12px;margin-bottom:16px;"></div>' +
      '<div style="margin-bottom:12px;"><label style="color:#94a3b8;font-size:11px;display:block;margin-bottom:4px;">EMAIL</label>' +
      '<input id="dw-email" type="email" placeholder="you@company.com" style="width:100%;box-sizing:border-box;background:#1e293b;border:1px solid #334155;border-radius:6px;padding:10px 12px;color:#e2e8f0;font-size:13px;outline:none;"></div>' +
      '<div style="margin-bottom:20px;"><label style="color:#94a3b8;font-size:11px;display:block;margin-bottom:4px;">PASSWORD</label>' +
      '<input id="dw-pw" type="password" placeholder="••••••••" style="width:100%;box-sizing:border-box;background:#1e293b;border:1px solid #334155;border-radius:6px;padding:10px 12px;color:#e2e8f0;font-size:13px;outline:none;"></div>' +
      '<div id="dw-org-row" style="display:none;margin-bottom:16px;"><label style="color:#94a3b8;font-size:11px;display:block;margin-bottom:4px;">ORGANISATION NAME</label>' +
      '<input id="dw-org" type="text" placeholder="ACME Corp" style="width:100%;box-sizing:border-box;background:#1e293b;border:1px solid #334155;border-radius:6px;padding:10px 12px;color:#e2e8f0;font-size:13px;outline:none;"></div>' +
      '<button id="dw-submit" style="width:100%;background:#00d4aa;color:#000;border:none;border-radius:6px;padding:11px;font-size:13px;font-weight:700;cursor:pointer;">Sign In</button>' +
      '<div style="margin-top:14px;text-align:center;"><span style="color:#64748b;font-size:12px;">No account? </span>' +
      '<a id="dw-toggle" href="#" style="color:#00d4aa;font-size:12px;text-decoration:none;">Register your organisation</a></div>' +
      '<button id="dw-close" style="position:absolute;top:14px;right:18px;background:none;border:none;color:#64748b;font-size:22px;cursor:pointer;line-height:1;">×</button>' +
      '</div>';
    document.body.appendChild(m);
    var isReg = false;
    document.getElementById('dw-close').onclick = function () { m.remove(); };
    document.getElementById('dw-toggle').onclick = function (e) {
      e.preventDefault(); isReg = !isReg;
      document.getElementById('dw-org-row').style.display = isReg ? 'block' : 'none';
      document.getElementById('dw-submit').textContent = isReg ? 'Create Account' : 'Sign In';
      this.textContent = isReg ? 'Back to sign in' : 'Register your organisation';
    };
    document.getElementById('dw-submit').onclick = function () {
      var email = document.getElementById('dw-email').value.trim();
      var pw = document.getElementById('dw-pw').value;
      var errEl = document.getElementById('dw-err');
      errEl.style.display = 'none';
      if (!email || !pw) { errEl.textContent = 'Please enter email and password.'; errEl.style.display = 'block'; return; }
      var btn = this; btn.textContent = '…'; btn.disabled = true;
      var endpoint = isReg ? '/auth/register' : '/auth/login';
      var body = isReg ? { org_name: (document.getElementById('dw-org').value.trim() || 'My Organisation'), email: email, password: pw } : { email: email, password: pw };
      fetch(PROAPI + endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, data: d }; }); })
        .then(function (res) {
          if (!res.ok) { errEl.textContent = res.data.detail || 'Authentication failed.'; errEl.style.display = 'block'; btn.textContent = isReg ? 'Create Account' : 'Sign In'; btn.disabled = false; return; }
          setSession(res.data);
          m.remove();
          updateNav();
          if (typeof onSuccess === 'function') onSuccess();
        })
        .catch(function () { errEl.textContent = 'Network error. Please try again.'; errEl.style.display = 'block'; btn.textContent = isReg ? 'Create Account' : 'Sign In'; btn.disabled = false; });
    };
    // Allow Enter key
    m.addEventListener('keydown', function(e) { if(e.key==='Enter') document.getElementById('dw-submit').click(); });
    setTimeout(function(){ var em=document.getElementById('dw-email'); if(em)em.focus(); }, 100);
  }

  function updateNav() {
    var userStr = localStorage.getItem(USER_KEY);
    var orgStr = localStorage.getItem(ORG_KEY);
    if (!userStr) return;
    var user = JSON.parse(userStr);
    var org = orgStr ? JSON.parse(orgStr) : {};
    // Update Pro Intel button label
    var proBtn = document.querySelector('[data-page="pro"]');
    if (proBtn) proBtn.innerHTML = 'Pro Intel <span style="color:#00d4aa;font-size:10px;font-weight:400;">✓ ' + esc(org.name || user.email) + '</span>';
    // Add logout chip if not there
    if (!document.getElementById('dw-logout')) {
      var lb = document.createElement('button');
      lb.id = 'dw-logout';
      lb.style.cssText = 'margin-left:8px;background:none;border:1px solid #334155;border-radius:4px;color:#64748b;font-size:11px;padding:2px 8px;cursor:pointer;';
      lb.textContent = '↺ ' + (user.email || 'Logout');
      lb.title = 'Sign out';
      lb.onclick = function () { clearSession(); location.reload(); };
      var nav = document.querySelector('nav') || document.querySelector('.navbar') || document.querySelector('#navbar') || document.querySelector('header');
      if (nav) nav.appendChild(lb);
    }
  }

  // Gate Pro Intel behind login
  function gatePro() {
    if (!getToken()) {
      showLoginModal(function () {
        if (typeof window.showPage === 'function') window.showPage('pro');
        if (typeof window.loadPro === 'function') window.loadPro();
      });
      return false;
    }
    return true;
  }

  // Wire Pro Intel nav button
  function wireProBtn() {
    var proBtn = document.querySelector('[data-page="pro"]');
    if (!proBtn) { setTimeout(wireProBtn, 500); return; }
    proBtn.addEventListener('click', function (e) {
      if (!getToken()) { e.stopImmediatePropagation(); gatePro(); }
    }, true); // capture phase so we intercept before app.js
  }

  // Expose globals
  window.dwShowLoginModal = showLoginModal;
  window.dwGetToken = getToken;
  window.dwClearSession = clearSession;
  window.dwGatePro = gatePro;

  // Init on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { updateNav(); wireProBtn(); });
  } else {
    updateNav();
    wireProBtn();
  }
})();
