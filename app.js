// ════════════════════════════════════════════════════════════════
// PA CONSENT POPUP DETECTION
// Wenn state=pa_consent_... in der URL steht, sind wir das Redirect-Ziel
// unseres eigenen PA-Consent-Popups. BroadcastChannel an Hauptfenster senden,
// dann "Erledigt"-Screen zeigen und schließen.
// Kein window.opener nötig — AAD setzt Cross-Origin-Opener-Policy, das nullt opener.
// ════════════════════════════════════════════════════════════════
window._paConsentPopup = new URLSearchParams(location.search).get('state')?.startsWith('pa_consent_') || false;
if (window._paConsentPopup) {
  try { new BroadcastChannel('pa-oauth-callback').postMessage({ href: location.href }); } catch {}
}

// ════════════════════════════════════════════════════════════════
// CONFIG
// ════════════════════════════════════════════════════════════════
const CLIENT_ID   = '75e627e8-2de0-4ec6-bec9-311757b89e08';
const TENANT_ID   = 'fdb70646-023a-403b-a4b9-1f474a935123';
const SCOPES      = ['User.Read','Sites.Read.All','Sites.ReadWrite.All','Files.ReadWrite.All','Mail.Send'];
const TICKET_SITE = 'dihag.sharepoint.com:/sites/ticket';

// ════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════
const $id = id => document.getElementById(id);
const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const fieldStr = v => {
  if (!v) return '';
  if (typeof v === 'string') {
    // Parse JSON arrays that SP sometimes returns as strings
    if (v.startsWith('[')) {
      try {
        const arr = JSON.parse(v);
        return arr.map(x=>x.LookupValue||x.displayName||x.Title||x.Email||'').filter(Boolean).join(', ');
      } catch {}
    }
    return v;
  }
  if (Array.isArray(v)) return v.map(x=>x.LookupValue||x.displayName||x.Title||x.Email||String(x)).filter(Boolean).join(', ');
  if (typeof v === 'object') return v.LookupValue||v.displayName||v.Title||v.Email||'';
  return String(v);
};
const fmt = s => s ? new Date(s).toLocaleDateString('de-DE',{day:'2-digit',month:'2-digit',year:'2-digit'}) : '';
const fmtFull = s => s ? new Date(s).toLocaleString('de-DE',{day:'2-digit',month:'2-digit',year:'2-digit',hour:'2-digit',minute:'2-digit'}) : '';

// Strip read-only / system fields before PATCH
const READONLY_FIELDS = new Set([
  'AppAuthorLookupId','AppEditorLookupId','AuthorLookupId','EditorLookupId',
  'Author','Editor','Created','Modified','_UIVersionString','ContentType',
  'Attachments','ID','id','LinkTitleNoMenu','LinkTitle',
  'ItemChildCount','FolderChildCount','ComplianceAssetId',
  'OData__ColorTag','@odata.etag'
]);
// Fields to hide in ticket detail views (superset of READONLY_FIELDS)
const DISPLAY_SKIP_KEYS = new Set([
  ...READONLY_FIELDS,
  'AppEditorLookupId','Modified','Created','@odata.etag','id',
  'OData__ColorTag','ComplianceAssetId','LinkTitleNoMenu','LinkTitle',
  'ItemChildCount','FolderChildCount'
]);
function stripReadOnly(fields) {
  const clean = {};
  Object.entries(fields).forEach(([k,v]) => {
    if (READONLY_FIELDS.has(k) || k.startsWith('@odata') || k.startsWith('_') || v === undefined) return;
    if (k.endsWith('LookupId')) {
      if (!ticketCols[k.replace(/LookupId$/, '')]) return; // unknown field — skip
      const intVal = parseInt(v, 10);
      if (isNaN(intVal)) return;
      const baseName = k.replace(/LookupId$/, '');
      if (ticketMultiCols.has(baseName)) {
        clean[k + '@odata.type'] = 'Collection(Edm.Int32)';
        clean[k] = [intVal];
      } else {
        clean[k] = intVal;
      }
      return;
    }
    clean[k] = v;
  });
  return clean;
}

// Extract display name from email or person field
function personName(v) {
  if (!v) return '';
  // Handle JSON string arrays: '[{"LookupId":23,"LookupValue":"Marco Maukisch",...}]'
  if (typeof v === 'string' && v.startsWith('[')) {
    try { return personName(JSON.parse(v)); } catch {}
  }
  if (Array.isArray(v)) return v.map(x=>personName(x)).filter(Boolean).join(', ');
  if (typeof v === 'object') {
    if (v.LookupValue) return v.LookupValue;
    if (v.displayName) return v.displayName;
    if (v.Title) return v.Title;
    if (v.Email) return v.Email.split('@')[0].replace(/\./g,' ').replace(/\b\w/g,c=>c.toUpperCase());
  }
  const s = String(v);
  if (s.includes('@')) return s.split('@')[0].replace(/\./g,' ').replace(/\b\w/g,c=>c.toUpperCase());
  return s;
}

// Clean SP ExternalClass HTML → readable HTML
function cleanHtml(v) {
  if (!v) return '';
  let s = String(v);
  // Not HTML? Auto-link URLs and return escaped with line breaks
  if (!/<[a-z][\s\S]*>/i.test(s)) {
    let escaped = esc(s);
    // Auto-link URLs
    escaped = escaped.replace(/(https?:\/\/[^\s<"']+)/g, '<a href="$1" target="_blank" style="color:var(--blue);word-break:break-all;">$1</a>');
    return escaped.replace(/\n/g,'<br>');
  }
  // Parse and extract inner content
  const tmp = document.createElement('div');
  tmp.innerHTML = s;
  // Remove ExternalClass wrapper divs (keep their content)
  tmp.querySelectorAll('div[class^="ExternalClass"]').forEach(el => {
    el.replaceWith(...el.childNodes);
  });
  // Process all elements
  const allowed = new Set(['UL','OL','LI','P','BR','B','STRONG','EM','I','A','H1','H2','H3','H4','SPAN']);
  tmp.querySelectorAll('*').forEach(el => {
    el.removeAttribute('style');
    el.removeAttribute('class');
    // Keep href on <a> tags, add target=_blank
    if (el.tagName === 'A') {
      const href = el.getAttribute('href');
      // Clear all attributes then re-add href
      [...el.attributes].forEach(a=>el.removeAttribute(a.name));
      if (href) {
        // Make relative links absolute (SP sometimes uses /sites/... paths)
        let absHref = href;
        if (href.startsWith('/') && !href.startsWith('//')) {
          absHref = 'https://dihag.sharepoint.com' + href;
        }
        el.setAttribute('href', absHref);
        el.setAttribute('target', '_blank');
        el.style.color = 'var(--blue)';
        el.style.wordBreak = 'break-all';
      }
    } else if (!allowed.has(el.tagName)) {
      if (el.tagName === 'DIV') {
        const p = document.createElement('p');
        p.innerHTML = el.innerHTML;
        el.replaceWith(p);
      }
    }
  });
  // Auto-link plain URLs in text nodes
  const walker = document.createTreeWalker(tmp, NodeFilter.SHOW_TEXT);
  const textNodes = [];
  while (walker.nextNode()) textNodes.push(walker.currentNode);
  textNodes.forEach(tn => {
    if (tn.parentElement?.tagName === 'A') return; // already a link
    const urlRe = /(https?:\/\/[^\s<"']+)/g;
    if (urlRe.test(tn.textContent)) {
      const span = document.createElement('span');
      span.innerHTML = tn.textContent.replace(urlRe, '<a href="$1" target="_blank" style="color:var(--blue);word-break:break-all;">$1</a>');
      tn.replaceWith(span);
    }
  });
  const clean = tmp.innerHTML.trim();
  return clean || esc(s).replace(/\n/g,'<br>');
}

// Detect if a value looks like HTML or rich text from SP
function isRichText(v) {
  if (!v || typeof v !== 'string') return false;
  return /<div[\s>]|<p[\s>]|<ul[\s>]|<br\s*\/?>|ExternalClass/i.test(v);
}

function toast(msg,type='info'){
  const ic={success:'✅',error:'❌',info:'ℹ️'};
  const t=document.createElement('div'); t.className='toast '+(type||'');
  t.innerHTML=`<span>${ic[type]||'ℹ️'}</span><span>${esc(msg)}</span>`;
  $id('toast-c').appendChild(t);
  setTimeout(()=>{t.classList.add('out');setTimeout(()=>t.remove(),260);},4000);
}

// ════════════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════════════
let msalApp, account;

async function initAuth() {
  // Use current page as redirectUri so it works locally, from GitHub Pages, or anywhere
  const redirectUri = window.location.href.split('?')[0].split('#')[0];
  const cfg = {
    auth:{ clientId:CLIENT_ID, authority:`https://login.microsoftonline.com/${TENANT_ID}`,
           redirectUri },
    cache:{ cacheLocation:'localStorage', storeAuthStateInCookie:true }
  };
  msalApp = new msal.PublicClientApplication(cfg);
  await msalApp.initialize();
  await msalApp.handleRedirectPromise();
  const accounts = msalApp.getAllAccounts();
  if (accounts.length) {
    account = accounts[0];
    return true;
  }
  return false;
}

async function doLogin() {
  $id('boot-btn').style.display='none';
  $id('boot-sub').textContent='Anmeldung läuft…';
  try {
    const r = await msalApp.loginPopup({scopes:SCOPES});
    account = r.account;
    bootDone();
  } catch(e) {
    $id('boot-err').textContent = e.message;
    $id('boot-err').style.display='block';
    $id('boot-btn').style.display='block';
    $id('boot-btn').textContent='Erneut versuchen';
  }
}

async function bootDone() {
  $id('boot-sub').textContent = 'Prüfe Berechtigungen…';
  // PERM CHECK DEACTIVATED — managed via M365 directly
  // const email = (account?.username || '').toLowerCase();
  // const role  = await checkPerm('tickets', email);
  // if (role === 'none') { showNoAccess(email); return; }
  // window._appRole = role;
  $id('boot').style.display='none';
  $id('app').style.display='flex';
  $id('hdr-av').textContent = (account?.name||'?').split(' ').map(n=>n[0]||'').join('').substring(0,2).toUpperCase();
  initTickets();
  buildAutoGrid();
}

/* ── PERMISSION CHECK ─────────────────────────────────────────────── */
const PERM_SITE = 'dihag.sharepoint.com:/sites/ticket';
const PERM_LIST = 'AppPermissions';
let _pSiteId = null, _pListId = null;

async function checkPerm(appName, userEmail) {
  try {
    if (!_pSiteId) {
      const s = await gGet(`/sites/${PERM_SITE}`);
      _pSiteId = s.id;
    }
    if (!_pListId) {
      try {
        const l = await gGet(`/sites/${_pSiteId}/lists/${PERM_LIST}`);
        _pListId = l.id;
      } catch { return 'none'; } // list not found → blocked
    }
    const data = await gGet(`/sites/${_pSiteId}/lists/${_pListId}/items?$expand=fields&$top=999`);
    const RANK = { admin: 3, editor: 2, viewer: 1, none: 0 };
    let best = -1;
    for (const item of (data.value || [])) {
      const f = item.fields || {};
      if ((f.UserEmail||'').toLowerCase() === userEmail) {
        if (f.App === appName || f.App === '*') {
          best = Math.max(best, RANK[f.Role] ?? 0);
        }
      }
    }
    // No entry found → blocked
    if (best === -1) return 'none';
    return Object.keys(RANK).find(k => RANK[k] === best) || 'none';
  } catch(e) {
    console.warn('[checkPerm]', e.message);
    return 'none'; // fail-safe: block on error
  }
}

function showNoAccess(email) {
  $id('boot').style.display = 'none';
  const el = $id('no-access');
  el.style.display = 'flex';
  $id('nac-msg').textContent =
    `Du (${email}) hast aktuell keinen Zugriff auf das Ticketsystem. ` +
    `Stelle eine Anfrage — die IT schaltet dich frei.`;
}

async function requestAccess() {
  const btn = $id('nac-req-btn');
  btn.disabled = true; btn.textContent = '…';
  const email = account?.username || '';
  const name  = account?.name || email;
  const now   = new Date().toLocaleString('de-DE');
  try {
    await gPost('/me/sendMail', {
      message: {
        subject: `Freigabe-Anfrage: Ticketsystem – ${name}`,
        body: {
          contentType: 'HTML',
          content: `<p>Hallo IT-Team,</p>
<p>folgende Person beantragt Zugriff auf das <strong>DIHAG Ticketsystem</strong>:</p>
<table style="border-collapse:collapse;font-size:14px;font-family:sans-serif">
  <tr><td style="padding:4px 12px 4px 0;color:#666">Name</td><td><strong>${name}</strong></td></tr>
  <tr><td style="padding:4px 12px 4px 0;color:#666">E-Mail</td><td>${email}</td></tr>
  <tr><td style="padding:4px 12px 4px 0;color:#666">App</td><td>Ticketsystem</td></tr>
  <tr><td style="padding:4px 12px 4px 0;color:#666">Datum</td><td>${now}</td></tr>
</table>
<p style="margin-top:16px">Freigabe im <a href="https://dfedorov12.github.io/admin/">Admin-Portal</a> erteilen.</p>
<p style="color:#888;font-size:12px">Diese Nachricht wurde automatisch vom DIHAG Ticketsystem gesendet.</p>`
        },
        toRecipients: [{ emailAddress: { address: 'ticket@dihag.com' } }]
      },
      saveToSentItems: false
    });
    $id('nac-sent').style.display = 'block';
    $id('nac-req-btn').style.display = 'none';
  } catch(e) {
    $id('nac-err').style.display = 'block';
    $id('nac-err').textContent = `Fehler: ${e.message}`;
    btn.disabled = false; btn.textContent = '📧 Freigabe anfragen';
  }
}

function doLogout() {
  msalApp?.logoutPopup({ account }).catch(() => {});
  location.reload();
}

async function getToken() {
  if (!account) throw new Error('Nicht angemeldet');
  try { return (await msalApp.acquireTokenSilent({scopes:SCOPES,account})).accessToken; }
  catch { return (await msalApp.acquireTokenPopup({scopes:SCOPES,account})).accessToken; }
}

async function getSpToken() {
  const origin = 'https://dihag.sharepoint.com';
  // Try AllSites.FullControl first (needed for RoleAssignments), fall back to Sites.ReadWrite.All
  for (const scope of [`${origin}/AllSites.FullControl`, `${origin}/Sites.ReadWrite.All`, `${origin}/AllSites.Write`]) {
    try {
      const res = await msalApp.acquireTokenSilent({scopes:[scope], account});
      return res.accessToken;
    } catch {}
  }
  // Final fallback with popup
  const res = await msalApp.acquireTokenPopup({scopes:[`${origin}/Sites.ReadWrite.All`], account});
  return res.accessToken;
}

// Also try re-requesting with user's site URL dynamically
async function getSpTokenForSite(siteUrl) {
  const origin = new URL(siteUrl).origin; // e.g. https://dihag.sharepoint.com
  for (const scope of [`${origin}/AllSites.FullControl`, `${origin}/Sites.ReadWrite.All`]) {
    try {
      const res = await msalApp.acquireTokenSilent({scopes:[scope], account});
      return res.accessToken;
    } catch {}
  }
  return await getSpToken();
}

// ════════════════════════════════════════════════════════════════
// GRAPH API
// ════════════════════════════════════════════════════════════════
const API = 'https://graph.microsoft.com/v1.0';

async function gGet(path, headers={}) {
  const tok = await getToken();
  const r = await fetch(API+path, {headers:{Authorization:'Bearer '+tok,...headers}});
  if (!r.ok) throw new Error(`Graph ${r.status}: ${await r.text().catch(()=>'')}`);
  return r.json();
}
async function gPost(path, body) {
  const tok = await getToken();
  const r = await fetch(API+path, {method:'POST',headers:{Authorization:'Bearer '+tok,'Content-Type':'application/json'},body:JSON.stringify(body)});
  if (!r.ok) throw new Error(`Graph POST ${r.status}: ${await r.text().catch(()=>'')}`);
  return r.json();
}
async function gPatch(path, body) {
  const tok = await getToken();
  const r = await fetch(API+path, {method:'PATCH',headers:{Authorization:'Bearer '+tok,'Content-Type':'application/json'},body:JSON.stringify(body)});
  if (r.status===204) return {};
  if (!r.ok) throw new Error(`Graph PATCH ${r.status}: ${await r.text().catch(()=>'')}`);
  return r.json().catch(()=>({}));
}

// ════════════════════════════════════════════════════════════════
// DEBUG SYSTEM
// ════════════════════════════════════════════════════════════════
let debugEnabled = false;

function toggleDebug() {
  debugEnabled = !debugEnabled;
  const btn = $id('btn-debug');
  const panel = $id('debug-panel');
  if (debugEnabled) {
    btn.textContent = '🐛 Debug: An';
    btn.style.background = '#f9e2af';
    btn.style.color = '#1e1e2e';
    btn.style.borderColor = '#f9e2af';
    panel.style.display = 'block';
    dbg('Debug aktiviert');
  } else {
    btn.textContent = '🐛 Debug: Aus';
    btn.style.background = 'none';
    btn.style.color = '';
    btn.style.borderColor = '';
    panel.style.display = 'none';
  }
}

function dbg(msg, data) {
  const ts = new Date().toLocaleTimeString('de-DE',{hour:'2-digit',minute:'2-digit',second:'2-digit',fractionalSecondDigits:3});
  const logEl = $id('debug-log');
  if (!logEl) return;
  let line = `<div><span style="color:#89b4fa;">[${ts}]</span> ${esc(String(msg))}`;
  if (data !== undefined) {
    try {
      const str = typeof data === 'object' ? JSON.stringify(data, null, 0) : String(data);
      line += ` <span style="color:#f5c2e7;">${esc(str.substring(0,300))}${str.length>300?'…':''}</span>`;
    } catch(e) { line += ` <span style="color:#f38ba8;">[nicht serialisierbar]</span>`; }
  }
  line += '</div>';
  logEl.innerHTML += line;
  logEl.parentElement.scrollTop = logEl.parentElement.scrollHeight;
  // Always log to console too
  console.log(`[DBG] ${msg}`, data !== undefined ? data : '');
}

function clearDebug() {
  const logEl = $id('debug-log');
  if (logEl) logEl.innerHTML = '';
}

// ════════════════════════════════════════════════════════════════
// PANEL SWITCHING
// ════════════════════════════════════════════════════════════════
function showPanel(id) {
  ['tickets','reports','devices','perms','auto','ticket-detail'].forEach(p => {
    const panel = $id('panel-'+p);
    const tab   = $id('tab-'+p);
    if(panel) panel.classList.toggle('active', p===id);
    if(tab)   tab.classList.toggle('on', p===id);
  });
  $id('btn-new').style.display     = (id==='tickets'||id==='ticket-detail') ? '' : 'none';
  $id('btn-refresh').style.display = id==='tickets' ? '' : 'none';
  if (id==='reports' && allTickets.length) buildReports();
  if (id==='devices') { if(!allDevices.length) loadDevices(); loadDevSP(false); }
}

// ════════════════════════════════════════════════════════════════
// COLUMN HELPERS
// ════════════════════════════════════════════════════════════════
function col(names) {
  if (!names) return null;
  const arr = Array.isArray(names) ? names : [names];
  for (const n of arr) {
    if (ticketCols[n]) return n;
    const found = Object.keys(ticketCols).find(k =>
      k.toLowerCase() === n.toLowerCase() ||
      (ticketCols[k]||'').toLowerCase() === n.toLowerCase()
    );
    if (found) return found;
  }
  return null;
}

function getCol(alias) {
  const map = {
    title:    ['Titel','Title'],
    status:   ['Status'],
    prio:     ['Priorit_x00e4_t','Priorität','Priority','Prio'],
    category: ['Kategorie','Category','Typ','Type'],
    assigned: ['Zugewiesen','AssignedTo','Zugewiesen_x0020_an','Bearbeiter'],
    werk:     ['Werk','Standort','Site'],
    type:     ['Art','Ticketart','TicketType'],
    desc:     ['Beschreibung','Description','Kommentar','Inhalt'],
    created:  ['Created','Erstellt']
  };
  const names = map[alias] || [alias];
  return col(names);
}

// ════════════════════════════════════════════════════════════════
// TICKET SYSTEM
// ════════════════════════════════════════════════════════════════
let ticketSiteId = null;
let ticketListId = null;
let ticketCols   = {};   // internal → display
let ticketChoices= {};   // internal → [choice1, choice2, ...]
let ticketMultiCols = new Set(); // internal names of multi-value person/lookup columns
let allTickets   = [];
let editingId    = null;
let allNextLink  = null;
let allTicketsComplete = false;
let allPrevSkip = 0;
let totalTicketCount = 0;
let allOlderNextUrl = null;
let displayedCount = 100;

// ── TICKET CACHE (sessionStorage) — schlanke Version ──
// Speichert nur die für die Anzeige nötigen Felder (kein vollständiges fields-Objekt)
const CACHE_FIELD_KEYS = ['Title','Status','Priorit_x00e4_t','Priorität','Priority','Prio',
  'Zugewiesen','AssignedTo','Zugewiesen_x0020_an','Bearbeiter','ZugewiesenAn','Assigned_x0020_To',
  'Kategorie','Category','Typ','Type','Werk','Standort','Site',
  'Art','Ticketart','TicketType','Beschreibung','Description','Kommentar','Inhalt'];

function slimTicket(t) {
  const f = t.fields||{};
  const slim = {};
  CACHE_FIELD_KEYS.forEach(k=>{ if(f[k]!==undefined) slim[k]=f[k]; });
  return { id:t.id, createdDateTime:t.createdDateTime, fields:slim, _attachCount:t._attachCount };
}

function saveTicketCache() {
  try {
    localStorage.removeItem('dihag_tickets');
    const slim = allTickets.slice(0,500).map(slimTicket);
    const data = JSON.stringify(slim);
    localStorage.setItem('dihag_tickets', data);
    localStorage.setItem('dihag_ticketCols', JSON.stringify(ticketCols));
    localStorage.setItem('dihag_ticketIds', JSON.stringify({siteId:ticketSiteId,listId:ticketListId}));
    localStorage.setItem('dihag_ticketTime', Date.now().toString());
    dbg('Cache gespeichert (localStorage)', {tickets: slim.length, bytes: data.length});
  } catch(e) {
    dbg('Cache-Fehler', e.message);
    try { localStorage.removeItem('dihag_tickets'); } catch{}
  }
}

function restoreTicketCache() {
  try {
    const raw     = localStorage.getItem('dihag_tickets');
    const colsRaw = localStorage.getItem('dihag_ticketCols');
    const idsRaw  = localStorage.getItem('dihag_ticketIds');
    const tsRaw   = localStorage.getItem('dihag_ticketTime');
    if (!raw || !colsRaw || !idsRaw) return false;
    // Invalidate cache older than 2 hours
    if (tsRaw && (Date.now() - parseInt(tsRaw)) > 2*3600*1000) {
      dbg('Cache abgelaufen (>2h), verwerfe');
      return false;
    }
    allTickets = JSON.parse(raw);
    ticketCols = JSON.parse(colsRaw);
    const ids = JSON.parse(idsRaw);
    ticketSiteId = ids.siteId;
    ticketListId = ids.listId;
    dbg('Cache wiederhergestellt', {tickets: allTickets.length});
    return true;
  } catch(e) { dbg('Cache-Restore-Fehler', e.message); return false; }
}

function filterActive() {
  return !!($id('tkt-search').value.trim() ||
            $id('tkt-st').value ||
            $id('tkt-prio').value ||
            ($id('tkt-kat')?.value||'') ||
            ($id('tkt-werk')?.value||'') ||
            ($id('tkt-art')?.value||'') ||
            ($id('tkt-assigned')?.value||''));
}

function sortByCreatedDesc(tickets) {
  dbg('Sortiere nach Erstellt am DESC', {anzahl: tickets.length});
  return tickets.sort((a, b) => {
    const dateA = new Date(a.createdDateTime || a.fields?.Created || 0);
    const dateB = new Date(b.createdDateTime || b.fields?.Created || 0);
    return dateB - dateA; // DESC
  });
}

function renderTickets(list) {
  const tbody = $id('tkt-tbody');
  const table = $id('tkt-table');
  const empty = $id('tkt-empty');

  dbg('renderTickets aufgerufen', {anzahl: list.length, gesamt: allTickets.length});

  if (!list.length) {
    empty.style.display = 'block';
    empty.textContent = filterActive() ? 'Keine Tickets für diesen Filter' : 'Keine Tickets vorhanden';
    table.style.display = 'none';
    return;
  }

  empty.style.display = 'none';
  table.style.display = '';

  const cTitle    = getCol('title') || 'Title';
  const cStatus   = getCol('status') || 'Status';
  const cPrio     = getCol('prio');
  const cAssigned = getCol('assigned') || _discoveredCols.asgn;
  const cKat      = getCol('category');
  const cWerk     = getCol('werk');
  const cType     = getCol('type');

  dbg('Spalten-Mapping', {cTitle, cStatus, cPrio, cAssigned, cKat, cWerk, cType});

  tbody.innerHTML = list.map(it => {
    const f = it.fields || {};
    const status = f[cStatus] || f.Status || '';
    const _prioRaw = cPrio ? (f[cPrio]||'') : '';
    const prio = _prioRaw.replace(/^high$/i,'Hoch').replace(/^normal$/i,'Normal').replace(/^mittel$/i,'Normal').replace(/^Mittel$/,'Normal');
    const _asgnRaw = cAssigned ? f[cAssigned]
      : (f['Zugewiesen']||f['AssignedTo']||f['Zugewiesen_x0020_an']||f['Bearbeiter']||f['ZugewiesenAn']||null);
    const assigned = _asgnRaw
      ? (typeof _asgnRaw==='string' && !_asgnRaw.startsWith('[') && !_asgnRaw.startsWith('{')
          ? _asgnRaw.replace(/\./g,' ').replace(/\w/g,c=>c.toUpperCase())  // "marco.maukisch" → "Marco Maukisch"
          : personName(_asgnRaw))
      : '';
    const kat = cKat ? (f[cKat]||'') : '';
    const werk = cWerk ? (f[cWerk]||'') : '';
    const art = cType ? (f[cType]||'') : '';
    const created = it.createdDateTime || f.Created || '';

    let stClass = 'st-offen';
    if (status.includes('Bearbeitung')) stClass = 'st-bearbeitung';
    else if (status.includes('Erledigt')) stClass = 'st-erledigt';
    else if (status.includes('Abgebrochen')) stClass = 'st-abgebrochen';

    let prioClass = '';
    if (/hoch|high/i.test(prio)) prioClass = 'prio-hoch';
    if (/kritisch|critical/i.test(prio)) prioClass = 'prio-kritisch';

    const attCount = it._attachCount;
    const attHtml = attCount > 0
      ? `<span class="attach-count">📎 ${attCount}</span>`
      : '<span style="color:var(--text-muted);font-size:10px;">—</span>';

    return `<tr class="clickable" onclick="openTicketTab('${it.id}')" ondblclick="openTicketTabBg('${it.id}')">
      <td style="font-weight:600;color:var(--navy);">#${it.id}</td>
      <td>${esc(f[cTitle] || f.Title || '')}</td>
      <td style="color:var(--text-dim);">${esc(assigned)}</td>
      <td class="${prioClass}">${esc(prio)}</td>
      <td><span class="st-badge ${stClass}">${esc(status)}</span></td>
      <td style="white-space:nowrap;">${fmtFull(created)}</td>
      <td>${esc(kat)}</td>
      <td>${esc(werk)}</td>
      <td>${esc(art)}</td>
      <td>${attHtml}</td>
    </tr>`;
  }).join('');

  dbg('Tabelle gerendert', {zeilen: list.length, ersteID: list[0]?.id, ersteDatum: list[0]?.createdDateTime});
}

function renderLoadMore() {
  const el = $id('tkt-loadmore');
  if (!el) return;
  if (!filterActive() && displayedCount < allTickets.length) {
    el.style.display = 'block';
    dbg('Mehr-laden Button angezeigt', {angezeigt: displayedCount, gesamt: allTickets.length});
  } else {
    el.style.display = 'none';
  }
}

function loadMoreTickets() {
  displayedCount += 100;
  dbg('Mehr Tickets laden', {neuesLimit: displayedCount});
  renderTickets(allTickets.slice(0, displayedCount));
  renderLoadMore();
}

async function initTickets() {
  try {
    // Restore from cache for instant display
    if (restoreTicketCache()) {
      sortByCreatedDesc(allTickets);
      buildFilterOptions(allTickets);
      renderTickets(allTickets.slice(0, displayedCount));
      $id('tkt-count').textContent = allTickets.length + ' Tickets (Cache)';
    } else {
      $id('tkt-empty').style.display='block';
      $id('tkt-empty').textContent='Verbinde…';
    }
    dbg('initTickets: Verbinde mit SharePoint…');
    const site = await gGet(`/sites/${TICKET_SITE}`);
    ticketSiteId = site.id;
    dbg('Site gefunden', {siteId: ticketSiteId});
    const lists = await gGet(`/sites/${ticketSiteId}/lists?$select=id,name,displayName&$top=100`);
    const lst = (lists.value||[]).find(l=>l.displayName==='Tickets'||l.name==='Tickets')
             || (lists.value||[]).find(l=>l.name.toLowerCase().includes('ticket')||l.displayName.toLowerCase().includes('ticket'));
    if (!lst) throw new Error('Liste nicht gefunden: '+(lists.value||[]).map(l=>l.displayName).join(', '));
    ticketListId = lst.id;
    dbg('Ticketliste gefunden', {listId: ticketListId, name: lst.displayName});
    const cols = await gGet(`/sites/${ticketSiteId}/lists/${ticketListId}/columns?$top=200`);
    (cols.value||[]).forEach(c=>{
      if(!c.readOnly) ticketCols[c.name]=c.displayName;
      if(c.choice?.choices?.length) ticketChoices[c.name]=c.choice.choices;
      if(c.personOrGroup?.allowMultipleSelection || c.lookup?.allowMultipleValues)
        ticketMultiCols.add(c.name);
    });
    dbg('Spalten geladen', {anzahl: Object.keys(ticketCols).length, choices: Object.keys(ticketChoices)});
    streamTickets();
  } catch(e) {
    dbg('FEHLER initTickets', e.message);
    $id('tkt-empty').textContent='⚠ '+e.message;
    $id('tkt-empty').style.color='var(--red)';
  }
}

async function streamTickets() {
  allTickets=[]; allTicketsComplete=false; allOlderNextUrl=null; displayedCount=100;
  $id('tkt-empty').style.display='block';
  $id('tkt-empty').textContent='Lade Tickets…';
  $id('tkt-table').style.display='none';

  // ── PHASE 1: Letzte 5 Tage (schneller Erstload) ──
  const recentDays = 5;
  const recentDate = new Date(Date.now() - recentDays*86400000).toISOString();
  dbg(`PHASE 1: Lade Tickets der letzten ${recentDays} Tage (seit ${recentDate})…`);
  let url=`/sites/${ticketSiteId}/lists/${ticketListId}/items?$expand=fields&$filter=fields/Created ge '${recentDate}'&$top=100`;
  let batchNr = 0;
  try {
    while (url) {
      batchNr++;
      dbg(`Phase 1 · Batch ${batchNr} laden…`, {url: url.substring(0,150)});
      const d = await gGet(url, {'Prefer':'HonorNonIndexedQueriesWarningMayFailRandomly'});
      const page = d.value||[];
      dbg(`Phase 1 · Batch ${batchNr} empfangen`, {items: page.length});
      allTickets = [...allTickets, ...page];
      url = d['@odata.nextLink']
        ? d['@odata.nextLink'].replace('https://graph.microsoft.com/v1.0','') : null;
      sortByCreatedDesc(allTickets);
      buildFilterOptions(allTickets);
      renderTickets(filterActive()?applyFilters(allTickets):allTickets.slice(0,displayedCount));
      $id('tkt-count').textContent=allTickets.length+' Tickets (neueste)';
    }
    dbg(`PHASE 1 abgeschlossen ✓`, {tickets: allTickets.length});
    saveTicketCache();
    if(filterActive()) filterTickets();
    renderLoadMore();

    // ── PHASE 2: Rest im Hintergrund nachladen ──
    loadOlderTicketsInBackground(recentDate);

  } catch(e) {
    dbg('FEHLER Phase 1', e.message);
    console.error('[Tickets]',e.message);
    if(allTickets.length) {
      renderTickets(allTickets.slice(0,displayedCount));
      toast('Teilladen: '+e.message,'info');
    } else {
      $id('tkt-empty').textContent='⚠ '+e.message;
      $id('tkt-empty').style.color='var(--red)';
    }
  }
}

async function refreshNewTickets() {
  if (!allTickets.length || !ticketSiteId || !ticketListId) { streamTickets(); return; }
  const btn = $id('btn-refresh');
  if (btn) { btn.disabled=true; btn.textContent='⏳'; }
  try {
    // Fetch the 100 most recently modified tickets — covers both new and updated tickets
    const url = `/sites/${ticketSiteId}/lists/${ticketListId}/items?$expand=fields&$orderby=fields/Modified desc&$top=100`;
    const d = await gGet(url, {'Prefer':'HonorNonIndexedQueriesWarningMayFailRandomly'});
    const fresh = d.value || [];
    dbg('Refresh: empfangen='+fresh.length);

    let newCount = 0, updCount = 0;
    fresh.forEach(t => {
      const idx = allTickets.findIndex(x => x.id === t.id);
      if (idx >= 0) {
        allTickets[idx] = t; // update existing ticket with latest properties
        updCount++;
      } else {
        allTickets.unshift(t); // new ticket
        newCount++;
      }
    });

    sortByCreatedDesc(allTickets);
    buildFilterOptions(allTickets);
    const list = filterActive() ? applyFilters(allTickets) : allTickets.slice(0, displayedCount);
    renderTickets(list);
    renderLoadMore();
    $id('tkt-count').textContent = allTickets.length + ' Tickets';
    saveTicketCache();
    const msg = newCount > 0
      ? `✓ ${updCount} aktualisiert, ${newCount} neu`
      : `✓ ${updCount} Tickets aktualisiert`;
    toast(msg, 'success');
  } catch(e) {
    dbg('Refresh Fehler', e.message);
    toast('Refresh-Fehler: '+e.message, 'error');
  } finally {
    if(btn){ btn.disabled=false; btn.textContent='🔄'; }
  }
}

async function loadOlderTicketsInBackground(recentDate) {
  dbg('PHASE 2: Lade ältere Tickets im Hintergrund (kein Re-Render)…');
  let url=`/sites/${ticketSiteId}/lists/${ticketListId}/items?$expand=fields&$filter=fields/Created lt '${recentDate}'&$top=100`;
  let batchNr = 0;
  const existingIds = new Set(allTickets.map(t=>t.id));
  try {
    while (url) {
      batchNr++;
      dbg(`Phase 2 · Batch ${batchNr} laden…`);
      const d = await gGet(url, {'Prefer':'HonorNonIndexedQueriesWarningMayFailRandomly'});
      const page = (d.value||[]).filter(it => !existingIds.has(it.id));
      page.forEach(it => existingIds.add(it.id));
      dbg(`Phase 2 · Batch ${batchNr} empfangen`, {neu: page.length, duplikate: (d.value||[]).length - page.length});
      allTickets = [...allTickets, ...page];
      url = d['@odata.nextLink']
        ? d['@odata.nextLink'].replace('https://graph.microsoft.com/v1.0','') : null;
      sortByCreatedDesc(allTickets);
      buildFilterOptions(allTickets);
      // Kein Re-Render! Nur Counter aktualisieren — Liste bleibt stabil
      $id('tkt-count').textContent=allTickets.length+(url?' + …':'')+' Tickets';
    }
    allTicketsComplete=true;
    renderLoadMore();
    dbg(`PHASE 2 abgeschlossen ✓ — Gesamt: ${allTickets.length} Tickets`);
    saveTicketCache();
    $id('tkt-count').textContent=allTickets.length+' Tickets';
    console.log('[Tickets] komplett:', allTickets.length);
  } catch(e) {
    dbg('FEHLER Phase 2 (Hintergrund)', e.message);
    console.warn('[Tickets Background]', e.message);
    allTicketsComplete=true;
    renderLoadMore();
    $id('tkt-count').textContent=allTickets.length+' Tickets (teilweise)';
  }
}


// Normalise prio value for consistent comparison
function normPrio(v) {
  const s = String(v||'').trim();
  if (/^high$/i.test(s)||/^hoch$/i.test(s)) return 'Hoch';
  if (/^normal$/i.test(s)||/^mittel$/i.test(s)) return 'Normal';
  if (/^niedrig$/i.test(s)||/^low$/i.test(s)) return 'Niedrig';
  if (/^kritisch$/i.test(s)||/^critical$/i.test(s)) return 'Kritisch';
  return s;
}

function applyFilters(list) {
  const raw  = ($id('tkt-search').value||'').trim();
  const q    = raw.toLowerCase();
  const st   = $id('tkt-st').value;
  const pr   = $id('tkt-prio').value;
  const kat  = $id('tkt-kat')?.value||'';
  const wrk  = $id('tkt-werk')?.value||'';
  const art  = $id('tkt-art')?.value||'';
  const asgn = $id('tkt-assigned')?.value||'';
  const cStatus=getCol('status')||'Status';
  const cPrio  =getCol('prio');
  const cKat   =getCol('category')  ||_discoveredCols.kat;
  const cWerk  =getCol('werk')      ||_discoveredCols.werk;
  const cType  =getCol('type')      ||_discoveredCols.type;
  const cTitle =getCol('title')||'Title';
  const cAsgn  =getCol('assigned')  ||_discoveredCols.asgn;
  return list.filter(it=>{
    const f=it.fields||{};
    const idStr=String(it.id);
    const titleStr=(f[cTitle]||f.Title||'').toLowerCase();
    const searchOk=!q||(q.replace(/^#/,'')===idStr)||(idStr.includes(q.replace(/^#/,'')))||titleStr.includes(q);
    const statusVal = f[cStatus]||f.Status||'';
    const statusOk  = !st || statusVal === st || statusVal.includes(st);
    const _prioVal = cPrio ? f[cPrio] : (f['Priorit_x00e4_t']||f['Priorität']||f['Priority']||f['Prio']||'');
    const prioOk  = !pr||normPrio(_prioVal)===pr;
    const _asgnVal = cAsgn ? f[cAsgn] : (f['Zugewiesen']||f['AssignedTo']||f['Zugewiesen_x0020_an']||f['Bearbeiter']||f['ZugewiesenAn']||'');
    const asgnOk  = !asgn||personName(_asgnVal).toLowerCase().includes(asgn.toLowerCase());
    const katOk   = !kat||!cKat||(f[cKat]||'')===kat;
    const werkOk  = !wrk||!cWerk||(f[cWerk]||'')===wrk;
    const artOk   = !art||!cType||(f[cType]||'')===art;
    return searchOk&&statusOk&&prioOk&&asgnOk&&katOk&&werkOk&&artOk;
  });
}

// Stored column keys discovered from full ticket data
let _discoveredCols = {};

function buildFilterOptions(tickets) {
  if (!tickets.length) return;

  // Skip system/known fields when scanning for art/kat
  const systemKeys = new Set(['Title','Status','Priorit_x00e4_t','Priorität','Priority','Prio',
    'Beschreibung','Description','Kommentar','Inhalt','Created','Modified','Author','Editor',
    'ContentType','Attachments','_UIVersionString','LinkTitleNoMenu','LinkTitle',
    'AuthorLookupId','EditorLookupId','AppAuthorLookupId','ItemChildCount','FolderChildCount',
    'ComplianceAssetId','OData__ColorTag','Werk','Standort','Site','id','ID']);

  const sets = {kat:new Set(), werk:new Set(), art:new Set(), assigned:new Set()};

  // Known column name candidates
  const katCandidates  = ['Kategorie','Category','Typ','Type'];
  const werkCandidates = ['Werk','Standort','Site','Niederlassung','Location'];
  const artCandidates  = ['Art','Ticketart','TicketType','Ticket_x0020_Art','Tickettyp','Ticketart_x0020_'];
  const asgnCandidates = ['Zugewiesen','AssignedTo','Zugewiesen_x0020_an','Bearbeiter','ZugewiesenAn','Assigned_x0020_To'];

  const findCol = (candidates) => {
    // Check getCol first
    const gc = candidates.find(c => { const r=col([c]); return r; });
    if (gc) { const r=col([gc]); if(r) return r; }
    // Scan actual ticket fields
    for (const k of candidates) {
      if (tickets.some(t => { const v=(t.fields||{})[k]; return v!=null && v!==''; })) return k;
    }
    // Widen: check ticketCols display names
    for (const c of candidates) {
      const found = Object.keys(ticketCols).find(k =>
        ticketCols[k].toLowerCase().includes(c.toLowerCase()) ||
        k.toLowerCase().includes(c.toLowerCase())
      );
      if (found && tickets.some(t=>(t.fields||{})[found]!=null)) return found;
    }
    return null;
  };

  const cKat  = findCol(katCandidates);
  const cWerk = findCol(werkCandidates);
  const cType = findCol(artCandidates);
  const cAsgn = findCol(asgnCandidates);

  // Cache discovered columns
  if(cKat)  _discoveredCols.kat  = cKat;
  if(cWerk) _discoveredCols.werk = cWerk;
  if(cType) _discoveredCols.type = cType;
  if(cAsgn) _discoveredCols.asgn = cAsgn;

  dbg('buildFilterOptions discovered', {cKat,cWerk,cType,cAsgn});

  tickets.forEach(it=>{
    const f=it.fields||{};
    if(cKat  && f[cKat])  sets.kat.add(String(f[cKat]));
    if(cWerk && f[cWerk]) sets.werk.add(String(f[cWerk]));
    if(cType && f[cType]) sets.art.add(String(f[cType]));
    if(cAsgn && f[cAsgn]){ const n=personName(f[cAsgn]); if(n && n.length>1) sets.assigned.add(n); }
  });

  const fill=(id,set,label)=>{
    const sel=$id(id); if(!sel) return;
    const cur=sel.value;
    sel.innerHTML='<option value="">'+label+'</option>';
    [...set].sort().forEach(v=>{ const o=document.createElement('option'); o.value=o.textContent=v; sel.appendChild(o); });
    if([...set].includes(cur)) sel.value=cur;
  };
  fill('tkt-kat',sets.kat,'Alle Kategorien');
  fill('tkt-werk',sets.werk,'Alle Werke');
  fill('tkt-art',sets.art,'Alle Arten');
  fill('tkt-assigned',sets.assigned,'Alle Zugewiesen');
}

function filterTickets() {
  displayedCount = 100;
  dbg('filterTickets aufgerufen', {filterAktiv: filterActive(), suche: $id('tkt-search').value, status: $id('tkt-st').value, prio: $id('tkt-prio').value});
  if (filterActive()) {
    const filtered = applyFilters(allTickets);
    dbg('Filter angewendet', {vorher: allTickets.length, nachher: filtered.length});
    renderTickets(filtered);
    renderLoadMore();
  } else {
    renderTickets(allTickets.slice(0, displayedCount));
    renderLoadMore();
  }
}

function openTicketDetail(id) {
  const it = allTickets.find(t=>t.id==id);
  if (!it) return;
  editingId = id;
  const f = it.fields||{};
  const sidebar = $id('tkt-sidebar');
  $id('sb-title').textContent = `Ticket #${id}`;

  // Status quick-change
  const colStatus  = col(['Status'])||'Status';
  const curStatus  = f[colStatus]||f.Status||'Offen';
  const assignedCol= getCol('assigned');
  const statuses = TICKET_STATUSES;
  const stColors = STATUS_COLORS;

  let html = `<div class="section-title">Status</div>
    <div style="display:flex;align-items:center;gap:10px;">
      <span class="st-badge" id="sb-status-badge-${id}" style="font-size:12px;padding:5px 14px;background:${stColors[curStatus]||'#666'}22;color:${stColors[curStatus]||'#666'};">${esc(curStatus)}</span>
      <select onchange="changeStatus('${id}',this.value)" style="padding:6px 10px;border:1.5px solid var(--border2);border-radius:6px;font-family:inherit;font-size:12px;cursor:pointer;">
        ${(ticketChoices[colStatus]&&ticketChoices[colStatus].length?ticketChoices[colStatus]:statuses).map(s=>`<option value="${esc(s)}"${s===curStatus?' selected':''}>${esc(s)}</option>`).join('')}
      </select>
    </div>`;

  // Always show assigned field — try multiple known column names
  const _assignedKey = assignedCol || _discoveredCols.asgn || col(['Zugewiesen','AssignedTo','Zugewiesen_x0020_an','Bearbeiter','ZugewiesenAn']);
  {
    const v = _assignedKey ? f[_assignedKey] : null;
    const nameStr = v ? personName(v) : '';
    const fid = 'sb_assigned_'+id;
    const fkKey = _assignedKey || 'AssignedTo';
    html+=`<div class="field-row"><label>Zugewiesen an</label>
      <div style="position:relative;">
        <input id="${fid}" data-fk-person="${esc(fkKey)}" value="${esc(nameStr)}"
          style="font-size:12px;width:100%;padding:8px 11px;border:1.5px solid var(--border2);border-radius:6px;outline:none;background:#fff;"
          placeholder="Name suchen…" autocomplete="off"
          oninput="searchUsers(this,'${fid}_dd')"/>
        <div id="${fid}_dd" style="display:none;position:absolute;top:100%;left:0;right:0;background:#fff;border:1.5px solid var(--border2);border-top:none;border-radius:0 0 7px 7px;z-index:201;max-height:180px;overflow:auto;box-shadow:var(--shadow);"></div>
        <input type="hidden" id="${fid}_id" data-fk="${esc(fkKey)}LookupId"/>
      </div>
    </div>`;
  }
  // Fields to hide completely
  const skip = new Set(DISPLAY_SKIP_KEYS);
  if (assignedCol) skip.add(assignedCol); // already shown above as editable field
  html += `<div class="section-title" style="margin-top:12px;">Details</div>`;
  // Detect description and person columns
  const descCol = getCol('desc');
  const authorCol = col(['Author0','Ticket_x0020_erstellt_x0020_von','TicketErstelltVon','ErstelltVon']);

  Object.entries(f).forEach(([k,v])=>{
    if(skip.has(k)||k.startsWith('_')||k.startsWith('@odata')) return;
    if(k===colStatus) return; // already shown
    if(v===null||v===undefined||v==='') return; // skip empty
    const label = ticketCols[k]||k;

    // Description/comment or any rich text HTML field → editable textarea + formatted preview
    if(k===descCol || isRichText(v)) {
      const rendered = cleanHtml(v);
      const taId = 'ta_'+k.replace(/[^a-z0-9]/gi,'_');
      const pvId = 'pv_'+k.replace(/[^a-z0-9]/gi,'_');
      html+=`<div class="field-row"><label>${esc(label)}</label>
        <div id="${pvId}" class="desc-box" style="padding:10px 12px;border:1.5px solid var(--border2);border-radius:6px;font-size:12px;line-height:1.7;background:var(--bg);min-height:40px;word-break:break-word;cursor:pointer;" title="Klicken zum Bearbeiten" onclick="if(!event.target.closest('a')){this.style.display='none';document.getElementById('${taId}').style.display='';document.getElementById('${taId}').focus();}">${rendered}<br><span style="font-size:10px;color:var(--blue);display:block;margin-top:4px;">✏️ Klicken zum Bearbeiten</span></div>
        <textarea id="${taId}" data-fk="${esc(k)}" style="font-size:12px;margin-top:0;display:none;width:100%;min-height:120px;padding:8px 11px;border:1.5px solid var(--navy);border-radius:6px;font-family:inherit;outline:none;" rows="6" onblur="if(!this.value.trim()){document.getElementById('${pvId}').style.display='';this.style.display='none';}">${esc(String(v||''))}</textarea>
      </div>`;
      return;
    }

    // Person fields — editable with user search
    const isPersonJson = typeof v === 'string' && v.startsWith('[') && /LookupValue|Email/.test(v);
    const isPersonObj  = Array.isArray(v) && v.length && (v[0]?.LookupValue || v[0]?.Email);
    if(k===assignedCol || k===authorCol || isPersonJson || isPersonObj) {
      const nameStr = personName(v);
      const isEditable = (k===assignedCol);
      if(isEditable){
        const fid='ppl_'+k.replace(/[^a-z0-9]/gi,'_');
        html+=`<div class="field-row"><label>${esc(label)}</label>
          <div style="position:relative;">
            <input id="${fid}" data-fk-person="${esc(k)}" value="${esc(nameStr)}" style="font-size:12px;width:100%;" placeholder="Name suchen…" autocomplete="off" oninput="searchUsers(this,'${fid}_dd')"/>
            <div id="${fid}_dd" style="display:none;position:absolute;top:100%;left:0;right:0;background:#fff;border:1.5px solid var(--border2);border-top:none;border-radius:0 0 7px 7px;z-index:200;max-height:180px;overflow:auto;box-shadow:var(--shadow);"></div>
            <input type="hidden" id="${fid}_id" data-fk="${esc(k)}LookupId"/>
          </div>
        </div>`;
      } else {
        html+=`<div class="field-row"><label>${esc(label)}</label>
          <input value="${esc(nameStr)}" style="font-size:12px;background:var(--bg);" readonly tabindex="-1"/></div>`;
      }
      return;
    }

    // Choice fields → dropdown select
    if (ticketChoices[k]) {
      let curVal = String(v||'');
      // Normalize priority variants (e.g. "Mittel"→"Normal", "high"→"Hoch") so the
      // select pre-selects correctly even when SP stores legacy or English values
      const choices = ticketChoices[k];
      if (!choices.includes(curVal)) {
        const norm = normPrio(curVal);
        if (choices.includes(norm)) curVal = norm;
      }
      html+=`<div class="field-row"><label>${esc(label)}</label>
        <select data-fk="${esc(k)}" style="padding:7px 10px;border:1.5px solid var(--border2);border-radius:6px;font-family:inherit;font-size:12px;">
          <option value="">— wählen —</option>
          ${choices.map(c=>`<option value="${esc(c)}"${c===curVal?' selected':''}>${esc(c)}</option>`).join('')}
        </select></div>`;
      return;
    }

    // Date fields → readonly, formatted
    const isDateField = /^(Created|Modified|Erstellt|Geändert|Datum|Date|Fällig|SLA)/i.test(k) ||
                        (typeof v==='string' && /^\d{4}-\d{2}-\d{2}T/.test(v));
    if (isDateField && v) {
      html+=`<div class="field-row"><label>${esc(label)}</label>
        <input value="${fmtFull(v)}" style="font-size:12px;background:var(--bg);color:var(--text-dim);cursor:default;" readonly tabindex="-1"/></div>`;
      return;
    }

    // Regular fields
    let valStr;
    if (typeof v === 'object') {
      valStr = v?.LookupValue || v?.displayName || v?.Title || v?.Email || '';
      if (!valStr) try { valStr = JSON.stringify(v); } catch { valStr = ''; }
    } else {
      valStr = String(v);
    }
    html+=`<div class="field-row"><label>${esc(label)}</label>
      <input data-fk="${esc(k)}" value="${esc(valStr)}" style="font-size:12px;"/></div>`;
  });

  // Attachments — fetched via SP REST (Graph doesn't support AttachmentFiles expand)
  html+=`<div class="section-title">Kommentare</div>
    <div id="comments-${id}" style="margin-bottom:8px;"><span style="font-size:11px;color:var(--text-muted);">Lade…</span></div>
    <div id="comment-add-${id}" style="display:none;">
      <div style="position:relative;">
        <textarea id="comment-input-${id}" rows="2" placeholder="Kommentar schreiben... (@Name für Erwähnung)"
          style="width:100%;font-size:12px;padding:7px 10px;border:1.5px solid var(--border2);border-radius:6px;font-family:inherit;outline:none;resize:vertical;"
          oninput="commentAtTrigger(this,'comment-input-${id}','sb-cmt-at-${id}')"></textarea>
        <div id="sb-cmt-at-${id}" style="display:none;position:absolute;bottom:100%;left:0;background:#fff;border:1.5px solid var(--border2);border-radius:7px 7px 0 0;z-index:202;max-height:180px;min-width:220px;overflow:auto;box-shadow:var(--shadow);"></div>
      </div>
      <button onclick="postTicketComment('${id}')"
        style="margin-top:4px;padding:5px 14px;background:var(--navy);color:#fff;border:none;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;">
        Kommentar senden
      </button>
    </div>`;
  html+=`<div class="section-title">Anhänge</div>
    <div id="atts-${id}" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px;">
      <span style="font-size:11px;color:var(--text-muted);">Lade…</span></div>`;
  html+=`<div class="section-title">Anhang hochladen</div>
    <label class="attach-pill" style="cursor:pointer;">
      ＋ Datei(en) wählen
      <input type="file" multiple style="display:none;" onchange="uploadAttachments(this.files,'${id}')"/>
    </label>
    <div style="font-size:10px;color:var(--text-muted);margin-top:4px;">
      Erstellt: ${fmtFull(it.createdDateTime)}
    </div>`;

  $id('sb-body').innerHTML = html;
  $id('sb-actions').innerHTML = `
    <button class="btn btn-primary" onclick="saveSidebar('${id}')" style="flex:1;">✓ Speichern</button>
    <button class="btn btn-ghost" onclick="openTabFromSidebar('${id}')" title="Als Tab in Hauptansicht öffnen">⊞ Tab</button>
    <button class="btn btn-ghost" onclick="openTicketFullscreen('${id}')">⛶</button>
    <button class="btn btn-ghost"   onclick="closeSidebar()">✕</button>`;

  sidebar.classList.add('open');
  fetchTicketComments(id);
  fetchTicketAttachments(id);
}

function renderCommentText(text, mentions) {
  if (!text) return '';
  let html = esc(text);
  if (mentions && mentions.length) {
    // SP GET response: mentions[].mentionText = "@Name", mentions[].mentioned.loginName flat
    mentions.forEach(m => {
      if (!m.mentionText) return;
      const safe = esc(m.mentionText);
      const loginName = m.mentioned?.loginName || '';
      const email = loginName.includes('|') ? loginName.split('|').pop()
                  : (m.mentioned?.email || '');
      const href = email ? `mailto:${email}` : `#`;
      html = html.split(safe).join(
        `<a href="${esc(href)}" style="color:#0078d4;font-weight:600;text-decoration:none;background:rgba(0,120,212,.08);border-radius:3px;padding:0 2px;" title="${esc(email)}">${safe}</a>`
      );
    });
  } else {
    // Fallback for plain-text comments: match capitalised "Firstname Lastname" patterns.
    // Each word must start with a capital letter → stops before normal sentence words.
    html = html.replace(/@([A-ZÄÖÜ][a-zA-ZäöüÄÖÜß]+(?: [A-ZÄÖÜ][a-zA-ZäöüÄÖÜß]+)*)/g,
      '<a href="#" style="color:#0078d4;font-weight:600;text-decoration:none;background:rgba(0,120,212,.08);border-radius:3px;padding:0 2px;">@$1</a>');
  }
  // Auto-link URLs
  html = html.replace(/(https?:\/\/[^\s<"'&]+)/g,
    '<a href="$1" target="_blank" style="color:var(--blue);word-break:break-all;">$1</a>');
  return html.replace(/\n/g, '<br>');
}

async function fetchTicketComments(id, containerId) {
  const container = $id(containerId||'comments-'+id);
  if (!container) return;
  try {
    const spTok = await getSpToken();
    const r = await fetch(
      `https://dihag.sharepoint.com/sites/ticket/_api/web/lists(guid'${ticketListId}')/GetItemById(${id})/Comments`,
      {headers:{Authorization:'Bearer '+spTok, Accept:'application/json;odata=nometadata'}}
    );
    if (!r.ok) { container.innerHTML='<span style="font-size:11px;color:var(--text-muted);">Kommentare nicht verfügbar</span>'; return; }
    const j = await r.json();
    const comments = j.value||[];
    const addBox = $id('comment-add-'+id);
    container.innerHTML = '';
    if (!comments.length) {
      container.innerHTML = '<div style="font-size:11px;color:var(--text-muted);padding:4px 0;">Noch keine Kommentare.</div>';
    } else {
      comments.forEach(c=>{
        const author = c.author?.name || c.author?.email || 'Unbekannt';
        const date   = c.createdDate ? fmtFull(c.createdDate) : '';
        const div = document.createElement('div');
        div.style.cssText='border:1px solid var(--border);border-radius:6px;padding:8px 10px;margin-bottom:6px;background:var(--bg);font-size:12px;';
        div.innerHTML=`<div style="display:flex;justify-content:space-between;margin-bottom:4px;">
          <span style="font-weight:600;color:var(--navy);">${esc(author)}</span>
          <span style="font-size:10px;color:var(--text-muted);">${esc(date)}</span>
        </div><div style="line-height:1.6;word-break:break-word;">${renderCommentText(c.text, c.mentions)}</div>`;
        container.appendChild(div);
      });
    }
    if (addBox) addBox.style.display='';
  } catch(e) {
    if (container) container.innerHTML=`<span style="font-size:11px;color:var(--red);">${esc(e.message)}</span>`;
  }
}

let _commentMentions = {};

function commentAtTrigger(ta, taId, ddId) {
  const dd = $id(ddId);
  if (!dd) return;
  const pos = ta.selectionStart;
  const before = ta.value.substring(0, pos);
  const atIdx = before.lastIndexOf('@');
  if (atIdx === -1 || (atIdx > 0 && /\S/.test(before[atIdx-1]))) { dd.style.display='none'; return; }
  const q = before.substring(atIdx+1);
  if (q.length < 2) { dd.style.display='none'; return; }
  clearTimeout(_userSearchTimer);
  _userSearchTimer = setTimeout(async ()=>{
    try {
      const res = await gGet(`/users?$filter=startswith(displayName,'${encodeURIComponent(q)}')&$select=id,displayName,mail,userPrincipalName&$top=6`);
      const users = res.value||[];
      if (!users.length) { dd.style.display='none'; return; }
      dd.innerHTML = users.map(u=>`
        <div style="padding:8px 12px;cursor:pointer;font-size:12px;border-bottom:1px solid var(--border);"
          onmouseover="this.style.background='var(--bg)'" onmouseout="this.style.background=''"
          data-name="${esc(u.displayName)}" data-mail="${esc(u.mail||u.userPrincipalName||'')}"
          onclick="selectCommentMention(this,'${taId}','${ddId}')">
          <div style="font-weight:600;">${esc(u.displayName)}</div>
          <div style="font-size:10px;color:var(--text-muted);">${esc(u.mail||u.userPrincipalName||'')}</div>
        </div>`).join('');
      dd.style.display = 'block';
    } catch(e) { dd.style.display='none'; }
  }, 300);
}

function selectCommentMention(el, taId, ddId) {
  const ta = $id(taId);
  const dd = $id(ddId);
  if (!ta || !dd) return;
  const name = el.dataset.name||'';
  const mail = el.dataset.mail||'';
  const pos = ta.selectionStart;
  const before = ta.value.substring(0, pos);
  const atIdx = before.lastIndexOf('@');
  ta.value = ta.value.substring(0, atIdx) + '@' + name + ' ' + ta.value.substring(pos);
  if (!_commentMentions[taId]) _commentMentions[taId] = [];
  _commentMentions[taId].push({name, mail});
  dd.style.display = 'none';
  ta.focus();
}

async function sendMentionNotifications(mentions, ticketId, commentText) {
  console.log('[MENTION-MAIL] Funktion aufgerufen', { mentions, ticketId, commentText });
  if (!mentions || mentions.length === 0) { console.warn('[MENTION-MAIL] Keine Mentions – Abbruch'); return; }

  const ticket      = allTickets.find(t => t.id == ticketId);
  const _tCol       = getCol('title') || 'Title';
  const ticketTitle = ticket?.fields?.[_tCol] || '';
  const senderName  = account?.name || 'Ticketsystem';
  const ticketUrl   = 'https://dfedorov12.github.io/tickets/';
  // Direct SharePoint link to the ticket item (DispForm)
  const spTicketUrl = ticketListId
    ? `https://dihag.sharepoint.com/sites/ticket/_layouts/15/listform.aspx?PageType=4&ListId={${ticketListId}}&ID=${ticketId}`
    : null;

  // Graph-Token mit Mail.Send holen (SCOPES enthält Mail.Send).
  // forceRefresh=true stellt sicher dass ein frischer Token mit allen Scopes geholt wird,
  // auch wenn der Nutzer sich vor Hinzufügen von Mail.Send angemeldet hatte.
  let mailTok;
  try {
    const res = await msalApp.acquireTokenSilent({ scopes: SCOPES, account, forceRefresh: true });
    mailTok = res.accessToken;
    console.log('[MENTION-MAIL] Token (silent+refresh) erhalten ✓, scopes:', res.scopes);
  } catch(silentErr) {
    console.warn('[MENTION-MAIL] Silent fehlgeschlagen, versuche Popup:', silentErr.message);
    try {
      const res = await msalApp.acquireTokenPopup({ scopes: SCOPES, account });
      mailTok = res.accessToken;
      console.log('[MENTION-MAIL] Token (popup) erhalten ✓, scopes:', res.scopes);
    } catch(popupErr) {
      console.error('[MENTION-MAIL] Token komplett fehlgeschlagen:', popupErr);
      toast('E-Mail: Anmeldung/Zustimmung fehlt – bitte neu einloggen (' + popupErr.message + ')', 'error');
      return;
    }
  }

  const bodyHtml =
    `<p><strong>${esc(senderName)}</strong> hat Sie in Ticket ` +
    `<strong>#${ticketId}${ticketTitle ? ' – ' + esc(ticketTitle) : ''}</strong> erwähnt:</p>` +
    `<blockquote style="border-left:3px solid #0078d4;padding:8px 12px;background:#f0f8ff;margin:12px 0;">` +
    `${esc(commentText)}</blockquote>` +
    `<p><a href="${spTicketUrl || ticketUrl}" style="color:#0078d4;font-weight:600;">In SharePoint öffnen →</a></p>`;

  let sent = 0;
  for (const m of mentions) {
    console.log('[MENTION-MAIL] Verarbeite Mention:', m);
    if (!m.mail) { console.warn('[MENTION-MAIL] Kein Mail-Feld:', m); continue; }
    try {
      const body = JSON.stringify({
        message: {
          subject: `${senderName} hat Sie in Ticket #${ticketId} erwähnt`,
          body: { contentType: 'HTML', content: bodyHtml },
          toRecipients: [{ emailAddress: { address: m.mail, name: m.name } }]
        },
        saveToSentItems: false
      });
      console.log('[MENTION-MAIL] POST me/sendMail →', m.mail);
      const r = await fetch('https://graph.microsoft.com/v1.0/me/sendMail', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + mailTok, 'Content-Type': 'application/json' },
        body
      });
      const respText = await r.text().catch(() => '');
      console.log('[MENTION-MAIL] Antwort:', r.status, respText || '(leer = OK)');
      if (!r.ok) throw new Error(`HTTP ${r.status}: ${respText}`);
      sent++;
    } catch(e) {
      console.error('[MENTION-MAIL] Fehler für', m.mail, e);
      toast(`E-Mail an ${m.name} fehlgeschlagen: ${e.message}`, 'error');
    }
  }
  if (sent > 0) toast(`Benachrichtigung an ${sent} Person${sent > 1 ? 'en' : ''} gesendet`, 'success');
  console.log('[MENTION-MAIL] Fertig – gesendet:', sent, '/', mentions.length);
}

async function postTicketComment(id, inputId) {
  const taId = inputId || 'comment-input-'+id;
  const ctnId = inputId && inputId.startsWith('dt-') ? 'dt-comments-'+id : 'comments-'+id;
  const ta = $id(taId);
  const text = (ta?.value||'').trim();
  if (!text) return;
  // SP Comments API rejects all mention properties — post as plain text only.
  // @mention notifications are delivered via SP email API instead.
  const rawMentions = _commentMentions[taId] || [];
  console.log('[COMMENT] taId:', taId, '| rawMentions:', JSON.stringify(rawMentions));
  try {
    const spTok = await getSpToken();
    const url = `https://dihag.sharepoint.com/sites/ticket/_api/web/lists(guid'${ticketListId}')/GetItemById(${id})/Comments`;
    const headers = {Authorization:'Bearer '+spTok, Accept:'application/json;odata=nometadata','Content-Type':'application/json'};
    const r = await fetch(url, {method:'POST', headers, body:JSON.stringify({text})});
    if (!r.ok) throw new Error('HTTP '+r.status);
    ta.value='';
    delete _commentMentions[taId];
    // Send email notification for every @mention via Graph
    if (rawMentions.length) sendMentionNotifications(rawMentions, id, text);
    toast('Kommentar gespeichert','success');
    fetchTicketComments(id, ctnId);
  } catch(e) { toast('Fehler: '+e.message,'error'); }
}

async function deleteAttachment(ticketId, fileName) {
  if (!confirm(`Anhang "${fileName}" wirklich löschen?`)) return;
  try {
    const spTok = await getSpToken();
    const r = await fetch(
      `https://dihag.sharepoint.com/sites/ticket/_api/web/lists(guid'${ticketListId}')/items(${ticketId})/AttachmentFiles('${encodeURIComponent(fileName)}')`,
      {method:'DELETE', headers:{Authorization:'Bearer '+spTok, Accept:'application/json;odata=verbose',
       'X-HTTP-Method':'DELETE','If-Match':'*'}}
    );
    if (!r.ok && r.status !== 200 && r.status !== 204) throw new Error('HTTP '+r.status);
    toast('Anhang geloescht','success');
    fetchTicketAttachments(ticketId);
    fetchTicketAttachmentsTo(ticketId,'dt-atts-'+ticketId);
    fetchTicketAttachmentsFs(ticketId);
    const it = allTickets.find(t=>t.id==ticketId);
    if(it && it._attachCount>0) it._attachCount--;
  } catch(e){ toast('Loeschen fehlgeschlagen: '+e.message,'error'); }
}

function _renderAttachFiles(files, container, ticketId) {
  container.innerHTML = '';
  if (!files.length) { container.innerHTML='<span style="font-size:11px;color:var(--text-muted);">Keine Anhänge</span>'; return; }
  files.forEach(a=>{
    const fileName = a.FileName||'Anhang';
    const url = a.ServerRelativeUrl ? 'https://dihag.sharepoint.com'+a.ServerRelativeUrl : (a.AbsoluteUri||'#');
    const wrap = document.createElement('span');
    wrap.style.cssText='display:inline-flex;align-items:center;gap:0;margin:0 4px 4px 0;';
    const link = document.createElement('a');
    link.href=url; link.target='_blank'; link.className='attach-pill';
    link.style.cssText='border-radius:6px 0 0 6px;margin:0;';
    link.textContent='📎 '+fileName;
    const del = document.createElement('button');
    del.title='Anhang loeschen'; del.textContent='✕';
    del.style.cssText='padding:5px 8px;background:var(--red-bg);border:1px solid var(--red);border-left:none;border-radius:0 6px 6px 0;cursor:pointer;font-size:10px;color:var(--red);font-weight:700;';
    del.onclick=()=>deleteAttachment(ticketId, fileName);
    wrap.appendChild(link); wrap.appendChild(del);
    container.appendChild(wrap);
  });
}

async function fetchTicketAttachments(id) {
  const container = document.getElementById('atts-'+id);
  if (!container) return;
  try {
    const spTok = await getSpToken();
    const r = await fetch(
      `https://dihag.sharepoint.com/sites/ticket/_api/web/lists(guid'${ticketListId}')/items(${id})/AttachmentFiles`,
      {headers:{Authorization:'Bearer '+spTok, Accept:'application/json;odata=verbose'}}
    );
    const j = await r.json();
    const files = j?.d?.results||j?.value||[];
    // Update count in table row
    const it = allTickets.find(t=>t.id==id);
    if (it) it._attachCount = files.length;

    _renderAttachFiles(files, container, id);
  } catch(e) {
    if (container) container.innerHTML='<span style="font-size:11px;color:var(--red);">'+esc(e.message)+'</span>';
  }
}

function closeSidebar() { $id('tkt-sidebar').classList.remove('open'); editingId=null; }

// ── IN-APP TICKET TABS ──
let _openTabs = {};
let _activeTabId = null;

function openTabFromSidebar(id) {
  // Open full detail panel as tab, keep sidebar closing
  const it = allTickets.find(t=>t.id==id);
  if (!it) return;
  const f = it.fields||{};
  const cTitle = getCol('title')||'Title';
  const title = String(f[cTitle]||f.Title||'#'+id).substring(0,30);
  _openTabs[id] = {id, title};
  _activeTabId = id;
  renderTabBar();
  showTicketDetailPanel(id);
  showPanel('ticket-detail');
  closeSidebar();
}

function openTicketTabBg(id) {
  // Open tab in background without switching to it
  const it = allTickets.find(t=>t.id==id);
  if (!it) { toast('Ticket nicht im Cache','error'); return; }
  const f = it.fields||{};
  const cTitle = getCol('title')||'Title';
  const title  = String(f[cTitle]||f.Title||'Ticket #'+id).substring(0,30);
  _openTabs[id] = {id, title};
  renderTabBar();
  toast(`Tab #${id} im Hintergrund geöffnet`, 'info');
}

function openTicketTab(id) {
  // Single click = open sidebar (quick view, keep ticket list visible)
  openTicketDetail(id);
}

function renderTabBar() {
  const bar = $id('ticket-tabs');
  if (!bar) return;
  const ids = Object.keys(_openTabs);
  bar.style.display = ids.length ? 'flex' : 'none';
  bar.innerHTML = ids.map(id => {
    const t = _openTabs[id];
    const active = _activeTabId==id ? ' active' : '';
    return '<div class="tkt-tab'+active+'" onclick="switchTab(\'' + id + '\')">'
      + '<span class="tkt-tab-label">#' + id + ' ' + esc(t.title) + '</span>'
      + '<span class="tkt-tab-close" onclick="event.stopPropagation();closeTab(\'' + id + '\')">✕</span>'
      + '</div>';
  }).join('');
}

function switchTab(id) {
  _activeTabId = id;
  renderTabBar();
  showTicketDetailPanel(id);
  showPanel('ticket-detail');
}

function closeTab(id) {
  delete _openTabs[id];
  const remaining = Object.keys(_openTabs);
  if (_activeTabId == id) {
    if (remaining.length) { _activeTabId=remaining[remaining.length-1]; showTicketDetailPanel(_activeTabId); showPanel('ticket-detail'); }
    else { _activeTabId=null; showPanel('tickets'); }
  }
  renderTabBar();
}

function showTicketDetailPanel(id) {
  const it = allTickets.find(t=>t.id==id);
  if (!it) return;
  const f = it.fields||{};
  const colStatus = col(['Status'])||'Status';
  const curStatus = f[colStatus]||'Offen';
  const cTitle    = getCol('title')||'Title';
  const cDesc     = getCol('desc');
  const cAssign   = getCol('assigned');
  const stColors = STATUS_COLORS;
  const statuses = TICKET_STATUSES;
  const skipKeys  = new Set(DISPLAY_SKIP_KEYS);
  const stColor   = stColors[curStatus]||'#666';
  const titleText = esc(f[cTitle]||f.Title||'');

  let fieldsHtml = '';
  Object.entries(f).forEach(([k,v])=>{
    if(skipKeys.has(k)||k.startsWith('_')||k.startsWith('@odata')||k===colStatus||v===null||v===undefined||v==='') return;
    const label    = ticketCols[k]||k;
    const isAssign = k===cAssign;
    const isDesc   = k===cDesc||isRichText(v);

    if(isDesc){
      const taId2='ta2_'+k.replace(/[^a-z0-9]/gi,'_');
      const pvId2='pv2_'+k.replace(/[^a-z0-9]/gi,'_');
      fieldsHtml+=`<div class="field-row" style="grid-column:1/-1"><label>${esc(label)}</label>
        <div id="${pvId2}" class="desc-box" style="padding:10px 12px;border:1.5px solid var(--border2);border-radius:6px;font-size:13px;line-height:1.7;background:var(--bg);cursor:pointer;" title="Klicken zum Bearbeiten" onclick="if(!event.target.closest('a')){this.style.display='none';document.getElementById('${taId2}').style.display='';document.getElementById('${taId2}').focus();}">${cleanHtml(v)}<br><span style="font-size:10px;color:var(--blue);display:block;margin-top:4px;">✏️ Klicken zum Bearbeiten</span></div>
        <textarea id="${taId2}" data-fk="${esc(k)}" style="display:none;font-size:12px;margin-top:0;width:100%;min-height:120px;padding:8px 11px;border:1.5px solid var(--navy);border-radius:6px;font-family:inherit;outline:none;" rows="6" onblur="if(!this.value.trim()){document.getElementById('${pvId2}').style.display='';this.style.display='none';}">${esc(String(v||''))}</textarea>
        </div>`;
    } else if(isAssign){
      const fid='dtppl_'+k.replace(/[^a-z0-9]/gi,'_');
      fieldsHtml+=`<div class="field-row"><label>${esc(label)}</label>
        <div style="position:relative;">
          <input id="${fid}" data-fk-person="${esc(k)}" value="${esc(personName(v))}" style="width:100%;font-size:12px;" placeholder="Name suchen..." autocomplete="off"/>
          <div id="${fid}_dd" style="display:none;position:absolute;top:100%;left:0;right:0;background:#fff;border:1.5px solid var(--border2);border-top:none;border-radius:0 0 7px 7px;z-index:200;max-height:180px;overflow:auto;box-shadow:var(--shadow);"></div>
          <input type="hidden" id="${fid}_id" data-fk="${esc(k)}LookupId"/>
        </div></div>`;
    } else if(ticketChoices[k]){
      let curVal=String(v||'');
      const ch=ticketChoices[k];
      if(!ch.includes(curVal)){const n=normPrio(curVal);if(ch.includes(n))curVal=n;}
      fieldsHtml+=`<div class="field-row"><label>${esc(label)}</label>
        <select data-fk="${esc(k)}" style="padding:7px 10px;border:1.5px solid var(--border2);border-radius:6px;font-family:inherit;font-size:12px;">
          <option value="">— wählen —</option>
          ${ch.map(c=>`<option value="${esc(c)}"${c===curVal?' selected':''}>${esc(c)}</option>`).join('')}
        </select></div>`;
    } else if(typeof v==='string'&&/^\d{4}-\d{2}-\d{2}T/.test(v)){
      fieldsHtml+=`<div class="field-row"><label>${esc(label)}</label><input value="${fmtFull(v)}" style="font-size:12px;background:var(--bg);" readonly/></div>`;
    } else if(Array.isArray(v)||(typeof v==='string'&&v.startsWith('['))){
      fieldsHtml+=`<div class="field-row"><label>${esc(label)}</label><input value="${esc(personName(v))}" style="font-size:12px;background:var(--bg);" readonly/></div>`;
    } else {
      const valStr = typeof v==='object'?(v?.LookupValue||v?.displayName||v?.Title||v?.Email||''):String(v);
      fieldsHtml+=`<div class="field-row"><label>${esc(label)}</label><input data-fk="${esc(k)}" value="${esc(valStr)}" style="font-size:12px;"/></div>`;
    }
  });

  const _sOpts = ticketChoices[colStatus]&&ticketChoices[colStatus].length?ticketChoices[colStatus]:statuses;
  const stOpts = _sOpts.map(s=>`<option value="${esc(s)}"${s===curStatus?' selected':''}>${esc(s)}</option>`).join('');

  const _dtAsnKey = cAssign || _discoveredCols.asgn || col(['Zugewiesen','AssignedTo','Zugewiesen_x0020_an','Bearbeiter','ZugewiesenAn']);
  const _dtAsnName = _dtAsnKey ? personName(f[_dtAsnKey]||'') : '';
  const dtAsnFid = 'dtasn_'+id;

  $id('tkt-detail-content').innerHTML = `
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap;">
      <div style="font-size:20px;font-weight:700;color:var(--navy);flex:1;">Ticket #${id} — ${titleText}</div>
      <button class="btn btn-primary" onclick="saveDetailTab('${id}')">✓ Speichern</button>
    </div>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:20px;">
      <span class="st-badge" id="dt-status-badge-${id}" style="font-size:13px;padding:5px 16px;background:${stColor}22;color:${stColor};">${esc(curStatus)}</span>
      <select onchange="changeStatus('${id}',this.value)" style="padding:6px 10px;border:1.5px solid var(--border2);border-radius:6px;font-family:inherit;font-size:12px;cursor:pointer;">
        ${stOpts}
      </select>
      <span style="font-size:11px;color:var(--text-muted);margin-left:4px;">Erstellt: ${fmtFull(it.createdDateTime)}</span>
    </div>
    <div style="margin-bottom:14px;max-width:360px;">
      <label style="display:block;font-size:10px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px;">Zugewiesen an</label>
      <div style="position:relative;">
        <input id="${dtAsnFid}" data-fk-person="${esc(_dtAsnKey||'AssignedTo')}" value="${esc(_dtAsnName)}"
          style="width:100%;padding:7px 11px;border:1.5px solid var(--border2);border-radius:6px;font-size:12px;outline:none;"
          placeholder="Name suchen..." autocomplete="off" oninput="searchUsers(this,'${dtAsnFid}_dd')"/>
        <div id="${dtAsnFid}_dd" style="display:none;position:absolute;top:100%;left:0;right:0;background:#fff;border:1.5px solid var(--border2);border-top:none;border-radius:0 0 7px 7px;z-index:201;max-height:180px;overflow:auto;box-shadow:var(--shadow);"></div>
        <input type="hidden" id="${dtAsnFid}_id" data-fk="${esc(_dtAsnKey||'AssignedTo')}LookupId"/>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;" id="dt-fields-${id}">${fieldsHtml}</div>
    <div class="section-title" style="margin-top:20px;">Kommentare</div>
    <div id="dt-comments-${id}" style="margin-bottom:8px;"><span style="font-size:11px;color:var(--text-muted);">Lade...</span></div>
    <div id="dt-comment-add-${id}">
      <div style="position:relative;">
        <textarea id="dt-cmt-in-${id}" rows="2"
          placeholder="Kommentar schreiben... (@Name für Erwähnung)"
          style="width:100%;font-size:12px;padding:7px 10px;border:1.5px solid var(--border2);border-radius:6px;font-family:inherit;outline:none;resize:vertical;"
          oninput="commentAtTrigger(this,'dt-cmt-in-${id}','dt-cmt-at-${id}')"></textarea>
        <div id="dt-cmt-at-${id}" style="display:none;position:absolute;bottom:100%;left:0;background:#fff;border:1.5px solid var(--border2);border-radius:7px 7px 0 0;z-index:202;max-height:180px;min-width:220px;overflow:auto;box-shadow:var(--shadow);"></div>
      </div>
      <button onclick="postTicketComment('${id}','dt-cmt-in-${id}')"
        style="margin-top:4px;padding:5px 14px;background:var(--navy);color:#fff;border:none;border-radius:6px;font-size:11px;font-weight:600;cursor:pointer;">
        Kommentar senden
      </button>
    </div>
    <div class="section-title" style="margin-top:20px;">Anhänge</div>
    <div id="dt-atts-${id}" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px;"><span style="font-size:11px;color:var(--text-muted);">Lade...</span></div>
    <label class="attach-pill" style="cursor:pointer;">＋ Datei(en) anhängen<input type="file" multiple style="display:none;" onchange="uploadAttachments(this.files,'${id}')"/></label>`;

  // Attach desc-edit buttons
  $id('tkt-detail-content').querySelectorAll('.desc-edit-btn').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const ta = btn.previousElementSibling;
      const dv = ta.previousElementSibling;
      ta.style.display=''; dv.style.display='none'; btn.style.display='none';
    });
  });
  // Attach person picker
  $id('tkt-detail-content').querySelectorAll('[data-fk-person]').forEach(inp=>{
    const ddId = inp.id+'_dd';
    inp.addEventListener('input', ()=>searchUsers(inp, ddId));
  });

  fetchTicketComments(id, 'dt-comments-'+id);
  fetchTicketAttachmentsTo(id, 'dt-atts-'+id);
}
async function fetchTicketAttachmentsTo(id, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  try {
    const spTok = await getSpToken();
    const r = await fetch('https://dihag.sharepoint.com/sites/ticket/_api/web/lists(guid\''+ticketListId+'\' )/items('+id+')/AttachmentFiles',
      {headers:{Authorization:'Bearer '+spTok, Accept:'application/json;odata=verbose'}});
    const j = await r.json();
    const files = j?.d?.results||j?.value||[];
    _renderAttachFiles(files, container, id);
  } catch(e){ if(container) container.innerHTML='<span style="font-size:11px;color:var(--red);">'+esc(e.message)+'</span>'; }
}

async function saveDetailTab(id) {
  const container = $id('dt-fields-'+id);
  if(!container||!ticketSiteId||!ticketListId) return;
  const raw={};
  container.querySelectorAll('[data-fk]').forEach(el=>{ if(el.value!==undefined&&el.value!=='') raw[el.dataset.fk]=el.value; });
  const fields=stripReadOnly(raw);
  try {
    await gPatch('/sites/'+ticketSiteId+'/lists/'+ticketListId+'/items/'+id+'/fields', fields);
    const it=allTickets.find(t=>t.id==id);
    if(it) Object.assign(it.fields||{}, fields);
    const cTitle=getCol('title')||'Title';
    if(_openTabs[id]&&fields[cTitle]){ _openTabs[id].title=String(fields[cTitle]).substring(0,30); renderTabBar(); }
    toast('Gespeichert ✓','success');
    saveTicketCache();
    const wrap2 = $id('tkt-table-wrap');
    const st2 = wrap2 ? wrap2.scrollTop : 0;
    const list=filterActive()?applyFilters(allTickets):allTickets.slice(0,displayedCount);
    renderTickets(list);
    if (wrap2) wrap2.scrollTop = st2;
  } catch(e){ toast('Fehler: '+e.message,'error'); }
}

function openTicketNewTab(id) {
  const it = allTickets.find(t=>t.id==id);
  if (!it) return;
  const f = it.fields||{};
  const cTitle  = getCol('title')||'Title';
  const cStatus = getCol('status')||'Status';
  const cPrio   = getCol('prio');
  const cAssign = getCol('assigned');
  const cDesc   = getCol('desc');
  const cWerk   = getCol('werk');
  const cKat    = getCol('category');
  const stColors = {Offen:'#2563eb',Neu:'#6366f1','In Bearbeitung':'#d97706','Warten auf Rückmeldung':'#ea580c',Erledigt:'#16a34a',Abgebrochen:'#6b7280'};
  const status = f[cStatus]||'Offen';
  const stColor = stColors[status]||'#6b7280';

  const skipKeys = new Set(['_UIVersionString','ContentType','Attachments','ID','AuthorLookupId',
    'EditorLookupId','AppAuthorLookupId','LinkTitleNoMenu','LinkTitle','ItemChildCount',
    'FolderChildCount','ComplianceAssetId','@odata.etag']);

  let fieldsHtml = '';
  Object.entries(f).forEach(([k,v])=>{
    if(skipKeys.has(k)||k.startsWith('_')||k.startsWith('@odata')||v===null||v===undefined||v==='') return;
    if(k===cStatus) return;
    const label = ticketCols[k]||k;
    let display;
    if(k===cDesc||isRichText(v)) display=`<div style="padding:10px;background:#f8fafc;border-radius:6px;font-size:13px;line-height:1.7;">${cleanHtml(v)}</div>`;
    else if(Array.isArray(v)||typeof v==='string'&&v.startsWith('[')) display=`<div style="font-size:13px;">${esc(personName(v))}</div>`;
    else if(typeof v==='string'&&/^\d{4}-\d{2}-\d{2}T/.test(v)) display=`<div style="font-size:13px;">${fmtFull(v)}</div>`;
    else if(typeof v==='object') display=`<div style="font-size:13px;">${esc(v?.LookupValue||v?.displayName||v?.Title||v?.Email||JSON.stringify(v))}</div>`;
    else {
      // Normalize priority field so "Mittel"→"Normal", "high"→"Hoch" etc.
      const strVal = k===cPrio ? normPrio(String(v)) : String(v);
      display=`<div style="font-size:13px;">${esc(strVal)}</div>`;
    }
    fieldsHtml+=`<div style="margin-bottom:14px;"><div style="font-size:10px;font-weight:700;color:#6b7a8f;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px;">${esc(label)}</div>${display}</div>`;
  });

  const html=`<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Ticket #${id} — ${esc(f[cTitle]||'')}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet"/>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:Inter,sans-serif;background:#f2f4f7;color:#1a2942;min-height:100vh;}
.header{background:#0a1f3c;color:#fff;padding:16px 32px;display:flex;align-items:center;gap:16px;}
.header-title{font-size:20px;font-weight:700;}
.badge{display:inline-flex;align-items:center;padding:4px 14px;border-radius:10px;font-size:12px;font-weight:700;}
.content{max-width:900px;margin:32px auto;padding:0 24px;}
.card{background:#fff;border-radius:12px;padding:28px;box-shadow:0 2px 12px rgba(10,31,60,.09);margin-bottom:20px;}
.card-title{font-size:13px;font-weight:700;color:#0a1f3c;text-transform:uppercase;letter-spacing:.05em;margin-bottom:16px;padding-bottom:8px;border-bottom:1.5px solid #e5e8ed;}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px;}
@media(max-width:600px){.two-col{grid-template-columns:1fr;}}
.field-label{font-size:10px;font-weight:700;color:#6b7a8f;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px;}
.print-btn{background:#0a1f3c;color:#fff;border:none;padding:8px 20px;border-radius:6px;font-family:inherit;font-size:13px;font-weight:600;cursor:pointer;margin-right:8px;}
@media print{.no-print{display:none!important;}.header{-webkit-print-color-adjust:exact;print-color-adjust:exact;}}
</style></head><body>
<div class="header">
  <div>
    <div style="font-size:11px;opacity:.6;margin-bottom:2px;">DIHAG · Ticketsystem</div>
    <div class="header-title">Ticket #${id}</div>
  </div>
  <span class="badge" style="background:${stColor}22;color:${stColor};margin-left:12px;">${esc(status)}</span>
  <div style="margin-left:auto;" class="no-print">
    <button class="print-btn" onclick="window.print()">🖨 Drucken</button>
    <button class="print-btn" style="background:#16345a;" onclick="window.close()">✕ Schließen</button>
  </div>
</div>
<div class="content">
  <div class="card">
    <div style="font-size:22px;font-weight:700;color:#0a1f3c;margin-bottom:6px;">${esc(f[cTitle]||f.Title||'Ohne Titel')}</div>
    <div style="font-size:12px;color:#6b7a8f;">Erstellt: ${fmtFull(it.createdDateTime)}
      ${cAssign&&f[cAssign]?` · Zugewiesen: ${esc(personName(f[cAssign]))}`:''}</div>
  </div>
  <div class="card">
    <div class="card-title">Details</div>
    <div class="two-col">${fieldsHtml}</div>
  </div>
  <div class="card" style="font-size:11px;color:#9ba8b8;">
    Ticket-ID: ${id} · Site: ${esc(ticketSiteId||'')} · Exportiert: ${fmtFull(new Date().toISOString())}
  </div>
</div>
</body></html>`;

  const blob = new Blob([html], {type:'text/html;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const tab = window.open(url,'_blank');
  if (tab) setTimeout(()=>URL.revokeObjectURL(url), 10000);
  else { toast('Popup blockiert — bitte Popup-Blocker deaktivieren','error'); }
}

let fullscreenId = null;

function openTicketFullscreen(id) {
  const it = allTickets.find(t=>t.id==id);
  if (!it) return;
  fullscreenId = id;
  closeSidebar();
  const f = it.fields||{};
  const colStatus = col(['Status'])||'Status';
  const curStatus = f[colStatus]||f.Status||'Offen';
  const statuses = TICKET_STATUSES;
  const stColors = STATUS_COLORS;

  $id('fs-title').textContent = `Ticket #${id}`;
  $id('fs-status-badge').innerHTML = `<span class="fs-status-current" style="background:${stColors[curStatus]||'#666'}22;color:${stColors[curStatus]||'#666'};">${esc(curStatus)}</span>`;

  // Status changer in footer as dropdown
  $id('fs-status-changer').innerHTML = `<span style="font-size:10px;color:var(--text-muted);margin-right:4px;">Status ändern:</span>
    <select onchange="if(this.value)changeStatusFs('${id}',this.value)" style="padding:5px 10px;border:1.5px solid var(--border2);border-radius:6px;font-family:inherit;font-size:11px;cursor:pointer;">
      <option value="">Auswählen…</option>
      ${statuses.filter(s=>s!==curStatus).map(s=>`<option value="${esc(s)}">${esc(s)}</option>`).join('')}
    </select>`;

  // Skip fields
  const skip = new Set(DISPLAY_SKIP_KEYS);
  const descCol = getCol('desc');
  const assignedCol = getCol('assigned');
  const authorCol = col(['Author0','Ticket_x0020_erstellt_x0020_von','TicketErstelltVon','ErstelltVon']);

  let html = '<div class="fs-section">Details</div>';

  Object.entries(f).forEach(([k,v])=>{
    if(skip.has(k)||k.startsWith('_')||k.startsWith('@odata')) return;
    if(k===colStatus) return;
    if(v===null||v===undefined||v==='') return;
    const label = ticketCols[k]||k;

    // Description / rich text
    if(k===descCol || isRichText(v)) {
      const rendered = cleanHtml(v);
      const taId3='ta3_'+k.replace(/[^a-z0-9]/gi,'_');
      const pvId3='pv3_'+k.replace(/[^a-z0-9]/gi,'_');
      html+=`<div class="fs-field fs-body-full"><div class="fs-field-label">${esc(label)}</div>
        <div id="${pvId3}" class="fs-desc-box" style="cursor:pointer;" title="Klicken zum Bearbeiten" onclick="if(!event.target.closest('a')){this.style.display='none';document.getElementById('${taId3}').style.display='';document.getElementById('${taId3}').focus();}">${rendered}<br><span style="font-size:10px;color:var(--blue);display:block;margin-top:4px;">✏️ Klicken zum Bearbeiten</span></div>
        <textarea id="${taId3}" data-fk="${esc(k)}" style="font-size:12px;margin-top:0;display:none;width:100%;min-height:120px;padding:8px;border:1.5px solid var(--navy);border-radius:6px;font-family:inherit;outline:none;" rows="6" onblur="if(!this.value.trim()){document.getElementById('${pvId3}').style.display='';this.style.display='none';}">${esc(String(v||''))}</textarea>
      </div>`;
      return;
    }

    // Person fields
    const isPersonJson = typeof v === 'string' && v.startsWith('[') && /LookupValue|Email/.test(v);
    const isPersonObj = Array.isArray(v) && v.length && (v[0].LookupValue || v[0].Email);
    if(k===assignedCol || k===authorCol || isPersonJson || isPersonObj) {
      html+=`<div class="fs-field"><div class="fs-field-label">${esc(label)}</div>
        <div class="fs-field-val">${esc(personName(v))}</div></div>`;
      return;
    }

    // Choice fields → dropdown
    if (ticketChoices[k]) {
      let curVal = String(v||'');
      const ch2=ticketChoices[k];
      if(!ch2.includes(curVal)){const n=normPrio(curVal);if(ch2.includes(n))curVal=n;}
      html+=`<div class="fs-field"><div class="fs-field-label">${esc(label)}</div>
        <select data-fk="${esc(k)}" style="width:100%;padding:6px 10px;border:1.5px solid var(--border2);border-radius:6px;font-size:13px;font-family:inherit;">
          <option value="">— wählen —</option>
          ${ch2.map(c=>`<option value="${esc(c)}"${c===curVal?' selected':''}>${esc(c)}</option>`).join('')}
        </select></div>`;
      return;
    }

    // Date fields → readonly formatted
    const isDateField = /^(Created|Modified|Erstellt|Geändert|Datum|Date|Fällig|SLA)/i.test(k) ||
                        (typeof v==='string' && /^\d{4}-\d{2}-\d{2}T/.test(v));
    if (isDateField && v) {
      html+=`<div class="fs-field"><div class="fs-field-label">${esc(label)}</div>
        <div class="fs-field-val" style="color:var(--text-dim);">${fmtFull(v)}</div></div>`;
      return;
    }

    // Regular
    let valStr;
    if (typeof v === 'object') {
      valStr = v?.LookupValue || v?.displayName || v?.Title || v?.Email || '';
      if (!valStr) try { valStr = JSON.stringify(v); } catch { valStr = ''; }
    } else { valStr = String(v); }
    html+=`<div class="fs-field"><div class="fs-field-label">${esc(label)}</div>
      <input data-fk="${esc(k)}" value="${esc(valStr)}" style="width:100%;padding:6px 10px;border:1.5px solid var(--border2);border-radius:6px;font-size:13px;font-family:inherit;"/></div>`;
  });

  // Attachments
  html+=`<div class="fs-section">Anhänge</div>
    <div class="fs-body-full" id="fs-atts-${id}" style="display:flex;flex-wrap:wrap;gap:6px;min-height:30px;">
      <span style="font-size:11px;color:var(--text-muted);">Lade…</span></div>
    <div class="fs-body-full">
      <label class="attach-pill" style="cursor:pointer;">＋ Datei(en) wählen
        <input type="file" multiple style="display:none;" onchange="uploadAttachments(this.files,'${id}')"/>
      </label>
      <span style="font-size:10px;color:var(--text-muted);margin-left:8px;">Erstellt: ${fmtFull(it.createdDateTime)}</span>
    </div>`;

  $id('fs-body').innerHTML = html;
  $id('fs-overlay').classList.add('open');
  fetchTicketAttachmentsFs(id);
}

function closeFullscreen() { $id('fs-overlay').classList.remove('open'); fullscreenId=null; }

async function changeStatusFs(id, newStatus) {
  if (!ticketSiteId||!ticketListId) return;
  const colStatus=col(['Status'])||'Status';
  try {
    await gPatch(`/sites/${ticketSiteId}/lists/${ticketListId}/items/${id}/fields`, {[colStatus]:newStatus});
    const it = allTickets.find(t=>t.id==id);
    if(it) it.fields[colStatus]=newStatus;
    toast(`Status → ${newStatus}`,'success');
    renderTickets(allTickets.slice(0, displayedCount));
    openTicketFullscreen(id); // refresh
  } catch(e){ toast('Fehler: '+e.message,'error'); }
}

async function saveFullscreen() {
  if (!fullscreenId) return;
  const raw={};
  $id('fs-body').querySelectorAll('[data-fk]').forEach(el=>{ if(el.value) raw[el.dataset.fk]=el.value; });
  const fields = stripReadOnly(raw);
  dbg('saveFullscreen', {id: fullscreenId, fieldCount: Object.keys(fields).length, keys: Object.keys(fields)});
  try {
    await gPatch(`/sites/${ticketSiteId}/lists/${ticketListId}/items/${fullscreenId}/fields`, fields);
    const it=allTickets.find(t=>t.id==fullscreenId);
    if(it) Object.assign(it.fields, fields);
    toast('Gespeichert ✓','success');
    renderTickets(allTickets.slice(0, displayedCount));
  } catch(e){ toast('Fehler: '+e.message,'error'); }
}

async function fetchTicketAttachmentsFs(id) {
  const container = document.getElementById('fs-atts-'+id);
  if (!container) return;
  try {
    const spTok = await getSpToken();
    const r = await fetch(
      `https://dihag.sharepoint.com/sites/ticket/_api/web/lists(guid'${ticketListId}')/items(${id})/AttachmentFiles`,
      {headers:{Authorization:'Bearer '+spTok, Accept:'application/json;odata=verbose'}}
    );
    const j = await r.json();
    const files = j?.d?.results||j?.value||[];
    _renderAttachFiles(files, container, id);
  } catch(e) { if(container) container.innerHTML='<span style="font-size:11px;color:var(--red);">'+esc(e.message)+'</span>'; }
}

async function changeStatus(id, newStatus) {
  if (!ticketSiteId||!ticketListId||!newStatus) return;
  const colStatus=col(['Status'])||'Status';
  try {
    await gPatch(`/sites/${ticketSiteId}/lists/${ticketListId}/items/${id}/fields`, {[colStatus]:newStatus});
    const it = allTickets.find(t=>t.id==id);
    if(it) { it.fields = it.fields||{}; it.fields[colStatus]=newStatus; }
    // Update badge live
    const badge = document.getElementById('sb-status-badge-'+id);
    if(badge){ badge.textContent=newStatus; badge.style.background=(STATUS_COLORS[newStatus]||'#666')+'22'; badge.style.color=STATUS_COLORS[newStatus]||'#666'; }
    const dtBadge = document.getElementById('dt-status-badge-'+id);
    if(dtBadge){ dtBadge.textContent=newStatus; dtBadge.style.background=(STATUS_COLORS[newStatus]||'#666')+'22'; dtBadge.style.color=STATUS_COLORS[newStatus]||'#666'; }
    toast(`Status → ${newStatus}`,'success');
    const list = filterActive() ? applyFilters(allTickets) : allTickets.slice(0,displayedCount);
    renderTickets(list);
  } catch(e){ toast('Fehler: '+e.message,'error'); }
}

async function saveSidebar(id) {
  const raw={};
  $id('sb-body').querySelectorAll('[data-fk]').forEach(el=>{
    if(el.value!==undefined && el.value!=='') raw[el.dataset.fk]=el.value;
  });
  const fields = stripReadOnly(raw);
  dbg('saveSidebar', {id, fieldCount: Object.keys(fields).length, keys: Object.keys(fields)});
  try {
    await gPatch(`/sites/${ticketSiteId}/lists/${ticketListId}/items/${id}/fields`, fields);
    const it=allTickets.find(t=>t.id==id);
    if(it) Object.assign(it.fields, fields);
    toast('Gespeichert ✓','success');
    saveTicketCache();
    const wrap = $id('tkt-table-wrap');
    const scrollTop = wrap ? wrap.scrollTop : 0;
    const list = filterActive() ? applyFilters(allTickets) : allTickets.slice(0,displayedCount);
    renderTickets(list);
    if (wrap) wrap.scrollTop = scrollTop;
  } catch(e){ toast('Fehler: '+e.message,'error'); }
}

async function uploadAttachments(files, id) {
  if (!files?.length) return;
  try {
    const spTok=await getSpToken();
    const siteBase='https://dihag.sharepoint.com/sites/ticket';
    for (const f of files) {
      const buf=await f.arrayBuffer();
      const r=await fetch(
        `${siteBase}/_api/web/lists(guid'${ticketListId}')/items(${id})/AttachmentFiles/add(FileName='${encodeURIComponent(f.name)}')`,
        {method:'POST',headers:{Authorization:'Bearer '+spTok,'Content-Type':'application/octet-stream',Accept:'application/json;odata=verbose'},body:buf}
      );
      if(r.ok||r.status===200) toast(`📎 ${f.name} angehängt ✓`,'success');
      else toast(`Upload Fehler ${r.status}`,'error');
    }
    await streamTickets();
    openTicketDetail(id);
  } catch(e){ toast('Upload: '+e.message,'error'); }
}

async function confirmDeleteTicket(id) {
  if(!confirm(`Ticket #${id} wirklich löschen?`)) return;
  try {
    const tok=await getToken();
    await fetch(`${API}/sites/${ticketSiteId}/lists/${ticketListId}/items/${id}`,
      {method:'DELETE',headers:{Authorization:'Bearer '+tok}});
    allTickets=allTickets.filter(t=>t.id!=id);
    closeSidebar();
    renderTickets(allTickets);
    toast('Ticket gelöscht','success');
  } catch(e){ toast('Löschen: '+e.message,'error'); }
}

// NEW TICKET MODAL
function openNewTicket() {
  editingId=null;
  $id('tm-title').textContent='Neues Ticket';
  const colTitle =col(['Titel','Title'])||'Title';
  const colStatus=col(['Status'])||'Status';
  const colPrio  =col(['Priorität','Priority']);
  const colCat   =col(['Kategorie','Typ','Type']);
  const colDesc  =col(['Beschreibung','Description','Kommentar','Inhalt']);

  let html=`<div class="form-row">
    <div class="form-field full"><label>Titel <span class="req">*</span></label>
      <input id="nm-title" data-fk="${colTitle}" placeholder="Kurze Beschreibung des Problems"/></div>`;
  if(colStatus) html+=`<div class="form-field"><label>Status</label>
    <select id="nm-status" data-fk="${colStatus}">
      <option>Offen</option><option>In Bearbeitung</option><option>Erledigt</option><option>Abgebrochen</option>
    </select></div>`;
  if(colPrio) html+=`<div class="form-field"><label>Priorität</label>
    <select data-fk="${colPrio}"><option>Niedrig</option><option>Mittel</option><option selected>Mittel</option><option>Hoch</option><option>Kritisch</option></select></div>`;
  if(colCat) html+=`<div class="form-field full"><label>Kategorie</label>
    <input data-fk="${colCat}" placeholder="z.B. Hardware, Software, Zugang…"/></div>`;
  if(colDesc) html+=`<div class="form-field full"><label>Beschreibung</label>
    <textarea data-fk="${colDesc}" rows="4" placeholder="Detaillierte Beschreibung…"></textarea></div>`;
  html+=`</div>`;

  $id('tm-body').innerHTML=html;
  $id('ticket-modal').classList.add('open');
}

function closeTicketModal() { $id('ticket-modal').classList.remove('open'); }

async function saveTicket() {
  if(!ticketSiteId||!ticketListId) return;
  const fields={};
  $id('tm-body').querySelectorAll('[data-fk]').forEach(el=>{ if(el.value) fields[el.dataset.fk]=el.value; });
  const titleCol=col(['Titel','Title'])||'Title';
  if(!fields[titleCol]){toast('Bitte Titel angeben','error');return;}
  try {
    await gPost(`/sites/${ticketSiteId}/lists/${ticketListId}/items`,{fields});
    toast('Ticket erstellt ✓','success');
    closeTicketModal();
    await streamTickets();
  } catch(e){ toast('Fehler: '+e.message,'error'); }
}

// ════════════════════════════════════════════════════════════════
// REPORTS
// ════════════════════════════════════════════════════════════════
const STATUS_COLORS = {
  'Offen':'var(--blue)','Neu':'#6366f1',
  'In Bearbeitung':'var(--yellow)',
  'Warten auf Rückmeldung':'var(--orange)',
  'Erledigt':'var(--green)',
  'Abgebrochen':'#6b7280',
  'Projekt':'#7c3aed'
};
const TICKET_STATUSES = Object.keys(STATUS_COLORS);
const PRIO_COLORS = {
  'Niedrig':'#94a3b8','Normal':'var(--blue)','Mittel':'var(--yellow)',
  'Hoch':'var(--orange)','high':'var(--orange)','Kritisch':'var(--red)'
};

function countBy(tickets, keyFn) {
  const m = {};
  tickets.forEach(t => { const k = keyFn(t)||'(leer)'; m[k] = (m[k]||0)+1; });
  return Object.entries(m).sort((a,b)=>b[1]-a[1]);
}

function barChart(data, colorFn, maxVal) {
  if (!maxVal) maxVal = Math.max(...data.map(d=>d[1]),1);
  return `<div class="rpt-bar-chart">${data.map(([label,val])=>{
    const pct = Math.round(val/maxVal*100);
    const color = colorFn(label);
    return `<div class="rpt-bar-row">
      <div class="rpt-bar-label" title="${esc(label)}">${esc(label)}</div>
      <div class="rpt-bar-track">
        <div class="rpt-bar-fill" style="width:${Math.max(pct,3)}%;background:${color};">
          ${pct>15?`<span class="rpt-bar-val">${val}</span>`:''}
        </div>
      </div>
      ${pct<=15?`<span class="rpt-bar-val-out">${val}</span>`:''}
    </div>`;
  }).join('')}</div>`;
}

function stackedChart(rows, colorMap) {
  // rows: [{label, counts:{status:n,...}}]
  const legend = Object.keys(colorMap);
  let html = '';
  rows.forEach(row => {
    const total = Object.values(row.counts).reduce((a,b)=>a+b,0);
    if (!total) return;
    html += `<div class="rpt-bar-row">
      <div class="rpt-bar-label" title="${esc(row.label)}">${esc(row.label)}</div>
      <div class="rpt-bar-track"><div class="rpt-stacked-row">`;
    legend.forEach(st => {
      const n = row.counts[st]||0;
      if (!n) return;
      const pct = (n/total*100);
      html += `<div class="rpt-stacked-seg" style="width:${pct}%;background:${colorMap[st]||'#94a3b8'};" title="${esc(st)}: ${n}">${n>0&&pct>8?n:''}</div>`;
    });
    html += `</div></div>
      <span class="rpt-bar-val-out">${total}</span>
    </div>`;
  });
  html += `<div class="rpt-legend">${legend.map(s=>`<div class="rpt-legend-item"><div class="rpt-legend-dot" style="background:${colorMap[s]||'#94a3b8'};"></div>${esc(s)}</div>`).join('')}</div>`;
  return html;
}

function buildReports() {
  const c = $id('reports-container');
  if (!allTickets.length) { c.innerHTML='<div class="empty">Keine Ticketdaten vorhanden.</div>'; return; }

  const cStatus = getCol('status')||'Status';
  const cPrio   = getCol('prio');
  const cWerk   = getCol('werk');
  const cKat    = getCol('category');
  const cType   = getCol('type');

  dbg('buildReports', {tickets: allTickets.length, cStatus, cPrio, cWerk, cKat});

  // KPIs
  const total = allTickets.length;
  const offen = allTickets.filter(t=>{const s=(t.fields||{})[cStatus]||'';return s==='Offen'||s==='Neu';}).length;
  const bearbeitung = allTickets.filter(t=>((t.fields||{})[cStatus]||'').includes('Bearbeitung')).length;
  const erledigt = allTickets.filter(t=>((t.fields||{})[cStatus]||'')==='Erledigt').length;
  const last30 = allTickets.filter(t=>new Date(t.createdDateTime)>new Date(Date.now()-30*86400000)).length;

  let html = `<div class="rpt-card rpt-card-full">
    <div class="rpt-title">📈 Übersicht</div>
    <div class="rpt-kpi-row">
      <div class="rpt-kpi"><div class="rpt-kpi-num">${total}</div><div class="rpt-kpi-label">Gesamt</div></div>
      <div class="rpt-kpi"><div class="rpt-kpi-num" style="color:var(--blue);">${offen}</div><div class="rpt-kpi-label">Offen / Neu</div></div>
      <div class="rpt-kpi"><div class="rpt-kpi-num" style="color:var(--yellow);">${bearbeitung}</div><div class="rpt-kpi-label">In Bearbeitung</div></div>
      <div class="rpt-kpi"><div class="rpt-kpi-num" style="color:var(--green);">${erledigt}</div><div class="rpt-kpi-label">Erledigt</div></div>
      <div class="rpt-kpi"><div class="rpt-kpi-num" style="color:var(--navy);">${last30}</div><div class="rpt-kpi-label">Letzte 30 Tage</div></div>
    </div>
  </div>`;

  html += '<div class="rpt-grid">';

  // Status chart
  const statusData = countBy(allTickets, t=>(t.fields||{})[cStatus]||'');
  html += `<div class="rpt-card">
    <div class="rpt-title">🔵 Tickets nach Status</div>
    ${barChart(statusData, l=>STATUS_COLORS[l]||'#94a3b8')}
  </div>`;

  // Prio chart — normalise raw SP values ("Mittel"→"Normal", "high"→"Hoch" etc.) before grouping
  if (cPrio) {
    const prioData = countBy(allTickets, t=>normPrio((t.fields||{})[cPrio]||''));
    html += `<div class="rpt-card">
      <div class="rpt-title">🔴 Tickets nach Priorität</div>
      ${barChart(prioData, l=>PRIO_COLORS[l]||'#94a3b8')}
    </div>`;
  }

  // Werk chart
  if (cWerk) {
    const werkData = countBy(allTickets, t=>(t.fields||{})[cWerk]||'');
    html += `<div class="rpt-card">
      <div class="rpt-title">🏭 Tickets nach Werk</div>
      ${barChart(werkData, ()=>'var(--navy)')}
    </div>`;
  }

  // Werk × Status stacked
  if (cWerk) {
    const werke = [...new Set(allTickets.map(t=>(t.fields||{})[cWerk]||'(leer)'))].sort();
    const statusKeys = Object.keys(STATUS_COLORS);
    const rows = werke.map(w => {
      const counts = {};
      statusKeys.forEach(s=>counts[s]=0);
      allTickets.filter(t=>(t.fields||{})[cWerk]===w||(!w&&!(t.fields||{})[cWerk])).forEach(t=>{
        const st = (t.fields||{})[cStatus]||'';
        const matched = statusKeys.find(s=>st.includes(s));
        if(matched) counts[matched]++;
        else counts[st]=(counts[st]||0)+1;
      });
      return {label:w||'(leer)',counts};
    });
    html += `<div class="rpt-card rpt-card-full">
      <div class="rpt-title">🏭 Werk × Status (Übersicht)</div>
      ${stackedChart(rows, STATUS_COLORS)}
    </div>`;
  }

  // Timeline: Tickets pro Monat (letzte 12 Monate)
  const months = {};
  const now = new Date();
  for (let i=11;i>=0;i--) {
    const d = new Date(now.getFullYear(), now.getMonth()-i, 1);
    const key = d.toLocaleDateString('de-DE',{month:'short',year:'2-digit'});
    months[key] = 0;
  }
  allTickets.forEach(t => {
    const d = new Date(t.createdDateTime);
    const key = d.toLocaleDateString('de-DE',{month:'short',year:'2-digit'});
    if (key in months) months[key]++;
  });
  const timeData = Object.entries(months);
  html += `<div class="rpt-card rpt-card-full">
    <div class="rpt-title">📅 Tickets pro Monat (letzte 12 Monate)</div>
    ${barChart(timeData, ()=>'var(--navy)')}
  </div>`;

  // Kategorie chart (ganz unten)
  if (cKat) {
    const katData = countBy(allTickets, t=>(t.fields||{})[cKat]||'');
    html += `<div class="rpt-card rpt-card-full">
      <div class="rpt-title">📂 Tickets nach Kategorie</div>
      ${barChart(katData, ()=>'var(--blue)')}
    </div>`;
  }

  // Top-10 Zugewiesen an — scan all known column names incl. discovered
  const _asgnColCandidates = ['Zugewiesen','AssignedTo','Zugewiesen_x0020_an','Bearbeiter','ZugewiesenAn','Assigned_x0020_To'];
  const _asgnKey = getCol('assigned') || _discoveredCols.asgn || _asgnColCandidates.find(k=>
    allTickets.some(t=>(t.fields||{})[k]!=null && (t.fields||{})[k]!=='')
  );
  {
    const asgnData = countBy(allTickets, t=>{
      const f = t.fields||{};
      const v = _asgnKey ? f[_asgnKey]
        : (_asgnColCandidates.reduce((acc,k)=>acc||f[k]||null, null));
      const name = personName(v);
      return name || '(Nicht zugewiesen)';
    });
    const top10named = asgnData.filter(([l])=>l!=='(Nicht zugewiesen)').slice(0,10);
    const top10 = top10named.length ? top10named : asgnData.slice(0,10);
    html += `<div class="rpt-card rpt-card-full">
      <div class="rpt-title">👤 Top 10 — Zugewiesen an</div>
      ${top10.length ? barChart(top10, (l)=>l==='(Nicht zugewiesen)'?'#94a3b8':'var(--navy)') : '<div class="empty" style="padding:16px;">Keine Zuweisungs-Daten (Spalte nicht gefunden)</div>'}
    </div>`;
  }

  html += '</div>';

  c.innerHTML = html;
  $id('rpt-info').textContent = `Basierend auf ${allTickets.length} Tickets`;
  dbg('Reports gerendert ✓');
}

// ════════════════════════════════════════════════════════════════
// DEVICES (Azure AD Geräte via Graph API)
// ════════════════════════════════════════════════════════════════
let allDevices=[], devEditingId=null;

async function loadDevices(force) {
  if (!force && allDevices.length) return;
  allDevices = [];
  $id('dev-empty').style.display='block';
  $id('dev-empty').textContent='Lade Azure-Geräte…';
  $id('dev-empty').style.color='';
  $id('dev-table').style.display='none';

  // Try 1: Intune managed devices (requires DeviceManagementManagedDevices.Read.All)
  try {
    dbg('Azure-Geräte: Versuch 1 — Intune /deviceManagement/managedDevices');
    let url = '/deviceManagement/managedDevices?$select=deviceName,operatingSystem,osVersion,lastSyncDateTime,complianceState,managementAgent,enrolledDateTime,manufacturer,model,userPrincipalName,serialNumber,totalStorageSpaceInBytes,freeStorageSpaceInBytes&$top=100';
    while (url) {
      const d = await gGet(url);
      allDevices = [...allDevices, ...(d.value||[])];
      url = d['@odata.nextLink'] ? d['@odata.nextLink'].replace('https://graph.microsoft.com/v1.0','') : null;
    }
    if (allDevices.length) { dbg('Intune Geräte geladen', {anzahl: allDevices.length}); buildDevTableIntune(); return; }
  } catch(e1) { dbg('Intune fehlgeschlagen', e1.message); }

  // Try 2: Azure AD /devices (requires Device.Read.All)
  try {
    dbg('Azure-Geräte: Versuch 2 — /devices');
    let url = '/devices?$select=displayName,operatingSystem,operatingSystemVersion,approximateLastSignInDateTime,deviceId,isCompliant,isManaged,registrationDateTime,manufacturer,model,trustType&$top=100';
    while (url) {
      const d = await gGet(url);
      allDevices = [...allDevices, ...(d.value||[])];
      url = d['@odata.nextLink'] ? d['@odata.nextLink'].replace('https://graph.microsoft.com/v1.0','') : null;
    }
    if (allDevices.length) { dbg('Azure AD Devices geladen', {anzahl: allDevices.length}); buildDevTable(); return; }
  } catch(e2) { dbg('/devices fehlgeschlagen', e2.message); }

  // Fallback: show config to enter SP list manually
  dbg('Beide APIs nicht verfügbar — zeige SP-Konfiguration');
  $id('dev-empty').innerHTML = `
    <div style="max-width:500px;margin:0 auto;text-align:left;">
      <div style="font-size:14px;font-weight:700;color:var(--navy);margin-bottom:8px;">⚠ Azure AD Berechtigungen fehlen</div>
      <div style="font-size:12px;color:var(--text-dim);margin-bottom:16px;">
        Die Scopes <code>DeviceManagementManagedDevices.Read.All</code> und <code>Device.Read.All</code> sind nicht erteilt.<br>
        Alternativ: Geräteliste aus SharePoint laden.
      </div>
      <div style="display:flex;gap:8px;margin-bottom:8px;">
        <input id="dev-sp-site" placeholder="Site z.B. dihag.sharepoint.com:/sites/IT" style="flex:1;padding:8px 12px;border:1.5px solid var(--border2);border-radius:6px;font-family:inherit;font-size:12px;" value="dihag.sharepoint.com:/sites/IT"/>
      </div>
      <div style="display:flex;gap:8px;">
        <input id="dev-sp-list" placeholder="Listenname z.B. IT Onboarding" style="flex:1;padding:8px 12px;border:1.5px solid var(--border2);border-radius:6px;font-family:inherit;font-size:12px;" value="IT Onboarding"/>
        <button onclick="loadDevicesFromSP()" style="padding:8px 18px;background:var(--navy);color:#fff;border:none;border-radius:6px;font-family:inherit;font-size:12px;font-weight:600;cursor:pointer;">Laden</button>
      </div>
    </div>`;
  $id('dev-empty').style.color='';
}

async function loadDevicesFromSP() {
  const site = ($id('dev-sp-site')?.value||'').trim();
  const listName = ($id('dev-sp-list')?.value||'').trim();
  if (!site||!listName) { toast('Bitte Site und Liste eingeben','error'); return; }
  $id('dev-empty').textContent='Lade aus SharePoint…';
  try {
    const siteData = await gGet(`/sites/${site}`);
    const siteId = siteData.id;
    const lists = await gGet(`/sites/${siteId}/lists?$select=id,displayName,name&$top=100`);
    const lst = (lists.value||[]).find(l=>l.displayName===listName||l.name===listName);
    if (!lst) throw new Error('Liste "'+listName+'" nicht gefunden in: '+(lists.value||[]).map(l=>l.displayName).join(', '));
    let url = `/sites/${siteId}/lists/${lst.id}/items?$expand=fields&$top=100`;
    while (url) {
      const d = await gGet(url, {'Prefer':'HonorNonIndexedQueriesWarningMayFailRandomly'});
      allDevices = [...allDevices, ...(d.value||[])];
      url = d['@odata.nextLink'] ? d['@odata.nextLink'].replace('https://graph.microsoft.com/v1.0','') : null;
    }
    if (!allDevices.length) { $id('dev-empty').textContent='Keine Einträge gefunden'; return; }
    buildDevTableSP(); // SP list format
  } catch(e) { $id('dev-empty').textContent='⚠ '+e.message; $id('dev-empty').style.color='var(--red)'; }
}

function buildDevTableIntune() {
  $id('dev-thead').innerHTML = '<th>#</th><th>Gerät</th><th>OS / User</th><th>Status</th><th>Letzter Sync</th>';
  renderDevices(allDevices);
  $id('dev-count').textContent = allDevices.length + ' Intune-Geräte';
}

// ── ENTRA GERATEINFO FLOW ─────────────────────────────────────────
const ENTRA_FLOW_ENV  = 'Default-fdb70646-023a-403b-a4b9-1f474a935123';
const ENTRA_FLOW_ID   = '722002ce-4393-4397-b0a1-0e918dccc91e';
const PA_API          = 'https://api.flow.microsoft.com';

const PA_SCOPE = 'https://service.flow.microsoft.com/.default';

// Holt PA-Token via Refresh-Token direkt (kein MSAL, kein Popup)
async function _getFlowTokenSilent(tenantId) {
  let refreshToken = null;
  try {
    for (const key of Object.keys(localStorage)) {
      if (key.toLowerCase().includes('refreshtoken')) {
        const val = JSON.parse(localStorage.getItem(key) || '{}');
        if (val?.secret) { refreshToken = val.secret; break; }
      }
    }
  } catch {}
  if (!refreshToken) throw new Error('Nicht angemeldet — bitte Seite neu laden');

  const r = await fetch(
    'https://login.microsoftonline.com/' + tenantId + '/oauth2/v2.0/token',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'refresh_token',
        client_id:     CLIENT_ID,
        refresh_token: refreshToken,
        scope:         PA_SCOPE
      })
    }
  );
  const d = await r.json();
  if (d.access_token) return d.access_token;
  throw new Error(d.error_description || d.error);
}

async function getFlowToken() {
  const tenantId = account?.tenantId || TENANT_ID;

  // Step 1: silent — Refresh-Token direkt gegen PA-Token tauschen
  try {
    return await _getFlowTokenSilent(tenantId);
  } catch (e) {
    // Nur bei fehlendem Consent weitermachen, sonst sofort werfen
    if (!e.message?.includes('AADSTS65001') && !e.message?.includes('consent')) throw e;
  }

  // Step 2: Consent fehlt → eigenes Popup ohne MSAL
  toast('Einmalige Einwilligung für Power Automate — Popup wird geöffnet…', 'info');
  return await _paConsentPopup(tenantId);
}

async function _paConsentPopup(tenantId) {
  const redirectUri = window.location.href.split('?')[0].split('#')[0];
  // Eindeutiger State mit Präfix — die IIFE oben erkennt diesen und setzt _paConsentPopup=true,
  // sodass die Boot-IIFE die App NICHT initialisiert, sondern nur "Erledigt" zeigt und schließt.
  const state = 'pa_consent_' + Math.random().toString(36).slice(2);

  const authUrl = 'https://login.microsoftonline.com/' + tenantId + '/oauth2/v2.0/authorize'
    + '?client_id='    + encodeURIComponent(CLIENT_ID)
    + '&response_type=code'
    + '&redirect_uri=' + encodeURIComponent(redirectUri)
    + '&scope='        + encodeURIComponent(PA_SCOPE)
    + '&state='        + state
    + '&login_hint='   + encodeURIComponent(account?.username || '');
    // Kein prompt=consent → AAD zeigt Consent nur wenn nötig, vermeidet erzwungenen Re-Login

  const popup = window.open(authUrl, 'pa-consent', 'width=520,height=640,left=200,top=100');
  if (!popup) throw new Error('Popup blockiert — bitte Popup-Blocker für diese Seite erlauben');

  return new Promise((resolve, reject) => {
    // BroadcastChannel statt window.opener — funktioniert auch wenn AAD COOP opener=null setzt
    const bc = new BroadcastChannel('pa-oauth-callback');

    bc.onmessage = async () => {
      bc.close();
      clearInterval(closedCheck);
      // Kurz warten damit AAD den Consent intern speichert, dann silent retry
      await new Promise(r => setTimeout(r, 800));
      try   { resolve(await _getFlowTokenSilent(tenantId)); }
      catch (err) { reject(err); }
    };

    const closedCheck = setInterval(() => {
      if (popup.closed) {
        clearInterval(closedCheck);
        bc.close();
        reject(new Error('Popup geschlossen ohne Einwilligung'));
      }
    }, 500);
  });
}

async function runEntraGeraeteFlow() {
  const btn = $id('btn-entra-flow');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Läuft…'; }
  try {
    const tok = await getFlowToken();
    const url = `${PA_API}/providers/Microsoft.ProcessSimple/environments/${ENTRA_FLOW_ENV}`
              + `/flows/${ENTRA_FLOW_ID}/triggers/manual/run?api-version=2016-11-01`;
    const r = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + tok,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({})
    });
    // 202 Accepted = Flow gestartet, kein Body
    if (r.status === 202 || r.status === 200) {
      toast('✓ Flow „Entra Gerateinfo" gestartet', 'success');
    } else {
      const txt = await r.text().catch(() => '');
      throw new Error(`PA ${r.status}: ${txt.slice(0, 200)}`);
    }
  } catch(e) {
    toast(`Flow-Fehler: ${e.message}`, 'error');
    dbg('runEntraGeraeteFlow Fehler', e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '▶ Entra Gerateinfo'; }
  }
}

function buildDevTableSP() {
  const skip = new Set(['ContentType','_UIVersionString','Attachments','ID','AuthorLookupId','EditorLookupId','AppAuthorLookupId','LinkTitleNoMenu','LinkTitle','ItemChildCount','FolderChildCount','ComplianceAssetId']);
  const colKeys = [];
  const seen = new Set();
  allDevices.slice(0,5).forEach(it => {
    Object.keys(it.fields||{}).forEach(k=>{
      if(!seen.has(k)&&!skip.has(k)&&!k.startsWith('_')&&!k.startsWith('@odata')){ seen.add(k); colKeys.push(k); }
    });
  });
  const spCols = colKeys.slice(0,8).map(k=>({key:'__sp_'+k, label:k}));
  $id('dev-thead').innerHTML = '<th>#</th>' + spCols.map(c=>`<th>${esc(c.label)}</th>`).join('');
  // Remap for render
  const mapped = allDevices.map(it=>{ const o={...it}; Object.entries(it.fields||{}).forEach(([k,v])=>{ o['__sp_'+k]=typeof v==='object'?personName(v):String(v||''); }); return o; });
  allDevices = mapped;
  renderDevices(allDevices, spCols);
  $id('dev-count').textContent = allDevices.length + ' SP-Einträge';
}

function buildDevTable() {
  if (!allDevices.length) { $id('dev-empty').textContent='Keine Geräte'; return; }
  $id('dev-thead').innerHTML = '<th>#</th><th>Gerät</th><th>OS / User</th><th>Status</th><th>Letzter Login</th>';
  renderDevices(allDevices);
  $id('dev-count').textContent = allDevices.length + ' Azure-Geräte';
}

function renderDevices(list, cols) {
  if (!cols) {
    cols = [
      {key:'displayName',label:'Name'},{key:'operatingSystem',label:'OS'},
      {key:'manufacturer',label:'Hersteller'},{key:'model',label:'Modell'},
      {key:'isManaged',label:'Verwaltet'},{key:'isCompliant',label:'Konform'},
      {key:'approximateLastSignInDateTime',label:'Letzter Login'},
    ];
  }
  const tbody = $id('dev-tbody');
  $id('dev-empty').style.display = list.length ? 'none' : 'block';
  $id('dev-table').style.display = list.length ? '' : 'none';
  tbody.innerHTML = list.map((it,i) => {
    // Build a 2-line card row: title row + details row
    const name = esc(String(it[cols[0]?.key||'displayName']||it.deviceName||'—'));
    const os   = esc(String(it.operatingSystem||it.operatingSystemVersion||''));
    const mfr  = esc(String(it.manufacturer||''));
    const mdl  = esc(String(it.model||''));
    const lastSync = it.approximateLastSignInDateTime||it.lastSyncDateTime
      ? fmt(it.approximateLastSignInDateTime||it.lastSyncDateTime) : '—';

    const managed = it.isManaged===true ? '<span style="background:var(--green-bg);color:var(--green);padding:2px 8px;border-radius:8px;font-size:10px;font-weight:700;">✓ Verwaltet</span>'
      : it.isManaged===false ? '<span style="background:var(--red-bg);color:var(--red);padding:2px 8px;border-radius:8px;font-size:10px;font-weight:700;">✗</span>' : '';
    const compliant = it.isCompliant===true ? '<span style="background:var(--green-bg);color:var(--green);padding:2px 8px;border-radius:8px;font-size:10px;font-weight:700;">✓ Konform</span>'
      : it.isCompliant===false ? '<span style="background:var(--red-bg);color:var(--red);padding:2px 8px;border-radius:8px;font-size:10px;font-weight:700;">✗ Nicht konform</span>'
      : (it.complianceState ? `<span style="background:var(--yellow-bg);color:var(--yellow);padding:2px 8px;border-radius:8px;font-size:10px;font-weight:700;">${esc(it.complianceState)}</span>` : '');
    const userPrincipal = esc(String(it.userPrincipalName||it.managedBy||''));

    return `<tr class="clickable" onclick="openDevDetail('${esc(it.deviceId||i)}')" style="vertical-align:top;">
      <td style="padding:10px 8px;font-weight:700;color:var(--navy);font-size:13px;white-space:nowrap;">${i+1}</td>
      <td style="padding:10px 8px;">
        <div style="font-weight:700;font-size:13px;color:var(--navy);margin-bottom:3px;">${name}</div>
        <div style="font-size:11px;color:var(--text-muted);">${mfr}${mfr&&mdl?' · ':''}${mdl}</div>
      </td>
      <td style="padding:10px 8px;">
        <div style="font-size:12px;font-weight:600;">${os}</div>
        ${userPrincipal?`<div style="font-size:10px;color:var(--text-muted);margin-top:2px;">👤 ${userPrincipal}</div>`:''}
      </td>
      <td style="padding:10px 8px;">
        <div style="display:flex;flex-direction:column;gap:4px;">${managed}${compliant}</div>
      </td>
      <td style="padding:10px 8px;font-size:11px;color:var(--text-muted);white-space:nowrap;">🕐 ${lastSync}</td>
    </tr>`;
  }).join('');
}

function filterDevices() {
  const q = ($id('dev-search').value||'').toLowerCase();
  const filtered = allDevices.filter(it =>
    Object.values(it).some(v => String(v||'').toLowerCase().includes(q))
  );
  renderDevices(filtered);
  $id('dev-count').textContent = filtered.length + '/' + allDevices.length + ' Geräte';
}

function openDevDetail(deviceId) {
  const it = allDevices.find(d=>d.deviceId===deviceId) || allDevices[parseInt(deviceId)];
  if (!it) return;
  devEditingId = deviceId;
  $id('dev-sb-title').textContent = it.displayName || 'Gerät';
  const skip = new Set(['@odata.type','id']);
  const labels = {
    displayName:'Name', operatingSystem:'Betriebssystem', operatingSystemVersion:'OS-Version',
    manufacturer:'Hersteller', model:'Modell', trustType:'Vertrauen', profileType:'Profil',
    deviceId:'Geräte-ID', isManaged:'Verwaltet', isCompliant:'Konform',
    registrationDateTime:'Registriert', approximateLastSignInDateTime:'Letzter Login'
  };
  let html = '';
  Object.entries(it).forEach(([k,v])=>{
    if(skip.has(k)||k.startsWith('@')) return;
    const label = labels[k]||k;
    let display;
    if(typeof v==='boolean') display=v?'<span style="color:var(--green);font-weight:700;">✓ Ja</span>':'<span style="color:var(--red);">✗ Nein</span>';
    else if(typeof v==='string'&&/^\d{4}-\d{2}-\d{2}T/.test(v)) display=esc(fmtFull(v));
    else display=esc(String(v||'—'));
    html+=`<div class="field-row"><label>${esc(label)}</label><div style="padding:7px 10px;background:var(--bg);border-radius:6px;font-size:12px;">${display}</div></div>`;
  });
  $id('dev-sb-body').innerHTML = html;
  $id('dev-sb-actions').innerHTML = `<button class="btn btn-ghost" onclick="closeDevSidebar()" style="flex:1;">Schließen</button>`;
  const _ds=$id('dev-sidebar'); if(_ds){ _ds.style.display='flex'; _ds.style.flexDirection='column'; }
}

function closeDevSidebar() {
  const s=$id('dev-sidebar'); if(s) s.style.display='none';
  devEditingId=null;
}

// ── DEVICE TABS ──
let _devTab = 'azure';
let _devSpItems = [], _devSpCols = {}, _devSpSiteId = null, _devSpListId = null;

function switchDevTab(tab) {
  _devTab = tab;
  const azBtn = $id('dev-tab-azure'), spBtn = $id('dev-tab-sp');
  const azPane = $id('dev-pane-azure'), spPane = $id('dev-pane-sp');
  if (!azBtn||!spBtn||!azPane||!spPane) return;

  azBtn.style.color = tab==='azure' ? 'var(--navy)' : 'var(--text-dim)';
  azBtn.style.borderBottom = tab==='azure' ? '3px solid var(--navy)' : '3px solid transparent';
  azBtn.style.fontWeight = tab==='azure' ? '700' : '600';
  spBtn.style.color = tab==='sp' ? 'var(--navy)' : 'var(--text-dim)';
  spBtn.style.borderBottom = tab==='sp' ? '3px solid var(--navy)' : '3px solid transparent';
  spBtn.style.fontWeight = tab==='sp' ? '700' : '600';

  azPane.style.display = tab==='azure' ? 'flex' : 'none';
  spPane.style.display = tab==='sp'    ? 'flex' : 'none';

  if (tab==='sp' && !_devSpItems.length) loadDevSP();
}

async function loadDevSP(force) {
  if(!force && _devSpItems.length) return;
  const empty = $id('dev-sp-empty');
  const table = $id('dev-sp-table');
  if (!empty||!table) return;
  empty.style.display='block'; empty.textContent='Lade SP-Liste AzureGerte…'; empty.style.color='';
  table.style.display='none';
  try {
    if (!_devSpSiteId) {
      const site = await gGet('/sites/dihag.sharepoint.com:/sites/IT');
      _devSpSiteId = site.id;
    }
    if (!_devSpListId) {
      const lists = await gGet(`/sites/${_devSpSiteId}/lists?$select=id,displayName,name&$top=100`);
      const lst = (lists.value||[]).find(l=>l.name==='AzureGerte'||l.displayName==='AzureGerte'||l.displayName==='Azure Geräte');
      if (!lst) throw new Error('AzureGerte-Liste nicht gefunden. Verfügbar: '+(lists.value||[]).map(l=>l.displayName).join(', '));
      _devSpListId = lst.id;
      const cols = await gGet(`/sites/${_devSpSiteId}/lists/${_devSpListId}/columns?$top=200`);
      (cols.value||[]).forEach(c=>{ if(!c.readOnly) _devSpCols[c.name]=c.displayName; });
    }
    _devSpItems = [];
    let url = `/sites/${_devSpSiteId}/lists/${_devSpListId}/items?$expand=fields&$top=100`;
    while (url) {
      const d = await gGet(url, {'Prefer':'HonorNonIndexedQueriesWarningMayFailRandomly'});
      _devSpItems = [..._devSpItems, ...(d.value||[])];
      url = d['@odata.nextLink'] ? d['@odata.nextLink'].replace('https://graph.microsoft.com/v1.0','') : null;
    }
    if (!_devSpItems.length) { empty.textContent='Keine Einträge'; return; }
    renderDevSP(_devSpItems);
  } catch(e) {
    empty.textContent='⚠ '+e.message; empty.style.color='var(--red)';
  }
}

function renderDevSP(list) {
  const skip = new Set(['ContentType','_UIVersionString','Attachments','ID','AuthorLookupId','EditorLookupId','AppAuthorLookupId','LinkTitleNoMenu','LinkTitle','ItemChildCount','FolderChildCount','ComplianceAssetId']);
  const colKeys = [];
  const seen = new Set();
  list.slice(0,5).forEach(it=>{
    Object.keys(it.fields||{}).forEach(k=>{
      if(!seen.has(k)&&!skip.has(k)&&!k.startsWith('_')&&!k.startsWith('@')){ seen.add(k); colKeys.push(k); }
    });
  });
  const showCols = colKeys.slice(0,8);
  const thead = $id('dev-sp-thead'), tbody = $id('dev-sp-tbody');
  const empty = $id('dev-sp-empty'), table = $id('dev-sp-table');
  if (!thead||!tbody) return;
  thead.innerHTML = '<th>#</th>'+showCols.map(k=>`<th>${esc(_devSpCols[k]||k)}</th>`).join('');
  tbody.innerHTML = list.map(it=>{
    const f=it.fields||{};
    return `<tr class="clickable" onclick="openDevSPDetail('${esc(it.id)}')">
      <td style="font-weight:600;color:var(--navy);">${it.id}</td>
      ${showCols.map(k=>{
        let v=f[k];
        if(typeof v==='object'&&v) v=personName(v);
        else v=esc(String(v||'').substring(0,50));
        return `<td style="font-size:11px;">${v}</td>`;
      }).join('')}
    </tr>`;
  }).join('');
  const spCntEl=$id('dev-sp-count'); if(spCntEl) spCntEl.textContent=list.length+' SP-Einträge';
  empty.style.display='none'; table.style.display='';
}

function openDevSPDetail(id) {
  const it = _devSpItems.find(x=>x.id==id);
  if (!it) return;
  const f = it.fields||{};
  const skip = new Set(['ContentType','_UIVersionString','Attachments','ID','AuthorLookupId','EditorLookupId','AppAuthorLookupId','LinkTitleNoMenu','LinkTitle','ItemChildCount','FolderChildCount','ComplianceAssetId']);
  let html='';
  Object.entries(f).forEach(([k,v])=>{
    if(skip.has(k)||k.startsWith('_')||k.startsWith('@')||v===null||v===undefined||v==='') return;
    const label=_devSpCols[k]||k;
    const valStr=typeof v==='object'?(personName(v)):String(v);
    html+=`<div class="field-row"><label>${esc(label)}</label><input data-spfk="${esc(k)}" value="${esc(valStr)}" style="font-size:12px;"/></div>`;
  });
  html+=`<div style="font-size:10px;color:var(--text-muted);margin-top:8px;">Erstellt: ${fmtFull(it.createdDateTime)}</div>`;
  $id('dev-sp-sb-title').textContent='Eintrag #'+id;
  $id('dev-sp-sb-body').innerHTML=html;
  $id('dev-sp-sb-actions').innerHTML=`
    <button class="btn btn-primary" onclick="saveDevSP('${id}')" style="flex:1;">✓ Speichern</button>
    <button class="btn btn-ghost" onclick="$id('dev-sp-sidebar').classList.remove('open')">✕</button>`;
  const _dss=$id('dev-sp-sidebar'); if(_dss){ _dss.style.display='flex'; _dss.style.flexDirection='column'; }
}

async function saveDevSP(id) {
  const raw={};
  $id('dev-sp-sb-body').querySelectorAll('[data-spfk]').forEach(el=>{ if(el.value) raw[el.dataset.spfk]=el.value; });
  const fields=stripReadOnly(raw);
  try {
    await gPatch(`/sites/${_devSpSiteId}/lists/${_devSpListId}/items/${id}/fields`, fields);
    const it=_devSpItems.find(x=>x.id==id);
    if(it) Object.assign(it.fields||{}, fields);
    toast('Gespeichert ✓','success');
    renderDevSP(_devSpItems);
  } catch(e){ toast('Fehler: '+e.message,'error'); }
}

// ════════════════════════════════════════════════════════════════
// PERMISSIONS SYSTEM (Tree-based, 4 Stufen)
// ════════════════════════════════════════════════════════════════
let permSiteId=null, permSiteUrl=null, permLibraries=[];
let searchTimeout=null;

// Clean URL: strip AllItems.aspx, list paths, etc.
function cleanSiteInput(input) {
  let s = input.trim();
  // Remove protocol
  s = s.replace(/^https?:\/\//,'');
  // Strip /Lists/xxx/AllItems.aspx or /AllItems.aspx
  s = s.replace(/\/Lists\/[^/]+\/[^/]*$/i,'');
  s = s.replace(/\/AllItems\.aspx.*$/i,'');
  // Strip /Freigegebene Dokumente/... etc
  s = s.replace(/\/Freigegebene%20Dokumente.*$/i,'');
  s = s.replace(/\/Shared%20Documents.*$/i,'');
  // Strip /SitePages/...
  s = s.replace(/\/SitePages\/.*$/i,'');
  // Strip /_layouts/...
  s = s.replace(/\/_layouts\/.*$/i,'');
  // If it looks like dihag.sharepoint.com/sites/X, convert to graph format
  const m = s.match(/^([\w.-]+\.sharepoint\.com)(\/sites\/[^/?#]+)/i);
  if (m) return m[1]+':'+m[2];
  return s;
}

async function searchSites(query) {
  clearTimeout(searchTimeout);
  const box = $id('perm-suggestions');
  if (!query || query.length < 2) { box.style.display='none'; return; }
  searchTimeout = setTimeout(async () => {
    try {
      // Search sites via Graph
      const d = await gGet(`/sites?search=${encodeURIComponent(query)}&$top=8`);
      const sites = d.value||[];
      if (!sites.length) { box.innerHTML='<div class="perm-sug" style="color:var(--text-muted);">Keine Sites gefunden</div>'; box.style.display='block'; return; }
      box.innerHTML = sites.map(s => `<div class="perm-sug" onclick="selectPermSite('${esc(s.id)}','${esc(s.webUrl)}','${esc(s.displayName)}')">
        <span style="font-size:16px;">🌐</span>
        <div><div class="perm-sug-name">${esc(s.displayName)}</div><div class="perm-sug-url">${esc(s.webUrl)}</div></div>
      </div>`).join('');
      box.style.display='block';
    } catch(e) {
      box.innerHTML=`<div class="perm-sug" style="color:var(--red);">Fehler: ${esc(e.message)}</div>`;
      box.style.display='block';
    }
  }, 350);
}

function selectPermSite(siteId, webUrl, name) {
  permSiteId = siteId;
  permSiteUrl = webUrl;
  $id('perm-site-url').value = name;
  $id('perm-suggestions').style.display='none';
  dbg('Site ausgewählt', {siteId, webUrl, name});
  startPermScan();
}

// Close suggestions on outside click
document.addEventListener('click', e => {
  if (!e.target.closest('#perm-site-url') && !e.target.closest('#perm-suggestions')) {
    const box=$id('perm-suggestions'); if(box) box.style.display='none';
  }
});

async function spGet(url) {
  // Try multiple token scopes — SP REST RoleAssignments needs AllSites.FullControl
  const origin = url.match(/^(https:\/\/[^\/]+)/)?.[1] || 'https://dihag.sharepoint.com';
  const scopesToTry = [
    `${origin}/AllSites.FullControl`,
    `${origin}/AllSites.Manage`,
    `${origin}/Sites.ReadWrite.All`,
    `${origin}/AllSites.Read`
  ];

  for (const scope of scopesToTry) {
    let tok;
    try { tok = (await msalApp.acquireTokenSilent({scopes:[scope], account})).accessToken; }
    catch { try { tok = (await msalApp.acquireTokenPopup({scopes:[scope], account})).accessToken; } catch { continue; } }
    const r = await fetch(url, {headers:{Authorization:'Bearer '+tok, Accept:'application/json;odata=verbose'}});
    if (r.ok) return r.json();
    const status = r.status;
    const body = await r.text().catch(()=>'');
    dbg(`spGet ${scope.split('/').pop()} → ${status}`);
    if (status === 403 || status === 401) continue; // try next scope
    throw new Error(`SP ${status}: ${body}`);
  }
  throw new Error('SP: Kein Token-Scope hatte Zugriff auf diese Ressource (403/401 bei allen Versuchen)');
}

function roleIcon(role) {
  if (/Full Control|Vollzugriff/i.test(role)) return {bg:'var(--red)',icon:'👑'};
  if (/Design|Entwerfen/i.test(role)) return {bg:'var(--orange)',icon:'🎨'};
  if (/Edit|Bearbeiten|Contribute|Mitwirken/i.test(role)) return {bg:'var(--yellow)',icon:'✏️'};
  if (/Read|Lesen|View/i.test(role)) return {bg:'var(--green)',icon:'👁️'};
  return {bg:'#94a3b8',icon:'🔑'};
}

let _permGroupCounter = 0;
function renderMembersTree(roleAssignments) {
  if (!roleAssignments?.length) return '<div class="tree-loading">Keine spezifischen Berechtigungen</div>';
  // Separate SharingLinks pseudo-groups from real permissions
  const sharingLinks = roleAssignments.filter(ra => /^SharingLinks\./i.test(ra.Member?.Title||''));
  const realPerms    = roleAssignments.filter(ra => !/^SharingLinks\./i.test(ra.Member?.Title||''));

  let sharingHtml = '';
  if (sharingLinks.length) {
    const slId = 'sl_inline_'+(++_permGroupCounter);
    const slItems = sharingLinks.map(ra=>{
      const roles=(ra.RoleDefinitionBindings?.results||ra.RoleDefinitionBindings||[]).map(r=>r.Name).filter(r=>r!=='Limited Access'&&r!=='Beschränkter Zugriff').join(', ');
      const users=(ra.Member?.Users?.results||[]);
      const ri=roleIcon(roles);
      return `<div style="padding:4px 8px;font-size:11px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;">
        <div class="perm-member-icon" style="background:${ri.bg};width:18px;height:18px;">${ri.icon}</div>
        <span style="font-family:monospace;font-size:10px;color:var(--text-muted);flex:1;overflow:hidden;text-overflow:ellipsis;">${esc(ra.Member?.Title||'?')}</span>
        <span style="font-size:9px;color:var(--text-muted);">${esc(roles)}</span>
        ${users.length?`<span style="font-size:9px;background:var(--bg);padding:1px 6px;border-radius:4px;">${users.length} User</span>`:''}
      </div>`;
    }).join('');
    sharingHtml = `<div style="margin-bottom:6px;">
      <div class="perm-group-hdr" onclick="dToggleGroup('${slId}')" style="background:var(--bg2);">
        <div class="perm-member-icon" style="background:#6b7280;font-size:9px;">🔗</div>
        <span class="perm-member-name" style="font-size:11px;">Sharing Links (${sharingLinks.length})</span>
        <span class="perm-group-toggle" id="tg_${slId}">▶</span>
      </div>
      <div class="perm-group-members" id="${slId}" style="font-size:10px;">${slItems}</div>
    </div>`;
  }

  const mainHtml = realPerms.map(ra => {
    const member = ra.Member;
    const roles = (ra.RoleDefinitionBindings?.results||ra.RoleDefinitionBindings||[])
      .map(r=>r.Name).filter(r=>r!=='Limited Access'&&r!=='Beschränkter Zugriff').join(', ');
    if (!roles) return '';
    const ri = roleIcon(roles);
    const isGroup = member.PrincipalType === 8;
    const typeIcon = isGroup ? '👥' : (member.PrincipalType===1 ? '👤' : '🔑');
    const displayName = esc(member.Title||member.LoginName||'?');

    if (isGroup) {
      const gid = 'pg_'+(++_permGroupCounter);
      const users = member.Users?.results || [];
      const usersHtml = users.length
        ? users.map(u => {
            const uname = esc(u.Title||u.LoginName||'?');
            const ulogin = esc(u.LoginName||u.Email||'');
            return `<div class="perm-user-row">
              <div style="width:20px;height:20px;border-radius:50%;background:#6b7280;display:flex;align-items:center;justify-content:center;font-size:9px;color:#fff;flex-shrink:0;">👤</div>
              <span style="font-weight:600;">${uname}</span>
              ${ulogin ? `<span style="font-size:10px;color:var(--text-muted);margin-left:auto;">${ulogin}</span>` : ''}
            </div>`;
          }).join('')
        : '<div style="font-size:11px;color:var(--text-muted);padding:4px 6px;">Keine Mitglieder geladen</div>';
      const countBadge = users.length ? `<span style="font-size:9px;padding:2px 7px;background:var(--bg);border:1px solid var(--border);border-radius:10px;color:var(--text-muted);">${users.length} User</span>` : '';
      return `<div class="perm-group-row">
        <div class="perm-group-hdr" onclick="dToggleGroup('${gid}')">
          <div class="perm-member-icon" style="background:${ri.bg};">${ri.icon}</div>
          <span style="font-size:13px;">${typeIcon}</span>
          <span class="perm-member-name">${displayName}</span>
          ${countBadge}
          <span class="perm-member-role">${esc(roles)}</span>
          <span class="perm-group-toggle" id="tg_${gid}">▶</span>
        </div>
        <div class="perm-group-members" id="${gid}">${usersHtml}</div>
      </div>`;
    }
    // Individual user / service account
    return `<div class="perm-member">
      <div class="perm-member-icon" style="background:${ri.bg};">${ri.icon}</div>
      <span>${typeIcon}</span>
      <span class="perm-member-name">${displayName}</span>
      <span class="perm-member-role">${esc(roles)}</span>
    </div>`;
  }).filter(Boolean).join('');

  return mainHtml + sharingHtml;
}

function dToggleGroup(id) {
  const el = document.getElementById(id);
  const tg = document.getElementById('tg_'+id);
  if (!el) return;
  el.classList.toggle('open');
  if (tg) tg.classList.toggle('open', el.classList.contains('open'));
}

// ════════════════════════════════════════════════════════════════
// BERECHTIGUNGEN — API-DIAGNOSE
// Prüft welche Graph- und SP-REST-Endpunkte erreichbar sind
// und erklärt fehlende Azure AD App-Berechtigungen
// ════════════════════════════════════════════════════════════════
async function runPermDiag() {
  const diag = $id('perm-diag');
  diag.style.display = 'block';
  diag.innerHTML = '<span class="perm-spinner"></span> Prüfe API-Zugriffe…';

  const siteUrl = permSiteUrl || 'https://dihag.sharepoint.com/sites/ticket';
  const siteId  = permSiteId  || null;

  const checks = [
    {
      label: 'Graph: /me (Anmeldung)',
      desc: 'User.Read',
      fn: ()=> gGet('/me?$select=displayName,mail')
    },
    {
      label: 'Graph: Sites durchsuchen',
      desc: 'Sites.Read.All',
      fn: ()=> gGet('/sites?search=ticket&$top=1')
    },
    {
      label: 'SP REST: Web-Info',
      desc: 'Kein extra Scope (SP-Token)',
      fn: ()=> spGet(`${siteUrl}/_api/web?$select=Title`)
    },
    {
      label: 'SP REST: RoleAssignments (Site-Berechtigungen)',
      desc: 'Benötigt: Site Collection Admin ODER "Full Control" auf der Site',
      fn: ()=> spGet(`${siteUrl}/_api/web/roleassignments?$top=1&$expand=Member,RoleDefinitionBindings`)
    },
    {
      label: 'SP REST: SiteGroups + Users',
      desc: 'Benötigt: Mitglied einer SP-Gruppe (Besitzer/Mitglieder/Besucher)',
      fn: ()=> spGet(`${siteUrl}/_api/web/sitegroups?$top=3&$expand=Users`)
    },
    {
      label: 'SP REST: Listen (nicht ausgeblendet)',
      desc: 'Benötigt: Lesen auf der Site',
      fn: ()=> spGet(`${siteUrl}/_api/web/lists?$filter=Hidden eq false&$top=3&$select=Title`)
    },
    ...(siteId ? [{
      label: 'Graph: Drives (Bibliotheken)',
      desc: 'Sites.Read.All oder Files.Read.All',
      fn: ()=> gGet(`/sites/${siteId}/drives?$top=3`)
    }] : [])
  ];

  let rows = `<div style="font-weight:700;color:var(--navy);margin-bottom:10px;">🔧 API-Diagnose — ${siteUrl}</div>
    <div style="font-size:10px;color:var(--text-muted);margin-bottom:10px;">
      Benötigte Azure AD App-Berechtigungen: <code>User.Read, Sites.Read.All, Sites.ReadWrite.All, Files.ReadWrite.All</code><br>
      SP-REST benötigt zusätzlich dass der angemeldete User <strong>Site Collection Admin</strong> ist oder zumindest Mitglied einer SP-Gruppe.
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:11px;">
      <tr style="background:var(--bg);"><th style="padding:5px 8px;text-align:left;border-bottom:2px solid var(--border);">Endpunkt</th><th style="padding:5px 8px;text-align:left;border-bottom:2px solid var(--border);">Scope/Voraussetzung</th><th style="padding:5px 8px;border-bottom:2px solid var(--border);">Status</th></tr>`;

  for (const c of checks) {
    let status, color;
    try {
      const r = await c.fn();
      status = '✓ OK';
      color = 'var(--green)';
      if (r?.value?.length !== undefined) status += ` (${r.value.length} Einträge)`;
      else if (r?.d?.results?.length !== undefined) status += ` (${r.d.results.length} Einträge)`;
      else if (r?.displayName) status += ` — ${r.displayName}`;
      else if (r?.d?.Title) status += ` — ${r.d.Title}`;
    } catch(e) {
      const msg = e.message||'';
      const code = msg.match(/\d{3}/)?.[0]||'';
      if (code==='403') { status='⛔ 403 Kein Zugriff'; color='var(--red)'; }
      else if (code==='401') { status='🔑 401 Nicht authentifiziert'; color='var(--red)'; }
      else if (code==='404') { status='❓ 404 Nicht gefunden'; color='var(--yellow)'; }
      else { status='⚠ '+msg.substring(0,60); color='var(--orange)'; }
    }
    rows += `<tr>
      <td style="padding:5px 8px;border-bottom:1px solid var(--border);">${esc(c.label)}</td>
      <td style="padding:5px 8px;border-bottom:1px solid var(--border);color:var(--text-muted);">${esc(c.desc)}</td>
      <td style="padding:5px 8px;border-bottom:1px solid var(--border);font-weight:700;color:${color};">${esc(status)}</td>
    </tr>`;
  }

  rows += `</table>
    <div style="margin-top:12px;padding:10px;background:#fffbeb;border:1px solid #fde68a;border-radius:6px;color:#92400e;font-size:10px;">
      <strong>Wenn RoleAssignments 403 zurückgibt aber SiteGroups OK ist:</strong><br>
      Der angemeldete User ist zwar SP-Mitglied, aber kein <em>Site Collection Admin</em>.<br>
      → In SharePoint Admin Center: Site auswählen → „Administrators" → User hinzufügen.<br>
      → Oder in der Site selbst: Zahnrad → Site-Einstellungen → Site Collection-Administratoren.<br><br>
      <strong>Wenn beide 403:</strong> Die Azure AD App hat möglicherweise nicht <code>Sites.ReadWrite.All</code> als delegierte Berechtigung — oder der Admin-Consent fehlt noch.
    </div>`;

  diag.innerHTML = rows;
}

let treeIdCounter = 0;
function treeNode(icon, label, badge, children, expandId) {
  const id = expandId || ('tn_'+(treeIdCounter++));
  const hasSub = children !== undefined;
  return `<div class="tree-node">
    <div class="tree-item" onclick="${hasSub?`toggleTree('${id}')`:''}" ${!hasSub?'style="cursor:default;"':''}>
      ${hasSub?`<span class="tree-toggle" id="tg_${id}">▶</span>`:'<span style="width:18px;"></span>'}
      <span class="tree-icon">${icon}</span>
      <span class="tree-label">${label}</span>
      ${badge||''}
    </div>
    ${hasSub?`<div class="tree-children" id="${id}" style="display:none;">${children}</div>`:''}
  </div>`;
}

function toggleTree(id) {
  const el = $id(id);
  const tg = $id('tg_'+id);
  if (!el) return;
  const open = el.style.display !== 'none';
  el.style.display = open ? 'none' : 'block';
  if (tg) tg.classList.toggle('open', !open);
}

async function startPermScan() {
  // If site was selected via autocomplete, permSiteId is set
  if (!permSiteId) {
    const input = $id('perm-site-url').value.trim();
    if (!input) { toast('Bitte Site suchen und auswählen','error'); return; }
    const clean = cleanSiteInput(input);
    dbg('Perm: Site-Eingabe bereinigt', {original: input, clean});
    try {
      const site = await gGet(`/sites/${clean}`);
      permSiteId = site.id;
      permSiteUrl = site.webUrl;
    } catch(e) {
      toast('Site nicht gefunden: '+e.message,'error');
      return;
    }
  }

  $id('perm-scan-btn').disabled = true;
  $id('perm-suggestions').style.display='none';
  $id('perm-status').innerHTML = '<span class="perm-spinner"></span> Stufe 1: Site-Berechtigungen…';
  $id('perm-container').innerHTML = '<div class="perm-spinner" style="margin:20px auto;"></div>';
  permLibraries = [];
  treeIdCounter = 0;

  try {
    const siteName = permSiteUrl.split('/').pop();

    // ── STUFE 1: Site perms — try roleassignments, fall back to sitegroups ──
    let siteMembers = '';
    let siteGroupsCache = []; // cache for later reuse in group lookups

    // Strategy 1: Graph API /sites/{id}/permissions (no SP admin needed)
    let roleAssignments = [];
    try {
      const gPerms = await gGet(`/sites/${permSiteId}/permissions?$top=100`);
      const gPA = gPerms.value||[];
      dbg('Graph permissions', {count: gPA.length});
      // Convert Graph permission format to SP roleassignment-like format for renderMembersTree
      roleAssignments = gPA.map(p => {
        const roles = p.roles||[];
        const roleLabel = roles.includes('fullControl')?'Vollzugriff':roles.includes('write')?'Bearbeiten':roles.includes('read')?'Lesen':roles.join(',');
        const identity = p.grantedToIdentitiesV2?.[0]||p.grantedToV2||{};
        const user = identity.user||identity.group||{};
        const isGroup = !!identity.group;
        return {
          Member: {
            PrincipalType: isGroup?8:1,
            Title: user.displayName||p.id||'?',
            LoginName: user.email||'',
            Users: {results:[]}
          },
          RoleDefinitionBindings: {results:[{Name:roleLabel}]}
        };
      });
    } catch(e) { dbg('Graph permissions Fehler', e.message); }

    // Strategy 2: SP REST sitegroups (works if user is SP member)
    try {
      const sgRes = await spGet(`${permSiteUrl}/_api/web/sitegroups?$select=Id,Title,Description&$top=100`);
      siteGroupsCache = sgRes.d?.results || [];
      for (const g of siteGroupsCache) {
        try {
          const uRes = await spGet(`${permSiteUrl}/_api/web/sitegroups(${g.Id})/users?$select=Id,Title,LoginName,Email&$top=200`);
          g._users = uRes.d?.results || [];
        } catch { g._users = []; }
      }
      dbg('SiteGroups geladen', {groups: siteGroupsCache.length});
    } catch(e) { dbg('SiteGroups Fehler', e.message); }

    // Strategy 3: SP REST roleassignments (needs AllSites.FullControl scope)
    if (!roleAssignments.length) {
      try {
        const raRes = await spGet(`${permSiteUrl}/_api/web/roleassignments?$expand=Member,RoleDefinitionBindings&$top=100`);
        const rawRA = raRes.d?.results || [];
        const groupMap = {};
        siteGroupsCache.forEach(g => { groupMap[g.Id] = g; });
        rawRA.forEach(ra => {
          if (ra.Member?.PrincipalType === 8 && ra.Member?.Id) {
            const g = groupMap[ra.Member.Id];
            if (g) ra.Member.Users = { results: g._users||[] };
          }
        });
        roleAssignments = rawRA;
        dbg('RoleAssignments (SP REST) geladen', {count: roleAssignments.length});
      } catch(e) { dbg('RoleAssignments SP REST nicht verfügbar', e.message); }
    }

    if (roleAssignments.length) {
      siteMembers = `<div class="perm-members" style="padding:4px 0;">${renderMembersTree(roleAssignments)}</div>`;
    } else if (siteGroupsCache.length) {
      // Render sitegroups directly with role inferred from group name
      siteMembers = '<div class="perm-members" style="padding:4px 0;">';
      siteGroupsCache.forEach(g => {
        const users = g._users || [];
        const roleLabel = /Besitzer|Owner|Full/i.test(g.Title) ? 'Vollzugriff' :
                          /Mitglieder|Member|Edit|Contribute/i.test(g.Title) ? 'Bearbeiten' : 'Lesen';
        const ri = roleIcon(roleLabel);
        const gid = 'sg_'+(++_permGroupCounter);
        const usersHtml = users.length
          ? users.map(u=>`<div class="perm-user-row">
              <div style="width:20px;height:20px;border-radius:50%;background:#6b7280;display:flex;align-items:center;justify-content:center;font-size:9px;color:#fff;flex-shrink:0;">👤</div>
              <span style="font-weight:600;">${esc(u.Title||u.LoginName||'?')}</span>
              <span style="font-size:10px;color:var(--text-muted);margin-left:auto;">${esc(u.Email||u.LoginName||'')}</span>
            </div>`).join('')
          : '<div style="font-size:11px;color:var(--text-muted);padding:4px 6px;">Keine Mitglieder</div>';
        siteMembers += `<div class="perm-group-row">
          <div class="perm-group-hdr" onclick="dToggleGroup('${gid}')">
            <div class="perm-member-icon" style="background:${ri.bg};">${ri.icon}</div>
            <span style="font-size:13px;">👥</span>
            <span class="perm-member-name">${esc(g.Title)}</span>
            <span style="font-size:9px;padding:2px 7px;background:var(--bg);border:1px solid var(--border);border-radius:10px;color:var(--text-muted);">${users.length} User</span>
            <span class="perm-member-role">${esc(roleLabel)}</span>
            <span class="perm-group-toggle" id="tg_${gid}">▶</span>
          </div>
          <div class="perm-group-members" id="${gid}">${usersHtml}</div>
        </div>`;
      });
      siteMembers += '</div>';
      if (!roleAssignments.length) {
        siteMembers += `<div style="margin-top:6px;padding:6px 10px;background:#fef9c3;border-radius:6px;font-size:10px;color:#854d0e;">
          ℹ️ Berechtigungsstufen ohne Site Collection Admin nicht lesbar — Gruppen aus SiteGroups-API angezeigt
        </div>`;
      }
    } else {
      siteMembers = `<div style="padding:10px;background:var(--red-bg);border-radius:8px;font-size:11px;color:var(--red);">⚠ Kein Zugriff auf Berechtigungen</div>`;
    }

    // ── STUFE 2 ──
    $id('perm-status').innerHTML = '<span class="perm-spinner"></span> Stufe 2: Bibliotheken & Listen…';
    let lists = [], libs = [], otherLists = [];
    try {
      const listsData = await spGet(`${permSiteUrl}/_api/web/lists?$filter=Hidden eq false&$select=Title,Id,BaseTemplate,HasUniqueRoleAssignments,ItemCount&$top=200`);
      lists = listsData.d?.results || [];
    } catch(e) {
      dbg('Stufe 2 Listen-Fehler, versuche Graph…', e.message);
      // Fallback: use Graph to at least list the libraries
      try {
        const gLists = await gGet(`/sites/${permSiteId}/lists?$select=id,displayName,list&$top=200`);
        lists = (gLists.value||[]).map(l=>({Title:l.displayName, Id:l.id, BaseTemplate:l.list?.template==='documentLibrary'?101:0, HasUniqueRoleAssignments:false, ItemCount:'?'}));
      } catch {}
    }
    libs = lists.filter(l=>[101,700].includes(l.BaseTemplate));
    otherLists = lists.filter(l=>![101,700].includes(l.BaseTemplate));
    permLibraries = libs;

    let subsites = [];
    try {
      const sd = await spGet(`${permSiteUrl}/_api/web/webs?$select=Title,Url,HasUniqueRoleAssignments`);
      subsites = sd.d?.results || [];
    } catch {}

    // Build library nodes
    let libNodes = '';
    for (const lib of libs) {
      const uTag = lib.HasUniqueRoleAssignments
        ? '<span class="tree-badge" style="background:var(--red-bg);color:var(--red);">⚠ Eigene</span>'
        : '<span class="tree-badge" style="background:var(--green-bg);color:var(--green);">✓ Vererbt</span>';
      let libPerms = '';
      if (lib.HasUniqueRoleAssignments) {
        try {
          const lp = await spGet(`${permSiteUrl}/_api/web/lists(guid'${lib.Id}')/roleassignments?$expand=Member,RoleDefinitionBindings&$top=100`);
          const lpRA = lp.d?.results||[];
          for (const ra of lpRA) {
            if (ra.Member?.PrincipalType===8 && ra.Member.Id) {
              try { const gu=await spGet(`${permSiteUrl}/_api/web/sitegroups(${ra.Member.Id})/users?$top=100`); ra.Member.Users={results:gu.d?.results||[]}; } catch{}
            }
          }
          libPerms = `<div class="perm-members" style="padding:4px 0 4px 6px;">${renderMembersTree(lpRA)}</div>`;
        } catch { libPerms = ''; }
      }
      const folderId = 'lib_'+lib.Id.replace(/-/g,'');
      libNodes += treeNode('📁', `${esc(lib.Title)} <span style="font-size:10px;color:var(--text-muted);">(${lib.ItemCount})</span>`, uTag,
        libPerms + `<div id="${folderId}" class="tree-loading"><span class="perm-spinner"></span> Ordner laden…</div>`, folderId+'_wrap');
    }

    // List nodes
    let listNodes = '';
    for (const lst of otherLists) {
      const uTag = lst.HasUniqueRoleAssignments
        ? '<span class="tree-badge" style="background:var(--red-bg);color:var(--red);">⚠ Eigene</span>'
        : '<span class="tree-badge" style="background:var(--green-bg);color:var(--green);">✓ Vererbt</span>';
      let lp = '';
      if (lst.HasUniqueRoleAssignments) {
        try {
          const d = await spGet(`${permSiteUrl}/_api/web/lists(guid'${lst.Id}')/roleassignments?$expand=Member,RoleDefinitionBindings&$top=100`);
          const dRA = d.d?.results||[];
          for (const ra of dRA) {
            if (ra.Member?.PrincipalType===8 && ra.Member.Id) {
              try { const gu=await spGet(`${permSiteUrl}/_api/web/sitegroups(${ra.Member.Id})/users?$top=100`); ra.Member.Users={results:gu.d?.results||[]}; } catch{}
            }
          }
          lp = `<div class="perm-members" style="padding:4px 0 4px 6px;">${renderMembersTree(dRA)}</div>`;
        } catch {}
      }
      listNodes += treeNode('📋', esc(lst.Title), uTag, lp||'<div class="tree-loading">Keine eigenen Berechtigungen</div>');
    }

    // Subsite nodes
    let subNodes = subsites.map(s => {
      const uTag = s.HasUniqueRoleAssignments
        ? '<span class="tree-badge" style="background:var(--red-bg);color:var(--red);">⚠ Eigene</span>'
        : '<span class="tree-badge" style="background:var(--green-bg);color:var(--green);">✓ Vererbt</span>';
      return treeNode('🌐', esc(s.Title), uTag, `<div class="tree-loading" style="font-size:10px;">${esc(s.Url)}</div>`);
    }).join('');

    // Site-level sharing links (on demand)
    const siteSLId = 'site_sl_'+Math.random().toString(36).slice(2);
    const siteSLBtn = `<div style="margin:8px 0 4px;">
      <button onclick="loadSiteSharingLinks('${esc(permSiteId)}','${siteSLId}')" id="${siteSLId}_btn"
        style="font-size:11px;padding:3px 10px;background:none;border:1.5px solid var(--border2);border-radius:5px;cursor:pointer;color:var(--text-dim);">
        🔗 Site Sharing Links anzeigen
      </button>
      <div id="${siteSLId}" style="display:none;margin-top:6px;"></div>
    </div>`;

    // Assemble tree
    const tree = `<div class="tree">
      ${treeNode('🌐', `<strong>${esc(siteName)}</strong> <span style="font-size:10px;color:var(--text-muted);">(Site)</span>`,
        '<span class="tree-badge" style="background:var(--navy);color:#fff;">Stufe 1</span>',
        siteMembers + siteSLBtn +
        treeNode('📚', `Bibliotheken (${libs.length})`, '<span class="tree-badge" style="background:var(--navy2);color:#fff;">Stufe 2</span>', libNodes, 'tree_libs') +
        (otherLists.length ? treeNode('📋', `Listen (${otherLists.length})`, '<span class="tree-badge" style="background:var(--navy2);color:#fff;">Stufe 2</span>', listNodes, 'tree_lists') : '') +
        (subsites.length ? treeNode('🌐', `Unterseiten (${subsites.length})`, '<span class="tree-badge" style="background:var(--navy2);color:#fff;">Stufe 2</span>', subNodes, 'tree_subs') : ''),
        'tree_root'
      )}
    </div>`;

    $id('perm-container').innerHTML = tree;
    // Auto-expand root
    toggleTree('tree_root');

    $id('perm-status').innerHTML = '✓ Stufe 1+2 geladen. <span class="perm-spinner"></span> Ordner laden (Stufe 3+4)…';
    await loadFolderPermsTree();

  } catch(e) {
    dbg('Perm FEHLER', e.message);
    $id('perm-container').innerHTML = `<div class="empty" style="color:var(--red);">⚠ ${esc(e.message)}</div>`;
    $id('perm-status').textContent = 'Fehler: ' + e.message;
  }
  $id('perm-scan-btn').disabled = false;
  // Keep permSiteId and permSiteUrl for folder loading
}

async function loadFolderPermsTree() {
  for (const lib of permLibraries) {
    const containerId = 'lib_'+lib.Id.replace(/-/g,'');
    const container = $id(containerId);
    if (!container) continue;
    try {
      const drivesData = await gGet(`/sites/${permSiteId}/lists/${lib.Id}/drive`);
      const driveId = drivesData.id;
      const rootChildren = await gGet(`/drives/${driveId}/root/children?$top=200`);
      const allItems = rootChildren.value||[];
      const folders = allItems.filter(f=>f.folder);
      const files   = allItems.filter(f=>!f.folder);
      if (!allItems.length) { container.innerHTML='<div class="tree-loading">Leer</div>'; continue; }

      let html = '';

      // Root-level files: check unique perms per file
      if (files.length) {
        html += `<div style="font-size:9px;font-weight:700;color:var(--text-muted);padding:6px 0 4px 0;">📄 Dateien in Bibliothek (${files.length}):</div>`;
        for (const f of files) {
          const filePermsHtml = await getItemPermsHtml(f.webUrl, driveId, f.id);
          const uTag = filePermsHtml
            ? '<span class="tree-badge" style="background:var(--red-bg);color:var(--red);">⚠ Eigene</span>'
            : '<span class="tree-badge" style="background:var(--green-bg);color:var(--green);">✓ Vererbt</span>';
          html += treeNode(dmsFileIconPerm(f.name),
            `${esc(f.name)} <span style="font-size:10px;color:var(--text-muted);">${dmsFormatBytesPerm(f.size||0)}</span>`,
            uTag + (f.webUrl?`<a href="${esc(f.webUrl)}" target="_blank" style="font-size:10px;color:var(--blue);text-decoration:none;margin-left:6px;">↗</a>`:''),
            filePermsHtml || '<div class="tree-loading" style="font-size:10px;">Berechtigungen vererbt</div>');
        }
      }

      // Folders (Stufe 3)
      if (folders.length) {
        html += `<div style="font-size:9px;font-weight:700;color:var(--text-muted);padding:6px 0 4px 0;">📁 Ordner — Stufe 3:</div>`;
        for (const folder of folders) {
          const folderPermsHtml = await getItemPermsHtml(folder.webUrl);
          const uTag = folderPermsHtml
            ? '<span class="tree-badge" style="background:var(--red-bg);color:var(--red);">⚠ Eigene</span>'
            : '<span class="tree-badge" style="background:var(--green-bg);color:var(--green);">✓ Vererbt</span>';

          // Stufe 4: subfolders + files inside
          let subHtml = '';
          try {
            const sub = await gGet(`/drives/${driveId}/items/${folder.id}/children?$top=200`);
            const subItems = sub.value||[];
            const subFolders = subItems.filter(i=>i.folder);
            const subFiles   = subItems.filter(i=>!i.folder);

            // Sub-files with unique perms
            if (subFiles.length) {
              subHtml += `<div style="font-size:9px;font-weight:700;color:var(--text-muted);padding:4px 0 2px 0;">📄 Dateien (${subFiles.length}):</div>`;
              for (const sf of subFiles) {
                const sfPH = await getItemPermsHtml(sf.webUrl);
                const sfTag = sfPH
                  ? '<span class="tree-badge" style="background:var(--red-bg);color:var(--red);">⚠ Eigene</span>'
                  : '<span class="tree-badge" style="background:var(--green-bg);color:var(--green);">✓</span>';
                subHtml += treeNode(dmsFileIconPerm(sf.name),
                  `${esc(sf.name)} <span style="font-size:10px;color:var(--text-muted);">${dmsFormatBytesPerm(sf.size||0)}</span>`,
                  sfTag + (sf.webUrl?`<a href="${esc(sf.webUrl)}" target="_blank" style="font-size:10px;color:var(--blue);text-decoration:none;margin-left:6px;">↗</a>`:''),
                  sfPH || '<div class="tree-loading" style="font-size:10px;">Vererbt</div>');
              }
            }

            // Sub-folders (Stufe 4)
            if (subFolders.length) {
              subHtml += `<div style="font-size:9px;font-weight:700;color:var(--text-muted);padding:4px 0 2px 0;">📁 Unterordner — Stufe 4:</div>`;
              for (const sf of subFolders) {
                const sfPH = await getItemPermsHtml(sf.webUrl);
                const sfTag = sfPH
                  ? '<span class="tree-badge" style="background:var(--red-bg);color:var(--red);">⚠ Eigene</span>'
                  : '<span class="tree-badge" style="background:var(--green-bg);color:var(--green);">✓</span>';
                subHtml += treeNode('📂',
                  `${esc(sf.name)} <span style="font-size:10px;color:var(--text-muted);">(${sf.folder?.childCount||0})</span>`,
                  sfTag, sfPH || '<div class="tree-loading" style="font-size:10px;">Vererbt</div>');
              }
            }
          } catch(e2) { dbg('Stufe 4 Fehler', e2.message); }

          const children = (folderPermsHtml||'') + subHtml || '<div class="tree-loading">—</div>';
          html += treeNode('📂',
            `${esc(folder.name)} <span style="font-size:10px;color:var(--text-muted);">(${folder.folder.childCount})</span>`,
            uTag, children);
        }
      }

      // Sharing links button (on demand)
      const slBtnId = 'sl_'+lib.Id.replace(/-/g,'');
      html += `<div style="margin-top:10px;padding-top:8px;border-top:1px solid var(--border);">
        <button onclick="loadSharingLinks('${esc(driveId)}','${slBtnId}')" id="${slBtnId}_btn"
          style="font-size:11px;padding:4px 12px;background:none;border:1.5px solid var(--border2);border-radius:5px;cursor:pointer;color:var(--text-dim);">
          🔗 Sharing Links anzeigen
        </button>
        <div id="${slBtnId}" style="display:none;margin-top:8px;"></div>
      </div>`;

      container.innerHTML = html;
      dbg(`Stufe 3+4: "${lib.Title}" fertig`);
    } catch(e) {
      if(container) container.innerHTML=`<span style="font-size:10px;color:var(--red);">${esc(e.message)}</span>`;
    }
  }
  $id('perm-status').textContent = `✓ Alle Stufen geladen`;
  dbg('Berechtigungs-Scan komplett ✓');
}

// Helper: get unique role assignments for a SharePoint item by webUrl
async function getItemPermsHtml(webUrl, driveId, itemId) {
  if (!webUrl) return '';
  try {
    const relUrl = new URL(webUrl).pathname;
    const fp = await spGet(`${permSiteUrl}/_api/web/GetFileByServerRelativeUrl('${encodeURIComponent(relUrl)}')/ListItemAllFields?$select=HasUniqueRoleAssignments`).catch(()=>
      spGet(`${permSiteUrl}/_api/web/GetFolderByServerRelativeUrl('${encodeURIComponent(relUrl)}')/ListItemAllFields?$select=HasUniqueRoleAssignments`)
    );
    if (!fp.d?.HasUniqueRoleAssignments) return '';
    // Has unique perms — fetch them
    const ra = await spGet(`${permSiteUrl}/_api/web/GetFileByServerRelativeUrl('${encodeURIComponent(relUrl)}')/ListItemAllFields/roleassignments?$expand=Member,RoleDefinitionBindings`).catch(()=>
      spGet(`${permSiteUrl}/_api/web/GetFolderByServerRelativeUrl('${encodeURIComponent(relUrl)}')/ListItemAllFields/roleassignments?$expand=Member,RoleDefinitionBindings`)
    );
    const results = ra.d?.results||[];
    // Enrich group users
    for (const r of results) {
      if (r.Member?.PrincipalType===8 && r.Member?.Id) {
        try { const gu=await spGet(`${permSiteUrl}/_api/web/sitegroups(${r.Member.Id})/users?$top=100`); r.Member.Users={results:gu.d?.results||[]}; } catch{}
      }
    }
    return `<div class="perm-members" style="padding:2px 0 2px 6px;">${renderMembersTree(results)}</div>`;
  } catch { return ''; }
}

// Site-level sharing links
async function loadSiteSharingLinks(siteId, containerId) {
  const btn = $id(containerId+'_btn');
  const box = $id(containerId);
  if(!btn||!box) return;
  btn.disabled=true; btn.textContent='⏳ Lade…';
  try {
    // Get sharing links via site drives
    const drives = await gGet('/sites/'+siteId+'/drives?$top=20');
    let allLinks = [];
    for (const drv of (drives.value||[]).slice(0,3)) {
      try {
        const r = await gGet('/drives/'+drv.id+'/root/permissions?$top=50');
        const links = (r.value||[]).filter(p=>p.link).map(p=>({...p, _libName:drv.name}));
        allLinks = [...allLinks, ...links];
      } catch{}
    }
    if(!allLinks.length){
      box.innerHTML='<div style="font-size:11px;color:var(--text-muted);">Keine aktiven Sharing Links</div>';
    } else {
      box.innerHTML='<div style="font-size:11px;font-weight:700;color:var(--navy);margin-bottom:6px;">🔗 '+allLinks.length+' Sharing Link(s) (Site):</div>'
        +allLinks.map(l=>'<div style="padding:5px 8px;background:var(--bg);border-radius:6px;margin-bottom:4px;font-size:11px;">'
          +'<span style="font-size:9px;color:var(--text-muted);">'+esc(l._libName||'')+'</span> '
          +'<span style="font-weight:600;">'+esc(l.link?.type||'Link')+'</span> '
          +'<span style="color:var(--text-muted);">'+esc(l.link?.scope||'')+'</span>'
          +(l.link?.webUrl?'<a href="'+esc(l.link.webUrl)+'" target="_blank" style="margin-left:8px;color:var(--blue);">↗</a>':'')
          +'</div>').join('');
    }
    box.style.display='block';
    btn.disabled=false;
    btn.textContent='🔗 Site Sharing Links verbergen';
    btn.onclick=()=>{ box.style.display=box.style.display==='none'?'block':'none'; btn.textContent=box.style.display==='none'?'🔗 Site Sharing Links anzeigen':'🔗 Site Sharing Links verbergen'; };
  } catch(e){
    box.innerHTML='<div style="font-size:11px;color:var(--red);">⚠ '+esc(e.message)+'</div>';
    box.style.display='block'; btn.disabled=false; btn.textContent='🔗 Site Sharing Links anzeigen';
  }
}

// Sharing links: load on demand
async function loadSharingLinks(driveId, containerId) {
  const btn = $id(containerId+'_btn');
  const box = $id(containerId);
  if (!btn||!box) return;
  btn.disabled=true; btn.textContent='⏳ Lade…';
  try {
    // Graph: list sharing links via permissions endpoint for drive root
    const r = await gGet(`/drives/${driveId}/root/permissions?$top=100`);
    const links = (r.value||[]).filter(p=>p.link);
    if (!links.length) {
      box.innerHTML='<div style="font-size:11px;color:var(--text-muted);">Keine aktiven Sharing Links gefunden</div>';
    } else {
      box.innerHTML='<div style="font-size:11px;font-weight:700;color:var(--navy);margin-bottom:6px;">🔗 '+links.length+' Sharing Link(s):</div>'+
        links.map(l=>`<div style="padding:5px 8px;background:var(--bg);border-radius:6px;margin-bottom:4px;font-size:11px;">
          <span style="font-weight:600;">${esc(l.link?.type||'Link')}</span>
          <span style="color:var(--text-muted);margin-left:8px;">${esc(l.link?.scope||'')}</span>
          ${l.link?.webUrl?`<a href="${esc(l.link.webUrl)}" target="_blank" style="margin-left:8px;color:var(--blue);">↗</a>`:''}
          ${l.grantedToIdentitiesV2?.length?`<div style="font-size:10px;color:var(--text-muted);margin-top:2px;">Geteilt mit: ${l.grantedToIdentitiesV2.map(g=>esc(g.user?.displayName||g.group?.displayName||'')).filter(Boolean).join(', ')}</div>`:''}
        </div>`).join('');
    }
    box.style.display='block';
    btn.textContent='🔗 Sharing Links verbergen';
    btn.onclick=()=>{ box.style.display=box.style.display==='none'?'block':'none'; btn.textContent=box.style.display==='none'?'🔗 Sharing Links anzeigen':'🔗 Sharing Links verbergen'; };
    btn.disabled=false;
  } catch(e) {
    box.innerHTML=`<div style="font-size:11px;color:var(--red);">⚠ ${esc(e.message)}</div>`;
    box.style.display='block';
    btn.textContent='🔗 Sharing Links anzeigen'; btn.disabled=false;
  }
}

// ════════════════════════════════════════════════════════════════
// AUTOMATISMEN
// ════════════════════════════════════════════════════════════════
const AUTO_FORMS = {
  onboarding:{
    title:'👋 Onboarding',tag:'Neuer Mitarbeiter',icon:'👋',
    desc:'Neuen Mitarbeiter einrichten — AD, E-Mail, Teams, Lizenzen, Hardware',
    sections:[
      {label:'Mitarbeiterdaten',fields:[
        {key:'vorname',label:'Vorname',type:'text',required:true},
        {key:'nachname',label:'Nachname',type:'text',required:true},
        {key:'email',label:'E-Mail-Adresse',type:'email',required:true,placeholder:'v.nachname@dihag.de'},
        {key:'abteilung',label:'Abteilung',type:'text'},
        {key:'vorgesetzter',label:'Vorgesetzter',type:'text'},
        {key:'standort',label:'Standort / Werk',type:'text'},
        {key:'startdatum',label:'Startdatum',type:'date',required:true},
      ]},
      {label:'IT-Einrichtung',fields:[
        {key:'ad_anlegen',label:'AD-Konto anlegen',type:'checkbox',def:true},
        {key:'email_anlegen',label:'E-Mail-Postfach einrichten',type:'checkbox',def:true},
        {key:'teams',label:'Teams-Lizenz zuweisen',type:'checkbox',def:true},
        {key:'vpn',label:'VPN-Zugang einrichten',type:'checkbox',def:false},
        {key:'sharepoint',label:'SharePoint-Zugriff',type:'checkbox',def:true},
      ]},
      {label:'Hardware',fields:[
        {key:'laptop',label:'Laptop benötigt',type:'checkbox',def:true},
        {key:'monitor',label:'Monitor benötigt',type:'checkbox',def:false},
        {key:'headset',label:'Headset benötigt',type:'checkbox',def:false},
        {key:'handy',label:'Diensthandy benötigt',type:'checkbox',def:false},
        {key:'hw_notiz',label:'Hardware-Details',type:'textarea',placeholder:'Spezielle Anforderungen…'},
      ]},
      {label:'Sonstiges',fields:[
        {key:'notizen',label:'Notizen',type:'textarea'},
      ]},
    ],
    submit:'👋 Onboarding-Ticket erstellen',
    onSubmit: async d=>{
      const title=`Onboarding: ${d.vorname} ${d.nachname}`;
      const body=`Neuer Mitarbeiter: ${d.vorname} ${d.nachname}\nE-Mail: ${d.email}\nAbteilung: ${d.abteilung||'-'}\nVorgesetzter: ${d.vorgesetzter||'-'}\nStandort: ${d.standort||'-'}\nStartdatum: ${d.startdatum}\n\nIT-Einrichtung:\n• AD-Konto: ${d.ad_anlegen?'✓':'✗'}\n• E-Mail: ${d.email_anlegen?'✓':'✗'}\n• Teams: ${d.teams?'✓':'✗'}\n• VPN: ${d.vpn?'✓':'✗'}\n• SharePoint: ${d.sharepoint?'✓':'✗'}\n\nHardware:\n• Laptop: ${d.laptop?'✓':'✗'}\n• Monitor: ${d.monitor?'✓':'✗'}\n• Headset: ${d.headset?'✓':'✗'}\n• Diensthandy: ${d.handy?'✓':'✗'}\n${d.hw_notiz?'Details: '+d.hw_notiz:''}\n\nNotizen: ${d.notizen||'-'}`;
      if(ticketSiteId&&ticketListId){
        const colTitle=col(['Titel','Title'])||'Title';
        const colStatus=col(['Status'])||'Status';
        const colPrio=col(['Priorität','Priority']);
        const fields={[colTitle]:title};
        if(colStatus) fields[colStatus]='Offen';
        if(colPrio) fields[colPrio]='Hoch';
        const colDesc=col(['Beschreibung','Description','Kommentar']);
        if(colDesc) fields[colDesc]=body;
        await gPost(`/sites/${ticketSiteId}/lists/${ticketListId}/items`,{fields});
        toast('✓ Onboarding-Ticket erstellt','success');
        showPanel('tickets'); await streamTickets();
      } else { await navigator.clipboard.writeText(body).catch(()=>{}); toast('In Zwischenablage kopiert','info'); }
    }
  },
  hw_anfrage:{
    title:'🖥️ Hardware-Anfrage',tag:'Bestellung',icon:'🖥️',
    desc:'Neue Hardware bestellen — Laptop, Monitor, Peripherie',
    sections:[
      {label:'Antragsteller',fields:[
        {key:'name',label:'Name',type:'text',required:true},
        {key:'abteilung',label:'Abteilung',type:'text'},
        {key:'standort',label:'Standort',type:'text'},
      ]},
      {label:'Gewünschte Hardware',fields:[
        {key:'typ',label:'Gerätetyp',type:'select',required:true,def:'laptop',options:[
          {value:'laptop',label:'Laptop'},{value:'desktop',label:'Desktop-PC'},{value:'monitor',label:'Monitor'},
          {value:'headset',label:'Headset'},{value:'drucker',label:'Drucker'},{value:'handy',label:'Diensthandy'},
          {value:'sonstige',label:'Sonstiges'},
        ]},
        {key:'grund',label:'Begründung',type:'textarea',required:true,placeholder:'Warum wird das Gerät benötigt?'},
        {key:'dringend',label:'Dringend (< 1 Woche)',type:'checkbox',def:false},
      ]},
    ],
    submit:'🖥️ Anfrage erstellen',
    onSubmit: async d=>{
      const title=`Hardware-Anfrage: ${d.typ} für ${d.name}`;
      const body=`Antragsteller: ${d.name}\nAbteilung: ${d.abteilung||'-'}\nStandort: ${d.standort||'-'}\nGerätetyp: ${d.typ}\nDringend: ${d.dringend?'Ja':'Nein'}\n\nBegründung:\n${d.grund}`;
      if(ticketSiteId&&ticketListId){
        const fields={[col(['Titel','Title'])||'Title']:title};
        const cs=col(['Status']); if(cs) fields[cs]='Offen';
        const cp=col(['Priorität','Priority']); if(cp) fields[cp]=d.dringend?'Hoch':'Normal';
        const cd=col(['Beschreibung','Description','Kommentar']); if(cd) fields[cd]=body;
        await gPost(`/sites/${ticketSiteId}/lists/${ticketListId}/items`,{fields});
        toast('✓ Hardware-Anfrage erstellt','success');
        showPanel('tickets'); await streamTickets();
      } else { await navigator.clipboard.writeText(body).catch(()=>{}); toast('In Zwischenablage kopiert','info'); }
    }
  },
  zugang:{
    title:'🔑 Zugangsanfrage',tag:'Berechtigung',icon:'🔑',
    desc:'VPN, Systeme, SharePoint-Sites, Laufwerke beantragen',
    sections:[
      {label:'Antragsteller',fields:[
        {key:'name',label:'Für Mitarbeiter',type:'text',required:true},
        {key:'email',label:'E-Mail',type:'email',required:true},
      ]},
      {label:'Zugang',fields:[
        {key:'system',label:'System / Ressource',type:'text',required:true,placeholder:'z.B. VPN, SAP, SharePoint /sites/HR…'},
        {key:'berechtigung',label:'Gewünschte Berechtigung',type:'select',def:'lesen',options:[
          {value:'lesen',label:'Lesen'},{value:'bearbeiten',label:'Bearbeiten'},{value:'vollzugriff',label:'Vollzugriff'},
        ]},
        {key:'grund',label:'Begründung',type:'textarea',required:true},
        {key:'befristet',label:'Befristet bis (optional)',type:'date'},
      ]},
    ],
    submit:'🔑 Zugang beantragen',
    onSubmit: async d=>{
      const title=`Zugangsanfrage: ${d.system} für ${d.name}`;
      const body=`Mitarbeiter: ${d.name} (${d.email})\nSystem: ${d.system}\nBerechtigung: ${d.berechtigung}\nBefristet: ${d.befristet||'unbefristet'}\n\nBegründung:\n${d.grund}`;
      if(ticketSiteId&&ticketListId){
        const fields={[col(['Titel','Title'])||'Title']:title};
        const cs=col(['Status']); if(cs) fields[cs]='Offen';
        const cd=col(['Beschreibung','Description','Kommentar']); if(cd) fields[cd]=body;
        await gPost(`/sites/${ticketSiteId}/lists/${ticketListId}/items`,{fields});
        toast('✓ Zugangsanfrage erstellt','success');
        showPanel('tickets'); await streamTickets();
      } else { await navigator.clipboard.writeText(body).catch(()=>{}); toast('In Zwischenablage kopiert','info'); }
    }
  },
  software:{
    title:'📊 Software-Anfrage',tag:'Lizenz',icon:'📊',
    desc:'Software-Lizenzen beantragen — Office, Spezial-Software',
    sections:[
      {label:'Antragsteller',fields:[
        {key:'name',label:'Name',type:'text',required:true},
        {key:'abteilung',label:'Abteilung',type:'text'},
      ]},
      {label:'Software',fields:[
        {key:'software',label:'Software / Lizenz',type:'text',required:true,placeholder:'z.B. Adobe Acrobat Pro, Visio, AutoCAD…'},
        {key:'anzahl',label:'Anzahl Lizenzen',type:'text',def:'1'},
        {key:'grund',label:'Begründung',type:'textarea',required:true},
      ]},
    ],
    submit:'📊 Anfrage erstellen',
    onSubmit: async d=>{
      const title=`Software-Anfrage: ${d.software} für ${d.name}`;
      const body=`Antragsteller: ${d.name}\nAbteilung: ${d.abteilung||'-'}\nSoftware: ${d.software}\nAnzahl: ${d.anzahl||'1'}\n\n${d.grund}`;
      if(ticketSiteId&&ticketListId){
        const fields={[col(['Titel','Title'])||'Title']:title};
        const cs=col(['Status']); if(cs) fields[cs]='Offen';
        const cd=col(['Beschreibung','Description','Kommentar']); if(cd) fields[cd]=body;
        await gPost(`/sites/${ticketSiteId}/lists/${ticketListId}/items`,{fields});
        toast('✓ Software-Anfrage erstellt','success');
        showPanel('tickets'); await streamTickets();
      } else { await navigator.clipboard.writeText(body).catch(()=>{}); toast('In Zwischenablage kopiert','info'); }
    }
  },
  standortwechsel:{
    title:'🏢 Standortwechsel',tag:'IT-Umzug',icon:'🏢',
    desc:'Arbeitsplatz-Umzug planen — Drucker, Netzwerk, Telefon',
    sections:[
      {label:'Mitarbeiter',fields:[
        {key:'name',label:'Name',type:'text',required:true},
        {key:'von',label:'Aktueller Standort',type:'text',required:true},
        {key:'nach',label:'Neuer Standort',type:'text',required:true},
        {key:'datum',label:'Umzugsdatum',type:'date',required:true},
      ]},
      {label:'Betroffene IT',fields:[
        {key:'pc',label:'PC/Laptop umziehen',type:'checkbox',def:true},
        {key:'telefon',label:'Telefon umziehen',type:'checkbox',def:false},
        {key:'drucker',label:'Drucker-Zuordnung ändern',type:'checkbox',def:false},
        {key:'netzwerk',label:'Netzwerkdose einrichten',type:'checkbox',def:false},
        {key:'notizen',label:'Sonstiges',type:'textarea'},
      ]},
    ],
    submit:'🏢 Umzug-Ticket erstellen',
    onSubmit: async d=>{
      const title=`Standortwechsel: ${d.name} (${d.von} → ${d.nach})`;
      const body=`Mitarbeiter: ${d.name}\nVon: ${d.von}\nNach: ${d.nach}\nDatum: ${d.datum}\n\n• PC: ${d.pc?'✓':'✗'}\n• Telefon: ${d.telefon?'✓':'✗'}\n• Drucker: ${d.drucker?'✓':'✗'}\n• Netzwerk: ${d.netzwerk?'✓':'✗'}\n${d.notizen?'\nSonstiges: '+d.notizen:''}`;
      if(ticketSiteId&&ticketListId){
        const fields={[col(['Titel','Title'])||'Title']:title};
        const cs=col(['Status']); if(cs) fields[cs]='Offen';
        const cd=col(['Beschreibung','Description','Kommentar']); if(cd) fields[cd]=body;
        await gPost(`/sites/${ticketSiteId}/lists/${ticketListId}/items`,{fields});
        toast('✓ Umzug-Ticket erstellt','success');
        showPanel('tickets'); await streamTickets();
      } else { await navigator.clipboard.writeText(body).catch(()=>{}); toast('In Zwischenablage kopiert','info'); }
    }
  },
  offboarding:{
    title:'🚪 Offboarding',tag:'Mitarbeiter-Austritt',icon:'🚪',
    desc:'Mitarbeiter-Austritt verwalten, Zugänge sperren, Hardware zurückfordern',
    sections:[
      {label:'Mitarbeiterdaten',fields:[
        {key:'vorname',    label:'Vorname',           type:'text',  required:true},
        {key:'nachname',   label:'Nachname',          type:'text',  required:true},
        {key:'email',      label:'E-Mail-Adresse',    type:'email', required:true},
        {key:'abteilung',  label:'Abteilung',         type:'text'},
        {key:'vorgesetzter',label:'Vorgesetzter',     type:'text'},
        {key:'letzter_tag',label:'Letzter Arbeitstag',type:'date',  required:true},
      ]},
      {label:'IT-Maßnahmen',fields:[
        {key:'ad_sperren',    label:'AD-Konto sperren',         type:'checkbox',def:true},
        {key:'email_weiter',  label:'E-Mail weiterleiten an',   type:'email',  placeholder:'nachfolger@dihag.de'},
        {key:'vpn_sperren',   label:'VPN-Zugang sperren',       type:'checkbox',def:true},
        {key:'teams_sperren', label:'Teams-Lizenz entfernen',   type:'checkbox',def:true},
        {key:'sharepoint',    label:'SharePoint-Zugriff sperren',type:'checkbox',def:true},
      ]},
      {label:'Hardware',fields:[
        {key:'hw_rueckgabe',  label:'Hardware-Rückgabe erforderlich',type:'checkbox',def:true},
        {key:'hw_liste',      label:'Hardware-Beschreibung',type:'textarea',placeholder:'Laptop (S/N: …), Handy, Badge, Schlüssel…'},
      ]},
      {label:'Sonstiges',fields:[
        {key:'notizen',label:'Notizen / Anmerkungen',type:'textarea'},
      ]},
    ],
    submit:'🚪 Offboarding einleiten',
    onSubmit: async d=>{
      const title=`Offboarding: ${d.vorname} ${d.nachname}`;
      const body=`
Mitarbeiter: ${d.vorname} ${d.nachname}
E-Mail: ${d.email}
Abteilung: ${d.abteilung||'-'}
Vorgesetzter: ${d.vorgesetzter||'-'}
Letzter Arbeitstag: ${d.letzter_tag}

IT-Maßnahmen:
• AD-Konto sperren: ${d.ad_sperren?'✓':'✗'}
• E-Mail weiterleiten an: ${d.email_weiter||'-'}
• VPN sperren: ${d.vpn_sperren?'✓':'✗'}
• Teams-Lizenz: ${d.teams_sperren?'✓':'✗'}
• SharePoint: ${d.sharepoint?'✓':'✗'}

Hardware-Rückgabe: ${d.hw_rueckgabe?'Ja':'Nein'}
${d.hw_liste?'Details: '+d.hw_liste:''}

Notizen: ${d.notizen||'-'}`.trim();

      if(ticketSiteId&&ticketListId){
        const colTitle =col(['Titel','Title'])||'Title';
        const colStatus=col(['Status'])||'Status';
        const colPrio  =col(['Priorität','Priority']);
        const colDesc  =col(['Beschreibung','Description','Kommentar']);
        const fields={[colTitle]:title};
        if(colStatus) fields[colStatus]='Offen';
        if(colPrio)   fields[colPrio]='Hoch';
        if(colDesc)   fields[colDesc]=body;
        await gPost(`/sites/${ticketSiteId}/lists/${ticketListId}/items`,{fields});
        toast('✓ Offboarding-Ticket erstellt','success');
        showPanel('tickets'); await streamTickets();
      } else {
        await navigator.clipboard.writeText(body).catch(()=>{});
        toast('Offboarding-Details in Zwischenablage kopiert','info');
      }
    }
  },
  abwesenheit:{
    title:'📅 Abwesenheitsnotiz',tag:'Formular',icon:'📅',
    desc:'Automatische Abwesenheitsnotiz für Outlook konfigurieren und einrichten',
    sections:[
      {label:'Zeitraum',fields:[
        {key:'von', label:'Abwesend von', type:'date', required:true},
        {key:'bis', label:'Abwesend bis', type:'date', required:true},
      ]},
      {label:'Vertretung',fields:[
        {key:'vertreter',label:'Vertretung (Name)',type:'text',placeholder:'Max Mustermann'},
        {key:'vertr_mail',label:'Vertretung (E-Mail)',type:'email',placeholder:'m.mustermann@dihag.de'},
      ]},
      {label:'Nachricht',fields:[
        {key:'msg_type',label:'Welche Nachricht versenden?',type:'select',def:'beide',options:[
          {value:'beide',label:'Intern + Extern'},
          {value:'intern',label:'Nur Intern (Deutsch)'},
          {value:'extern',label:'Nur Extern (Englisch)'},
        ]},
        {key:'vorlage_intern',label:'Vorlage (Intern)',type:'select',def:'urlaub',options:[
          {value:'urlaub',label:'🏖️ Urlaub'},
          {value:'urlaub_keine_weiterleitung',label:'🏖️ Urlaub (keine Weiterleitung)'},
          {value:'krank',label:'🤒 Krankheit (mit Verständnis)'},
          {value:'krank2',label:'🤒 Krankheit (sachlich)'},
          {value:'abwesend',label:'📋 Allgemein abwesend'},
          {value:'kurz',label:'✉️ Kurz & knapp'},
          {value:'custom',label:'✏️ Benutzerdefiniert'},
        ]},
        {key:'intern',label:'Interne Nachricht (Deutsch)',type:'textarea',rows:4,
          def:'Vielen Dank für Ihre Nachricht. Ich bin derzeit im Urlaub und habe keinen Zugriff auf meine E-Mails.\nBei dringenden Angelegenheiten wenden Sie sich bitte an {{vertreter}} ({{vertr_mail}}).\nIch melde mich nach meiner Rückkehr am {{bis}} bei Ihnen.'},
        {key:'vorlage_extern',label:'Vorlage (Extern)',type:'select',def:'urlaub_en',options:[
          {value:'urlaub_en',label:'🏖️ Holiday (English)'},
          {value:'general_en',label:'📋 General (English)'},
          {value:'custom_en',label:'✏️ Custom'},
        ]},
        {key:'extern',label:'Externe Nachricht (Englisch)',type:'textarea',rows:4,
          def:'Thank you for your email. I am currently out of office from {{von}} to {{bis}}.\nFor urgent matters please contact {{vertreter}} ({{vertr_mail}}).\nI will reply to your message upon my return.'},
      ]},
    ],
    _vorlagen_intern:{
      urlaub:'Vielen Dank für Ihre Nachricht. Ich bin derzeit im Urlaub und habe keinen Zugriff auf meine E-Mails.\nBei dringenden Angelegenheiten wenden Sie sich bitte an {{vertreter}} ({{vertr_mail}}).\nIch melde mich nach meiner Rückkehr am {{bis}} bei Ihnen.',
      urlaub_keine_weiterleitung:'Ich bin bis auf Weiteres nicht im Büro. Ihre E-Mail wird nicht weitergeleitet.\nIch bin ab dem {{bis}} wieder für Sie da.',
      krank:'Aufgrund von Krankheit bin ich vorübergehend nicht erreichbar.\nBei dringenden Angelegenheiten wenden Sie sich bitte an {{vertreter}} ({{vertr_mail}}).\nVielen Dank für Ihr Verständnis.',
      krank2:'Ich bin derzeit erkrankt und nicht im Büro.\nIch bearbeite Ihre Nachricht, sobald ich zurück bin.\nBei dringenden Anliegen wenden Sie sich bitte an {{vertreter}} ({{vertr_mail}}).',
      abwesend:'Ich bin vorübergehend nicht verfügbar.\nBei dringenden Angelegenheiten wenden Sie sich bitte an {{vertreter}} ({{vertr_mail}}).\nIch melde mich schnellstmöglich nach meiner Rückkehr.',
      kurz:'Vielen Dank für Ihre E-Mail. Ich bin derzeit abwesend und ab dem {{bis}} wieder erreichbar.\nVertretung: {{vertreter}} ({{vertr_mail}}).',
      custom:'',
    },
    _vorlagen_extern:{
      urlaub_en:'Thank you for your email. I am currently out of office from {{von}} to {{bis}}.\nFor urgent matters please contact {{vertreter}} ({{vertr_mail}}).\nI will reply to your message upon my return.',
      general_en:'Thank you for your message. I am currently unavailable.\nFor urgent enquiries please contact {{vertreter}} ({{vertr_mail}}).\nI will respond as soon as possible after my return on {{bis}}.',
      custom_en:'',
    },
    submit:'📅 Nachricht erstellen & kopieren',
    onSubmit: async d=>{
      const fill=s=>s.replace(/\{\{von\}\}/g,d.von).replace(/\{\{bis\}\}/g,d.bis)
                     .replace(/\{\{vertreter\}\}/g,d.vertreter||'').replace(/\{\{vertr_mail\}\}/g,d.vertr_mail||'');
      let text = '';
      if (d.msg_type === 'intern' || d.msg_type === 'beide') {
        text += `INTERN:\n${fill(d.intern)}`;
      }
      if (d.msg_type === 'extern' || d.msg_type === 'beide') {
        if (text) text += '\n\n';
        text += `EXTERN:\n${fill(d.extern)}`;
      }
      await navigator.clipboard.writeText(text).catch(()=>{});
      const labels = {beide:'Intern + Extern',intern:'Nur Intern',extern:'Nur Extern'};
      toast(`✓ ${labels[d.msg_type]||'Nachricht'} in Zwischenablage kopiert — jetzt in Outlook einfügen`,'success');
      window.open('https://outlook.office.com/mail/options/mail/automaticReplies','_blank');
    }
  },
};

let currentAutoKey=null;

// Explizit freigegebene Automatismen (vom Admin aktiviert)
const AUTO_ACTIVE = new Set(['offboarding', 'abwesenheit']);

function buildAutoGrid(){
  const grid=$id('auto-grid'); grid.innerHTML='';
  // Active first, then grayed out
  const sorted = Object.entries(AUTO_FORMS).sort((a,b)=>{
    return (AUTO_ACTIVE.has(b[0])?1:0) - (AUTO_ACTIVE.has(a[0])?1:0);
  });
  sorted.forEach(([key,form])=>{
    const isLive = AUTO_ACTIVE.has(key);
    const card=document.createElement('div');
    card.className='auto-card' + (isLive ? ' live' : ' planned');
    const tagLabel = isLive ? '✓ Aktiv' : '⏸ Inaktiv';
    card.innerHTML=`<div class="auto-card-icon">${form.icon}</div>
      <div class="auto-card-title">${esc(form.title)}</div>
      <div class="auto-card-desc">${esc(form.desc)}</div>
      <div class="auto-card-tag">${tagLabel}</div>`;
    if(isLive) card.onclick=()=>openAutoForm(key);
    grid.appendChild(card);
  });
}

function openAutoForm(key){
  const form=AUTO_FORMS[key]; if(!form) return;
  currentAutoKey=key;
  $id('am-title').textContent=form.title;
  $id('am-submit').textContent=form.submit;
  const body=$id('am-body'); body.innerHTML='';
  form.sections.forEach(sec=>{
    const sh=document.createElement('div'); sh.className='form-section'; sh.textContent=sec.label;
    body.appendChild(sh);
    const row=document.createElement('div'); row.className='form-row'; body.appendChild(row);
    sec.fields.forEach(f=>{
      const wrap=document.createElement('div');
      wrap.className='form-field'+(f.type==='textarea'||f.type==='checkbox'?f.type==='checkbox'?'':' full':'');
      const def=f.def!==undefined?f.def:'';
      if(f.type==='checkbox'){
        wrap.innerHTML=`<div class="checkbox-row">
          <input type="checkbox" id="af_${f.key}" data-key="${f.key}" ${def?'checked':''}>
          <label for="af_${f.key}">${esc(f.label)}</label></div>`;
      } else if(f.type==='select'){
        wrap.innerHTML=`<label>${esc(f.label)}${f.required?'<span class="req">*</span>':''}</label>
          <select data-key="${f.key}" style="padding:8px 12px;border:1.5px solid var(--border2);border-radius:6px;font-family:inherit;font-size:13px;">
            ${(f.options||[]).map(o=>`<option value="${esc(o.value||o)}"${(o.value||o)===String(def)?' selected':''}>${esc(o.label||o)}</option>`).join('')}
          </select>`;
      } else if(f.type==='textarea'){
        wrap.style.gridColumn='1/-1';
        wrap.innerHTML=`<label>${esc(f.label)}${f.required?'<span class="req">*</span>':''}</label>
          <textarea data-key="${f.key}" rows="${f.rows||3}" placeholder="${f.placeholder||''}">${esc(String(def))}</textarea>`;
      } else {
        wrap.innerHTML=`<label>${esc(f.label)}${f.required?'<span class="req">*</span>':''}</label>
          <input type="${f.type||'text'}" data-key="${f.key}" value="${esc(String(def))}" placeholder="${f.placeholder||''}"/>`;
      }
      row.appendChild(wrap);
    });
  });
  $id('auto-modal').classList.add('open');

  // Vorlage change handlers for Abwesenheitsnotiz
  if (key === 'abwesenheit') {
    const vorlageIntern = body.querySelector('[data-key="vorlage_intern"]');
    const vorlageExtern = body.querySelector('[data-key="vorlage_extern"]');
    const internTA = body.querySelector('[data-key="intern"]');
    const externTA = body.querySelector('[data-key="extern"]');
    if (vorlageIntern && internTA) {
      vorlageIntern.addEventListener('change', () => {
        const tmpl = form._vorlagen_intern?.[vorlageIntern.value];
        if (tmpl !== undefined) internTA.value = tmpl;
        internTA.focus();
      });
    }
    if (vorlageExtern && externTA) {
      vorlageExtern.addEventListener('change', () => {
        const tmpl = form._vorlagen_extern?.[vorlageExtern.value];
        if (tmpl !== undefined) externTA.value = tmpl;
        externTA.focus();
      });
    }
  }
}

function closeAutoModal(){$id('auto-modal').classList.remove('open'); currentAutoKey=null;}

async function submitAutoForm(){
  if(!currentAutoKey) return;
  const form=AUTO_FORMS[currentAutoKey];
  const data={};
  $id('am-body').querySelectorAll('[data-key]').forEach(el=>{
    data[el.dataset.key]=el.type==='checkbox'?el.checked:el.value;
  });
  for(const sec of form.sections){
    for(const f of sec.fields){
      if(f.required&&!data[f.key]){toast('Pflichtfeld: '+f.label,'error');return;}
    }
  }
  try{ await form.onSubmit(data); closeAutoModal(); }
  catch(e){ toast('Fehler: '+e.message,'error'); }
}

// ════════════════════════════════════════════════════════════════
// PEOPLE PICKER
// ════════════════════════════════════════════════════════════════
let _userSearchTimer = null;
function searchUsers(inp, ddId) {
  clearTimeout(_userSearchTimer);
  const q = inp.value.trim();
  const dd = document.getElementById(ddId);
  if (!dd) return;
  if (q.length < 2) { dd.style.display='none'; return; }
  _userSearchTimer = setTimeout(async ()=>{
    try {
      // Try Graph /users first
      const res = await gGet(`/users?$filter=startswith(displayName,'${encodeURIComponent(q)}') or startswith(mail,'${encodeURIComponent(q)}')&$select=id,displayName,mail,userPrincipalName&$top=8`);
      const users = res.value||[];
      if(!users.length){ dd.innerHTML='<div style="padding:8px 12px;font-size:11px;color:var(--text-muted);">Keine User gefunden</div>'; dd.style.display='block'; return; }
      dd.innerHTML = users.map(u=>`<div
          style="padding:8px 12px;cursor:pointer;font-size:12px;border-bottom:1px solid var(--border);"
          onmouseover="this.style.background='var(--bg)'" onmouseout="this.style.background=''"
          data-name="${esc(u.displayName)}" data-mail="${esc(u.mail||u.userPrincipalName||'')}" data-aad="${esc(u.id)}"
          onclick="selectUser(this,'${ddId}')">
          <div style="font-weight:600;">${esc(u.displayName)}</div>
          <div style="font-size:10px;color:var(--text-muted);">${esc(u.mail||u.userPrincipalName||'')}</div>
        </div>`).join('');
      dd.style.display='block';
    } catch(e){
      // Fallback: SP people search (works with SP token)
      try {
        const spTok = await getSpToken();
        const r = await fetch(`https://dihag.sharepoint.com/sites/ticket/_api/SP.UI.ApplicationPages.ClientPeoplePickerWebServiceInterface.ClientPeoplePickerSearchUser`,{
          method:'POST',
          headers:{Authorization:'Bearer '+spTok,'Content-Type':'application/json;odata=verbose',Accept:'application/json;odata=verbose'},
          body:JSON.stringify({queryParams:{__metadata:{type:'SP.UI.ApplicationPages.ClientPeoplePickerQueryParameters'},AllowEmailAddresses:true,AllowMultipleEntities:false,MaximumEntitySuggestions:8,QueryString:q}})
        });
        if(r.ok){
          const j=await r.json(); const raw=j?.d?.ClientPeoplePickerSearchUser||'[]';
          const people=JSON.parse(raw); 
          if(people.length){
            dd.innerHTML=people.map(p=>`<div
                style="padding:8px 12px;cursor:pointer;font-size:12px;border-bottom:1px solid var(--border);"
                onmouseover="this.style.background='var(--bg)'" onmouseout="this.style.background=''"
                data-name="${esc(p.DisplayText||p.Key||q)}" data-mail="${esc(p.EntityData?.Email||p.Key||'')}" data-aad=""
                onclick="selectUser(this,'${ddId}')">
                <div style="font-weight:600;">${esc(p.DisplayText||p.Key||'?')}</div>
                <div style="font-size:10px;color:var(--text-muted);">${esc(p.EntityData?.Email||p.Description||'')}</div>
              </div>`).join('');
            dd.style.display='block'; return;
          }
        }
      } catch{}
      dd.innerHTML=`<div style="padding:8px 12px;font-size:11px;color:var(--red);">⚠ ${esc(e.message.substring(0,60))}</div>`;
      dd.style.display='block';
    }
  }, 300);
}

async function selectUser(el, ddId) {
  const dd = document.getElementById(ddId);
  const inp = dd?.previousElementSibling;
  const hiddenId = document.getElementById(ddId.replace('_dd','_id'));
  if (!inp) return;
  const name = el.dataset.name||'';
  const mail = el.dataset.mail||'';
  inp.value = name;
  if(dd) dd.style.display='none';
  // Resolve SP user ID via ensureuser
  if(hiddenId && mail){
    try {
      const spTok = await getSpToken();
      const r = await fetch(`https://dihag.sharepoint.com/sites/ticket/_api/web/ensureuser`,{
        method:'POST',
        headers:{Authorization:'Bearer '+spTok,'Content-Type':'application/json;odata=verbose',Accept:'application/json;odata=verbose'},
        body:JSON.stringify({logonName:`i:0#.f|membership|${mail}`})
      });
      const j = await r.json();
      const spId = j?.d?.Id;
      if(spId){ hiddenId.value=String(spId); dbg('SP User ID resolved',{name,spId}); }
    } catch(e){ dbg('ensureuser Fehler',e.message); }
  }
}

// Close people picker on outside click
document.addEventListener('click', e=>{
  if(!e.target.closest('[data-fk-person]')&&!e.target.closest('[id$="_dd"]')){
    document.querySelectorAll('[id$="_dd"]').forEach(dd=>dd.style.display='none');
  }
});

function dmsFileIconPerm(name){
  const ext=(name||'').split('.').pop().toLowerCase();
  const m={pdf:'📄',doc:'📝',docx:'📝',xls:'📊',xlsx:'📊',ppt:'🖥️',pptx:'🖥️',jpg:'🖼️',jpeg:'🖼️',png:'🖼️',gif:'🖼️',zip:'🗜️',txt:'📋',csv:'📊',msg:'✉️'};
  return m[ext]||'📎';
}
function dmsFormatBytesPerm(b){
  if(b<1024) return b+'B';
  if(b<1024*1024) return (b/1024).toFixed(0)+'KB';
  return (b/1024/1024).toFixed(1)+'MB';
}


// ════════════════════════════════════════════════════════════════
// BOOT
// ════════════════════════════════════════════════════════════════
(async()=>{
  // Wenn wir als PA-Consent-Popup geladen werden, App nicht initialisieren
  if (window._paConsentPopup) {
    document.body.style.cssText = 'margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:Inter,sans-serif;background:#f0f4ff';
    document.body.innerHTML = '<div style="text-align:center;padding:2rem;background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.12);max-width:340px">'
      + '<div style="font-size:2.5rem;margin-bottom:.75rem">✅</div>'
      + '<h2 style="margin:0 0 .5rem;font-size:1.2rem;color:#1a3a6b">Einwilligung erteilt</h2>'
      + '<p style="margin:0;color:#666;font-size:.9rem">Dieses Fenster schließt sich automatisch…</p>'
      + '</div>';
    setTimeout(() => window.close(), 1500);
    return;
  }
  try{
    const ok = await initAuth();
    if(ok){ bootDone(); }
    else {
      $id('boot-sub').textContent='Bitte anmelden';
      $id('boot-spinner').style.display='none';
      $id('boot-btn').style.display='block';
    }
  } catch(e){
    $id('boot-err').textContent=e.message;
    $id('boot-err').style.display='block';
    $id('boot-spinner').style.display='none';
    $id('boot-btn').style.display='block';
  }
})();
