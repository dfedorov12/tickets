/**
 * Zugriff auf Microsoft Graph und SharePoint-REST
 * ===============================================
 * Graph für Nutzer, Mail und Listen-Anlage; SharePoint-REST für alles, was Graph
 * bei Listen nicht kann: Berechtigungen, Kommentare, Anhänge, „Erstellt von",
 * effektive Rechte. Beide mit Wiederholung bei Drosselung (429/503).
 */
import { token, spScopes } from './auth.js';
import { KONFIG, siteUrl } from './config.js';

const GRAPH = 'https://graph.microsoft.com/v1.0';
const warte = ms => new Promise(r => setTimeout(r, ms));

export class ApiFehler extends Error {
  constructor(text, status, quelle) { super(text); this.status = status; this.quelle = quelle; }
}

async function _meldung(res) {
  const roh = await res.text().catch(() => '');
  try {
    const j = JSON.parse(roh);
    return j?.error?.message?.value || j?.['odata.error']?.message?.value || j?.error?.message || j?.error_description || roh;
  } catch { return roh.slice(0, 300); }
}

async function _abruf(url, init, quelle) {
  for (let versuch = 0; ; versuch++) {
    const res = await fetch(url, init);
    if ((res.status === 429 || res.status === 503) && versuch < 4) {
      const sek = Number(res.headers.get('Retry-After')) || 2 ** versuch;
      await warte(Math.min(sek, 30) * 1000);
      continue;
    }
    if (!res.ok) throw new ApiFehler(`${quelle} ${res.status}: ${await _meldung(res)}`, res.status, quelle);
    return res;
  }
}

// ── Graph ────────────────────────────────────────────────────────────────

export async function graph(pfad, { method = 'GET', body, headers = {} } = {}) {
  const tok = await token(KONFIG.graphScopes);
  const url = pfad.startsWith('https://') ? pfad : GRAPH + pfad;
  const init = { method, headers: { Authorization: 'Bearer ' + tok, ...headers } };
  if (body !== undefined) { init.body = JSON.stringify(body); init.headers['Content-Type'] = 'application/json'; }
  const res = await _abruf(url, init, 'Graph');
  if (res.status === 202 || res.status === 204) return null;
  const txt = await res.text();
  return txt ? JSON.parse(txt) : null;
}

/** Mail aus dem eigenen Postfach senden. */
export async function sendeMail({ an, betreff, html, antwortAn, wichtigkeit = 'normal', anhaenge = [] }) {
  const empf = (Array.isArray(an) ? an : [an]).filter(Boolean).map(a => ({ emailAddress: { address: a } }));
  if (!empf.length) throw new Error('Kein Empfänger');
  const message = {
    subject: betreff,
    body: { contentType: 'HTML', content: html },
    toRecipients: empf,
    importance: wichtigkeit,
  };
  if (antwortAn) message.replyTo = [{ emailAddress: { address: antwortAn } }];
  if (anhaenge.length) {
    message.attachments = anhaenge.map(a => ({ '@odata.type': '#microsoft.graph.fileAttachment', name: a.name, contentType: a.typ || 'application/octet-stream', contentBytes: a.base64 }));
  }
  await graph('/me/sendMail', { method: 'POST', body: { message, saveToSentItems: true } });
}

/** Personensuche (Name oder Mail beginnt mit …). */
export async function sucheNutzer(text) {
  const s = String(text || '').trim().replace(/'/g, "''");
  if (s.length < 2) return [];
  const filter = encodeURIComponent(`startswith(displayName,'${s}') or startswith(mail,'${s}') or startswith(userPrincipalName,'${s}')`);
  const r = await graph(`/users?$filter=${filter}&$select=displayName,mail,userPrincipalName,jobTitle&$top=8`);
  return (r?.value || []).filter(u => u.mail || u.userPrincipalName)
    .map(u => ({ name: u.displayName, mail: String(u.mail || u.userPrincipalName).toLowerCase(), titel: u.jobTitle || '' }));
}

// ── SharePoint-REST ──────────────────────────────────────────────────────

/** OData-Stringliteral für Pfade/Filter: 'O''Brien' (URL-kodiert). */
export const lit = s => `'${encodeURIComponent(String(s ?? '').replace(/'/g, "''"))}'`;

/** Nur echte GUIDs in Pfade setzen. */
export function guid(id) {
  const s = String(id || '').replace(/[{}]/g, '').toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s)) throw new Error('Ungültige Listen-ID: ' + id);
  return `guid'${s}'`;
}

/**
 * SharePoint-REST-Aufruf relativ zur Ticket-Site („_api/web/…").
 * verbose: odata=verbose (nötig für __metadata-Typen), sonst nometadata.
 * roh: Response zurückgeben (Downloads).
 */
export async function sp(pfad, { method = 'GET', body, headers = {}, verbose = false, roh = false } = {}) {
  const tok = await token(spScopes());
  const url = pfad.startsWith('https://') ? pfad : `${siteUrl()}/${pfad.replace(/^\//, '')}`;
  const art = verbose ? 'application/json;odata=verbose' : 'application/json;odata=nometadata';
  const init = { method: method === 'MERGE' || method === 'DELETE' ? 'POST' : method, headers: { Authorization: 'Bearer ' + tok, Accept: art, ...headers } };
  if (method === 'MERGE' || method === 'DELETE') { init.headers['X-HTTP-Method'] = method; init.headers['IF-MATCH'] = '*'; }
  if (body instanceof ArrayBuffer || (typeof Blob !== 'undefined' && body instanceof Blob)) {
    init.body = body;
    init.headers['Content-Type'] = 'application/octet-stream';
  } else if (body !== undefined) {
    init.body = JSON.stringify(body);
    init.headers['Content-Type'] = art;
  }
  const res = await _abruf(url, init, 'SharePoint');
  if (roh) return res;
  if (res.status === 204) return null;
  const txt = await res.text();
  if (!txt) return null;
  const j = JSON.parse(txt);
  return verbose ? j.d ?? j : j;
}

/** Alle Seiten einer SP-REST-Sammlung laden (nometadata). */
export async function spAlle(pfad, beiSeite) {
  const alle = [];
  let naechste = pfad;
  while (naechste) {
    const r = await sp(naechste);
    const seite = r?.value || [];
    alle.push(...seite);
    beiSeite?.(alle.length);
    naechste = r?.['odata.nextLink'] || null;
  }
  return alle;
}

/**
 * Formularwerte über ValidateUpdateListItem setzen – der Weg für Personenfelder
 * (per Mail-Claim) und für „Erstellt von". Wirft, wenn SharePoint einen Wert ablehnt.
 */
export async function validateUpdate(listId, itemId, werte, { neueVersion = true } = {}) {
  const formValues = Object.entries(werte).map(([FieldName, FieldValue]) => ({ FieldName, FieldValue: String(FieldValue ?? '') }));
  const r = await sp(`_api/web/lists(${guid(listId)})/items(${Number(itemId)})/ValidateUpdateListItem`, {
    method: 'POST',
    body: { formValues, bNewDocumentUpdate: !neueVersion },
  });
  const fehler = (r?.value || []).filter(v => v.HasException);
  if (fehler.length) throw new Error(fehler.map(f => `${f.FieldName}: ${f.ErrorMessage}`).join('; '));
  return r;
}

/** Personenfeld-Wert für ValidateUpdateListItem aus Mailadressen. */
export const personenWert = mails => JSON.stringify((mails || []).map(m => ({ Key: `i:0#.f|membership|${m}` })));
