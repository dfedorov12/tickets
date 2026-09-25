#!/usr/bin/env node
/**
 * Nachtlauf des Ticketsystems (GitHub Actions)
 * ============================================
 *   1. Rechteprüfung: jede Ticket-, Notiz- und Archivliste gegen das Soll (dieselbe
 *      Logik wie „Verwaltung → Rechte" in der App). Abweichungen → Mail an den Admin.
 *      Mit REPARIEREN=true werden sie behoben (wie „Abgleichen" in der App).
 *   2. Tagesübersicht (werktags): je Queue offene, neue, unzugewiesene und überfällige
 *      Tickets an die Bearbeiter-Gruppe.
 *
 * Anmeldung: App-Registrierung mit ZERTIFIKAT (SharePoint lässt Rechte-/Listen-
 * Aufrufe app-only nur mit Zertifikat zu, nicht mit Client-Secret).
 *
 * Umgebung:
 *   AZURE_TENANT_ID, AZURE_CLIENT_ID   App-Registrierung
 *   AZURE_ZERTIFIKAT                   PEM mit privatem Schlüssel UND Zertifikat
 *   MAIL_SENDER                        Absender-Postfach (Application Access Policy!)
 *   DRY_RUN=true                       nichts senden, nichts ändern (nur Log)
 *   REPARIEREN=true                    Rechte-Abweichungen beheben
 *   AUFGABEN=rechte,uebersicht         Auswahl (Standard: beides; Übersicht nur Mo–Fr)
 *
 * Das Repo ist öffentlich – die Action-Logs auch. Deshalb landen im Log nur Zähler und
 * Listennamen, nie Namen, Adressen oder Ticketinhalte. Die Details stehen in den Mails.
 */
import crypto from 'crypto';
import { KONFIG, SOLL_LISTENEINSTELLUNGEN, SOLL_NOTIZEINSTELLUNGEN, NOTIZ_ENDUNG } from '../js/config.js';
import { tokenQuelle, sp, spAlle, lit } from '../js/api.js';
import { queueAusFeldern, sollRechte, sollKonfigRechte, rechteAbgleich, einstellungsAbgleich, kennzahlen, istOffen, istUeberfaellig, sortiereTickets } from '../js/modell.js';
import { zustand, ladeTickets } from '../js/daten.js';
import { sollKontext, listeLesen, rechteLesen, rechteAnwenden, einstellungenAnwenden, gruppeLesen } from '../js/einrichtung.js';
import { mailTagesuebersicht, mailRechtebericht } from '../js/mails.js';

const env = process.env;
const DRY = /^(1|true|ja)$/i.test(env.DRY_RUN || '');
const REPARIEREN = /^(1|true|ja)$/i.test(env.REPARIEREN || '');
const AUFGABEN = new Set((env.AUFGABEN || 'rechte,uebersicht').split(',').map(s => s.trim()));
const log = (...a) => console.log(...a);

// ── Anmeldung per Zertifikat ────────────────────────────────────────────────

const b64url = b => Buffer.from(b).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');

export function zertifikatLesen(pem) {
  const text = String(pem || '').replace(/\\n/g, '\n');
  const schluessel = text.match(/-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA )?PRIVATE KEY-----/)?.[0];
  const zert = text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)?.[0];
  if (!schluessel || !zert) throw new Error('AZURE_ZERTIFIKAT braucht privaten Schlüssel UND Zertifikat im PEM-Format');
  const der = Buffer.from(zert.replace(/-----[^-]+-----|\s/g, ''), 'base64');
  return { schluessel: crypto.createPrivateKey(schluessel), x5t: b64url(crypto.createHash('sha1').update(der).digest()) };
}

export function clientAssertion({ tenantId, clientId, schluessel, x5t }, jetzt = Math.floor(Date.now() / 1000)) {
  const kopf = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', x5t }));
  const inhalt = b64url(JSON.stringify({
    aud: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    iss: clientId, sub: clientId, jti: crypto.randomUUID(), nbf: jetzt - 60, exp: jetzt + 600,
  }));
  const signatur = crypto.sign('RSA-SHA256', Buffer.from(`${kopf}.${inhalt}`), schluessel);
  return `${kopf}.${inhalt}.${b64url(signatur)}`;
}

const _tokens = new Map();
async function appToken(scopes) {
  const ressource = scopes.some(s => s.startsWith(KONFIG.spHost)) ? KONFIG.spHost : 'https://graph.microsoft.com';
  const gecacht = _tokens.get(ressource);
  if (gecacht && gecacht.bis > Date.now() + 60e3) return gecacht.token;
  const z = zertifikatLesen(env.AZURE_ZERTIFIKAT);
  const res = await fetch(`https://login.microsoftonline.com/${env.AZURE_TENANT_ID}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.AZURE_CLIENT_ID,
      scope: ressource + '/.default',
      grant_type: 'client_credentials',
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: clientAssertion({ tenantId: env.AZURE_TENANT_ID, clientId: env.AZURE_CLIENT_ID, ...z }),
    }),
  });
  const j = await res.json();
  if (!res.ok) throw new Error(`Token (${res.status}): ${j.error}: ${String(j.error_description || '').split('\n')[0]}`);
  _tokens.set(ressource, { token: j.access_token, bis: Date.now() + j.expires_in * 1000 });
  return j.access_token;
}

async function sendeAppMail(an, { betreff, html }) {
  const empfaenger = [...new Set(an.filter(Boolean))];
  if (!empfaenger.length) return;
  if (DRY) { log(`  (Probelauf) Mail an ${empfaenger.length} Empfänger: ${betreff.replace(/[\w.+-]+@[\w.-]+/g, '…')}`); return; }
  const tok = await appToken(['https://graph.microsoft.com/.default']);
  const res = await fetch(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(env.MAIL_SENDER)}/sendMail`, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: { subject: betreff, body: { contentType: 'HTML', content: html }, toRecipients: empfaenger.map(a => ({ emailAddress: { address: a } })) }, saveToSentItems: false }),
  });
  if (!res.ok) throw new Error(`sendMail ${res.status}: ${(await res.text()).slice(0, 200)}`);
}

// ── Aufgaben ────────────────────────────────────────────────────────────────

async function kontextLaden() {
  const web = await sp('_api/web?$select=Title,AssociatedOwnerGroup/Title&$expand=AssociatedOwnerGroup');
  const zeilen = await spAlle(`_api/web/lists/getbytitle(${lit(KONFIG.konfigListe)})/items?$top=500`);
  zustand.site = { titel: web.Title, ownerGruppe: web.AssociatedOwnerGroup?.Title || '', istAdmin: true };
  zustand.queues = zeilen.map(queueAusFeldern).filter(q => q.aktiv);
  for (const q of zustand.queues.filter(x => x.listId && x.modus !== 'Hinweis')) {
    zustand.listen.set(q.kennung, { queue: q, rolle: 'admin', felder: null, auswahl: {}, fehlend: [] });
  }
  log(`Konfiguration: ${zustand.queues.length} aktive Queues`);
}

async function rechtepruefung() {
  log('\n▶ Rechteprüfung' + (REPARIEREN ? ' mit Reparatur' : ''));
  const ctx = sollKontext();
  const befunde = [];
  const pruefe = async (titel, soll, sollEinst) => {
    const l = await listeLesen(titel);
    if (!l) { log(`  ${titel}: fehlt`); befunde.push({ liste: titel, text: 'Liste fehlt – in der App einrichten' }); return; }
    const e = einstellungsAbgleich(l, sollEinst);
    const r = rechteAbgleich(soll, await rechteLesen(l.Id));
    const texte = [
      !l.HasUniqueRoleAssignments && 'erbt Berechtigungen von der Site',
      ...e.map(x => `${x.feld}: ${x.ist} statt ${x.soll}`),
      ...r.fehlt.map(s => `fehlt: ${s.anzeige} → ${s.rolle.anzeige}`),
      ...r.zuviel.map(z => `zu viel: ${z.titel || z.login} → ${z.rolle.name}`),
    ].filter(Boolean);
    log(`  ${titel}: ${texte.length ? texte.length + ' Abweichung(en)' : 'ok'}`);
    if (!texte.length) return;
    texte.forEach(text => befunde.push({ liste: titel, text }));
    if (REPARIEREN && !DRY) {
      if (e.length) await einstellungenAnwenden(l.Id, sollEinst);
      await rechteAnwenden(l.Id, soll, () => {});
      log(`    → behoben`);
    }
  };
  await pruefe(KONFIG.konfigListe, sollKonfigRechte(ctx), { NoCrawl: true, EnableVersioning: true });
  for (const q of zustand.queues.filter(x => x.modus !== 'Hinweis' && x.liste)) {
    await pruefe(q.liste, sollRechte(q, ctx, 'tickets'), SOLL_LISTENEINSTELLUNGEN);
    if (q.modus === 'Ticket') await pruefe(q.liste + NOTIZ_ENDUNG, sollRechte(q, ctx, 'notizen'), SOLL_NOTIZEINSTELLUNGEN);
  }
  log(`  gesamt: ${befunde.length} Abweichung(en)`);
  if (befunde.length) await sendeAppMail([KONFIG.adminPostfach], mailRechtebericht({ befunde, repariert: REPARIEREN && !DRY }));
  return befunde.length;
}

async function tagesuebersicht(jetzt = new Date()) {
  log('\n▶ Tagesübersicht');
  // Wochenende nur, wenn die Übersicht ausdrücklich angefordert wurde (manueller Lauf).
  if ([0, 6].includes(jetzt.getDay()) && !env.AUFGABEN) { log('  Wochenende – keine Übersicht'); return; }
  for (const q of zustand.queues.filter(x => x.modus === 'Ticket' && x.listId)) {
    const tickets = await ladeTickets(q.kennung);
    const offen = tickets.filter(t => istOffen(t.status));
    const kz = kennzahlen(tickets, jetzt);
    const wichtig = sortiereTickets(offen.filter(t => istUeberfaellig(t, jetzt) || !t.bearbeiter.length || t.status === 'Neu'), 'prio');
    log(`  ${q.kennung}: ${kz.offen} offen, ${kz.ueberfaellig} überfällig, ${kz.unzugewiesen} ohne Bearbeiter`);
    if (!wichtig.length) continue;
    const gruppe = await gruppeLesen(q.gruppe);
    const an = (gruppe?.mitglieder.map(m => m.mail) || []).concat(gruppe?.mitglieder.length ? [] : q.bearbeiter);
    await sendeAppMail(an, mailTagesuebersicht({ queue: q, kennzahlen: kz, tickets: wichtig }));
  }
}

export async function main() {
  for (const n of ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_ZERTIFIKAT', 'MAIL_SENDER']) {
    if (!env[n]) { log(`${n} fehlt – Einrichtung siehe docs/EINRICHTUNG.md (Nachtlauf). Lauf übersprungen.`); return 0; }
  }
  tokenQuelle(appToken);
  log(`Nachtlauf ${new Date().toISOString()}${DRY ? ' (Probelauf)' : ''}`);
  await kontextLaden();
  if (AUFGABEN.has('rechte')) await rechtepruefung();
  if (AUFGABEN.has('uebersicht')) await tagesuebersicht();
  log('\n✓ fertig');
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().then(code => process.exit(code)).catch(e => {
    // Meldung ohne personenbezogene Daten ins öffentliche Log
    console.error('✗ ' + String(e.message || e).replace(/[\w.+-]+@[\w.-]+/g, '…'));
    process.exit(1);
  });
}
