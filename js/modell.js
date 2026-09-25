/**
 * Fachliche Logik des Ticketsystems – ohne DOM, ohne Netzwerk
 * ==========================================================
 * Ticketnummern, Routing (Absender-Domain → Queue), Betreff-Token, Normalisierung
 * der SharePoint-Daten, Berechtigungen (Soll-Zustand und Abgleich mit dem Ist),
 * Status/SLA und Kennzahlen. Dieselben Funktionen nutzen die App im Browser, der
 * Nachtlauf in GitHub Actions und die Tests – eine Regel steht genau einmal hier.
 *
 * Das Routing und das Betreff-Token spiegeln sich im Power-Automate-Flow
 * (scripts/flow-paket.mjs). Wer hier etwas ändert, prüft den Flow mit.
 */

import { STATUS, SLA_STUNDEN, PRIORITAETEN } from './config.js';

// ── Ticketnummern ───────────────────────────────────────────────────────────

/** Kennung einer Queue: Großbuchstabe, dann 1–9 Großbuchstaben/Ziffern (SCH, EWA, IT2). */
export const KENNUNG_MUSTER = /^[A-Z][A-Z0-9]{1,9}$/;

export function ticketNummer(kennung, id) {
  return `${kennung}-${id}`;
}

/** „SCH-12" → { kennung: 'SCH', id: 12 } – sonst null. */
export function parseTicketNummer(s) {
  const m = String(s ?? '').trim().toUpperCase().match(/^([A-Z][A-Z0-9]{1,9})-(\d{1,9})$/);
  return m ? { kennung: m[1], id: Number(m[2]) } : null;
}

/**
 * Die Ticketnummer aus einem Betreff lesen – so erkennt der Flow Antworten.
 *   „AW: [#SCH-12] Eingangsbestätigung: Drucker"     → SCH-12
 *   „AW: Neues Ticket: 1234 (Drucker)" (alte Mails)  → ALT-1234
 * Sonst ''.
 */
export function tokenAusBetreff(betreff, archivKennung = 'ALT') {
  const s = String(betreff ?? '');
  const m = s.match(/\[#([A-Za-z][A-Za-z0-9]{1,9}-\d{1,9})\]/);
  if (m) return m[1].toUpperCase();
  const alt = s.match(/Neues Ticket:\s*(\d{1,9})\b/i);
  return alt ? `${archivKennung}-${alt[1]}` : '';
}

/** Betreff mit genau einem Token vorn: „[#SCH-12] Drucker". */
export function betreffMitToken(nummer, betreff) {
  const rein = String(betreff ?? '').replace(/\[#[A-Za-z][A-Za-z0-9]{1,9}-\d{1,9}\]\s*/g, '').trim();
  return `[#${nummer}] ${rein}`.trim();
}

// ── Adressen & Routing ──────────────────────────────────────────────────────

/** Nur plausible Mailadressen (bewusst eng: der Wert landet in Texten und Claims). */
export function istMail(s) {
  return /^[a-z0-9._%+'-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(String(s ?? '').trim());
}

/** Domain einer Adresse in Kleinbuchstaben, '' wenn keine. */
export function domainAus(adresse) {
  const s = String(adresse ?? '').trim().toLowerCase().replace(/[<>\s]/g, '');
  const i = s.lastIndexOf('@');
  return i > 0 ? s.slice(i + 1) : '';
}

/** „schmie-guss.de, @shb-guss.de\nx.de" → ['schmie-guss.de','shb-guss.de','x.de'] */
export function domainsAusText(text) {
  const liste = String(text ?? '').toLowerCase().split(/[\s,;]+/)
    .map(d => d.replace(/^@/, '').trim())
    .filter(d => /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d));
  return [...new Set(liste)];
}

/** „a@x.de; B@y.de" → ['a@x.de','b@y.de'] (nur gültige, ohne Dubletten). */
export function mailsAusText(text) {
  const liste = String(text ?? '').split(/[\s,;]+/).map(s => s.trim().toLowerCase()).filter(istMail);
  return [...new Set(liste)];
}

/** Claim eines Kontos für SharePoint (Personenfelder, ensureUser). */
export function claimFuerMail(mail) {
  return `i:0#.f|membership|${String(mail ?? '').trim().toLowerCase()}`;
}

/** Mail-Adresse aus einem Claim oder Login-Namen. */
export function mailAusLogin(login) {
  const s = String(login ?? '');
  const teil = s.includes('|') ? s.split('|').pop() : s;
  return istMail(teil) ? teil.toLowerCase() : '';
}

/**
 * Welche Queue ist für diesen Absender zuständig? Exakte Domain-Treffer vor der
 * Standard-Queue; Archiv-Queues nehmen nie neue Tickets an.
 * Spiegelung im Flow: Aktion „Queue_nach_Domain" / „Standard_Queue".
 */
export function queueFuerAbsender(queues, adresse) {
  const d = domainAus(adresse);
  const kandidaten = (queues || []).filter(q => q.aktiv && q.modus !== 'Archiv');
  return (d && kandidaten.find(q => q.domains.includes(d))) || kandidaten.find(q => q.standard) || null;
}

// ── Konfiguration (Liste „TicketQueues") ────────────────────────────────────

const _txt = v => String(v ?? '').trim();
const _bool = v => v === true || v === 1 || v === '1' || /^(true|ja|yes)$/i.test(String(v ?? ''));
const _guid = v => {
  const s = _txt(v).replace(/[{}]/g, '').toLowerCase();
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s) ? s : '';
};

export const MODI = Object.freeze(['Ticket', 'Hinweis', 'Archiv']);

/** Zeile der Konfigurationsliste (Graph `fields` oder SP-REST-Item) → Queue-Objekt. */
export function queueAusFeldern(item) {
  const f = item?.fields || item || {};
  return {
    itemId: Number(item?.id ?? item?.Id ?? f.id ?? f.Id ?? 0) || 0,
    name: _txt(f.Title),
    kennung: _txt(f.Kennung).toUpperCase(),
    liste: _txt(f.ListenName),
    listId: _guid(f.ListenId),
    listUrl: _txt(f.ListenUrl),
    domains: domainsAusText(f.Domains),
    werk: _txt(f.Werk),
    bearbeiter: mailsAusText(f.Bearbeiter),
    gruppe: _txt(f.Gruppe),
    modus: MODI.includes(f.Modus) ? f.Modus : 'Ticket',
    hinweis: String(f.Hinweistext ?? ''),
    standard: _bool(f.Standard),
    // Neue Zeilen ohne Wert gelten als aktiv – ein leeres Kästchen soll keine Queue abschalten.
    aktiv: f.Aktiv === undefined || f.Aktiv === null ? true : _bool(f.Aktiv),
    benachrichtigen: _bool(f.Benachrichtigen),
    reihenfolge: Number(f.Reihenfolge) || 0,
  };
}

/** Queue-Objekt → Felder für Graph (so, wie der Flow sie liest: Domains mit ';'). */
export function queueZuFeldern(q) {
  return {
    Title: _txt(q.name),
    Kennung: _txt(q.kennung).toUpperCase(),
    ListenName: _txt(q.liste),
    ListenId: _guid(q.listId),
    ListenUrl: _txt(q.listUrl),
    Domains: domainsAusText(Array.isArray(q.domains) ? q.domains.join(';') : q.domains).join(';'),
    Werk: _txt(q.werk),
    Bearbeiter: mailsAusText(Array.isArray(q.bearbeiter) ? q.bearbeiter.join(';') : q.bearbeiter).join(';'),
    Gruppe: _txt(q.gruppe),
    Modus: MODI.includes(q.modus) ? q.modus : 'Ticket',
    Hinweistext: String(q.hinweis ?? ''),
    Standard: !!q.standard,
    Aktiv: q.aktiv !== false,
    Benachrichtigen: !!q.benachrichtigen,
    Reihenfolge: Number(q.reihenfolge) || 0,
  };
}

/** Vorschläge für Listen- und Gruppennamen einer neuen Queue. */
export function standardNamen(kennung) {
  const k = _txt(kennung).toUpperCase();
  return { liste: `Tickets-${k}`, gruppe: `Tickets ${k} – Bearbeiter` };
}

/**
 * Konfiguration prüfen. Liefert Meldungen { kennung, schwere: 'fehler'|'hinweis', text }.
 * Fehler blockieren das Speichern, Hinweise nicht.
 */
export function pruefeQueues(queues) {
  const out = [];
  const add = (q, schwere, text) => out.push({ kennung: q?.kennung || '?', schwere, text });
  const aktiv = (queues || []).filter(q => q.aktiv);
  const kennungen = new Map();
  const domains = new Map();
  for (const q of queues || []) {
    if (!KENNUNG_MUSTER.test(q.kennung)) add(q, 'fehler', 'Kennung: 2–10 Zeichen, Großbuchstaben/Ziffern, beginnt mit einem Buchstaben.');
    if (kennungen.has(q.kennung)) add(q, 'fehler', `Kennung ${q.kennung} ist doppelt vergeben.`);
    kennungen.set(q.kennung, q);
    if (!q.name) add(q, 'fehler', 'Name fehlt.');
    if (q.modus !== 'Hinweis' && !q.liste) add(q, 'fehler', 'Listenname fehlt.');
    if (q.modus === 'Hinweis' && !q.hinweis.trim()) add(q, 'fehler', 'Hinweis-Queue ohne Hinweistext.');
    if (q.modus === 'Ticket' && !q.gruppe) add(q, 'hinweis', 'Keine Bearbeiter-Gruppe – nur Admins sehen die Tickets.');
    if (q.modus === 'Ticket' && !q.listId) add(q, 'hinweis', 'Liste noch nicht eingerichtet (Verwaltung → Einrichtung).');
    if (q.modus === 'Archiv' && (q.domains.length || q.standard)) add(q, 'hinweis', 'Archiv nimmt keine neuen Tickets an – Domains/Standard werden ignoriert.');
    if (!q.aktiv) continue;
    for (const d of q.domains) {
      if (domains.has(d) && q.modus !== 'Archiv') add(q, 'fehler', `Domain ${d} ist schon ${domains.get(d)} zugeordnet.`);
      if (q.modus !== 'Archiv') domains.set(d, q.kennung);
    }
  }
  const standards = aktiv.filter(q => q.standard && q.modus !== 'Archiv');
  if (standards.length > 1) add(standards[1], 'fehler', 'Mehr als eine Standard-Queue aktiv.');
  if (aktiv.length && !standards.length) out.push({ kennung: '–', schwere: 'hinweis', text: 'Keine Standard-Queue: Mails unbekannter Domains werden abgewiesen (Fehler-Mail an Admin).' });
  if (aktiv.filter(q => q.modus === 'Archiv').length > 1) out.push({ kennung: '–', schwere: 'fehler', text: 'Mehr als ein Archiv aktiv.' });
  return out;
}

// ── Berechtigungen ──────────────────────────────────────────────────────────

/** SharePoint-Rechte (SP.PermissionKind), soweit hier gebraucht. */
export const RECHT = Object.freeze({
  ansehen: 1,            // ViewListItems
  hinzufuegen: 2,        // AddListItems
  bearbeiten: 3,         // EditListItems
  loeschen: 4,           // DeleteListItems
  versionenLoeschen: 8,  // DeleteVersions
  ueberschreiben: 9,     // CancelCheckout = „Listenverhalten außer Kraft setzen"
  listenVerwalten: 12,   // ManageLists
  rechteVerwalten: 26,   // ManagePermissions
});

/** Hat die Maske { High, Low } (Zahlen oder Strings aus SP-REST) dieses Recht? */
export function hatRecht(maske, recht) {
  if (!maske) return false;
  const bit = recht - 1;
  const wert = bit < 32 ? Number(maske.Low) || 0 : Number(maske.High) || 0;
  const pos = bit < 32 ? bit : bit - 32;
  return Math.floor(wert / 2 ** pos) % 2 === 1;
}

/**
 * Rolle einer Person in einer Liste aus ihren effektiven Rechten:
 * admin (Rechte verwalten) · bearbeiter (alle Elemente bearbeiten) · melder (lesen) · keine.
 */
export function rolleAusRechten(maske) {
  if (!maske) return 'keine';
  if (hatRecht(maske, RECHT.rechteVerwalten)) return 'admin';
  if (hatRecht(maske, RECHT.bearbeiten) && hatRecht(maske, RECHT.ueberschreiben)) return 'bearbeiter';
  if (hatRecht(maske, RECHT.ansehen)) return 'melder';
  return 'keine';
}

/**
 * Maske der Stufe „Ticket-Bearbeitung" aus der Maske von „Mitwirken":
 * + Listenverhalten außer Kraft setzen, − Elemente löschen, − Versionen löschen.
 */
export function bearbeitungsMaske(mitwirken) {
  const bit = n => 2 ** (n - 1);
  let low = Number(mitwirken?.Low) || 0;
  if (!hatRecht({ Low: low, High: 0 }, RECHT.ueberschreiben)) low += bit(RECHT.ueberschreiben);
  if (hatRecht({ Low: low, High: 0 }, RECHT.loeschen)) low -= bit(RECHT.loeschen);
  if (hatRecht({ Low: low, High: 0 }, RECHT.versionenLoeschen)) low -= bit(RECHT.versionenLoeschen);
  return { High: String(Number(mitwirken?.High) || 0), Low: String(low) };
}

/** Rollen im Soll: eingebaute über RoleTypeKind (sprachunabhängig), eigene über den Namen. */
export const ROLLE = Object.freeze({
  voll: Object.freeze({ typ: 5, anzeige: 'Vollzugriff' }),
  lesen: Object.freeze({ typ: 2, anzeige: 'Lesen' }),
});
export const rolleBearbeitung = name => ({ name, anzeige: name });

/**
 * Soll-Berechtigungen einer Liste.
 * @param {object} q          Queue
 * @param {object} ctx        { ownerGruppe, dienstkonto, melderClaim, melderAnzeige, stufeBearbeitung, queues, melderSehen }
 * @param {'tickets'|'notizen'} art
 * @returns {Array<{schluessel:string, art:'gruppe'|'login', wert:string, anzeige:string, rolle:object, grund:string}>}
 */
export function sollRechte(q, ctx, art = 'tickets') {
  if (!q || q.modus === 'Hinweis') return [];
  const soll = [];
  const add = (artP, wert, anzeige, rolle, grund) => {
    if (!wert) return;
    const schluessel = `${artP}:${String(wert).toLowerCase()}|${rolle.typ ?? String(rolle.name).toLowerCase()}`;
    if (!soll.some(s => s.schluessel === schluessel)) soll.push({ schluessel, art: artP, wert, anzeige, rolle, grund });
  };
  const bearbeitung = rolleBearbeitung(ctx.stufeBearbeitung);
  add('gruppe', ctx.ownerGruppe, ctx.ownerGruppe, ROLLE.voll, 'Websitebesitzer = Admins');
  if (ctx.dienstkonto) add('login', claimFuerMail(ctx.dienstkonto), ctx.dienstkonto, ROLLE.voll, 'Konto des Flows (legt Tickets an, setzt „Erstellt von")');

  if (q.modus === 'Archiv') {
    const gruppen = q.gruppe === '*'
      ? (ctx.queues || []).filter(x => x.modus === 'Ticket' && x.aktiv && x.gruppe).map(x => x.gruppe)
      : (q.gruppe ? [q.gruppe] : []);
    for (const g of gruppen) add('gruppe', g, g, bearbeitung, 'Bearbeiter dürfen Alt-Tickets weiter bearbeiten');
    return soll;
  }
  if (q.gruppe) add('gruppe', q.gruppe, q.gruppe, bearbeitung, `Bearbeiter der Queue ${q.kennung}`);
  if (art === 'tickets' && ctx.melderSehen !== false && ctx.melderClaim) {
    add('login', ctx.melderClaim, ctx.melderAnzeige || ctx.melderClaim, ROLLE.lesen, 'Melder sehen nur ihre eigenen Tickets');
  }
  return soll;
}

const _lc = s => String(s ?? '').toLowerCase();

/** Rolle aus SharePoint, die für den Abgleich zählt (nicht „Beschränkter Zugriff"/versteckt). */
function _zaehlt(r) {
  return !r.hidden && r.typ !== 1;
}

function _rolleGleich(soll, ist) {
  return soll.typ != null ? ist.typ === soll.typ : _lc(ist.name) === _lc(soll.name);
}

function _prinzipalGleich(soll, ist) {
  if (soll.art === 'gruppe') return ist.typ === 8 && (_lc(ist.titel) === _lc(soll.wert) || _lc(ist.login) === _lc(soll.wert));
  return _lc(ist.login) === _lc(soll.wert);
}

/**
 * Soll gegen Ist.
 * @param soll  Ergebnis von sollRechte()
 * @param ist   [{ principalId, login, titel, typ, rollen: [{ id, name, typ, hidden }] }]
 * @returns { fehlt: soll[], zuviel: [{ principalId, login, titel, rolle }], ok: soll[] }
 */
export function rechteAbgleich(soll, ist) {
  const fehlt = [], ok = [], zuviel = [];
  for (const s of soll) {
    const treffer = (ist || []).some(p => _prinzipalGleich(s, p) && (p.rollen || []).some(r => _zaehlt(r) && _rolleGleich(s.rolle, r)));
    (treffer ? ok : fehlt).push(s);
  }
  for (const p of ist || []) {
    for (const r of p.rollen || []) {
      if (!_zaehlt(r)) continue;
      const gewollt = soll.some(s => _prinzipalGleich(s, p) && _rolleGleich(s.rolle, r));
      if (!gewollt) zuviel.push({ principalId: p.principalId, login: p.login, titel: p.titel, typ: p.typ, rolle: r });
    }
  }
  return { fehlt, zuviel, ok };
}

/** Listeneinstellungen: Abweichungen [{ feld, ist, soll }]. */
export function einstellungsAbgleich(ist, soll) {
  return Object.entries(soll)
    .filter(([k, v]) => ist?.[k] !== v)
    .map(([feld, v]) => ({ feld, ist: ist?.[feld], soll: v }));
}

/** SP-REST-Rollenzuweisungen (nometadata, $expand=Member,RoleDefinitionBindings) → Ist-Format. */
export function istAusRollenzuweisungen(value) {
  return (value || []).map(ra => ({
    principalId: ra.PrincipalId ?? ra.Member?.Id,
    login: ra.Member?.LoginName || '',
    titel: ra.Member?.Title || '',
    typ: ra.Member?.PrincipalType,
    rollen: (ra.RoleDefinitionBindings?.results || ra.RoleDefinitionBindings || []).map(b => ({
      id: b.Id, name: b.Name, typ: b.RoleTypeKind, hidden: !!b.Hidden,
    })),
  }));
}

// ── Tickets ─────────────────────────────────────────────────────────────────

export const STATUS_WERTE = STATUS.map(s => s.wert);
export const statusInfo = wert => STATUS.find(s => s.wert === wert) || { wert, offen: true, farbe: 'grau' };
export const istOffen = wert => statusInfo(wert).offen;
export const istWartend = wert => !!statusInfo(wert).wartet;

/** Priorität vereinheitlichen: high/(1) Hoch/mittel/… → Kritisch|Hoch|Normal|Niedrig ('' bleibt ''). */
export function normPrio(v) {
  const s = _lc(v).trim();
  if (!s) return '';
  if (/krit|crit/.test(s)) return 'Kritisch';
  if (/hoch|high/.test(s)) return 'Hoch';
  if (/niedrig|low/.test(s)) return 'Niedrig';
  return 'Normal';
}

/** Wichtigkeit einer Mail (low/normal/high) → Priorität. */
export function prioAusWichtigkeit(w) {
  return { high: 'Hoch', low: 'Niedrig' }[_lc(w)] || 'Normal';
}

/**
 * Den passenden Auswahlwert einer Choice-Spalte finden (z. B. „Hoch" → „(1) Hoch",
 * wenn die Liste so benannt ist). Kein Treffer → Wert unverändert.
 */
export function passendeAuswahl(auswahl, wert, norm = x => _lc(x).trim()) {
  const ziel = norm(wert);
  return (auswahl || []).find(c => norm(c) === ziel) ?? wert;
}

function _person(v) {
  if (!v || typeof v !== 'object') return null;
  const mail = _lc(v.EMail || v.Email || v.email || mailAusLogin(v.Name || v.LoginName));
  const name = v.Title || v.LookupValue || v.displayName || mail;
  if (!name && !mail) return null;
  return { id: v.Id ?? v.LookupId ?? null, name: String(name || ''), mail };
}

function _personen(v) {
  const arr = Array.isArray(v) ? v : Array.isArray(v?.results) ? v.results : v ? [v] : [];
  return arr.map(_person).filter(Boolean);
}

/**
 * SP-REST-Element (nometadata, Personen expandiert) → Ticket.
 * @param it    Element
 * @param q     Queue
 * @param felder  { kategorie?: 'InternerName', art?: '…' } – optionale Spalten dieser Liste
 */
export function ticketAusSp(it, q, felder = {}) {
  const melder = _person(it.Issueloggedby);
  const autor = _person(it.Author);
  const melderMail = _lc(it.E_x002d_Mail_x002d_Adresse || melder?.mail || '').trim();
  return {
    nummer: ticketNummer(q.kennung, it.Id),
    kennung: q.kennung,
    id: Number(it.Id),
    titel: String(it.Title ?? ''),
    status: String(it.Status ?? ''),
    prio: normPrio(it.Priority),
    prioRoh: String(it.Priority ?? ''),
    werk: String(it.Werk ?? ''),
    kategorie: felder.kategorie ? String(it[felder.kategorie] ?? '') : '',
    art: felder.art ? String(it[felder.art] ?? '') : '',
    bearbeiter: _personen(it.Assignedto0),
    melder: melder || (melderMail ? { id: null, name: melderMail, mail: melderMail } : null),
    melderMail,
    autor,
    gemeldetAm: it.DateReported || it.Created || '',
    erstellt: it.Created || '',
    geaendert: it.Modified || '',
    anhaenge: !!it.Attachments,
  };
}

/** Ist das Ticket „meins" als Melder? (Melder-Mail, Personenfeld oder Ersteller) */
export function istMeineAnfrage(t, mail) {
  const m = _lc(mail);
  if (!m) return false;
  return t.melderMail === m || _lc(t.melder?.mail) === m || _lc(t.autor?.mail) === m;
}

export const istMirZugewiesen = (t, mail) => t.bearbeiter.some(b => _lc(b.mail) === _lc(mail));

/** Fälligkeit nach Priorität (Kalenderstunden ab Meldung). */
export function faelligAm(t, sla = SLA_STUNDEN) {
  const basis = Date.parse(t.gemeldetAm || t.erstellt);
  if (isNaN(basis)) return null;
  const std = sla[t.prio] ?? sla.Normal;
  return new Date(basis + std * 3600e3);
}

export function istUeberfaellig(t, jetzt = new Date(), sla = SLA_STUNDEN) {
  if (!istOffen(t.status) || istWartend(t.status)) return false;
  const f = faelligAm(t, sla);
  return !!f && f < jetzt;
}

/**
 * Tickets filtern.
 * f: { suche, status: 'offen'|'alle'|'geschlossen'|<Status>, kennung, prio, zuweisung: 'alle'|'ich'|'keiner', ueberfaellig }
 */
export function filtereTickets(tickets, f = {}, ich = '', jetzt = new Date()) {
  const such = _lc(f.suche).trim();
  return (tickets || []).filter(t => {
    if (f.kennung && t.kennung !== f.kennung) return false;
    if (f.status === 'offen' && !istOffen(t.status)) return false;
    if (f.status === 'geschlossen' && istOffen(t.status)) return false;
    if (f.status && !['offen', 'alle', 'geschlossen'].includes(f.status) && t.status !== f.status) return false;
    if (f.prio && t.prio !== f.prio) return false;
    if (f.zuweisung === 'ich' && !istMirZugewiesen(t, ich)) return false;
    if (f.zuweisung === 'keiner' && t.bearbeiter.length) return false;
    if (f.ueberfaellig && !istUeberfaellig(t, jetzt)) return false;
    if (such) {
      const heu = [t.nummer, t.titel, t.melder?.name, t.melderMail, t.kategorie, t.werk, ...t.bearbeiter.map(b => b.name)]
        .map(_lc).join(' ');
      if (!such.split(/\s+/).every(w => heu.includes(w))) return false;
    }
    return true;
  });
}

const _prioRang = p => { const i = PRIORITAETEN.indexOf(p); return i < 0 ? PRIORITAETEN.length : i; };

/** Sortierung: 'neu' (Meldung absteigend), 'prio' (Priorität, dann älteste zuerst), 'geaendert'. */
export function sortiereTickets(tickets, art = 'neu') {
  const zeit = v => Date.parse(v) || 0;
  const liste = [...(tickets || [])];
  if (art === 'prio') return liste.sort((a, b) => _prioRang(a.prio) - _prioRang(b.prio) || zeit(a.gemeldetAm) - zeit(b.gemeldetAm));
  if (art === 'geaendert') return liste.sort((a, b) => zeit(b.geaendert) - zeit(a.geaendert));
  return liste.sort((a, b) => zeit(b.gemeldetAm) - zeit(a.gemeldetAm) || b.id - a.id);
}

// ── Kennzahlen ──────────────────────────────────────────────────────────────

/** Montag 00:00 der Woche von d (lokale Zeit). */
export function wochenStart(d) {
  const x = new Date(d);
  x.setHours(0, 0, 0, 0);
  x.setDate(x.getDate() - ((x.getDay() + 6) % 7));
  return x;
}

/** ISO-Kalenderwoche. */
export function kalenderwoche(d) {
  const x = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  const tag = x.getUTCDay() || 7;
  x.setUTCDate(x.getUTCDate() + 4 - tag);
  const jahresStart = new Date(Date.UTC(x.getUTCFullYear(), 0, 1));
  return Math.ceil(((x - jahresStart) / 86400000 + 1) / 7);
}

export function kennzahlen(tickets, jetzt = new Date(), sla = SLA_STUNDEN) {
  const offen = tickets.filter(t => istOffen(t.status));
  const vor30 = jetzt - 30 * 86400e3;
  // „Erledigt am" gibt es nicht als Spalte – für geschlossene Tickets ist die letzte Änderung die beste Näherung.
  const erledigt30 = tickets.filter(t => !istOffen(t.status) && Date.parse(t.geaendert) >= vor30);
  const loesung = erledigt30
    .map(t => (Date.parse(t.geaendert) - Date.parse(t.gemeldetAm || t.erstellt)) / 3600e3)
    .filter(h => isFinite(h) && h >= 0)
    .sort((a, b) => a - b);
  const median = loesung.length ? loesung[Math.floor(loesung.length / 2)] : null;
  return {
    gesamt: tickets.length,
    offen: offen.length,
    neu: tickets.filter(t => t.status === 'Neu').length,
    unzugewiesen: offen.filter(t => !t.bearbeiter.length).length,
    wartend: offen.filter(t => istWartend(t.status)).length,
    ueberfaellig: offen.filter(t => istUeberfaellig(t, jetzt, sla)).length,
    erledigt30: erledigt30.length,
    eingang30: tickets.filter(t => Date.parse(t.gemeldetAm || t.erstellt) >= vor30).length,
    medianLoesungStunden: median,
  };
}

/** Eingang/Erledigt je Kalenderwoche der letzten n Wochen (älteste zuerst). */
export function verlaufNachWoche(tickets, wochen = 12, jetzt = new Date()) {
  const start0 = wochenStart(jetzt);
  const zeilen = [];
  for (let i = wochen - 1; i >= 0; i--) {
    const von = new Date(start0); von.setDate(von.getDate() - 7 * i);
    const bis = new Date(von); bis.setDate(bis.getDate() + 7);
    const inWoche = v => { const t = Date.parse(v); return t >= von && t < bis; };
    zeilen.push({
      kw: kalenderwoche(von),
      von,
      eingang: tickets.filter(t => inWoche(t.gemeldetAm || t.erstellt)).length,
      erledigt: tickets.filter(t => !istOffen(t.status) && inWoche(t.geaendert)).length,
    });
  }
  return zeilen;
}

/** Zählen nach Schlüssel → [{ wert, anzahl }] absteigend. */
export function zaehleNach(tickets, fn) {
  const m = new Map();
  for (const t of tickets) {
    const k = fn(t) || '–';
    m.set(k, (m.get(k) || 0) + 1);
  }
  return [...m].map(([wert, anzahl]) => ({ wert, anzahl })).sort((a, b) => b.anzahl - a.anzahl || String(a.wert).localeCompare(String(b.wert)));
}

// ── Navigation ──────────────────────────────────────────────────────────────

/** „#/t/SCH-12" → { seite: 'ticket', nummer: 'SCH-12' } usw. Unbekanntes → Startseite. */
export function parseRoute(hash) {
  const teile = String(hash ?? '').replace(/^#\/?/, '').split('/').filter(Boolean).map(s => decodeURIComponent(s));
  const [a, b] = teile;
  if (a === 't' && parseTicketNummer(b)) return { seite: 'ticket', nummer: parseTicketNummer(b) && b.toUpperCase() };
  if (a === 'verwaltung') return { seite: 'verwaltung', bereich: ['queues', 'rechte', 'migration', 'eingang'].includes(b) ? b : 'queues' };
  if (['posteingang', 'meine', 'neu', 'berichte'].includes(a)) return { seite: a };
  return { seite: '' };
}

export const ticketLink = (appUrl, nummer) => `${appUrl}#/t/${nummer}`;
