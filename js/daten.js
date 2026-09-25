/**
 * Datenschicht: Queues, Rollen, Tickets, Kommentare, Notizen, Anhänge
 * ==================================================================
 * Wer was sieht, entscheidet SharePoint – nicht die App. Die App fragt je Liste die
 * effektiven Rechte der angemeldeten Person ab und leitet daraus die Rolle ab
 * (admin/bearbeiter/melder/keine). Melder bekommen von SharePoint ohnehin nur ihre
 * eigenen Tickets geliefert („nur selbst erstellte Elemente lesen").
 */
import { KONFIG, FELDER, OPTIONALE_FELDER, NOTIZ_ENDUNG } from './config.js';
import { sp, spAlle, graph, guid, lit, validateUpdate, personenWert, ApiFehler } from './api.js';
import {
  queueAusFeldern, rolleAusRechten, hatRecht, RECHT, ticketAusSp, parseTicketNummer, ticketNummer, passendeAuswahl, normPrio,
} from './modell.js';
import { meineMail } from './auth.js';

export const zustand = {
  site: null,          // { graphId, titel, ownerGruppe, istAdmin }
  queues: [],          // alle Zeilen der Konfigurationsliste
  konfigFehlt: false,  // Konfigurationsliste existiert noch nicht
  listen: new Map(),   // kennung → { queue, rolle, felder, auswahl, fehlend }
  tickets: new Map(),  // kennung → Ticket[]
  laeuft: new Map(),   // kennung → Promise (Laden)
};

// ── Kontext ────────────────────────────────────────────────────────────────

export async function ladeKontext() {
  const web = await sp('_api/web?$select=Id,Title,EffectiveBasePermissions,AssociatedOwnerGroup/Title&$expand=AssociatedOwnerGroup');
  const g = await graph(`/sites/${new URL(KONFIG.spHost).hostname}:${KONFIG.sitePfad}?$select=id`);
  zustand.site = {
    graphId: g.id,
    titel: web.Title,
    ownerGruppe: web.AssociatedOwnerGroup?.Title || '',
    istAdmin: hatRecht(web.EffectiveBasePermissions, RECHT.rechteVerwalten),
  };
  await ladeQueues();
}

export async function ladeQueues() {
  zustand.konfigFehlt = false;
  let zeilen = [];
  try {
    zeilen = await spAlle(`_api/web/lists/getbytitle(${lit(KONFIG.konfigListe)})/items?$top=500`);
  } catch (e) {
    if (e instanceof ApiFehler && (e.status === 404 || /does not exist|existiert nicht/i.test(e.message))) zustand.konfigFehlt = true;
    else throw e;
  }
  zustand.queues = zeilen.map(queueAusFeldern).sort((a, b) => a.reihenfolge - b.reihenfolge || a.name.localeCompare(b.name));
  zustand.listen.clear();
  await Promise.all(zustand.queues.filter(q => q.listId && q.modus !== 'Hinweis').map(async q => {
    let rolle = 'keine';
    try {
      rolle = rolleAusRechten(await sp(`_api/web/lists(${guid(q.listId)})/EffectiveBasePermissions`));
    } catch { /* kein Zugriff oder Liste weg */ }
    zustand.listen.set(q.kennung, { queue: q, rolle, felder: null, auswahl: {}, fehlend: [] });
  }));
}

/** Listen, in denen ich etwas sehe – optional nur ab einer Rolle. */
export function meineListen(mindestens = 'melder') {
  const rang = { keine: 0, melder: 1, bearbeiter: 2, admin: 3 };
  return [...zustand.listen.values()].filter(l => rang[l.rolle] >= rang[mindestens]);
}

export const istBearbeiterIrgendwo = () => meineListen('bearbeiter').length > 0;
export const liste = kennung => zustand.listen.get(kennung) || null;

// ── Spalten ────────────────────────────────────────────────────────────────

/** Spalten einer Ticketliste laden (Auswahlwerte, optionale Spalten, fehlende Pflichtspalten). */
export async function ladeFelder(kennung) {
  const l = liste(kennung);
  if (!l) throw new Error('Unbekannte Queue ' + kennung);
  if (l.felder) return l;
  const felder = await spAlle(`_api/web/lists(${guid(l.queue.listId)})/fields?$filter=Hidden eq false`);
  const namen = new Set(felder.map(f => f.InternalName));
  const finde = kandidaten => felder.find(f => kandidaten.some(k => k.toLowerCase() === String(f.InternalName).toLowerCase() || k.toLowerCase() === String(f.Title).toLowerCase()))?.InternalName || '';
  l.felder = { kategorie: finde(OPTIONALE_FELDER.kategorie), art: finde(OPTIONALE_FELDER.art) };
  l.fehlend = Object.values(FELDER).filter(n => !namen.has(n));
  for (const f of felder) {
    const auswahl = Array.isArray(f.Choices) ? f.Choices : f.Choices?.results;
    if (auswahl?.length) l.auswahl[f.InternalName] = auswahl;
  }
  return l;
}

// ── Tickets ────────────────────────────────────────────────────────────────

const PERSONEN = ['Author', FELDER.bearbeiter, FELDER.melder];

function _select(l) {
  const vorhanden = n => !l.fehlend.includes(n);
  const sel = ['Id', 'Created', 'Modified', 'Attachments', 'Author/Title', 'Author/EMail'];
  for (const n of [FELDER.titel, FELDER.status, FELDER.prio, FELDER.werk, FELDER.gemeldetAm, FELDER.melderMail]) if (vorhanden(n)) sel.push(n);
  for (const n of [FELDER.bearbeiter, FELDER.melder]) if (vorhanden(n)) sel.push(`${n}/Id`, `${n}/Title`, `${n}/EMail`);
  if (l.felder.kategorie) sel.push(l.felder.kategorie);
  if (l.felder.art) sel.push(l.felder.art);
  const exp = PERSONEN.filter(vorhanden);
  return `$select=${sel.join(',')}&$expand=${exp.join(',')}`;
}

/** Alle Tickets einer Queue (sichtbar für mich). Parallelaufrufe teilen sich eine Anfrage. */
export function ladeTickets(kennung, { neu = false, fortschritt } = {}) {
  if (!neu && zustand.tickets.has(kennung)) return Promise.resolve(zustand.tickets.get(kennung));
  if (!neu && zustand.laeuft.has(kennung)) return zustand.laeuft.get(kennung);
  const p = (async () => {
    const l = await ladeFelder(kennung);
    const roh = await spAlle(`_api/web/lists(${guid(l.queue.listId)})/items?${_select(l)}&$orderby=Id desc&$top=2000`, fortschritt);
    const tickets = roh.map(it => ticketAusSp(it, l.queue, l.felder));
    zustand.tickets.set(kennung, tickets);
    return tickets;
  })().finally(() => zustand.laeuft.delete(kennung));
  zustand.laeuft.set(kennung, p);
  return p;
}

/** Tickets mehrerer Queues (Archiv nur auf ausdrücklichen Wunsch). */
export async function ladeAlle({ mindestens = 'melder', mitArchiv = false, neu = false } = {}) {
  const ls = meineListen(mindestens).filter(l => mitArchiv || l.queue.modus !== 'Archiv');
  const ergebnisse = await Promise.allSettled(ls.map(l => ladeTickets(l.queue.kennung, { neu })));
  const fehler = ergebnisse.map((r, i) => r.status === 'rejected' ? `${ls[i].queue.kennung}: ${r.reason?.message}` : '').filter(Boolean);
  return { tickets: ergebnisse.flatMap(r => r.status === 'fulfilled' ? r.value : []), fehler };
}

/** Ein Ticket mit Beschreibung und allen Werten. */
export async function ladeTicket(nummer) {
  const n = parseTicketNummer(nummer);
  if (!n) throw new Error('Ungültige Ticketnummer');
  const l = liste(n.kennung);
  if (!l || l.rolle === 'keine') throw new Error(`Ticket ${nummer}: keine Berechtigung oder Queue unbekannt.`);
  await ladeFelder(n.kennung);
  const beschr = l.fehlend.includes(FELDER.beschreibung) ? '' : `,${FELDER.beschreibung}`;
  let it;
  try {
    it = await sp(`_api/web/lists(${guid(l.queue.listId)})/items(${n.id})?${_select(l)}${beschr}`);
  } catch (e) {
    // Melder bekommen fremde Tickets von SharePoint gar nicht erst geliefert (404).
    if (e instanceof ApiFehler && (e.status === 404 || e.status === 403)) throw new Error(`Ticket ${nummer} gibt es nicht, oder Sie haben keinen Zugriff darauf.`);
    throw e;
  }
  const t = ticketAusSp(it, l.queue, l.felder);
  t.beschreibung = String(it[FELDER.beschreibung] ?? '');
  // Liste im Speicher aktuell halten
  const alle = zustand.tickets.get(n.kennung);
  if (alle) { const i = alle.findIndex(x => x.id === t.id); if (i >= 0) alle[i] = t; else alle.unshift(t); }
  return { ticket: t, liste: l };
}

function _merke(kennung, id, aenderung) {
  const t = zustand.tickets.get(kennung)?.find(x => x.id === id);
  if (t) Object.assign(t, aenderung, { geaendert: new Date().toISOString() });
}

/**
 * Status/Priorität setzen. `werte` = SharePoint-Spalten mit Auswahlwerten der Liste,
 * `anzeige` = dieselben Werte im Ticket-Objekt (status, prio) für die Liste im Speicher.
 */
export async function setzeWerte(nummer, werte, anzeige = {}) {
  const n = parseTicketNummer(nummer);
  const l = liste(n.kennung);
  await validateUpdate(l.queue.listId, n.id, werte);
  _merke(n.kennung, n.id, anzeige);
}

export async function setzeBearbeiter(nummer, personenListe) {
  const n = parseTicketNummer(nummer);
  const l = liste(n.kennung);
  await validateUpdate(l.queue.listId, n.id, { [FELDER.bearbeiter]: personenWert(personenListe.map(p => p.mail)) });
  _merke(n.kennung, n.id, { bearbeiter: personenListe });
}

// ── Kommentare (für Melder sichtbar) ───────────────────────────────────────

export async function ladeKommentare(nummer) {
  const n = parseTicketNummer(nummer);
  const l = liste(n.kennung);
  const r = await sp(`_api/web/lists(${guid(l.queue.listId)})/GetItemById(${n.id})/Comments`);
  return (r?.value || []).map(c => ({
    id: c.id, text: c.text || '', datum: c.createdDate,
    name: c.author?.name || c.author?.email || 'Unbekannt', mail: String(c.author?.email || '').toLowerCase(),
  })).sort((a, b) => Date.parse(a.datum) - Date.parse(b.datum));
}

export async function kommentieren(nummer, text) {
  const n = parseTicketNummer(nummer);
  const l = liste(n.kennung);
  await sp(`_api/web/lists(${guid(l.queue.listId)})/GetItemById(${n.id})/Comments`, { method: 'POST', body: { text } });
}

// ── Interne Notizen (eigene Liste je Queue, nur Bearbeiter) ────────────────

const _notizListen = new Map();

export async function notizListe(kennung) {
  if (_notizListen.has(kennung)) return _notizListen.get(kennung);
  const l = liste(kennung);
  let id = null;
  try {
    const r = await sp(`_api/web/lists/getbytitle(${lit(l.queue.liste + NOTIZ_ENDUNG)})?$select=Id`);
    id = r?.Id || null;
  } catch { id = null; }
  _notizListen.set(kennung, id);
  return id;
}

export async function ladeNotizen(nummer) {
  const n = parseTicketNummer(nummer);
  const id = await notizListe(n.kennung);
  if (!id) return null;
  const r = await spAlle(`_api/web/lists(${guid(id)})/items?$filter=TicketId eq ${n.id}&$select=Id,Text,Created,Author/Title,Author/EMail&$expand=Author&$orderby=Created asc&$top=500`);
  return r.map(x => ({ id: x.Id, text: x.Text || '', datum: x.Created, name: x.Author?.Title || '', mail: String(x.Author?.EMail || '').toLowerCase() }));
}

export async function notieren(nummer, text) {
  const n = parseTicketNummer(nummer);
  const id = await notizListe(n.kennung);
  if (!id) throw new Error('Für diese Queue gibt es noch keine Notizliste (Verwaltung → Rechte → Einrichten).');
  await graph(`/sites/${zustand.site.graphId}/lists/${id}/items`, { method: 'POST', body: { fields: { Title: nummer, TicketId: n.id, Text: text } } });
}

// ── Anhänge ────────────────────────────────────────────────────────────────

export async function ladeAnhaenge(nummer) {
  const n = parseTicketNummer(nummer);
  const l = liste(n.kennung);
  const r = await sp(`_api/web/lists(${guid(l.queue.listId)})/items(${n.id})/AttachmentFiles`);
  return (r?.value || []).map(a => ({ name: a.FileName, url: KONFIG.spHost + a.ServerRelativeUrl }));
}

export async function anhangHochladen(nummer, datei) {
  const n = parseTicketNummer(nummer);
  const l = liste(n.kennung);
  const puffer = await datei.arrayBuffer();
  await sp(`_api/web/lists(${guid(l.queue.listId)})/items(${n.id})/AttachmentFiles/add(FileName=${lit(datei.name)})`, { method: 'POST', body: puffer });
  _merke(n.kennung, n.id, { anhaenge: true });
}

export async function anhangLoeschen(nummer, name) {
  const n = parseTicketNummer(nummer);
  const l = liste(n.kennung);
  await sp(`_api/web/lists(${guid(l.queue.listId)})/items(${n.id})/AttachmentFiles/getByFileName(${lit(name)})`, { method: 'DELETE' });
}

// ── Neues Ticket direkt in einer Queue (Bearbeiter, z. B. nach Anruf) ──────

/**
 * Legt das Ticket an und trägt – wenn möglich – den Melder als „Erstellt von" ein,
 * damit er es unter „Meine Anfragen" sieht. Gibt { nummer, warnung } zurück.
 */
export async function ticketAnlegen(kennung, { titel, beschreibung, prio, melderMail, bearbeiterMails = [] }) {
  const l = await ladeFelder(kennung);
  const q = l.queue;
  const felder = { [FELDER.titel]: titel, [FELDER.status]: passendeAuswahl(l.auswahl[FELDER.status], 'Neu') };
  if (!l.fehlend.includes(FELDER.beschreibung)) felder[FELDER.beschreibung] = beschreibung;
  if (prio && !l.fehlend.includes(FELDER.prio)) felder[FELDER.prio] = passendeAuswahl(l.auswahl[FELDER.prio], prio, normPrio);
  // Werk nur setzen, wenn die Liste den Wert kennt (Auswahlspalte ohne eigene Werte).
  const werke = l.auswahl[FELDER.werk];
  if (q.werk && !l.fehlend.includes(FELDER.werk) && (!werke || werke.includes(q.werk))) felder[FELDER.werk] = q.werk;
  if (melderMail && !l.fehlend.includes(FELDER.melderMail)) felder[FELDER.melderMail] = melderMail;
  if (!l.fehlend.includes(FELDER.gemeldetAm)) felder[FELDER.gemeldetAm] = new Date().toISOString();
  const neu = await graph(`/sites/${zustand.site.graphId}/lists/${q.listId}/items`, { method: 'POST', body: { fields: felder } });
  const id = Number(neu.id);
  const nummer = ticketNummer(kennung, id);
  const warnungen = [];
  const personen = {};
  if (bearbeiterMails.length && !l.fehlend.includes(FELDER.bearbeiter)) personen[FELDER.bearbeiter] = personenWert(bearbeiterMails);
  if (melderMail && !l.fehlend.includes(FELDER.melder)) personen[FELDER.melder] = personenWert([melderMail]);
  if (Object.keys(personen).length) {
    try { await validateUpdate(q.listId, id, personen); }
    catch (e) { warnungen.push('Personen: ' + e.message); }
  }
  if (melderMail && melderMail !== meineMail()) {
    try { await validateUpdate(q.listId, id, { Author: personenWert([melderMail]) }, { neueVersion: false }); }
    catch (e) { warnungen.push('Der Melder konnte nicht als „Erstellt von" eingetragen werden – er sieht das Ticket nicht in der App (' + e.message + ').'); }
  }
  zustand.tickets.delete(kennung);
  return { nummer, warnungen };
}
