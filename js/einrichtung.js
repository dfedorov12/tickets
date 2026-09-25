/**
 * Einrichtung & Rechte (nur Websitebesitzer)
 * ==========================================
 * Alles idempotent – jeder Schritt prüft erst, was da ist, und ergänzt nur das
 * Fehlende. So lässt sich „Einrichten" beliebig oft ausführen.
 *
 *  - Konfigurationsliste „TicketQueues"
 *  - Berechtigungsstufe „Ticket-Bearbeitung" (Mitwirken + Listenverhalten überschreiben − Löschen)
 *  - je Queue: Ticketliste (Spalten aus der Basisliste „Tickets"), interne Notizliste,
 *    Bearbeiter-Gruppe, Listeneinstellungen („nur eigene Elemente", nicht in der Suche),
 *    eigene Berechtigungen nach Soll (Besitzer, Flow-Konto, Bearbeiter, Melder)
 *
 * Rechte werden nie entzogen, bevor die Soll-Rechte vergeben sind – so sperrt sich
 * niemand aus. Die Websitebesitzer stehen immer im Soll.
 */
import { KONFIG, KONFIG_SPALTEN, SOLL_LISTENEINSTELLUNGEN, SOLL_NOTIZEINSTELLUNGEN, NOTIZ_ENDUNG, STATUS, PRIORITAETEN, FELDER } from './config.js';
import { sp, spAlle, graph, guid, lit } from './api.js';
import {
  sollRechte, rechteAbgleich, einstellungsAbgleich, istAusRollenzuweisungen, bearbeitungsMaske,
  queueZuFeldern, claimFuerMail, mailAusLogin, normPrio,
} from './modell.js';
import { zustand } from './daten.js';
import { meineMail } from './auth.js';

// ── Kontext für das Soll ────────────────────────────────────────────────────

export function sollKontext() {
  return {
    ownerGruppe: zustand.site.ownerGruppe,
    dienstkonto: KONFIG.ticketPostfach,
    melderClaim: KONFIG.melderClaim,
    melderAnzeige: KONFIG.melderAnzeige,
    stufeBearbeitung: KONFIG.stufeBearbeitung,
    queues: zustand.queues,
    melderSehen: true,
  };
}

// ── Konfigurationsliste ─────────────────────────────────────────────────────

export async function konfigListeAnlegen() {
  await graph(`/sites/${zustand.site.graphId}/lists`, {
    method: 'POST',
    body: { displayName: KONFIG.konfigListe, description: 'Queues des Ticketsystems (gepflegt in der Tickets-App, gelesen vom Flow)', list: { template: 'genericList' }, columns: KONFIG_SPALTEN },
  });
}

async function konfigListeId() {
  return (await sp(`_api/web/lists/getbytitle(${lit(KONFIG.konfigListe)})?$select=Id`)).Id;
}

export async function queueSpeichern(q) {
  const id = await konfigListeId();
  const fields = queueZuFeldern(q);
  if (q.itemId) await graph(`/sites/${zustand.site.graphId}/lists/${id}/items/${q.itemId}/fields`, { method: 'PATCH', body: fields });
  else await graph(`/sites/${zustand.site.graphId}/lists/${id}/items`, { method: 'POST', body: { fields } });
}

export async function queueLoeschen(q) {
  const id = await konfigListeId();
  await graph(`/sites/${zustand.site.graphId}/lists/${id}/items/${q.itemId}`, { method: 'DELETE' });
}

// ── Berechtigungsstufe ──────────────────────────────────────────────────────

const _rollenCache = new Map();

/** Rollendefinition über Typ (eingebaut) oder Namen → Id. */
async function rollenId(rolle) {
  const k = rolle.typ != null ? 'typ:' + rolle.typ : 'name:' + rolle.name.toLowerCase();
  if (_rollenCache.has(k)) return _rollenCache.get(k);
  const r = rolle.typ != null
    ? await sp(`_api/web/roledefinitions/getbytype(${Number(rolle.typ)})?$select=Id`)
    : await sp(`_api/web/roledefinitions/getbyname(${lit(rolle.name)})?$select=Id`);
  _rollenCache.set(k, r.Id);
  return r.Id;
}

export async function stufePruefen() {
  const mitwirken = await sp('_api/web/roledefinitions/getbytype(3)?$select=BasePermissions');
  const soll = bearbeitungsMaske(mitwirken.BasePermissions);
  try {
    const ist = await sp(`_api/web/roledefinitions/getbyname(${lit(KONFIG.stufeBearbeitung)})?$select=Id,BasePermissions`);
    const gleich = String(ist.BasePermissions.High) === soll.High && String(ist.BasePermissions.Low) === soll.Low;
    return { vorhanden: true, id: ist.Id, gleich, soll };
  } catch {
    return { vorhanden: false, gleich: false, soll };
  }
}

export async function stufeSicherstellen() {
  const s = await stufePruefen();
  const body = {
    __metadata: { type: 'SP.RoleDefinition' },
    BasePermissions: { __metadata: { type: 'SP.BasePermissions' }, High: s.soll.High, Low: s.soll.Low },
    Description: 'Ticketsystem: alle Tickets der Liste lesen und bearbeiten (auch fremde), nicht löschen.',
    Name: KONFIG.stufeBearbeitung,
  };
  if (!s.vorhanden) {
    await sp('_api/web/roledefinitions', { method: 'POST', verbose: true, body: { ...body, Order: 900 } });
  } else if (!s.gleich) {
    await sp(`_api/web/roledefinitions(${Number(s.id)})`, { method: 'MERGE', verbose: true, body });
  }
  _rollenCache.clear();
}

// ── Gruppen ─────────────────────────────────────────────────────────────────

export async function gruppeLesen(titel) {
  if (!titel) return null;
  try {
    const g = await sp(`_api/web/sitegroups/getbyname(${lit(titel)})?$select=Id,Title`);
    const nutzer = await sp(`_api/web/sitegroups(${Number(g.Id)})/users?$select=Id,Title,Email,LoginName`);
    return { id: g.Id, titel: g.Title, mitglieder: (nutzer?.value || []).map(u => ({ id: u.Id, name: u.Title, mail: String(u.Email || mailAusLogin(u.LoginName)).toLowerCase(), login: u.LoginName })) };
  } catch { return null; }
}

export async function gruppeSicherstellen(titel, beschreibung = '') {
  const da = await gruppeLesen(titel);
  if (da) return da;
  const g = await sp('_api/web/sitegroups', { method: 'POST', verbose: true, body: { __metadata: { type: 'SP.Group' }, Title: titel, Description: beschreibung } });
  // Besitzer der Gruppe = Websitebesitzer, damit jeder Admin die Mitglieder pflegen kann.
  try {
    const owner = await sp(`_api/web/sitegroups/getbyname(${lit(zustand.site.ownerGruppe)})?$select=Id`);
    await sp(`_api/web/sitegroups(${Number(g.Id)})/SetUserAsOwner(${Number(owner.Id)})`, { method: 'POST' });
  } catch { /* bleibt beim Ersteller – unkritisch */ }
  return { id: g.Id, titel, mitglieder: [] };
}

export async function mitgliedHinzufuegen(gruppenId, mail) {
  await sp(`_api/web/sitegroups(${Number(gruppenId)})/users`, { method: 'POST', verbose: true, body: { __metadata: { type: 'SP.User' }, LoginName: claimFuerMail(mail) } });
}

export async function mitgliedEntfernen(gruppenId, nutzerId) {
  await sp(`_api/web/sitegroups(${Number(gruppenId)})/users/removebyid(${Number(nutzerId)})`, { method: 'POST' });
}

// ── Listen ──────────────────────────────────────────────────────────────────

export async function listeLesen(titel) {
  try {
    return await sp(`_api/web/lists/getbytitle(${lit(titel)})?$select=Id,Title,ReadSecurity,WriteSecurity,NoCrawl,EnableVersioning,EnableAttachments,HasUniqueRoleAssignments,ItemCount,RootFolder/ServerRelativeUrl&$expand=RootFolder`);
  } catch { return null; }
}

/** SchemaXml einer Spalte für eine andere Liste säubern (IDs vergibt SharePoint neu). */
export function schemaFuerKopie(xml) {
  return String(xml)
    .replace(/\s(ID|SourceID|Version|ColName|RowOrdinal|Customization)="[^"]*"/g, '')
    .replace(/\sVersion='[^']*'/g, '');
}

/**
 * Ticketliste für eine Queue anlegen – Spalten aus der Basisliste übernehmen.
 * Gibt { id, url, neu, spalten } zurück.
 */
export async function ticketListeAnlegen(q, protokoll = () => {}) {
  const vorhanden = await listeLesen(q.liste);
  let id = vorhanden?.Id;
  let neu = false;
  if (!id) {
    const l = await sp('_api/web/lists', {
      method: 'POST', verbose: true,
      body: { __metadata: { type: 'SP.List' }, BaseTemplate: 100, Title: q.liste, Description: `Tickets der Queue ${q.name} (${q.kennung})`, ContentTypesEnabled: false },
    });
    id = l.Id; neu = true;
    protokoll(`Liste „${q.liste}" angelegt`);
  }
  // Spalten angleichen
  const basis = await spAlle(`_api/web/lists/getbytitle(${lit(KONFIG.basisListe)})/fields?$filter=Hidden eq false and ReadOnlyField eq false&$select=InternalName,Title,SchemaXml,TypeAsString,FromBaseType`);
  const ziel = new Set((await spAlle(`_api/web/lists(${guid(id)})/fields?$select=InternalName`)).map(f => f.InternalName));
  const eigene = basis.filter(f => !f.FromBaseType && !ziel.has(f.InternalName));
  const reihenfolge = [...eigene.filter(f => f.TypeAsString !== 'Calculated'), ...eigene.filter(f => f.TypeAsString === 'Calculated')];
  const fehler = [];
  for (const f of reihenfolge) {
    try {
      await sp(`_api/web/lists(${guid(id)})/fields/createfieldasxml`, {
        method: 'POST', verbose: true,
        // 8 = interner Name wie angegeben, 16 = in Standardansicht, 1 = Standard-Inhaltstyp
        body: { parameters: { __metadata: { type: 'SP.XmlSchemaFieldCreationInformation' }, SchemaXml: schemaFuerKopie(f.SchemaXml), Options: 8 | 16 | 1 } },
      });
      protokoll(`Spalte ${f.Title} (${f.InternalName})`);
    } catch (e) { fehler.push(`${f.InternalName}: ${e.message}`); }
  }
  // Anzeigename von „Title" übernehmen (z. B. „Problem")
  const titel = basis.find(f => f.InternalName === 'Title');
  if (neu && titel?.Title && titel.Title !== 'Title') {
    try {
      await sp(`_api/web/lists(${guid(id)})/fields/getbyinternalnameortitle('Title')`, { method: 'MERGE', verbose: true, body: { __metadata: { type: 'SP.Field' }, Title: titel.Title } });
    } catch { /* nur Kosmetik */ }
  }
  const l = await listeLesen(q.liste);
  return { id: l.Id, url: l.RootFolder?.ServerRelativeUrl || '', neu, fehler };
}

export async function notizListeAnlegen(q) {
  const titel = q.liste + NOTIZ_ENDUNG;
  const da = await listeLesen(titel);
  if (da) return da.Id;
  const l = await graph(`/sites/${zustand.site.graphId}/lists`, {
    method: 'POST',
    body: {
      displayName: titel, description: `Interne Notizen zu Tickets ${q.kennung} – nur IT`, list: { template: 'genericList' },
      columns: [{ name: 'TicketId', number: {}, indexed: true }, { name: 'Text', text: { allowMultipleLines: true, linesForEditing: 6 } }],
    },
  });
  return l.id;
}

// ── Einstellungen & Rechte ──────────────────────────────────────────────────

export async function einstellungenAnwenden(listId, soll) {
  await sp(`_api/web/lists(${guid(listId)})`, { method: 'MERGE', verbose: true, body: { __metadata: { type: 'SP.List' }, ...soll } });
}

export async function rechteLesen(listId) {
  const r = await sp(`_api/web/lists(${guid(listId)})/roleassignments?$expand=Member,RoleDefinitionBindings`);
  return istAusRollenzuweisungen(r?.value || []);
}

async function prinzipalId(s) {
  if (s.art === 'gruppe') return (await sp(`_api/web/sitegroups/getbyname(${lit(s.wert)})?$select=Id`)).Id;
  return (await sp('_api/web/ensureuser', { method: 'POST', body: { logonName: s.wert } })).Id;
}

/**
 * Rechte einer Liste auf das Soll bringen. Reihenfolge: Vererbung aufheben (Kopie
 * der bisherigen Rechte), fehlende vergeben, erst dann Überzähliges entziehen.
 */
export async function rechteAnwenden(listId, soll, protokoll = () => {}) {
  const info = await sp(`_api/web/lists(${guid(listId)})?$select=HasUniqueRoleAssignments`);
  if (!info.HasUniqueRoleAssignments) {
    await sp(`_api/web/lists(${guid(listId)})/breakroleinheritance(copyRoleAssignments=true,clearSubscopes=true)`, { method: 'POST' });
    protokoll('Vererbung aufgehoben');
  }
  let abgleich = rechteAbgleich(soll, await rechteLesen(listId));
  for (const s of abgleich.fehlt) {
    const pid = await prinzipalId(s);
    const rid = await rollenId(s.rolle);
    await sp(`_api/web/lists(${guid(listId)})/roleassignments/addroleassignment(principalid=${Number(pid)},roledefid=${Number(rid)})`, { method: 'POST' });
    protokoll(`+ ${s.anzeige}: ${s.rolle.anzeige}`);
  }
  abgleich = rechteAbgleich(soll, await rechteLesen(listId));
  if (abgleich.fehlt.length) throw new Error('Soll-Rechte ließen sich nicht vollständig vergeben – es wird nichts entzogen.');
  const ich = claimFuerMail(meineMail());
  for (const z of abgleich.zuviel) {
    // Den eigenen direkten Zugang nie entziehen – sonst wäre die Liste für diesen Admin zu.
    if (String(z.login).toLowerCase() === ich) { protokoll(`• eigener Zugang (${z.rolle.name}) bleibt – bitte ggf. von Hand entfernen`); continue; }
    await sp(`_api/web/lists(${guid(listId)})/roleassignments/removeroleassignment(principalid=${Number(z.principalId)},roledefid=${Number(z.rolle.id)})`, { method: 'POST' });
    protokoll(`− ${z.titel || z.login}: ${z.rolle.name}`);
  }
}

/** Zustand einer Queue für die Verwaltung (nichts wird verändert). */
export async function queuePruefen(q) {
  const ergebnis = { liste: null, notiz: null, gruppe: null, einstellungen: [], rechte: null, notizRechte: null, eindeutig: false, fehler: [] };
  if (q.modus === 'Hinweis') return ergebnis;
  ergebnis.liste = await listeLesen(q.liste);
  if (q.modus === 'Ticket') {
    ergebnis.gruppe = await gruppeLesen(q.gruppe);
    ergebnis.notiz = await listeLesen(q.liste + NOTIZ_ENDUNG);
  }
  const ctx = sollKontext();
  if (ergebnis.liste) {
    ergebnis.eindeutig = ergebnis.liste.HasUniqueRoleAssignments;
    ergebnis.einstellungen = einstellungsAbgleich(ergebnis.liste, SOLL_LISTENEINSTELLUNGEN);
    try { ergebnis.rechte = rechteAbgleich(sollRechte(q, ctx, 'tickets'), await rechteLesen(ergebnis.liste.Id)); }
    catch (e) { ergebnis.fehler.push('Rechte: ' + e.message); }
  }
  if (ergebnis.notiz) {
    try { ergebnis.notizRechte = rechteAbgleich(sollRechte(q, ctx, 'notizen'), await rechteLesen(ergebnis.notiz.Id)); }
    catch (e) { ergebnis.fehler.push('Notiz-Rechte: ' + e.message); }
  }
  return ergebnis;
}

/**
 * Eine Queue vollständig einrichten. Gibt die (ggf. neue) Listen-ID/URL zurück,
 * damit die Konfigurationszeile aktualisiert werden kann.
 */
export async function queueEinrichten(q, protokoll = () => {}) {
  if (q.modus === 'Hinweis') { protokoll('Hinweis-Queue: keine Liste nötig'); return {}; }
  await stufeSicherstellen();
  protokoll(`Berechtigungsstufe „${KONFIG.stufeBearbeitung}" ok`);
  const ctx = sollKontext();

  let liste;
  if (q.modus === 'Archiv') {
    const l = await listeLesen(q.liste);
    if (!l) throw new Error(`Archivliste „${q.liste}" nicht gefunden.`);
    liste = { id: l.Id, url: l.RootFolder?.ServerRelativeUrl || '', fehler: [] };
  } else {
    liste = await ticketListeAnlegen(q, protokoll);
    liste.fehler.forEach(f => protokoll('⚠ Spalte ' + f));
  }
  if (q.gruppe && q.gruppe !== '*') {
    await gruppeSicherstellen(q.gruppe, `Bearbeiter der Ticket-Queue ${q.name}`);
    protokoll(`Gruppe „${q.gruppe}" ok`);
  }
  await einstellungenAnwenden(liste.id, SOLL_LISTENEINSTELLUNGEN);
  protokoll('Listeneinstellungen: nur eigene Elemente, nicht in der Suche, Versionierung');
  await rechteAnwenden(liste.id, sollRechte(q, ctx, 'tickets'), protokoll);

  if (q.modus === 'Ticket') {
    const notizId = await notizListeAnlegen(q);
    await einstellungenAnwenden(notizId, SOLL_NOTIZEINSTELLUNGEN);
    await rechteAnwenden(notizId, sollRechte(q, ctx, 'notizen'), m => protokoll('Notizliste: ' + m));
    protokoll('Notizliste ok');
  }
  return { listId: liste.id, listUrl: liste.url };
}

// ── Schema angleichen (Auswahlwerte) ────────────────────────────────────────

/**
 * Fehlende Auswahlwerte ergänzen: Status (alle der App), Priorität (sofern keine
 * gleichwertige vorhanden), Werk (alle Werke der Queues). Nichts wird entfernt.
 */
export async function auswahlAngleichen(listId, queues, protokoll = () => {}) {
  const felder = await spAlle(`_api/web/lists(${guid(listId)})/fields?$filter=Hidden eq false`);
  const wunsch = {
    [FELDER.status]: { werte: STATUS.map(s => s.wert), gleich: (a, b) => a === b },
    [FELDER.prio]: { werte: PRIORITAETEN, gleich: (a, b) => normPrio(a) === normPrio(b) },
    [FELDER.werk]: { werte: [...new Set(queues.map(q => q.werk).filter(Boolean))], gleich: (a, b) => a === b },
  };
  for (const [name, w] of Object.entries(wunsch)) {
    const f = felder.find(x => x.InternalName === name);
    const ist = Array.isArray(f?.Choices) ? f.Choices : f?.Choices?.results;
    if (!f || !ist) continue; // keine Auswahlspalte
    const fehlt = w.werte.filter(v => !ist.some(i => w.gleich(i, v)));
    if (!fehlt.length) continue;
    await sp(`_api/web/lists(${guid(listId)})/fields/getbyinternalnameortitle(${lit(name)})`, {
      method: 'MERGE', verbose: true,
      body: { __metadata: { type: f.TypeAsString === 'MultiChoice' ? 'SP.FieldMultiChoice' : 'SP.FieldChoice' }, Choices: { __metadata: { type: 'Collection(Edm.String)' }, results: [...ist, ...fehlt] } },
    });
    protokoll(`${name}: + ${fehlt.join(', ')}`);
  }
}
