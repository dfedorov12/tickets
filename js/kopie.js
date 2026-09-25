/**
 * Ein Ticket in eine andere Liste kopieren – für „Weiterleiten" (Bearbeiter) und die
 * Migration aus der Basisliste (Admin). Übernimmt Spaltenwerte, Personen, Anhänge,
 * Kommentare und interne Notizen; „Erstellt von" wird auf den Melder gesetzt, damit
 * er das Ticket in der neuen Liste sieht.
 *
 * Da Quelle und Ziel auf derselben Site liegen, gelten dieselben Personen-/Lookup-IDs –
 * die Werte lassen sich 1:1 übertragen (odata=verbose, Mehrfachwerte als {results}).
 */
import { FELDER, NOTIZ_ENDUNG } from './config.js';
import { sp, spAlle, guid, lit, validateUpdate, personenWert } from './api.js';
import { datumZeit } from './text.js';

// Spaltentypen, deren Werte sich nicht (sinnvoll) per REST übertragen lassen.
const NICHT_KOPIERBAR = new Set(['Computed', 'Calculated', 'TaxonomyFieldType', 'TaxonomyFieldTypeMulti', 'Attachments', 'ContentTypeId', 'File', 'Counter', 'Guid', 'Location', 'Thumbnail', 'Geolocation']);
const NIE = new Set(['ContentType', 'Attachments', 'Author', 'Editor', 'Created', 'Modified', 'ID', 'Id', '_ModerationStatus', '_ModerationComments', 'ComplianceAssetId', '_ColorTag', 'AppAuthor', 'AppEditor']);

const _schemaCache = new Map();

async function zielSchema(listId) {
  if (_schemaCache.has(listId)) return _schemaCache.get(listId);
  const [liste, felder] = await Promise.all([
    sp(`_api/web/lists(${guid(listId)})?$select=ListItemEntityTypeFullName,Title`),
    spAlle(`_api/web/lists(${guid(listId)})/fields?$filter=ReadOnlyField eq false and Hidden eq false&$select=InternalName,TypeAsString`),
  ]);
  const s = { typ: liste.ListItemEntityTypeFullName, titel: liste.Title, felder: felder.filter(f => !NIE.has(f.InternalName) && !NICHT_KOPIERBAR.has(f.TypeAsString)) };
  _schemaCache.set(listId, s);
  return s;
}

async function notizListeId(listenName) {
  try { return (await sp(`_api/web/lists/getbytitle(${lit(listenName + NOTIZ_ENDUNG)})?$select=Id`))?.Id || null; }
  catch { return null; }
}

/**
 * @param quelle { listId, id, listenName? }
 * @param ziel   { listId, listenName?, kennung? }
 * @param optionen { hinweis?: string, werk?: string, status?: string }
 * @returns { id, warnungen: string[] }
 */
export async function kopiereTicket(quelle, ziel, optionen = {}) {
  const warnungen = [];
  const schema = await zielSchema(ziel.listId);
  const pers = [FELDER.melder, 'Author'].join(',');
  const it = await sp(`_api/web/lists(${guid(quelle.listId)})/items(${Number(quelle.id)})?$select=*,Author/EMail,${FELDER.melder}/EMail&$expand=${pers}`, { verbose: true });

  const body = { __metadata: { type: schema.typ } };
  for (const f of schema.felder) {
    const name = f.InternalName;
    if (/^(User|UserMulti|Lookup|LookupMulti)$/.test(f.TypeAsString)) {
      const v = it[name + 'Id'];
      if (v !== undefined && v !== null && !(v.results && !v.results.length)) body[name + 'Id'] = v.results ? { results: v.results } : v;
    } else if (it[name] !== undefined && it[name] !== null) {
      const v = it[name];
      if (v && typeof v === 'object' && v.__deferred) continue;
      body[name] = v;
    }
  }
  if (optionen.werk && schema.felder.some(f => f.InternalName === FELDER.werk)) body[FELDER.werk] = optionen.werk;
  if (optionen.status) body[FELDER.status] = optionen.status;

  const neu = await sp(`_api/web/lists(${guid(ziel.listId)})/items`, { method: 'POST', body, verbose: true });
  const neueId = neu.Id ?? neu.ID;

  // „Erstellt von" = Melder (sonst sieht er das Ticket nicht), ersatzweise der bisherige Ersteller.
  const autor = String(it[FELDER.melder]?.EMail || it.Author?.EMail || '').toLowerCase();
  if (autor) {
    try { await validateUpdate(ziel.listId, neueId, { Author: personenWert([autor]) }, { neueVersion: false }); }
    catch (e) { warnungen.push(`„Erstellt von" nicht gesetzt (${e.message})`); }
  }

  // Anhänge
  if (it.Attachments) {
    const anh = await sp(`_api/web/lists(${guid(quelle.listId)})/items(${Number(quelle.id)})/AttachmentFiles`);
    for (const a of anh?.value || []) {
      try {
        const res = await sp(`_api/web/lists(${guid(quelle.listId)})/items(${Number(quelle.id)})/AttachmentFiles/getByFileName(${lit(a.FileName)})/$value`, { roh: true });
        await sp(`_api/web/lists(${guid(ziel.listId)})/items(${neueId})/AttachmentFiles/add(FileName=${lit(a.FileName)})`, { method: 'POST', body: await res.arrayBuffer() });
      } catch (e) { warnungen.push(`Anhang ${a.FileName}: ${e.message}`); }
    }
  }

  // Kommentare – mit ursprünglichem Autor und Datum im Text (die API legt sie als mich an).
  try {
    const k = await sp(`_api/web/lists(${guid(quelle.listId)})/GetItemById(${Number(quelle.id)})/Comments`);
    const liste = (k?.value || []).sort((a, b) => Date.parse(a.createdDate) - Date.parse(b.createdDate));
    for (const c of liste) {
      await sp(`_api/web/lists(${guid(ziel.listId)})/GetItemById(${neueId})/Comments`, {
        method: 'POST', body: { text: `[${datumZeit(c.createdDate)} · ${c.author?.name || c.author?.email || '?'}]\n${c.text || ''}` },
      });
    }
  } catch (e) { warnungen.push('Kommentare: ' + e.message); }

  // Interne Notizen (nur wenn beide Queues eine Notizliste haben)
  if (quelle.listenName && ziel.listenName) {
    const [qn, zn] = await Promise.all([notizListeId(quelle.listenName), notizListeId(ziel.listenName)]);
    if (qn && zn) {
      try {
        const notizen = await spAlle(`_api/web/lists(${guid(qn)})/items?$filter=TicketId eq ${Number(quelle.id)}&$select=Text,Created,Author/Title&$expand=Author&$top=500`);
        const zs = await zielSchema(zn);
        for (const n of notizen) {
          await sp(`_api/web/lists(${guid(zn)})/items`, {
            method: 'POST', verbose: true,
            body: { __metadata: { type: zs.typ }, Title: ziel.kennung ? `${ziel.kennung}-${neueId}` : String(neueId), TicketId: neueId, Text: `[${datumZeit(n.Created)} · ${n.Author?.Title || '?'}]\n${n.Text || ''}` },
          });
        }
      } catch (e) { warnungen.push('Notizen: ' + e.message); }
    }
  }

  if (optionen.hinweis) {
    try { await sp(`_api/web/lists(${guid(ziel.listId)})/GetItemById(${neueId})/Comments`, { method: 'POST', body: { text: optionen.hinweis } }); }
    catch (e) { warnungen.push('Hinweis-Kommentar: ' + e.message); }
  }
  return { id: neueId, warnungen };
}

/** Element in den Papierkorb (wiederherstellbar). */
export async function inPapierkorb(listId, id) {
  await sp(`_api/web/lists(${guid(listId)})/items(${Number(id)})/recycle()`, { method: 'POST' });
}
