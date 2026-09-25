/**
 * Einrichtung/Abgleich gegen eine zustandsbehaftete SharePoint-Attrappe (nur Rechte):
 * Vererbung aufheben, erst vergeben, dann entziehen, eigenen Zugang behalten,
 * zweiter Lauf ändert nichts; Spalten der Basisliste werden kopiert.
 */
import { ok, gleich, ende } from './_pruef.mjs';
import { tokenQuelle } from '../js/api.js';
import { zustand } from '../js/daten.js';
import { KONFIG } from '../js/config.js';
import { rechteAnwenden, sollKontext, schemaFuerKopie, ticketListeAnlegen, stufeSicherstellen, stufePruefen } from '../js/einrichtung.js';
import { sollRechte, rechteAbgleich, istAusRollenzuweisungen, queueAusFeldern } from '../js/modell.js';

tokenQuelle(async () => 'test');
zustand.site = { graphId: 'g', titel: 'Ticket', ownerGruppe: 'Ticket Besitzer', istAdmin: true };

const LISTE = '00000000-0000-4000-8000-000000000010';
const ROLLEN = {
  1073741829: { Id: 1073741829, Name: 'Vollzugriff', RoleTypeKind: 5 },
  1073741827: { Id: 1073741827, Name: 'Mitwirken', RoleTypeKind: 3, BasePermissions: { High: '432', Low: '1011028719' } },
  1073741826: { Id: 1073741826, Name: 'Lesen', RoleTypeKind: 2 },
  1073741830: { Id: 1073741830, Name: 'Bearbeiten', RoleTypeKind: 6 },
};
const PRINZIPALE = {
  3: { Id: 3, LoginName: 'Ticket Besitzer', Title: 'Ticket Besitzer', PrincipalType: 8 },
  4: { Id: 4, LoginName: 'Ticket Mitglieder', Title: 'Ticket Mitglieder', PrincipalType: 8 },
  5: { Id: 5, LoginName: 'Ticket Besucher', Title: 'Ticket Besucher', PrincipalType: 8 },
  30: { Id: 30, LoginName: 'Tickets SCH – Bearbeiter', Title: 'Tickets SCH – Bearbeiter', PrincipalType: 8 },
  9: { Id: 9, LoginName: 'i:0#.f|membership|admin@dihag.com', Title: 'Ada Admin', PrincipalType: 1 },
};
const zustandSp = {
  eindeutig: false,
  // Site-Rechte, die beim Aufheben der Vererbung kopiert werden
  site: [[3, 1073741829], [4, 1073741830], [5, 1073741826]],
  liste: [],
  protokoll: [],
  naechsteId: 100,
  basisFelder: [
    { InternalName: 'Title', Title: 'Problem', SchemaXml: '<Field Name="Title"/>', TypeAsString: 'Text', FromBaseType: true },
    { InternalName: 'Status', Title: 'Status', SchemaXml: '<Field ID="{1}" Type="Choice" Name="Status" StaticName="Status" SourceID="{abc}" ColName="nvarchar4" RowOrdinal="0" Version="3"><CHOICES><CHOICE>Neu</CHOICE></CHOICES></Field>', TypeAsString: 'Choice', FromBaseType: false },
    { InternalName: 'E_x002d_Mail_x002d_Adresse', Title: 'E-Mail-Adresse', SchemaXml: '<Field Type="Text" Name="E_x002d_Mail_x002d_Adresse"/>', TypeAsString: 'Text', FromBaseType: false },
    { InternalName: 'Comment', Title: 'Kommentar', SchemaXml: '<Field Type="Note" Name="Comment"/>', TypeAsString: 'Note', FromBaseType: true },
    { InternalName: 'Summe', Title: 'Summe', SchemaXml: '<Field Type="Calculated" Name="Summe"/>', TypeAsString: 'Calculated', FromBaseType: false },
  ],
  zielFelder: ['Title', 'ContentType', 'Attachments'],
  angelegt: [],
  rollenDef: null,
};
const antwort = (body, status = 200) => new Response(body === null ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

globalThis.fetch = async (url, init = {}) => {
  const u = decodeURIComponent(String(url)).replace('https://dihag.sharepoint.com/sites/ticket/', '');
  const methode = init.headers?.['X-HTTP-Method'] || init.method || 'GET';
  const body = init.body ? JSON.parse(init.body) : undefined;
  const pfad = u.replace(/\?.*$/, '');
  zustandSp.protokoll.push(`${methode} ${pfad}`);
  let m;
  if (pfad === `_api/web/lists(guid'${LISTE}')` && methode === 'GET') return antwort({ HasUniqueRoleAssignments: zustandSp.eindeutig });
  if (pfad.endsWith('/breakroleinheritance(copyRoleAssignments=true,clearSubscopes=true)')) {
    zustandSp.eindeutig = true; zustandSp.liste = zustandSp.site.map(x => [...x]); return antwort(null, 200);
  }
  if (pfad === `_api/web/lists(guid'${LISTE}')/roleassignments`) {
    const nachP = new Map();
    for (const [p, r] of zustandSp.liste) nachP.set(p, [...(nachP.get(p) || []), r]);
    return antwort({ value: [...nachP].map(([p, rs]) => ({ PrincipalId: p, Member: PRINZIPALE[p], RoleDefinitionBindings: rs.map(r => ROLLEN[r]) })) });
  }
  if ((m = pfad.match(/roleassignments\/addroleassignment\(principalid=(\d+),roledefid=(\d+)\)$/))) { zustandSp.liste.push([+m[1], +m[2]]); return antwort(null); }
  if ((m = pfad.match(/roleassignments\/removeroleassignment\(principalid=(\d+),roledefid=(\d+)\)$/))) {
    zustandSp.liste = zustandSp.liste.filter(([p, r]) => !(p === +m[1] && r === +m[2])); return antwort(null);
  }
  if ((m = pfad.match(/^_api\/web\/sitegroups\/getbyname\('(.+)'\)$/))) {
    const p = Object.values(PRINZIPALE).find(x => x.PrincipalType === 8 && x.Title === m[1]);
    return p ? antwort({ Id: p.Id }) : antwort({ 'odata.error': { message: { value: 'fehlt' } } }, 404);
  }
  if (pfad === '_api/web/ensureuser') {
    const vorhanden = Object.values(PRINZIPALE).find(x => x.LoginName === body.logonName);
    if (vorhanden) return antwort({ Id: vorhanden.Id });
    const id = zustandSp.naechsteId++;
    PRINZIPALE[id] = { Id: id, LoginName: body.logonName, Title: body.logonName.includes('spo-grid-all-users') ? 'Jeder außer externen Benutzern' : body.logonName, PrincipalType: 1 };
    return antwort({ Id: id });
  }
  if ((m = pfad.match(/^_api\/web\/roledefinitions\/getbytype\((\d+)\)$/))) return antwort(Object.values(ROLLEN).find(r => r.RoleTypeKind === +m[1]));
  if ((m = pfad.match(/^_api\/web\/roledefinitions\/getbyname\('(.+)'\)$/))) {
    const r = Object.values(ROLLEN).find(x => x.Name.toLowerCase() === m[1].toLowerCase());
    return r ? antwort(r) : antwort({ 'odata.error': { message: { value: 'fehlt' } } }, 404);
  }
  if (pfad === '_api/web/roledefinitions' && methode === 'POST') {
    ROLLEN[1100] = { Id: 1100, Name: body.d?.Name || body.Name, RoleTypeKind: 0, BasePermissions: body.BasePermissions };
    zustandSp.rollenDef = body;
    return antwort({ d: ROLLEN[1100] });
  }
  // Listen-Anlage und Spalten
  if ((m = pfad.match(/^_api\/web\/lists\/getbytitle\('(.+)'\)(\/fields)?$/))) {
    if (m[1] === KONFIG.basisListe && m[2]) return antwort({ value: zustandSp.basisFelder });
    if (m[1] === 'Tickets-NEU' && zustandSp.neueListe) return antwort({ Id: LISTE, Title: 'Tickets-NEU', HasUniqueRoleAssignments: false, RootFolder: { ServerRelativeUrl: '/sites/ticket/Lists/TicketsNEU' } });
    return antwort({ 'odata.error': { message: { value: 'List does not exist' } } }, 404);
  }
  if (pfad === '_api/web/lists' && methode === 'POST') { zustandSp.neueListe = body; return antwort({ d: { Id: LISTE } }); }
  if (pfad === `_api/web/lists(guid'${LISTE}')/fields`) return antwort({ value: zustandSp.zielFelder.map(n => ({ InternalName: n })) });
  if (pfad === `_api/web/lists(guid'${LISTE}')/fields/createfieldasxml`) {
    const xml = body.parameters.SchemaXml;
    zustandSp.angelegt.push({ xml, optionen: body.parameters.Options });
    zustandSp.zielFelder.push(xml.match(/Name="([^"]+)"/)[1]);
    return antwort({ d: {} });
  }
  if (pfad.startsWith(`_api/web/lists(guid'${LISTE}')/fields/getbyinternalnameortitle`)) { zustandSp.titelUmbenannt = body.Title; return antwort(null, 204); }
  return antwort({ 'odata.error': { message: { value: 'unbekannt: ' + methode + ' ' + pfad } } }, 501);
};

// ── Rechte abgleichen ──
const q = { ...queueAusFeldern({ Kennung: 'SCH', ListenName: 'Tickets-SCH', Modus: 'Ticket', Gruppe: 'Tickets SCH – Bearbeiter' }) };
zustand.queues = [q];
ROLLEN[1100] = { Id: 1100, Name: KONFIG.stufeBearbeitung, RoleTypeKind: 0 };
const soll = sollRechte(q, sollKontext());
const log = [];
await rechteAnwenden(LISTE, soll, t => log.push(t));
const reihe = zustandSp.protokoll.filter(z => /breakrole|addrole|removerole/.test(z)).map(z => z.match(/(breakrole|addrole|removerole)/)[1]);
ok(reihe[0] === 'breakrole', 'zuerst Vererbung aufheben');
ok(reihe.lastIndexOf('addrole') < reihe.indexOf('removerole'), 'erst alle Rechte vergeben, dann entziehen');
const ist = istAusRollenzuweisungen((await (await fetch(`https://dihag.sharepoint.com/sites/ticket/_api/web/lists(guid'${LISTE}')/roleassignments`)).json()).value);
const ab = rechteAbgleich(soll, ist);
gleich([ab.fehlt.length, ab.zuviel.length], [0, 0], 'danach Ist = Soll');
ok(!ist.some(p => p.titel === 'Ticket Mitglieder' || p.titel === 'Ticket Besucher'), 'Site-Mitglieder/-Besucher haben keinen Zugriff mehr auf die Liste');
ok(ist.some(p => /spo-grid-all-users/.test(p.login) && p.rollen.some(r => r.typ === 2)), 'Melder (Jeder außer Externen): Lesen');

const vorher = zustandSp.protokoll.length;
await rechteAnwenden(LISTE, soll);
ok(!zustandSp.protokoll.slice(vorher).some(z => /addrole|removerole|breakrole/.test(z)), 'zweiter Lauf ändert nichts (idempotent)');

// Eigener Direktzugang bleibt (sonst sperrte sich der Admin aus), fremder wird entzogen
zustandSp.liste.push([9, 1073741829]);
const log2 = [];
await rechteAnwenden(LISTE, soll, t => log2.push(t), { ichMail: 'admin@dihag.com' });
ok(zustandSp.liste.some(([p]) => p === 9) && log2.some(t => /eigener Zugang/.test(t)), 'eigener Direktzugang bleibt, mit Hinweis im Protokoll');
await rechteAnwenden(LISTE, soll, () => {}, { ichMail: 'jemand.anders@dihag.com' });
ok(!zustandSp.liste.some(([p]) => p === 9), 'fremder Direktzugang wird entzogen');

// Wenn Soll-Rechte nicht vergeben werden können, wird nichts entzogen
zustandSp.liste.push([4, 1073741830]);
const kaputt = [...soll, { art: 'gruppe', wert: 'Gibt es nicht', anzeige: 'Gibt es nicht', rolle: { typ: 2, anzeige: 'Lesen' }, schluessel: 'x' }];
let fehler = '';
try { await rechteAnwenden(LISTE, kaputt); } catch (e) { fehler = e.message; }
ok(fehler.length > 0, 'unbekannte Gruppe → Fehler');
ok(zustandSp.liste.some(([p, r]) => p === 4 && r === 1073741830), '… und nichts wurde entzogen');

// ── Berechtigungsstufe ──
delete ROLLEN[1100];
await stufeSicherstellen();
const stufe = await stufePruefen();
ok(stufe.vorhanden && stufe.gleich, 'Stufe Ticket-Bearbeitung angelegt und korrekt');
ok(zustandSp.rollenDef?.BasePermissions?.__metadata?.type === 'SP.BasePermissions', 'Stufe mit SP.BasePermissions angelegt');

// ── Spalten kopieren ──
gleich(schemaFuerKopie('<Field ID="{1}" Name="A" SourceID="{2}" ColName="x" RowOrdinal="0" Version="4" StaticName="A"/>'), '<Field Name="A" StaticName="A"/>', 'SchemaXml: IDs raus, Namen bleiben');
const r = await ticketListeAnlegen({ ...q, kennung: 'NEU', liste: 'Tickets-NEU', name: 'Neu' });
const neu = zustandSp.angelegt.map(a => a.xml.match(/Name="([^"]+)"/)[1]);
gleich(neu, ['Status', 'E_x002d_Mail_x002d_Adresse', 'Comment', 'Summe'], 'fehlende Spalten kopiert (auch Vorlagen-Spalten), berechnete zuletzt, Titel nicht');
ok(zustandSp.angelegt.every(a => a.optionen === 25), 'interner Name wie angegeben + Standardansicht');
ok(!zustandSp.angelegt.some(a => /SourceID|ColName/.test(a.xml)), 'keine listen-spezifischen Attribute');
gleich(zustandSp.titelUmbenannt, 'Problem', 'Anzeigename von Titel übernommen');
gleich(r.url, '/sites/ticket/Lists/TicketsNEU', 'Listen-URL für den Flow zurückgegeben');

ende();
