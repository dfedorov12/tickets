import { ok, gleich, ende } from './_pruef.mjs';
import * as M from '../js/modell.js';
import { KONFIG } from '../js/config.js';

// ── Nummern & Betreff ──
gleich(M.parseTicketNummer('sch-12'), { kennung: 'SCH', id: 12 }, 'Nummer: Kleinschreibung wird akzeptiert');
gleich(M.parseTicketNummer('SCH-'), null, 'Nummer: ohne ID → null');
gleich(M.parseTicketNummer('1AB-3'), null, 'Nummer: Kennung muss mit Buchstaben beginnen');
gleich(M.parseTicketNummer("SCH-1' or 1=1"), null, 'Nummer: Anhängsel → null');
gleich(M.tokenAusBetreff('AW: [#SCH-12] Eingangsbestätigung: Drucker'), 'SCH-12', 'Token aus Antwort');
gleich(M.tokenAusBetreff('WG: AW: [#ewa-3] x'), 'EWA-3', 'Token: Kleinschreibung → groß');
gleich(M.tokenAusBetreff('AW: Neues Ticket: 1234 (Drucker)'), 'ALT-1234', 'Token: alte Eingangsbestätigung → Archiv');
gleich(M.tokenAusBetreff('Neues Ticket: 99 (x)', 'ARCH'), 'ARCH-99', 'Token: Archiv-Kennung einstellbar');
gleich(M.tokenAusBetreff('Drucker [#] kaputt'), '', 'Token: nichts erkennbar → leer');
gleich(M.tokenAusBetreff(null), '', 'Token: null → leer');
gleich(M.betreffMitToken('SCH-12', 'AW: [#SCH-12] Drucker'), '[#SCH-12] AW: Drucker', 'Betreff: Token nicht doppelt');
gleich(M.betreffMitToken('SCH-12', ''), '[#SCH-12]', 'Betreff: leer');

// ── Adressen & Routing ──
gleich(M.domainAus('Max <MAX@Schmie-Guss.de>'), 'schmie-guss.de', 'Domain aus Adresse mit Namen');
gleich(M.domainAus('keinemail'), '', 'Domain: ohne @ leer');
gleich(M.domainsAusText('schmie-guss.de, @SHB-guss.de\n\nfoo;bar.de'), ['schmie-guss.de', 'shb-guss.de', 'bar.de'], 'Domains: Trenner, @, ungültige raus');
gleich(M.mailsAusText('a@x.de; B@x.de, a@x.de kaputt@'), ['a@x.de', 'b@x.de'], 'Mails: normalisiert, ohne Dubletten');
gleich(M.claimFuerMail(' Max@DIHAG.com '), 'i:0#.f|membership|max@dihag.com', 'Claim für Mail');
gleich(M.mailAusLogin('i:0#.f|membership|max@dihag.com'), 'max@dihag.com', 'Mail aus Claim');
gleich(M.mailAusLogin('Tickets SCH – Bearbeiter'), '', 'Mail aus Gruppenname: leer');

const q = (kennung, extra = {}) => ({ ...M.queueAusFeldern({ Title: kennung, Kennung: kennung, ListenName: 'Tickets-' + kennung }), ...extra });
const queues = [
  q('SCH', { domains: ['schmie-guss.de'] }),
  q('DIHAG', { domains: ['dihag.com'], standard: true }),
  q('GIE', { domains: ['gienanth.com'], modus: 'Hinweis', hinweis: 'x' }),
  q('ALT', { modus: 'Archiv', domains: ['alt.de'] }),
  q('AUS', { domains: ['aus.de'], aktiv: false }),
];
gleich(M.queueFuerAbsender(queues, 'x@schmie-guss.de')?.kennung, 'SCH', 'Routing: exakte Domain');
gleich(M.queueFuerAbsender(queues, 'x@unbekannt.de')?.kennung, 'DIHAG', 'Routing: unbekannt → Standard');
gleich(M.queueFuerAbsender(queues, 'x@gienanth.com')?.kennung, 'GIE', 'Routing: Hinweis-Queue wird gefunden');
gleich(M.queueFuerAbsender(queues, 'x@alt.de')?.kennung, 'DIHAG', 'Routing: Archiv nimmt nie neue Tickets');
gleich(M.queueFuerAbsender(queues, 'x@aus.de')?.kennung, 'DIHAG', 'Routing: inaktive Queue wird übergangen');
gleich(M.queueFuerAbsender(queues, 'x@sub.schmie-guss.de')?.kennung, 'DIHAG', 'Routing: Subdomain ist kein Treffer (bewusst exakt)');
gleich(M.queueFuerAbsender([], 'x@y.de'), null, 'Routing: ohne Queues null');

// ── Konfiguration ──
const zeile = { id: '7', fields: { Title: 'Schmiedeguss', Kennung: 'sch', ListenName: 'Tickets-SCH', ListenId: '{ABCDEF01-2345-6789-ABCD-EF0123456789}', Domains: 'schmie-guss.de;x.de', Bearbeiter: 'a@dihag.com;b@dihag.com', Modus: 'Ticket', Standard: false } };
const qa = M.queueAusFeldern(zeile);
gleich([qa.itemId, qa.kennung, qa.listId, qa.domains, qa.bearbeiter, qa.aktiv], [7, 'SCH', 'abcdef01-2345-6789-abcd-ef0123456789', ['schmie-guss.de', 'x.de'], ['a@dihag.com', 'b@dihag.com'], true], 'Konfig-Zeile → Queue (aktiv ohne Wert = an)');
gleich(M.queueAusFeldern({ fields: { Modus: 'Quatsch', Aktiv: false } }).modus, 'Ticket', 'Unbekannter Modus → Ticket');
gleich(M.queueAusFeldern({ fields: { ListenId: 'kein-guid' } }).listId, '', 'Ungültige Listen-ID → leer');
const felder = M.queueZuFeldern({ ...qa, domains: ['A.de', 'b.de'], bearbeiter: 'x@y.de, kaputt' });
gleich([felder.Domains, felder.Bearbeiter, felder.Aktiv], ['a.de;b.de', 'x@y.de', true], 'Queue → Felder (so liest der Flow)');
gleich(M.standardNamen('ewa'), { liste: 'Tickets-EWA', gruppe: 'Tickets EWA – Bearbeiter' }, 'Standardnamen');

const pr = M.pruefeQueues([
  { ...q('SCH'), domains: ['a.de'], gruppe: 'G', listId: 'x' },
  { ...q('SCH'), domains: ['a.de'], gruppe: 'G', listId: 'x' },
  { ...q('x'), gruppe: '' },
]);
ok(pr.some(m => m.schwere === 'fehler' && /doppelt/.test(m.text)), 'Prüfung: doppelte Kennung');
ok(pr.some(m => m.schwere === 'fehler' && /a\.de/.test(m.text)), 'Prüfung: doppelte Domain');
ok(pr.some(m => m.schwere === 'fehler' && /Kennung:/.test(m.text)), 'Prüfung: ungültige Kennung');
ok(pr.some(m => /Standard-Queue/.test(m.text)), 'Prüfung: fehlende Standard-Queue als Hinweis');
const pr2 = M.pruefeQueues([{ ...q('A1'), standard: true, gruppe: 'G', listId: 'x' }, { ...q('B1'), standard: true, gruppe: 'G', listId: 'x' }]);
ok(pr2.some(m => /Mehr als eine Standard/.test(m.text)), 'Prüfung: zwei Standard-Queues');
ok(M.pruefeQueues([{ ...q('HIN'), modus: 'Hinweis', hinweis: '' }]).some(m => /Hinweistext/.test(m.text)), 'Prüfung: Hinweis ohne Text');

// ── Rechte ──
const lesen = { High: '176', Low: '138612833' };
ok(M.hatRecht(lesen, M.RECHT.ansehen) && !M.hatRecht(lesen, M.RECHT.bearbeiten), 'Maske Lesen: ansehen ja, bearbeiten nein');
ok(M.hatRecht({ High: '0', Low: String(2 ** 31) }, 32), 'Bit 32 ohne Vorzeichenfehler');
ok(M.hatRecht({ High: String(2 ** 4), Low: '0' }, 37), 'High-Teil (Recht 37)');
gleich(M.rolleAusRechten(lesen), 'melder', 'Rolle: Lesen → Melder');
gleich(M.rolleAusRechten({ High: '2147483647', Low: '4294967295' }), 'admin', 'Rolle: Vollzugriff → Admin');
gleich(M.rolleAusRechten(null), 'keine', 'Rolle: keine Maske');
const mitwirken = { High: '432', Low: String(1 + 2 + 4 + 8 + 32 + 64 + 128 + 512 + 4096) };
const bearb = M.bearbeitungsMaske(mitwirken);
ok(M.hatRecht(bearb, M.RECHT.ueberschreiben), 'Stufe Bearbeitung: überschreibt Listenverhalten');
ok(!M.hatRecht(bearb, M.RECHT.loeschen) && !M.hatRecht(bearb, M.RECHT.versionenLoeschen), 'Stufe Bearbeitung: kein Löschen');
ok(M.hatRecht(bearb, M.RECHT.bearbeiten) && M.hatRecht(bearb, M.RECHT.hinzufuegen), 'Stufe Bearbeitung: bearbeiten + hinzufügen bleibt');
gleich(M.rolleAusRechten(bearb), 'bearbeiter', 'Rolle aus Stufe Bearbeitung → Bearbeiter');
gleich(M.bearbeitungsMaske(bearb), bearb, 'Stufe Bearbeitung: idempotent');

const ctx = {
  ownerGruppe: 'Ticket – Besitzer', dienstkonto: 'ticket@dihag.com',
  melderClaim: KONFIG.melderClaim, melderAnzeige: 'Jeder', stufeBearbeitung: 'Ticket-Bearbeitung',
  queues: [{ ...q('SCH'), gruppe: 'Tickets SCH – Bearbeiter' }, { ...q('SHB'), gruppe: 'Tickets SHB – Bearbeiter' }, { ...q('X'), gruppe: 'G-X', aktiv: false }],
};
const sollSch = M.sollRechte({ ...q('SCH'), gruppe: 'Tickets SCH – Bearbeiter' }, ctx);
gleich(sollSch.map(s => `${s.wert}=${s.rolle.anzeige}`), [
  'Ticket – Besitzer=Vollzugriff', 'i:0#.f|membership|ticket@dihag.com=Vollzugriff',
  'Tickets SCH – Bearbeiter=Ticket-Bearbeitung', `${KONFIG.melderClaim}=Lesen`,
], 'Soll-Rechte Queue-Liste');
gleich(M.sollRechte({ ...q('SCH'), gruppe: 'G' }, ctx, 'notizen').some(s => s.rolle.typ === 2), false, 'Notizliste: keine Melder');
gleich(M.sollRechte({ ...q('SCH'), gruppe: 'G' }, { ...ctx, melderSehen: false }).length, 3, 'Melder abschaltbar');
gleich(M.sollRechte({ ...q('ALT'), modus: 'Archiv', gruppe: '*' }, ctx).map(s => s.wert).slice(2), ['Tickets SCH – Bearbeiter', 'Tickets SHB – Bearbeiter'], 'Archiv „*": alle aktiven Bearbeiter-Gruppen, keine Melder');
gleich(M.sollRechte({ ...q('ALT'), modus: 'Archiv', gruppe: '' }, ctx).length, 2, 'Archiv leer: nur Admins + Flow-Konto');
gleich(M.sollRechte({ ...q('GIE'), modus: 'Hinweis' }, ctx), [], 'Hinweis-Queue: keine Liste, kein Soll');

const ist = M.istAusRollenzuweisungen([
  { PrincipalId: 3, Member: { Id: 3, LoginName: 'Ticket – Besitzer', Title: 'Ticket – Besitzer', PrincipalType: 8 }, RoleDefinitionBindings: [{ Id: 1073741829, Name: 'Vollzugriff', RoleTypeKind: 5 }] },
  { PrincipalId: 9, Member: { Id: 9, LoginName: 'Tickets SCH – Bearbeiter', Title: 'Tickets SCH – Bearbeiter', PrincipalType: 8 }, RoleDefinitionBindings: [{ Id: 1100, Name: 'ticket-bearbeitung', RoleTypeKind: 0 }, { Id: 1073741827, Name: 'Mitwirken', RoleTypeKind: 3 }] },
  { PrincipalId: 4, Member: { Id: 4, LoginName: 'Ticket – Mitglieder', Title: 'Ticket – Mitglieder', PrincipalType: 8 }, RoleDefinitionBindings: { results: [{ Id: 1073741827, Name: 'Bearbeiten', RoleTypeKind: 6 }] } },
  { PrincipalId: 12, Member: { Id: 12, LoginName: 'i:0#.f|membership|x@dihag.com', Title: 'X', PrincipalType: 1 }, RoleDefinitionBindings: [{ Id: 1073741825, Name: 'Beschränkter Zugriff', RoleTypeKind: 1 }] },
]);
const ab = M.rechteAbgleich(sollSch, ist);
gleich(ab.ok.map(s => s.wert), ['Ticket – Besitzer', 'Tickets SCH – Bearbeiter'], 'Abgleich: vorhandene Soll-Rechte (Name ohne Groß/klein)');
gleich(ab.fehlt.map(s => s.wert), ['i:0#.f|membership|ticket@dihag.com', KONFIG.melderClaim], 'Abgleich: fehlende Rechte');
gleich(ab.zuviel.map(z => `${z.titel}/${z.rolle.name}`), ['Tickets SCH – Bearbeiter/Mitwirken', 'Ticket – Mitglieder/Bearbeiten'], 'Abgleich: zu viel (beschränkter Zugriff zählt nicht)');
gleich(M.einstellungsAbgleich({ ReadSecurity: 1, NoCrawl: true }, { ReadSecurity: 2, NoCrawl: true }), [{ feld: 'ReadSecurity', ist: 1, soll: 2 }], 'Einstellungs-Abgleich');

// ── Tickets ──
gleich(['high', '(1) Hoch', 'Mittel', 'low', 'Critical', ''].map(M.normPrio), ['Hoch', 'Hoch', 'Normal', 'Niedrig', 'Kritisch', ''], 'Priorität vereinheitlichen');
gleich(['high', 'LOW', 'normal', undefined].map(M.prioAusWichtigkeit), ['Hoch', 'Niedrig', 'Normal', 'Normal'], 'Priorität aus Mail-Wichtigkeit');
gleich(M.passendeAuswahl(['(1) Hoch', '(2) Normal'], 'Hoch', M.normPrio), '(1) Hoch', 'Passender Auswahlwert');
gleich(M.passendeAuswahl(['A'], 'B'), 'B', 'Kein Auswahltreffer → Wert bleibt');

const qSch = { ...q('SCH') };
const t = M.ticketAusSp({
  Id: 12, Title: 'Drucker', Status: 'Neu', Priority: 'high', Werk: 'SCH',
  Assignedto0: [{ Id: 5, Title: 'Henry Quinque', EMail: 'Henry.Quinque@dihag.com' }],
  Issueloggedby: { Id: 8, Title: 'Max M', EMail: 'max@schmie-guss.de' },
  E_x002d_Mail_x002d_Adresse: 'Max@Schmie-Guss.de', Author: { Title: 'Ticket', EMail: 'ticket@dihag.com' },
  Created: '2026-09-20T08:00:00Z', Modified: '2026-09-21T08:00:00Z', DateReported: '2026-09-20T07:59:00Z', Attachments: true, Kategorie: 'Hardware',
}, qSch, { kategorie: 'Kategorie' });
gleich([t.nummer, t.prio, t.bearbeiter[0].mail, t.melderMail, t.kategorie, t.anhaenge], ['SCH-12', 'Hoch', 'henry.quinque@dihag.com', 'max@schmie-guss.de', 'Hardware', true], 'Ticket aus SharePoint');
const leer = M.ticketAusSp({ Id: 1, Assignedto0: { results: [] }, Issueloggedby: null }, qSch);
gleich([leer.bearbeiter, leer.melder, leer.titel], [[], null, ''], 'Ticket ohne Personen');
ok(M.istMeineAnfrage(t, 'MAX@schmie-guss.de'), 'Meine Anfrage über Melder-Mail');
ok(M.istMirZugewiesen(t, 'henry.quinque@dihag.com'), 'Mir zugewiesen');

const jetzt = new Date('2026-09-25T12:00:00Z');
const mk = (id, extra) => ({ ...leer, id, nummer: 'SCH-' + id, prio: 'Normal', status: 'Neu', gemeldetAm: '2026-09-25T10:00:00Z', geaendert: '2026-09-25T10:00:00Z', bearbeiter: [], ...extra });
ok(!M.istUeberfaellig(mk(1), jetzt), 'SLA: frisches Ticket nicht überfällig');
ok(M.istUeberfaellig(mk(2, { prio: 'Kritisch', gemeldetAm: '2026-09-25T07:00:00Z' }), jetzt), 'SLA: Kritisch nach 5 Std. überfällig');
ok(!M.istUeberfaellig(mk(3, { prio: 'Kritisch', gemeldetAm: '2026-09-01T00:00:00Z', status: 'Warten auf Rückmeldung' }), jetzt), 'SLA: Wartend zählt nicht');
ok(!M.istUeberfaellig(mk(4, { gemeldetAm: '2026-01-01T00:00:00Z', status: 'Erledigt' }), jetzt), 'SLA: Erledigt zählt nicht');
ok(M.istOffen('Unbekannter Status'), 'Unbekannter Status gilt als offen');

const liste = [
  mk(1, { titel: 'Drucker kaputt', bearbeiter: [{ name: 'A', mail: 'a@x.de' }] }),
  mk(2, { titel: 'VPN', status: 'Erledigt', prio: 'Hoch' }),
  mk(3, { titel: 'Drucker Toner', prio: 'Kritisch', gemeldetAm: '2026-09-24T00:00:00Z' }),
];
gleich(M.filtereTickets(liste, { status: 'offen' }).map(x => x.id), [1, 3], 'Filter: offen');
gleich(M.filtereTickets(liste, { suche: 'drucker toner' }).map(x => x.id), [3], 'Filter: Suche mit mehreren Wörtern');
gleich(M.filtereTickets(liste, { suche: 'sch-2' }).map(x => x.id), [2], 'Filter: Suche nach Nummer');
gleich(M.filtereTickets(liste, { zuweisung: 'ich' }, 'A@x.de').map(x => x.id), [1], 'Filter: mir zugewiesen');
gleich(M.filtereTickets(liste, { zuweisung: 'keiner' }).map(x => x.id), [2, 3], 'Filter: nicht zugewiesen');
gleich(M.filtereTickets(liste, { ueberfaellig: true }, '', jetzt).map(x => x.id), [3], 'Filter: überfällig');
gleich(M.sortiereTickets(liste, 'prio').map(x => x.id), [3, 2, 1], 'Sortierung nach Priorität');
gleich(M.sortiereTickets(liste).map(x => x.id), [2, 1, 3], 'Sortierung: neueste Meldung zuerst (gleiche Zeit → höhere ID)');

const kz = M.kennzahlen(liste, jetzt);
gleich([kz.offen, kz.unzugewiesen, kz.ueberfaellig, kz.erledigt30], [2, 1, 1, 1], 'Kennzahlen');
const verlauf = M.verlaufNachWoche(liste, 2, jetzt);
gleich(verlauf.length, 2, 'Verlauf: Anzahl Wochen');
gleich(verlauf[1].eingang, 3, 'Verlauf: Eingang aktuelle Woche');
gleich(M.kalenderwoche(new Date('2026-09-25T12:00:00')), 39, 'Kalenderwoche');
gleich(M.zaehleNach(liste, x => x.prio), [{ wert: 'Hoch', anzahl: 1 }, { wert: 'Kritisch', anzahl: 1 }, { wert: 'Normal', anzahl: 1 }], 'Zählen nach Priorität');

// ── Navigation ──
gleich(M.parseRoute('#/t/sch-12'), { seite: 'ticket', nummer: 'SCH-12' }, 'Route: Ticket');
gleich(M.parseRoute('#/t/<script>'), { seite: '' }, 'Route: kaputte Nummer → Start');
gleich(M.parseRoute('#/verwaltung/rechte'), { seite: 'verwaltung', bereich: 'rechte' }, 'Route: Verwaltung');
gleich(M.parseRoute('#/verwaltung/xyz'), { seite: 'verwaltung', bereich: 'queues' }, 'Route: Verwaltung unbekannt → Queues');
gleich(M.parseRoute('#/meine'), { seite: 'meine' }, 'Route: Meine');
gleich(M.parseRoute(''), { seite: '' }, 'Route: leer');
gleich(M.ticketLink('https://a/b/', 'SCH-1'), 'https://a/b/#/t/SCH-1', 'Ticket-Link');

ende();
