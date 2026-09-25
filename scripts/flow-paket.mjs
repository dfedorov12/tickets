#!/usr/bin/env node
/**
 * Power-Automate-Flow „Helpdesk v2" als Importpaket erzeugen
 * ==========================================================
 *   node scripts/flow-paket.mjs        → flow/Helpdesk-v2.zip + flow/paket/ (lesbar)
 *
 * Ein generischer Flow statt je Werk kopierter Zweige: Welche Domain in welche Liste
 * geht, wer zugewiesen wird und ob nur ein Hinweis zurückgeht, liest er aus der Liste
 * „TicketQueues" (gepflegt in der App). Neues Werk = neue Zeile, kein Flow-Umbau.
 *
 * Ablauf je Mail an das Ticketpostfach:
 *   1. Schleifenschutz (eigene Mails, Abwesenheitsnotizen, Mailer-Daemon)
 *   2. Konfiguration laden
 *   3. Ticketnummer im Betreff ([#SCH-12] oder alt „Neues Ticket: 123")?
 *      → Antwort: als Kommentar anhängen, Anhänge ergänzen, Status wieder öffnen,
 *        Bearbeiter informieren
 *   4. Sonst neues Ticket: Queue nach Domain (sonst Standard), Modus „Hinweis" → nur
 *      Antwort-Mail; sonst Ticket anlegen, Werte/Personen setzen, „Erstellt von" =
 *      Melder, Original-Mail (.eml) + Anhänge anhängen, Eingangsbestätigung mit
 *      [#Nummer], optional Zuständige informieren
 *   Fehler → Mail an den Admin mit Link zum Flow-Lauf.
 *
 * Die Ausdrücke spiegeln js/modell.js (tokenAusBetreff, queueFuerAbsender); die
 * Tests (tests/flow.test.mjs) werten sie mit einem kleinen WDL-Auswerter gegen die
 * JavaScript-Fassung aus.
 */
import fs from 'fs';
import path from 'path';
import zlib from 'zlib';
import { fileURLToPath } from 'url';
import { KONFIG, siteUrl } from '../js/config.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Feste IDs → das Paket ist bei gleichem Inhalt byte-gleich (Test prüft Aktualität).
const FLOW_ID = '5d1c7b0e-2f7a-4c1e-9b1d-7e2a4c6f0a21';
const RES = {
  flow: 'b2f0c4de-7d1a-4f3b-8e61-1c9a0d5e7f42',
  apiOutlook: 'ac553e49-a869-41ab-979f-587fbd6fb09c',
  apiSharepoint: '3c0c12f4-fe78-4424-9fe4-8354beb9bcfe',
  apiKonvertierung: '6f7e2a10-3b5c-4d8e-a1f2-9c0b7d6e5a43',
  conOutlook: '9e513651-01ba-4ccd-bccf-4ccf07fc9881',
  conSharepoint: '22d13a71-79e5-404c-b2d1-070a447a78da',
  conKonvertierung: '8a4d3c2b-1e0f-4a9b-b7c6-5d4e3f2a1b09',
};
// Posteingang von ticket@dihag.com (aus dem bisherigen Flow übernommen).
const POSTEINGANG = 'Id::AAMkADlkOWIyYWZhLTNkZTMtNGE3MS04NDQ5LTI0MjZhNTQ0MWJhYwAuAAAAAACHPNBSpfHVT6UmJVKUkxEKAQAuCOzBabrOSZOZR9xisADKAAAAAAEMAAA=';

const SITE = siteUrl();
const LF = "decodeUriComponent('%0A')";

// ── Bausteine ────────────────────────────────────────────────────────────────

const auth = "@parameters('$authentication')";
const outlook = (operationId, parameters) => ({
  type: 'OpenApiConnection',
  inputs: { host: { apiId: '/providers/Microsoft.PowerApps/apis/shared_office365', connectionName: 'shared_office365', operationId }, parameters, authentication: auth },
});
const sharepoint = (operationId, parameters) => ({
  type: 'OpenApiConnection',
  inputs: { host: { apiId: '/providers/Microsoft.PowerApps/apis/shared_sharepointonline', connectionName: 'shared_sharepointonline', operationId }, parameters: { dataset: SITE, ...parameters }, authentication: auth },
});
/** „An SharePoint eine HTTP-Anforderung senden" (Standard-Aktion, läuft als Flow-Konto). */
const spHttp = (method, uri, body) => sharepoint('HttpRequest', {
  'parameters/method': method,
  'parameters/uri': uri,
  'parameters/headers': { Accept: 'application/json;odata=nometadata', 'Content-Type': 'application/json;odata=nometadata' },
  ...(body !== undefined ? { 'parameters/body': body } : {}),
});
const compose = inputs => ({ type: 'Compose', inputs });
const wenn = (expression, actions, sonst = {}) => ({ type: 'If', expression, actions, else: { actions: sonst } });
const nach = (aktion, runAfter) => ({ ...aktion, runAfter });
const ok = name => ({ [name]: ['Succeeded'] });
const egal = name => ({ [name]: ['Succeeded', 'Failed', 'Skipped', 'TimedOut'] });
const fehlschlag = name => ({ [name]: ['Failed', 'TimedOut'] });
const ende = (runStatus, message) => ({ type: 'Terminate', inputs: runStatus === 'Failed' ? { runStatus, runError: { code: 'Ticketsystem', message } } : { runStatus } });

/** Aktionen in Reihe schalten: jede läuft nach der vorigen (außer sie bringt runAfter mit). */
function kette(eintraege) {
  const out = {};
  let vorher = null;
  for (const [name, aktion] of eintraege) {
    out[name] = aktion.runAfter ? aktion : { ...aktion, runAfter: vorher ? ok(vorher) : {} };
    vorher = name;
  }
  return out;
}

const lauflink = "concat('https://make.powerautomate.com/environments/', workflow()?['tags']?['environmentName'], '/flows/', workflow()?['name'], '/runs/', workflow()?['run']?['name'])";
const adminMail = (betreff, text) => outlook('SendEmailV2', {
  'emailMessage/To': KONFIG.adminPostfach,
  'emailMessage/Subject': betreff,
  'emailMessage/Body': `<p>${text}</p><p><b>Absender:</b> @{outputs('Absender')}<br><b>Betreff:</b> @{outputs('Betreff')}</p><p><a href="@{${lauflink}}">Flow-Lauf öffnen</a> · Die Mail liegt weiter im Posteingang von ${KONFIG.ticketPostfach}.</p>`,
  'emailMessage/Importance': 'High',
});

// ── Ausdrücke (gespiegelt aus js/modell.js) ──────────────────────────────────

/** tokenAusBetreff(): [#KEN-12] → KEN-12; „Neues Ticket: 123" → ALT-123; sonst ''. */
export const AUSDRUCK_TICKETNUMMER = "@if(contains(outputs('Betreff'), '[#'), toUpper(trim(first(split(last(split(outputs('Betreff'), '[#')), ']')))), "
  + `if(contains(outputs('Betreff'), 'Neues Ticket: '), concat('${KONFIG.archivKennung}-', first(split(trim(last(split(outputs('Betreff'), 'Neues Ticket: '))), ' '))), ''))`;

/** queueFuerAbsender(): exakte Domain (ohne Archiv), Domains in der Liste mit ';' getrennt. */
export const AUSDRUCK_DOMAIN_TREFFER = "@and(not(equals(item()?['Modus']?['Value'], 'Archiv')), contains(concat(';', toLower(coalesce(item()?['Domains'], '')), ';'), concat(';', outputs('Domain'), ';')))";
export const AUSDRUCK_STANDARD = "@and(equals(item()?['Standard'], true), not(equals(item()?['Modus']?['Value'], 'Archiv')))";

/** Antworttext ohne zitierten Verlauf, gekürzt (SharePoint-Kommentare sind begrenzt). */
export const AUSDRUCK_ANTWORTTEXT = `@take(trim(first(split(first(split(first(split(first(split(first(split(body('Html_zu_Text'), '-----Ursprüngliche Nachricht-----')), '-----Original Message-----')), '________________________________')), concat(${LF}, 'Von: '))), concat(${LF}, 'From: ')))), 1800)`;

/** Personenfeld-Wert aus „a@x;b@y" für ValidateUpdateListItem. */
const personen = quelle => `@{concat('[{''Key'':''i:0#.f|membership|', join(split(${quelle}, ';'), '''},{''Key'':''i:0#.f|membership|'), '''}]')}`;

/** Anhänge, die ins Ticket gehören: alle echten, eingebettete nur ab 15 KB (keine Signatur-Logos). */
const ANHANG_FILTER = "@or(not(equals(item()?['isInline'], true)), greater(coalesce(item()?['size'], 999999), 15000))";

// ── Antwort auf ein bestehendes Ticket ───────────────────────────────────────

const Q_A = "first(body('Antwort_Queue'))";
const ITEM_A = `lists(guid'@{${Q_A}?['ListenId']}')/items(@{int(outputs('TicketId'))})`;

const antwortZweig = kette([
  ['Html_zu_Text', {
    type: 'OpenApiConnection',
    inputs: { host: { apiId: '/providers/Microsoft.PowerApps/apis/shared_conversionservice', connectionName: 'shared_conversionservice', operationId: 'HtmlToText' }, parameters: { Content: "@triggerOutputs()?['body/body']" }, authentication: auth },
  }],
  ['Antworttext', compose(AUSDRUCK_ANTWORTTEXT)],
  ['Kommentar_Inhalt', compose({ text: `✉ Antwort per Mail von @{outputs('Absender')}:@{${LF}}@{${LF}}@{if(empty(outputs('Antworttext')), '(ohne Text – siehe Anhänge)', outputs('Antworttext'))}` })],
  ['Kommentar_anfuegen', spHttp('POST', `_api/web/lists(guid'@{${Q_A}?['ListenId']}')/GetItemById(@{int(outputs('TicketId'))})/Comments`, "@string(outputs('Kommentar_Inhalt'))")],
  ['Wieder_oeffnen', nach(wenn(
    { or: [{ equals: ["@body('Ticket_lesen')?['Status']", 'Warten auf Rückmeldung'] }, { equals: ["@body('Ticket_lesen')?['Status']", 'Erledigt'] }] },
    kette(validate('Status_in_Bearbeitung', [{ FieldName: 'Status', FieldValue: 'In Bearbeitung' }], { item: ITEM_A })),
  ), ok('Kommentar_anfuegen'))],
  ['Antwort_Anhaenge', nach({ type: 'Query', inputs: { from: "@triggerOutputs()?['body/attachments']", where: ANHANG_FILTER } }, egal('Wieder_oeffnen'))],
  ['Antwort_Anhaenge_speichern', {
    type: 'Foreach',
    foreach: "@body('Antwort_Anhaenge')",
    actions: {
      Antwort_Anhang: nach(sharepoint('CreateAttachment', {
        table: `@${Q_A}?['ListenId']`,
        itemId: "@int(outputs('TicketId'))",
        displayName: "@{formatDateTime(utcNow(), 'yyyyMMdd-HHmm')}_@{items('Antwort_Anhaenge_speichern')?['name']}",
        body: "@items('Antwort_Anhaenge_speichern')?['contentBytes']",
      }), {}),
    },
    runAfter: ok('Antwort_Anhaenge'),
  }],
  ['Bearbeiter_Mails', nach({ type: 'Select', inputs: { from: "@coalesce(body('Ticket_lesen')?['Assignedto0'], json('[]'))", select: "@item()?['EMail']" } }, egal('Antwort_Anhaenge_speichern'))],
  ['Empfaenger', compose(`@if(greater(length(body('Bearbeiter_Mails')), 0), join(body('Bearbeiter_Mails'), ';'), coalesce(${Q_A}?['Bearbeiter'], ''))`)],
  ['Bearbeiter_informieren', wenn(
    { not: { equals: ["@outputs('Empfaenger')", ''] } },
    {
      Info_an_Bearbeiter: nach(outlook('SendEmailV2', {
        'emailMessage/To': "@outputs('Empfaenger')",
        'emailMessage/Subject': "Neue Antwort zu [#@{outputs('Ticketnummer')}] @{body('Ticket_lesen')?['Title']}",
        'emailMessage/Body': `<p><b>@{outputs('Absender')}</b> hat auf das Ticket <b>@{outputs('Ticketnummer')}</b> geantwortet:</p><blockquote>@{replace(outputs('Antworttext'), ${LF}, '<br>')}</blockquote><p><a href="${KONFIG.appUrl}#/t/@{outputs('Ticketnummer')}">Ticket in der App öffnen</a> – bitte dort antworten, damit der Melder die Nachricht bekommt.</p>`,
        'emailMessage/Importance': 'Normal',
      }), {}),
    },
  )],
]);

// ── Neues Ticket ─────────────────────────────────────────────────────────────

const Z = "outputs('Ziel')";
const ITEM_N = `lists(guid'@{${Z}?['ListenId']}')/items(@{outputs('Neue_Id')})`;
/**
 * ValidateUpdateListItem in zwei Schritten: erst der Inhalt als Compose (nur dort werden
 * @{…} ausgewertet und als JSON sauber maskiert), dann der Aufruf mit string(outputs(…)).
 */
function validate(name, werte, { item = ITEM_N, neueVersion = true, runAfter } = {}) {
  const inhalt = compose({ formValues: werte, bNewDocumentUpdate: !neueVersion });
  return [
    [name + '_Inhalt', runAfter ? nach(inhalt, runAfter) : inhalt],
    [name, spHttp('POST', `_api/web/${item}/ValidateUpdateListItem`, `@string(outputs('${name}_Inhalt'))`)],
  ];
}

const neuZweig = kette([
  ['Domain', compose("@last(split(outputs('Absender'), '@'))")],
  ['Queue_nach_Domain', { type: 'Query', inputs: { from: "@outputs('Queues')", where: AUSDRUCK_DOMAIN_TREFFER } }],
  ['Standard_Queue', { type: 'Query', inputs: { from: "@outputs('Queues')", where: AUSDRUCK_STANDARD } }],
  ['Ziel', compose("@if(greater(length(body('Queue_nach_Domain')), 0), first(body('Queue_nach_Domain')), if(greater(length(body('Standard_Queue')), 0), first(body('Standard_Queue')), null))")],
  ['Keine_Queue', wenn(
    { equals: [`@empty(${Z})`, true] },
    kette([
      ['Admin_keine_Queue', adminMail('Ticketsystem: keine Queue für Absender', 'Für diese Mail gibt es keine passende Queue und keine Standard-Queue. Bitte in der App unter Verwaltung → Queues eine Standard-Queue festlegen.')],
      ['Ende_keine_Queue', nach(ende('Cancelled'), egal('Admin_keine_Queue'))],
    ]),
  )],
  ['Nur_Hinweis', wenn(
    { equals: [`@${Z}?['Modus']?['Value']`, 'Hinweis'] },
    kette([
      ['Hinweis_senden', outlook('ReplyToV3', {
        messageId: "@triggerOutputs()?['body/id']",
        'replyParameters/Body': `<p>@{replace(coalesce(${Z}?['Hinweistext'], ''), ${LF}, '<br>')}</p>`,
        'replyParameters/ReplyAll': false,
      })],
      ['Ende_Hinweis', nach(ende('Succeeded'), egal('Hinweis_senden'))],
    ]),
  )],
  ['Neu_Inhalt', compose({
    listItemCreateInfo: { FolderPath: { DecodedUrl: `@{${Z}?['ListenUrl']}` }, UnderlyingObjectType: 0 },
    formValues: [
      { FieldName: 'Title', FieldValue: "@{take(outputs('Betreff'), 255)}" },
      { FieldName: 'E_x002d_Mail_x002d_Adresse', FieldValue: "@{outputs('Absender')}" },
      { FieldName: 'Description', FieldValue: "@{take(coalesce(triggerOutputs()?['body/body'], ''), 60000)}" },
    ],
    bNewDocumentUpdate: false,
  })],
  ['Ticket_anlegen', spHttp('POST', `_api/web/lists(guid'@{${Z}?['ListenId']}')/AddValidateUpdateItemUsingPath`, "@string(outputs('Neu_Inhalt'))")],
  ['Fehler_Anlage', {
    type: 'Scope',
    actions: kette([
      ['Admin_Anlage', adminMail('Ticketsystem: Ticket konnte nicht angelegt werden', "Das Anlegen in der Liste @{outputs('Ziel')?['ListenName']} ist fehlgeschlagen (Liste eingerichtet? Flow-Konto berechtigt?).")],
      ['Ende_Anlage', nach(ende('Failed', 'Ticket konnte nicht angelegt werden'), egal('Admin_Anlage'))],
    ]),
    runAfter: fehlschlag('Ticket_anlegen'),
  }],
  ['Id_Feld', nach({ type: 'Query', inputs: { from: "@body('Ticket_anlegen')?['value']", where: "@equals(item()?['FieldName'], 'Id')" } }, ok('Ticket_anlegen'))],
  ['Neue_Id', compose("@if(greater(length(body('Id_Feld')), 0), first(body('Id_Feld'))?['FieldValue'], '')")],
  ['Id_fehlt', wenn(
    { equals: ["@outputs('Neue_Id')", ''] },
    kette([
      ['Admin_Id', adminMail('Ticketsystem: SharePoint hat das Ticket abgelehnt', "Antwort von SharePoint: @{string(body('Ticket_anlegen'))}")],
      ['Ende_Id', nach(ende('Failed', 'Ticket ohne ID'), egal('Admin_Id'))],
    ]),
  )],
  ['Nummer', compose(`@concat(${Z}?['Kennung'], '-', outputs('Neue_Id'))`)],
  // Einzeln und fehlertolerant: Ein unbekannter Auswahlwert oder ein externer Melder soll das Ticket nicht verhindern.
  ...validate('Status_Werk_setzen', [{ FieldName: 'Status', FieldValue: 'Neu' }, { FieldName: 'Werk', FieldValue: `@{${Z}?['Werk']}` }]),
  ...validate('Prio_setzen', [{ FieldName: 'Priority', FieldValue: "@{if(equals(triggerOutputs()?['body/importance'], 'high'), 'Hoch', if(equals(triggerOutputs()?['body/importance'], 'low'), 'Niedrig', 'Normal'))}" }], { runAfter: egal('Status_Werk_setzen') }),
  ['Zustaendige_setzen', nach(wenn(
    { not: { equals: [`@coalesce(${Z}?['Bearbeiter'], '')`, ''] } },
    kette(validate('Bearbeiter_eintragen', [{ FieldName: 'Assignedto0', FieldValue: personen(`${Z}?['Bearbeiter']`) }])),
  ), egal('Prio_setzen'))],
  ...validate('Melder_setzen', [{ FieldName: 'Issueloggedby', FieldValue: personen("outputs('Absender')") }], { runAfter: egal('Zustaendige_setzen') }),
  // „Erstellt von" = Melder: so sieht er das Ticket (Liste: nur eigene Elemente lesen).
  ...validate('Erstellt_von_setzen', [{ FieldName: 'Author', FieldValue: personen("outputs('Absender')") }], { neueVersion: false, runAfter: egal('Melder_setzen') }),
  ['Mail_exportieren', nach(outlook('ExportEmail_V2', { messageId: "@triggerOutputs()?['body/id']" }), egal('Erstellt_von_setzen'))],
  ['Original_anhaengen', sharepoint('CreateAttachment', {
    table: `@${Z}?['ListenId']`, itemId: "@int(outputs('Neue_Id'))", displayName: 'Original-Mail.eml', body: "@body('Mail_exportieren')",
  })],
  ['Neu_Anhaenge', nach({ type: 'Query', inputs: { from: "@triggerOutputs()?['body/attachments']", where: ANHANG_FILTER } }, egal('Original_anhaengen'))],
  ['Neu_Anhaenge_speichern', {
    type: 'Foreach',
    foreach: "@body('Neu_Anhaenge')",
    actions: {
      Neu_Anhang: nach(sharepoint('CreateAttachment', {
        table: `@${Z}?['ListenId']`,
        itemId: "@int(outputs('Neue_Id'))",
        displayName: "@{if(equals(items('Neu_Anhaenge_speichern')?['isInline'], true), concat('Bild-', substring(guid(), 0, 6), '-'), '')}@{items('Neu_Anhaenge_speichern')?['name']}",
        body: "@items('Neu_Anhaenge_speichern')?['contentBytes']",
      }), {}),
    },
    runAfter: ok('Neu_Anhaenge'),
  }],
  ['Eingangsbestaetigung', nach(outlook('ReplyToV3', {
    messageId: "@triggerOutputs()?['body/id']",
    'replyParameters/Subject': "[#@{outputs('Nummer')}] Eingangsbestätigung: @{outputs('Betreff')}",
    'replyParameters/Body': `<p>Liebe Kollegin, lieber Kollege,</p><p>Ihre Anfrage ist als Ticket <b>@{outputs('Nummer')}</b> bei der IT eingegangen und wird schnellstmöglich bearbeitet.</p><p><a href="${KONFIG.appUrl}#/t/@{outputs('Nummer')}">Ticket ansehen</a> – dort finden Sie jederzeit den aktuellen Stand unter „Meine Anfragen".</p><p>Möchten Sie etwas ergänzen? Antworten Sie einfach auf diese Mail; die Nummer im Betreff ordnet Ihre Antwort dem Ticket zu.</p><p>Vielen Dank!<br>Ihr IT-Team</p>`,
    'replyParameters/ReplyAll': true,
    'replyParameters/Importance': 'Normal',
  }), egal('Neu_Anhaenge_speichern'))],
  ['Zustaendige_informieren', nach(wenn(
    { and: [{ equals: [`@${Z}?['Benachrichtigen']`, true] }, { not: { equals: [`@coalesce(${Z}?['Bearbeiter'], '')`, ''] } }] },
    {
      Info_neues_Ticket: nach(outlook('SendEmailV2', {
        'emailMessage/To': `@${Z}?['Bearbeiter']`,
        'emailMessage/Subject': "Neues Ticket @{outputs('Nummer')}: @{outputs('Betreff')}",
        'emailMessage/Body': `<p>Neues Ticket in der Queue <b>@{${Z}?['Title']}</b> von @{outputs('Absender')}:</p><p><b>@{outputs('Betreff')}</b></p><p>@{triggerOutputs()?['body/bodyPreview']}</p><p><a href="${KONFIG.appUrl}#/t/@{outputs('Nummer')}">Ticket öffnen</a></p>`,
        'emailMessage/Importance': "@{if(equals(triggerOutputs()?['body/importance'], 'high'), 'High', 'Normal')}",
      }), {}),
    },
  ), egal('Eingangsbestaetigung'))],
]);

// ── Gesamtablauf ─────────────────────────────────────────────────────────────

export function bauDefinition() {
  const actions = kette([
    ['Absender', compose("@toLower(trim(coalesce(triggerOutputs()?['body/from'], '')))")],
    ['Betreff', compose("@coalesce(triggerOutputs()?['body/subject'], '(ohne Betreff)')")],
    ['IstAntwort', { type: 'InitializeVariable', inputs: { variables: [{ name: 'IstAntwort', type: 'boolean', value: false }] } }],
    ['Schleifenschutz', wenn(
      {
        or: [
          { equals: ["@outputs('Absender')", KONFIG.ticketPostfach] },
          { startsWith: ["@toLower(outputs('Betreff'))", 'automatische antwort'] },
          { startsWith: ["@toLower(outputs('Betreff'))", 'automatic reply'] },
          { startsWith: ["@toLower(outputs('Betreff'))", 'abwesend'] },
          { startsWith: ["@toLower(outputs('Betreff'))", 'unzustellbar'] },
          { startsWith: ["@toLower(outputs('Betreff'))", 'undeliverable'] },
          { startsWith: ["@outputs('Absender')", 'mailer-daemon'] },
          { startsWith: ["@outputs('Absender')", 'postmaster'] },
          { contains: ["@outputs('Absender')", 'noreply'] },
          { contains: ["@outputs('Absender')", 'no-reply'] },
        ],
      },
      { Ende_automatisch: nach(ende('Cancelled'), {}) },
    )],
    ['Konfiguration_laden', sharepoint('GetItems', { table: KONFIG.konfigListe, $filter: 'Aktiv eq 1', $top: 500 })],
    ['Fehler_Konfiguration', {
      type: 'Scope',
      actions: kette([
        ['Admin_Konfiguration', adminMail('Ticketsystem: Konfiguration nicht lesbar', `Die Liste ${KONFIG.konfigListe} konnte nicht gelesen werden (existiert sie? darf ${KONFIG.ticketPostfach} sie lesen?).`)],
        ['Ende_Konfiguration', nach(ende('Failed', 'Konfiguration nicht lesbar'), egal('Admin_Konfiguration'))],
      ]),
      runAfter: fehlschlag('Konfiguration_laden'),
    }],
    ['Queues', nach(compose("@body('Konfiguration_laden')?['value']"), ok('Konfiguration_laden'))],
    ['Ticketnummer', compose(AUSDRUCK_TICKETNUMMER)],
    ['Kennung', compose("@if(empty(outputs('Ticketnummer')), '', first(split(outputs('Ticketnummer'), '-')))")],
    ['TicketId', compose("@if(empty(outputs('Ticketnummer')), '', last(split(outputs('Ticketnummer'), '-')))")],
    ['Antwort_Queue', { type: 'Query', inputs: { from: "@outputs('Queues')", where: "@and(not(equals(outputs('Kennung'), '')), equals(toUpper(coalesce(item()?['Kennung'], '')), outputs('Kennung')), not(equals(coalesce(item()?['ListenId'], ''), '')))" } }],
    ['Antwort_pruefen', wenn(
      { greater: ["@length(body('Antwort_Queue'))", 0] },
      kette([
        // Schlägt fehl, wenn es das Ticket nicht (mehr) gibt oder die ID keine Zahl ist → dann neues Ticket.
        ['Ticket_lesen', spHttp('GET', `_api/web/lists(guid'@{${Q_A}?['ListenId']}')/items(@{int(outputs('TicketId'))})?$select=Id,Title,Status,Assignedto0/EMail&$expand=Assignedto0`)],
        ['Antwort_erkannt', { type: 'SetVariable', inputs: { name: 'IstAntwort', value: true } }],
      ]),
    )],
    ['Verzweigung', nach(wenn({ equals: ["@variables('IstAntwort')", true] }, antwortZweig, neuZweig), { Antwort_pruefen: ['Succeeded', 'Failed'] })],
  ]);

  return {
    $schema: 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#',
    contentVersion: '1.0.0.0',
    parameters: { $authentication: { defaultValue: {}, type: 'SecureObject' }, $connections: { defaultValue: {}, type: 'Object' } },
    triggers: {
      'Bei_Eingang_einer_neuen_E-Mail_(V3)': {
        splitOn: "@triggerOutputs()?['body/value']",
        metadata: { [POSTEINGANG]: 'Posteingang' },
        type: 'OpenApiConnectionNotification',
        inputs: {
          parameters: { includeAttachments: true, importance: 'Any', fetchOnlyWithAttachment: false, folderPath: POSTEINGANG },
          host: { apiId: '/providers/Microsoft.PowerApps/apis/shared_office365', connectionName: 'shared_office365', operationId: 'OnNewEmailV3' },
          authentication: auth,
        },
      },
    },
    actions,
  };
}

const VERBINDUNGEN = {
  shared_office365: { connectionName: 'shared-office365-51276fb3-f156-458e-8e20-6e10c333af31', source: 'Embedded', id: '/providers/Microsoft.PowerApps/apis/shared_office365', tier: 'NotSpecified', apiName: 'office365' },
  shared_sharepointonline: { connectionName: 'shared-sharepointonl-d01ec634-24e0-4793-b043-00a25695b7e6', source: 'Embedded', id: '/providers/Microsoft.PowerApps/apis/shared_sharepointonline', tier: 'NotSpecified', apiName: 'sharepointonline' },
  shared_conversionservice: { connectionName: 'shared-conversionser-2b7c9e41-5a3d-4f6b-8c1e-0d9a7b6c5e4f', source: 'Embedded', id: '/providers/Microsoft.PowerApps/apis/shared_conversionservice', tier: 'NotSpecified', apiName: 'conversionservice' },
};

/** Dateien des Legacy-Importpakets (wie ein Export aus „Meine Flows → Exportieren → Paket"). */
export function bauPaket() {
  const definition = {
    name: FLOW_ID,
    id: `/providers/Microsoft.Flow/flows/${FLOW_ID}`,
    type: 'Microsoft.Flow/flows',
    properties: {
      apiId: '/providers/Microsoft.PowerApps/apis/shared_logicflows',
      displayName: 'Helpdesk v2',
      definition: bauDefinition(),
      connectionReferences: VERBINDUNGEN,
      flowFailureAlertSubscribed: false,
      isManaged: false,
    },
  };
  const api = (id, name, anzeige) => ({ id: `/providers/Microsoft.PowerApps/apis/${name}`, name, type: 'Microsoft.PowerApps/apis', suggestedCreationType: 'Existing', details: { displayName: anzeige }, configurableBy: 'System', hierarchy: 'Child', dependsOn: [] });
  const con = (apiRes, anzeige) => ({ type: 'Microsoft.PowerApps/apis/connections', suggestedCreationType: 'Existing', creationType: 'Existing', details: { displayName: anzeige }, configurableBy: 'User', hierarchy: 'Child', dependsOn: [apiRes] });
  const manifest = {
    schema: '1.0',
    details: { displayName: 'Helpdesk v2', description: 'Ticketsystem: Mail-Eingang ticket@dihag.com – konfigurationsgetrieben (Liste TicketQueues)', createdTime: '2026-09-25T00:00:00Z', packageTelemetryId: RES.flow, creator: 'n/v', sourceEnvironment: '' },
    resources: {
      [RES.flow]: { type: 'Microsoft.Flow/flows', suggestedCreationType: 'New', creationType: 'Existing, New, Update', details: { displayName: 'Helpdesk v2' }, configurableBy: 'User', hierarchy: 'Root', dependsOn: [RES.apiOutlook, RES.conOutlook, RES.apiSharepoint, RES.conSharepoint, RES.apiKonvertierung, RES.conKonvertierung] },
      [RES.apiOutlook]: api(RES.apiOutlook, 'shared_office365', 'Office 365 Outlook'),
      [RES.conOutlook]: con(RES.apiOutlook, KONFIG.ticketPostfach),
      [RES.apiSharepoint]: api(RES.apiSharepoint, 'shared_sharepointonline', 'SharePoint'),
      [RES.conSharepoint]: con(RES.apiSharepoint, KONFIG.ticketPostfach),
      [RES.apiKonvertierung]: api(RES.apiKonvertierung, 'shared_conversionservice', 'Content Conversion'),
      [RES.conKonvertierung]: con(RES.apiKonvertierung, 'Content Conversion'),
    },
  };
  return {
    'manifest.json': manifest,
    'Microsoft.Flow/flows/manifest.json': { packageSchemaVersion: '1.0', flowAssets: { assetPaths: [RES.flow] } },
    [`Microsoft.Flow/flows/${RES.flow}/definition.json`]: definition,
    [`Microsoft.Flow/flows/${RES.flow}/apisMap.json`]: { shared_office365: RES.apiOutlook, shared_sharepointonline: RES.apiSharepoint, shared_conversionservice: RES.apiKonvertierung },
    [`Microsoft.Flow/flows/${RES.flow}/connectionsMap.json`]: { shared_office365: RES.conOutlook, shared_sharepointonline: RES.conSharepoint, shared_conversionservice: RES.conKonvertierung },
  };
}

// ── ZIP ohne Abhängigkeiten (Deflate, feste Zeitstempel → reproduzierbar) ────

const CRC_TABELLE = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABELLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

export function zip(dateien) {
  const teile = [], zentral = [];
  let offset = 0;
  const DATUM = ((2026 - 1980) << 9) | (9 << 5) | 25, ZEIT = 0;
  for (const [name, inhalt] of Object.entries(dateien)) {
    const roh = Buffer.from(inhalt);
    const gepackt = zlib.deflateRawSync(roh, { level: 9 });
    const n = Buffer.from(name, 'utf8');
    const crc = crc32(roh);
    const lokal = Buffer.alloc(30);
    lokal.writeUInt32LE(0x04034b50, 0); lokal.writeUInt16LE(20, 4); lokal.writeUInt16LE(0x0800, 6); lokal.writeUInt16LE(8, 8);
    lokal.writeUInt16LE(ZEIT, 10); lokal.writeUInt16LE(DATUM, 12); lokal.writeUInt32LE(crc, 14);
    lokal.writeUInt32LE(gepackt.length, 18); lokal.writeUInt32LE(roh.length, 22); lokal.writeUInt16LE(n.length, 26); lokal.writeUInt16LE(0, 28);
    teile.push(lokal, n, gepackt);
    const z = Buffer.alloc(46);
    z.writeUInt32LE(0x02014b50, 0); z.writeUInt16LE(20, 4); z.writeUInt16LE(20, 6); z.writeUInt16LE(0x0800, 8); z.writeUInt16LE(8, 10);
    z.writeUInt16LE(ZEIT, 12); z.writeUInt16LE(DATUM, 14); z.writeUInt32LE(crc, 16); z.writeUInt32LE(gepackt.length, 20); z.writeUInt32LE(roh.length, 24);
    z.writeUInt16LE(n.length, 28); z.writeUInt32LE(offset, 42);
    zentral.push(z, n);
    offset += 30 + n.length + gepackt.length;
  }
  const zentralBuf = Buffer.concat(zentral);
  const endeRec = Buffer.alloc(22);
  endeRec.writeUInt32LE(0x06054b50, 0);
  endeRec.writeUInt16LE(Object.keys(dateien).length, 8); endeRec.writeUInt16LE(Object.keys(dateien).length, 10);
  endeRec.writeUInt32LE(zentralBuf.length, 12); endeRec.writeUInt32LE(offset, 16);
  return Buffer.concat([...teile, zentralBuf, endeRec]);
}

export function paketDateien() {
  return Object.fromEntries(Object.entries(bauPaket()).map(([k, v]) => [k, JSON.stringify(v, null, 2) + '\n']));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const dateien = paketDateien();
  const ziel = path.join(ROOT, 'flow');
  fs.rmSync(path.join(ziel, 'paket'), { recursive: true, force: true });
  for (const [name, inhalt] of Object.entries(dateien)) {
    const p = path.join(ziel, 'paket', name);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, inhalt);
  }
  fs.writeFileSync(path.join(ziel, 'Helpdesk-v2.zip'), zip(dateien));
  console.log(`flow/Helpdesk-v2.zip geschrieben (${Object.keys(dateien).length} Dateien, ${Object.keys(bauDefinition().actions).length} Hauptschritte)`);
}
