/**
 * Feste Einstellungen des Ticketsystems
 * =====================================
 * Alles, was sich nur bei einem Umzug ändert (Tenant, Site, Postfach, Adresse der
 * App). Die fachliche Konfiguration – welche Queues es gibt, welche Domains wohin
 * gehen, wer bearbeitet – steht NICHT hier, sondern in der SharePoint-Liste
 * „TicketQueues" und wird in der App unter „Verwaltung" gepflegt. Dieselbe Liste
 * liest der Power-Automate-Flow; so muss für ein neues Werk niemand den Flow anfassen.
 *
 * Bewusst ohne DOM: Diese Datei laden auch der Nachtlauf (scripts/nachtlauf.mjs),
 * der Flow-Generator (scripts/flow-paket.mjs) und die Tests.
 */

export const TENANT_ID = 'fdb70646-023a-403b-a4b9-1f474a935123';

export const KONFIG = Object.freeze({
  tenantId: TENANT_ID,
  // App-Registrierung der Web-App (dieselbe wie bisher – Einwilligungen bleiben gültig).
  clientId: '75e627e8-2de0-4ec6-bec9-311757b89e08',
  spHost: 'https://dihag.sharepoint.com',
  sitePfad: '/sites/ticket',
  // Konfigurationsliste: eine Zeile pro Queue (Werk/Team). Lesbar für alle, enthält nichts Vertrauliches.
  konfigListe: 'TicketQueues',
  // Die bisherige Liste. Sie bleibt bestehen: Vorlage für das Spaltenschema der
  // Queue-Listen und Archiv für die Alt-Tickets (Kennung ALT).
  basisListe: 'Tickets',
  archivKennung: 'ALT',
  // Postfach, an das Melder schreiben; zugleich das Konto der Flow-Verbindungen.
  ticketPostfach: 'ticket@dihag.com',
  // Empfänger für Fehlermeldungen des Flows und den Rechtebericht des Nachtlaufs.
  adminPostfach: 'administrator@dihag.com',
  appUrl: 'https://dfedorov12.github.io/tickets/',
  // Eigene Berechtigungsstufe der Bearbeiter: „Mitwirken" + „Listenverhalten außer
  // Kraft setzen" (sieht alle Tickets der Liste trotz „nur eigene Elemente") –
  // ohne Löschen. Wird bei der Einrichtung angelegt.
  stufeBearbeitung: 'Ticket-Bearbeitung',
  // „Jeder außer externen Benutzern" – so sehen Melder ihre eigenen Tickets. Die
  // Listeneinstellung „nur selbst erstellte Elemente lesen" schränkt auf die eigenen ein.
  melderClaim: `c:0-.f|rolemanager|spo-grid-all-users/${TENANT_ID}`,
  melderAnzeige: 'Jeder außer externen Benutzern',
  // Graph-Rechte wie bisher (bereits erteilt, keine neue Einwilligung nötig).
  graphScopes: ['User.Read', 'Sites.Read.All', 'Sites.ReadWrite.All', 'Files.ReadWrite.All', 'Mail.Send'],
});

export const siteUrl = () => KONFIG.spHost + KONFIG.sitePfad;

/**
 * Interne Spaltennamen der Ticketlisten. Die Queue-Listen entstehen als Kopie
 * der Basisliste „Tickets" – die Namen sind daher überall gleich (so, wie der
 * bisherige Flow sie schreibt).
 */
export const FELDER = Object.freeze({
  titel: 'Title',
  beschreibung: 'Description',
  status: 'Status',
  prio: 'Priority',
  bearbeiter: 'Assignedto0',
  melder: 'Issueloggedby',
  melderMail: 'E_x002d_Mail_x002d_Adresse',
  gemeldetAm: 'DateReported',
  werk: 'Werk',
});

/** Spalten, die es geben KANN – erkannt über internen oder Anzeigenamen. */
export const OPTIONALE_FELDER = Object.freeze({
  kategorie: ['Kategorie', 'Category'],
  art: ['Art', 'Ticketart', 'TicketType'],
});

/** Statuswerte in Anzeige-Reihenfolge. `offen` = zählt als unerledigt. */
export const STATUS = Object.freeze([
  { wert: 'Neu', offen: true, farbe: 'blau' },
  { wert: 'Offen', offen: true, farbe: 'blau' },
  { wert: 'In Bearbeitung', offen: true, farbe: 'orange' },
  { wert: 'Warten auf Rückmeldung', offen: true, farbe: 'lila', wartet: true },
  { wert: 'Projekt', offen: true, farbe: 'grau', wartet: true },
  { wert: 'Erledigt', offen: false, farbe: 'gruen' },
  { wert: 'Abgebrochen', offen: false, farbe: 'grau' },
  { wert: 'Weitergeleitet', offen: false, farbe: 'grau' },
]);

export const PRIORITAETEN = Object.freeze(['Kritisch', 'Hoch', 'Normal', 'Niedrig']);

/**
 * Bearbeitungsziel je Priorität in Kalenderstunden ab Meldung. Offene Tickets
 * darüber gelten als „überfällig" (Liste, Berichte, Tagesübersicht).
 * Wartende Tickets (Rückmeldung, Projekt) laufen nicht in die Überfälligkeit.
 */
export const SLA_STUNDEN = Object.freeze({ Kritisch: 4, Hoch: 24, Normal: 72, Niedrig: 120 });

/**
 * Spalten der Konfigurationsliste „TicketQueues" (Graph-Spaltendefinitionen).
 * Title = Anzeigename der Queue.
 */
export const KONFIG_SPALTEN = Object.freeze([
  { name: 'Kennung', text: {} },
  { name: 'ListenName', text: {} },
  { name: 'ListenId', text: {} },
  { name: 'ListenUrl', text: {} },
  { name: 'Domains', text: { allowMultipleLines: true, linesForEditing: 3 } },
  { name: 'Werk', text: {} },
  { name: 'Bearbeiter', text: { allowMultipleLines: true, linesForEditing: 3 } },
  { name: 'Gruppe', text: {} },
  { name: 'Modus', choice: { choices: ['Ticket', 'Hinweis', 'Archiv'], displayAs: 'dropDownMenu' } },
  { name: 'Hinweistext', text: { allowMultipleLines: true, linesForEditing: 6 } },
  { name: 'Standard', boolean: {} },
  { name: 'Aktiv', boolean: {} },
  { name: 'Benachrichtigen', boolean: {} },
  { name: 'Reihenfolge', number: {} },
]);

/** Soll-Einstellungen jeder Ticketliste (Queue- und Archivliste). */
export const SOLL_LISTENEINSTELLUNGEN = Object.freeze({
  ReadSecurity: 2,      // nur selbst erstellte Elemente lesen (Bearbeiter/Admins sehen dank Stufe alles)
  WriteSecurity: 2,     // nur selbst erstellte Elemente bearbeiten
  NoCrawl: true,        // nicht in der SharePoint-Suche
  EnableVersioning: true,
  EnableAttachments: true,
});

/** Soll-Einstellungen der internen Notizlisten (nur Bearbeiter, keine Melder). */
export const SOLL_NOTIZEINSTELLUNGEN = Object.freeze({
  NoCrawl: true,
  EnableVersioning: true,
});

/** Endung der internen Notizliste je Queue: „Tickets-SCH" → „Tickets-SCH-Intern". */
export const NOTIZ_ENDUNG = '-Intern';
