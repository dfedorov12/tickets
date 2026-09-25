# Ticketsystem v2 – Architektur

## Grundsatz

**Wer was sieht, entscheidet SharePoint – nicht eine Ansicht und nicht die App.**
Bisher lagen alle Tickets in einer Liste, die alle lesen konnten; „versteckt" wurde über Ansichten. Eine Ansicht ist aber nur ein Filter in der Oberfläche – über die Listen-URL, die Suche, Excel-Export oder die API war alles lesbar.

Jetzt:

- **Eine Liste je Queue** (Werk/Team) mit **eigenen Berechtigungen**. SCH-Bearbeiter sehen nur SCH-Tickets.
- **Melder sehen nur ihre eigenen Tickets** – über die Listeneinstellung *„Nur Elemente lesen, die vom Benutzer erstellt wurden"* (ReadSecurity = 2), serverseitig durchgesetzt. Damit das greift, trägt der Flow den Melder als **„Erstellt von"** ein.
- Bearbeiter sehen trotzdem alles in ihrer Queue: Ihre Stufe **Ticket-Bearbeitung** enthält das Recht *„Listenverhalten außer Kraft setzen"*.
- Ticketlisten sind **aus der SharePoint-Suche genommen** (NoCrawl) – doppelte Sicherung.
- Die **Basisliste „Tickets"** bleibt: Spaltenvorlage für neue Queue-Listen und Archiv der Alt-Tickets (Kennung `ALT`), künftig nur für IT.

```
 Mail an ticket@dihag.com                         GitHub Pages (diese App)
          │                                        ┌──────────────────────────────┐
          ▼                                        │ Posteingang · Meine Anfragen │
 ┌──────────────────────┐   liest Konfiguration    │ Ticket · Neu · Berichte      │
 │ Power Automate        │◄───────────┐           │ Verwaltung (Websitebesitzer) │
 │ „Helpdesk v2"          │            │           └──────────────┬───────────────┘
 └─────────┬────────────┘            │                          │ Graph + SharePoint-REST
           │ legt an / hängt an       │                          │ (delegiert, eigene Rechte)
           ▼                          │                          ▼
 ┌────────────────────────────────────┴──────────────────────────────────────────┐
 │ SharePoint-Site /sites/ticket                                                  │
 │  TicketQueues        Konfiguration (Queue, Domains, Liste, Gruppe, Modus …)    │
 │  Tickets-SCH         Tickets der Queue SCH   ← eigene Rechte, nur eigene Elemente│
 │  Tickets-SCH-Intern  interne Notizen SCH     ← nur Bearbeiter                    │
 │  Tickets-…           weitere Queues                                            │
 │  Tickets             Basisliste = Vorlage + Archiv (ALT)                        │
 └───────────────────────────────────────────────▲────────────────────────────────┘
                                                 │ Zertifikat (app-only)
                                       GitHub Actions „Nachtlauf": Rechte prüfen/beheben,
                                       Tagesübersicht an die Bearbeiter
```

## Berechtigungen je Liste (Soll)

| Wer | Ticketliste `Tickets-XY` | Notizliste `Tickets-XY-Intern` | Archiv `Tickets` |
|---|---|---|---|
| Websitebesitzer (= Admins) | Vollzugriff | Vollzugriff | Vollzugriff |
| ticket@dihag.com (Flow) | Vollzugriff | Vollzugriff | Vollzugriff |
| Gruppe `Tickets XY – Bearbeiter` | Ticket-Bearbeitung | Ticket-Bearbeitung | Ticket-Bearbeitung (bei `*`) |
| Jeder außer externen Benutzern | Lesen – **nur eigene** | – | – |

*Ticket-Bearbeitung* = „Mitwirken" + „Listenverhalten außer Kraft setzen" − „Elemente löschen" − „Versionen löschen". Löschen bleibt Admins vorbehalten (Nachvollziehbarkeit).

Listeneinstellungen: eigene Berechtigungen (keine Vererbung), ReadSecurity 2, WriteSecurity 2, NoCrawl, Versionierung, Anhänge.

Das Soll steht an **einer** Stelle (`sollRechte()` in `js/modell.js`); die App (Verwaltung → Rechte) und der Nachtlauf vergleichen damit das Ist und gleichen ab. Beim Abgleich wird nie etwas entzogen, bevor das Soll vollständig vergeben ist; die Websitebesitzer stehen immer im Soll.

## Rollen in der App

Die App fragt je Liste die **effektiven Rechte** der angemeldeten Person ab (`EffectiveBasePermissions`) und leitet ab:

| effektive Rechte | Rolle | sieht |
|---|---|---|
| Rechte verwalten | admin | alles, Verwaltung |
| bearbeiten + Listenverhalten außer Kraft setzen | bearbeiter | Posteingang, Berichte, Detail mit Status/Zuweisung/Notizen |
| nur lesen | melder | „Meine Anfragen" (SharePoint liefert ohnehin nur die eigenen) |

Die App selbst hat keine Rechte-Logik, die man umgehen könnte – sie zeigt nur, was SharePoint ihr für diese Person liefert.

## Konfiguration: Liste `TicketQueues`

| Spalte | Bedeutung |
|---|---|
| Title | Anzeigename der Queue |
| Kennung | Präfix der Ticketnummern (`SCH` → `SCH-12`) |
| ListenName / ListenId / ListenUrl | Ticketliste (ID/URL setzt „Einrichten") |
| Domains | Absender-Domains, `;`-getrennt, exakter Vergleich |
| Werk | Wert der Spalte „Werk" in neuen Tickets |
| Bearbeiter | wird bei Eingang zugewiesen (Mails, `;`-getrennt) |
| Gruppe | SharePoint-Gruppe der Bearbeiter; bei Archiv `*` = alle Bearbeiter-Gruppen |
| Modus | `Ticket` · `Hinweis` (nur Antwort-Mail) · `Archiv` (keine neuen Tickets) |
| Hinweistext | Antwort im Modus Hinweis |
| Standard | Queue für unbekannte Domains (genau eine) |
| Aktiv, Benachrichtigen, Reihenfolge | — |

## Ticketnummern und Mail-Verlauf

- Nummer = `Kennung-ID` der Liste (`SCH-12`). IDs zählen je Liste.
- Die Eingangsbestätigung trägt `[#SCH-12]` im Betreff. Antworten darauf erkennt der Flow und hängt sie als **Kommentar** an (zitierter Verlauf wird abgeschnitten), ergänzt Anhänge, öffnet „Erledigt"/„Warten auf Rückmeldung" wieder und informiert die Bearbeiter.
- Alte Bestätigungen („Neues Ticket: 1234") werden als `ALT-1234` erkannt, solange das Ticket im Archiv steht.
- **Verlauf** (SharePoint-Kommentare) ist für den Melder sichtbar. **Interne Notizen** stehen in einer eigenen Liste, die Melder nicht lesen dürfen.
- Bearbeiter antworten in der App: Kommentar + Mail aus dem eigenen Postfach mit Reply-To auf das Ticketpostfach – die Antwort des Melders landet wieder im Ticket.
- Melder antworten per Mail oder in der App (die App schickt dafür eine Mail an das Ticketpostfach; Melder brauchen keine Schreibrechte).

## Sicherheit der Web-App

- MSAL 5 selbst ausgeliefert (`vendor/`), Anmeldung über `redirect.html`.
- CSP `script-src 'self'` – keine Inline-Skripte, keine Inline-Handler (Aktionen per `data-aktion` und Delegation), keine fremden Skriptquellen.
- Clickjacking-Schutz (`js/rahmenschutz.js`).
- Mail-HTML (Ticketbeschreibung) wird in einem inerten Dokument zerlegt und über eine **Positivliste** neu aufgebaut: keine Skripte, Event-Attribute, Stile, Rahmen oder nachgeladenen Bilder; Links nur http(s)/mailto, sonst Text.
- Alle anderen Fremdwerte laufen durch `esc()`; Ticketnummern und Listen-IDs werden vor jeder Verwendung in URLs geprüft.
- Keine Ticketdaten in `localStorage` (nur Filtereinstellungen in `sessionStorage`).

## Grenzen (bewusst)

- „Erstellt von" lässt sich nur für Konten im Tenant setzen. Externe Absender bekommen Mails, sehen das Ticket aber nicht in der App.
- „Erledigt am" gibt es nicht als Spalte; Berichte nähern das über die letzte Änderung geschlossener Tickets an.
- Bearbeiter können nur in Queues weiterleiten, in denen sie selbst Bearbeiter sind; sonst verschiebt ein Admin.
- Queue-Wechsel und Migration vergeben neue Nummern (Liste = Nummernkreis). Das alte Ticket verweist auf das neue.

## Dateien

| Pfad | Inhalt |
|---|---|
| `index.html`, `redirect.html`, `css/app.css` | Oberfläche |
| `js/config.js` | feste Einstellungen (Tenant, Site, Postfach, Spalten, Status, SLA) |
| `js/modell.js` | fachliche Logik ohne DOM: Nummern, Routing, Rechte-Soll/Abgleich, SLA, Kennzahlen |
| `js/daten.js`, `js/api.js`, `js/auth.js` | Daten, Graph/SharePoint-REST, Anmeldung |
| `js/einrichtung.js`, `js/kopie.js` | Listen/Gruppen/Rechte anlegen und abgleichen; Ticket kopieren (Weiterleiten, Migration) |
| `js/ansicht-*.js` | Seiten |
| `scripts/flow-paket.mjs` → `flow/Helpdesk-v2.zip` | Power-Automate-Flow (Quelle + Importpaket) |
| `scripts/nachtlauf.mjs`, `.github/workflows/nachtlauf.yml` | Nachtlauf |
| `tests/`, `scripts/test.mjs` | Tests ohne Abhängigkeiten (`node scripts/test.mjs`) |
| `e2e/rundgang.mjs`, `e2e/attrappe.mjs` | Browser-Rundgang gegen eine SharePoint/Graph-Attrappe (lokal, braucht Playwright) |
| `alt/` | bisherige App (Übergang) |
