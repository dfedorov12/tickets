# Ticketsystem v2 – Einrichtung

Reihenfolge: **A** Entra → **B** in der App einrichten → **C** Flow tauschen → **D** Nachtlauf (optional) → **E** Go-live.
Die alte App bleibt unter `/tickets/alt/` erreichbar, der alte Flow bleibt bis zum Umschalten unverändert.

---

## A · Entra ID (einmalig, ~5 Min.)

App-Registrierung der Web-App (`75e627e8-2de0-4ec6-bec9-311757b89e08`) → **Authentifizierung → Single-Page-Anwendung → Umleitungs-URIs**:

| URI | wofür |
|---|---|
| `https://dfedorov12.github.io/tickets/redirect.html` | neue App (MSAL 5 „Redirect-Bridge") |
| `https://dfedorov12.github.io/tickets/alt/` | alte App (Übergangszeit) |

**API-Berechtigungen** – schon vorhanden, nur prüfen, dass sie *erteilt* sind:
- Microsoft Graph (delegiert): `User.Read`, `Sites.ReadWrite.All`, `Mail.Send`, `User.ReadBasic.All` (Personensuche)
- SharePoint (delegiert): `AllSites.FullControl` – nötig nur für Websitebesitzer (Rechte setzen, Listen anlegen). Für alle anderen wirken ohnehin nur ihre eigenen SharePoint-Rechte.

> Delegierte Rechte heißen: Die App kann nie mehr als die angemeldete Person. Wer in SharePoint nichts sieht, sieht auch in der App nichts.

---

## B · In der App einrichten (Websitebesitzer der Site `/sites/ticket`)

Nach dem Merge nach `main` ist die App unter `https://dfedorov12.github.io/tickets/` live. Als **Websitebesitzer** anmelden → Menü **Verwaltung**.

1. **Konfigurationsliste anlegen** – legt `TicketQueues` an (eine Zeile je Queue; der Flow liest sie).
2. **Queues & Routing → „Startaufstellung wie bisheriger Flow"** – legt an:

   | Kennung | Domain | Werk | Modus |
   |---|---|---|---|
   | DIHAG | dihag.com | DIHAG | Ticket |
   | SCH | schmie-guss.de | SCH | Ticket |
   | SHB | shb-guss.de | SHB | Ticket |
   | WGC | walze-coswig.de | WGC | Ticket |
   | EWA | ewa-guss.de | EWA | Ticket |
   | LEG | lintorfereg.de | LEG | Ticket |
   | ALLG | *(alle anderen)* | Kein | Ticket, **Standard** |
   | GIE | gienanth.com | – | **Hinweis** (Antwort „bitte it-support@… nutzen", kein Ticket) |
   | ALT | – | – | **Archiv** = bisherige Liste `Tickets` |

   Danach je Queue **Bearbeiten** → „Zuständig bei Eingang" eintragen (wie bisher im Flow fest verdrahtet). Namen, Kennungen, Domains frei anpassbar; **„Routing testen"** zeigt sofort, wohin eine Adresse ginge.
3. **Rechte & Einrichtung**
   1. *Berechtigungsstufe* „Ticket-Bearbeitung" anlegen (Knopf oben).
   2. Bei **ALT** zuerst **„Auswahlwerte"** – ergänzt in der Basisliste fehlende Status-/Prioritäts-/Werk-Werte. Die Queue-Listen übernehmen die Spalten von dort.
   3. Je Ticket-Queue **„Mitglieder …"** – die Bearbeiter in die Gruppe `Tickets XY – Bearbeiter` aufnehmen.
   4. Je Ticket-Queue **„Einrichten"** – legt Liste `Tickets-XY` (Spalten aus `Tickets`), Notizliste `Tickets-XY-Intern`, Gruppe, Einstellungen und Berechtigungen an. Das Protokoll zeigt jeden Schritt; beliebig oft wiederholbar.
   5. Zuletzt **ALT „Abgleichen"** – die bisherige Liste bekommt eigene Rechte: nur noch Admins, Flow-Konto und Bearbeiter (`*` = alle Bearbeiter-Gruppen; leer = nur Admins). **Ab hier sehen Melder die Alt-Liste nicht mehr.**
4. **Migration (optional)** – je Queue die Alt-Tickets ihres Werks aus `Tickets` übernehmen (Vorschau → Übernehmen). Originale gehen in den Papierkorb (wiederherstellbar), die Tickets bekommen neue Nummern.

---

## C · Flow tauschen

1. In der App **Verwaltung → Mail-Eingang → „Flow-Paket herunterladen"** (`flow/Helpdesk-v2.zip`).
2. make.powerautomate.com → **Meine Flows → Importieren → Paket importieren (Legacy)** → Zip wählen.
   - *Helpdesk v2*: „Als neu erstellen".
   - *Office 365 Outlook* und *SharePoint*: vorhandene Verbindungen von **ticket@dihag.com** wählen.
   - *Content Conversion*: „Neu erstellen" (keine Anmeldung nötig – wandelt Antwort-Mails in Text).
3. Den importierten Flow öffnen und speichern (Power Automate prüft dabei die Verbindungen).
4. **Alten Flow „Helpdesk" ausschalten**, dann **„Helpdesk v2" einschalten**. Nie beide gleichzeitig – sonst entstehen Tickets doppelt.
5. Test mit einem Testkonto:
   - Mail an ticket@dihag.com → Eingangsbestätigung `[#XY-1] Eingangsbestätigung: …` kommt zurück, Ticket steht im Posteingang der Queue, der Absender sieht es unter „Meine Anfragen".
   - Auf die Bestätigung antworten → Antwort steht im Verlauf, Bearbeiter bekommen eine Mail.
   - Mail von einer gienanth.com-Adresse → nur Hinweis-Mail, kein Ticket.

**Was der Flow tut** (Details: `scripts/flow-paket.mjs`): Schleifenschutz → Konfiguration laden → Ticketnummer im Betreff? → *Antwort* (Kommentar, Anhänge, Status wieder öffnen, Bearbeiter informieren) oder *neues Ticket* (Queue nach Domain/Standard, Hinweis-Modus, Ticket anlegen, Status/Werk/Priorität/Zuständige/Melder setzen, **„Erstellt von" = Melder**, Original-Mail + Anhänge ans Ticket, Eingangsbestätigung). Fehler → Mail an administrator@dihag.com mit Link zum Lauf.

> Das Flow-Konto ticket@dihag.com bekommt beim Einrichten **Vollzugriff auf die Ticketlisten** – nötig, um „Erstellt von" zu setzen und Antworten an fremde Tickets zu hängen.

---

## D · Nachtlauf (GitHub Actions, optional)

`.github/workflows/nachtlauf.yml` prüft täglich die Rechte aller Ticketlisten gegen das Soll (Bericht an administrator@dihag.com, optional automatische Reparatur) und schickt Mo–Fr jeder Queue eine Tagesübersicht (neu, ohne Bearbeiter, überfällig).

SharePoint erlaubt Rechte-Abfragen app-only **nur mit Zertifikat** (ein Client-Secret reicht dort nicht). Ohne die Secrets überspringt der Lauf sich selbst.

1. **Zertifikat** erzeugen (2 Jahre):
   ```bash
   openssl req -x509 -newkey rsa:2048 -nodes -days 730 -subj "/CN=DIHAG Tickets Nachtlauf" \
     -keyout nachtlauf.key -out nachtlauf.cer
   cat nachtlauf.key nachtlauf.cer > nachtlauf.pem      # Inhalt → Secret AZURE_ZERTIFIKAT
   ```
2. **App-Registrierung** (eigene, z. B. „DIHAG Tickets Nachtlauf", oder die vorhandene „DIHAG Cron-Job"):
   - *Zertifikate & Geheimnisse → Zertifikat hochladen*: `nachtlauf.cer`
   - *API-Berechtigungen → Anwendungsberechtigungen*:
     - **SharePoint → `Sites.Selected`** (Listen, Rechte, Tickets – alles über SharePoint-REST)
     - **Microsoft Graph → `Mail.Send`** (Tagesübersicht, Rechtebericht)
     - danach „Administratorzustimmung erteilen"
   - Zugriff nur auf die Ticket-Site gewähren (Graph Explorer als Admin, Site-ID vorher per `GET https://graph.microsoft.com/v1.0/sites/dihag.sharepoint.com:/sites/ticket?$select=id`):
     ```http
     POST https://graph.microsoft.com/v1.0/sites/{site-id}/permissions
     { "roles": ["fullcontrol"],
       "grantedToIdentities": [{ "application": { "id": "<client-id>", "displayName": "DIHAG Tickets Nachtlauf" } }] }
     ```
   - `Mail.Send` auf **ein** Absender-Postfach beschränken (Exchange Online PowerShell, wie beim RMS-Cron):
     ```powershell
     New-ApplicationAccessPolicy -AppId "<client-id>" -PolicyScopeGroupId "<mail-aktivierte Gruppe mit dem Absender>" `
       -AccessRight RestrictAccess -Description "Tickets-Nachtlauf sendet nur als Absender-Postfach"
     ```
3. **GitHub → dfedorov12/tickets → Settings → Secrets and variables → Actions**:

   | Secret | Wert |
   |---|---|
   | `AZURE_TENANT_ID` | `fdb70646-023a-403b-a4b9-1f474a935123` |
   | `AZURE_CLIENT_ID` | Client-ID der App-Registrierung |
   | `AZURE_ZERTIFIKAT` | Inhalt von `nachtlauf.pem` (Schlüssel + Zertifikat) |
   | `MAIL_SENDER` | Absender-Postfach (erlaubt durch die Access Policy) |

   Optional als **Variable**: `RECHTE_AUTO_REPARATUR = true` – dann behebt der nächtliche Lauf Abweichungen selbst (wie „Abgleichen" in der App). Sonst nur Bericht.
4. **Testen:** Actions → „Nachtlauf Tickets" → *Run workflow* mit `dry_run = true`. Das Log zeigt je Liste „ok" oder die Zahl der Abweichungen – nie Namen oder Adressen (das Repo und damit die Logs sind öffentlich).

> 🔔 Zertifikat läuft nach 2 Jahren ab – vorher neu erzeugen und Secret + App-Registrierung aktualisieren.
> GitHub pausiert Zeitpläne in öffentlichen Repos nach 60 Tagen ohne Commit und schickt vorher eine Mail; ein Klick auf „Enable workflow" reaktiviert ihn.

---

## E · Go-live-Checkliste

- [ ] Redirect-URIs eingetragen (A)
- [ ] Alle Ticket-Queues **eingerichtet**, Prüfung zeigt überall ✓ (B)
- [ ] Bearbeiter-Gruppen gefüllt; jede Bearbeiterin sieht ihren Posteingang
- [ ] Archiv ALT abgeglichen – Test mit einem Nicht-IT-Konto: `…/sites/ticket/Lists/Tickets` ist **nicht** mehr sichtbar
- [ ] Flow v2 an, alter Flow aus; Test-Mail, Antwort, Hinweis-Domain geprüft (C)
- [ ] Alte SharePoint-Ansichten, die bisher „versteckt" haben, können weg – sie schützen nichts
- [ ] Nachtlauf-Probelauf grün (D, optional)

**Zurück zum alten Stand:** Flow v2 aus, alter Flow an. Die alte App liegt unter `/tickets/alt/`. Rechte der Basisliste bei Bedarf in SharePoint → Listeneinstellungen → Berechtigungen → „Berechtigungen erben".

---

## Fehlersuche

| Symptom | Ursache / Lösung |
|---|---|
| Anmeldung endet auf leerer Seite | Redirect-URI `…/tickets/redirect.html` fehlt in Entra (A) |
| „Einrichten" → 403 | Nicht Websitebesitzer, oder SharePoint-Recht `AllSites.FullControl` ohne Zustimmung |
| Spalte wurde nicht kopiert | Protokoll zeigt `⚠ Spalte …` – meist verwaltete Metadaten/Lookup auf gelöschte Liste; von Hand ergänzen |
| Melder sieht sein Ticket nicht | „Erstellt von" konnte nicht gesetzt werden (externer Absender ohne Konto im Tenant) – das Ticket ist dann nur für die IT sichtbar |
| Flow: „keine Queue für Absender" | keine Standard-Queue aktiv (Queues → Standard setzen) |
| Flow: „Ticket konnte nicht angelegt werden" | Queue nicht eingerichtet (Liste/ListenUrl fehlt) oder ticket@ ohne Rechte → in der App „Abgleichen" |
| Priorität bleibt leer | Auswahlwert fehlt in der Liste → „Auswahlwerte" in Rechte & Einrichtung |
| Nachtlauf: `Token (401)` | Zertifikat nicht hochgeladen/abgelaufen oder falsche Client-ID |
| Nachtlauf: `SharePoint 403` | Sites.Selected-Freigabe (`fullcontrol`) für die Ticket-Site fehlt |
