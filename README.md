# DIHAG Tickets

Ticketsystem der DIHAG-IT auf GitHub Pages – Daten in SharePoint (`/sites/ticket`), Mail-Eingang über Power Automate.

- **Queues je Werk** mit eigenen SharePoint-Berechtigungen statt versteckender Ansichten
- **Melder sehen nur ihre eigenen Tickets** (SharePoint „nur eigene Elemente", serverseitig)
- **Verwaltung in der App**: Queues, Routing nach Absender-Domain, Bearbeiter-Gruppen, Rechte-Abgleich, Migration
- **Ein** konfigurationsgetriebener Flow statt kopierter Zweige – neues Werk = neue Zeile in der App
- Nachtlauf (GitHub Actions): Rechteprüfung und Tagesübersicht

| | |
|---|---|
| App | https://dfedorov12.github.io/tickets/ |
| Alte App (Übergang) | https://dfedorov12.github.io/tickets/alt/ |
| Einrichtung | [docs/EINRICHTUNG.md](docs/EINRICHTUNG.md) |
| Architektur & Rechtemodell | [docs/ARCHITEKTUR.md](docs/ARCHITEKTUR.md) |
| Flow-Paket | [flow/Helpdesk-v2.zip](flow/Helpdesk-v2.zip) (Quelle: `scripts/flow-paket.mjs`) |

## Entwickeln

Keine Build-Schritte – ES-Module direkt im Browser.

```bash
node scripts/test.mjs            # alle Tests (Modell, Module/CSP, Flow, Nachtlauf)
node scripts/flow-paket.mjs      # Flow-Paket neu erzeugen (nach Änderungen am Flow)
node e2e/rundgang.mjs            # Browser-Rundgang gegen SharePoint-Attrappe (braucht Playwright)
```
