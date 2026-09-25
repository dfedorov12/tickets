/**
 * DIHAG Tickets – Einstieg
 * ========================
 * Anmelden → Kontext laden (Queues, Rollen je Liste) → Navigation → Ansicht nach
 * Hash-Route. Welche Bereiche jemand sieht, folgt aus den SharePoint-Rechten:
 *   Posteingang/Berichte – Bearbeiter einer Queue (oder Admin)
 *   Meine Anfragen/Neues Ticket – alle
 *   Verwaltung – Websitebesitzer (Rechte verwalten)
 */
import { anmelden, abmelden, meinName, meineMail } from './auth.js';
import { ladeKontext, zustand, istBearbeiterIrgendwo } from './daten.js';
import { parseRoute } from './modell.js';
import { esc, initialen } from './text.js';
import { $, aktion, aktionenAktivieren, meldung, dialog } from './ui.js';
import * as liste from './ansicht-liste.js';
import * as ticket from './ansicht-ticket.js';
import * as neu from './ansicht-neu.js';
import * as berichte from './ansicht-berichte.js';
import * as verwaltung from './ansicht-verwaltung.js';

function bootFehler(text) {
  $('#boot-text').textContent = 'Das hat nicht geklappt';
  $('#boot-spinner').hidden = true;
  const f = $('#boot-fehler');
  f.textContent = text;
  f.hidden = false;
  $('#boot-knopf').hidden = false;
}

function navigation(route) {
  const bearbeiter = istBearbeiterIrgendwo();
  const punkte = [
    bearbeiter && { seite: 'posteingang', text: 'Posteingang' },
    { seite: 'meine', text: 'Meine Anfragen' },
    bearbeiter && { seite: 'berichte', text: 'Berichte' },
    zustand.site.istAdmin && { seite: 'verwaltung', text: 'Verwaltung' },
  ].filter(Boolean);
  $('#navigation').innerHTML = punkte.map(p =>
    `<a href="#/${p.seite}" class="nav-punkt${route.seite === p.seite ? ' aktiv' : ''}"${route.seite === p.seite ? ' aria-current="page"' : ''}>${esc(p.text)}</a>`).join('');
}

function startseite() {
  if (zustand.konfigFehlt && zustand.site.istAdmin) return 'verwaltung';
  return istBearbeiterIrgendwo() ? 'posteingang' : 'meine';
}

let _renderNr = 0;
async function zeige() {
  const nr = ++_renderNr;
  let route = parseRoute(location.hash);
  if (!route.seite) {
    history.replaceState(null, '', '#/' + startseite());
    route = parseRoute(location.hash);
  }
  navigation(route);
  const main = $('#hauptinhalt');
  main.className = 'seite-' + route.seite;
  const aktuell = () => nr === _renderNr;
  try {
    if (route.seite === 'ticket') await ticket.zeige(main, route, aktuell);
    else if (route.seite === 'neu') await neu.zeige(main, route, aktuell);
    else if (route.seite === 'berichte') await berichte.zeige(main, route, aktuell);
    else if (route.seite === 'verwaltung') {
      if (!zustand.site.istAdmin) { main.innerHTML = '<p class="hinweis">Nur für Websitebesitzer der Ticket-Site.</p>'; return; }
      await verwaltung.zeige(main, route, aktuell);
    } else await liste.zeige(main, route, aktuell);
  } catch (e) {
    console.error(e);
    if (aktuell()) main.innerHTML = `<div class="fehlerbox"><strong>Fehler:</strong> ${esc(e.message || e)}</div>`;
  }
}

aktion('neu-laden', () => location.reload());
aktion('nutzermenue', async () => {
  const r = await dialog({
    titel: meinName(),
    inhalt: `<p class="leise">${esc(meineMail())}</p><p>Rollen: ${[...zustand.listen.values()].filter(l => l.rolle !== 'keine').map(l => `${esc(l.queue.kennung)}: ${esc(l.rolle)}`).join(' · ') || 'Melder'}</p>`,
    knoepfe: [{ wert: 'schliessen', text: 'Schließen' }, { wert: 'abmelden', text: 'Abmelden', primaer: true }],
  });
  if (r.wert === 'abmelden') abmelden();
});

async function start() {
  aktionenAktivieren();
  try {
    const k = await anmelden();
    if (!k) return; // Umleitung zur Anmeldung läuft
    $('#boot-text').textContent = 'Lade Queues und Berechtigungen …';
    await ladeKontext();
  } catch (e) {
    console.error(e);
    bootFehler(e.message || String(e));
    return;
  }
  $('#nutzer').textContent = initialen(meinName());
  $('#boot').hidden = true;
  $('#app').hidden = false;
  window.addEventListener('hashchange', () => { zeige(); $('#hauptinhalt').focus({ preventScroll: true }); });
  await zeige();
  if (zustand.konfigFehlt && !zustand.site.istAdmin) meldung('Das Ticketsystem wird gerade eingerichtet.', 'info');
}

start();
