/**
 * Posteingang (Bearbeiter) und Meine Anfragen (alle)
 */
import { KONFIG } from './config.js';
import { zustand, ladeAlle, meineListen } from './daten.js';
import { filtereTickets, sortiereTickets, istOffen, istUeberfaellig, istMeineAnfrage, kennzahlen } from './modell.js';
import { meineMail } from './auth.js';
import { esc, relativ, datumZeit } from './text.js';
import { $, aktion, statusBadge, prioBadge, personen, leer, ladeAnzeige, meldung } from './ui.js';

const SPEICHER = 'tickets.filter.v1';
const SICHTEN = [
  { id: 'offen', text: 'Offen', f: { status: 'offen' } },
  { id: 'meine', text: 'Mir zugewiesen', f: { status: 'offen', zuweisung: 'ich' } },
  { id: 'ohne', text: 'Ohne Bearbeiter', f: { status: 'offen', zuweisung: 'keiner' } },
  { id: 'ueberfaellig', text: 'Überfällig', f: { status: 'offen', ueberfaellig: true } },
  { id: 'geschlossen', text: 'Geschlossen', f: { status: 'geschlossen' } },
  { id: 'alle', text: 'Alle', f: { status: 'alle' } },
];

let filter = { sicht: 'offen', kennung: '', suche: '', sort: 'neu', prio: '' };
try { filter = { ...filter, ...JSON.parse(sessionStorage.getItem(SPEICHER) || '{}') }; } catch { /* gesperrt */ }
const merke = () => { try { sessionStorage.setItem(SPEICHER, JSON.stringify(filter)); } catch { /* egal */ } };
let anzahl = 200;
let _tickets = [];

export async function zeige(main, route, aktuell) {
  if (route.seite === 'meine') return zeigeMeine(main, aktuell);
  return zeigePosteingang(main, aktuell);
}

// ── Posteingang ────────────────────────────────────────────────────────────

async function zeigePosteingang(main, aktuell, neu = false) {
  const listen = meineListen('bearbeiter');
  if (!listen.length) { main.innerHTML = leer('Du bist in keiner Queue als Bearbeiter eingetragen.'); return; }
  if (filter.kennung && !listen.some(l => l.queue.kennung === filter.kennung)) filter.kennung = '';
  const archiv = filter.kennung && listen.find(l => l.queue.kennung === filter.kennung)?.queue.modus === 'Archiv';

  main.innerHTML = `
    <div class="seitenkopf">
      <h1>Posteingang</h1>
      <div class="werkzeuge">
        <input type="search" class="suche" placeholder="Suchen: Nummer, Titel, Melder …" value="${esc(filter.suche)}" data-eingabe="pe-suche" aria-label="Tickets durchsuchen"/>
        <select data-aendern="pe-sort" aria-label="Sortierung">
          <option value="neu"${filter.sort === 'neu' ? ' selected' : ''}>Neueste zuerst</option>
          <option value="prio"${filter.sort === 'prio' ? ' selected' : ''}>Nach Priorität</option>
          <option value="geaendert"${filter.sort === 'geaendert' ? ' selected' : ''}>Zuletzt geändert</option>
        </select>
        <button class="knopf" data-aktion="pe-neu-laden" title="Neu laden">↻ Aktualisieren</button>
      </div>
    </div>
    <div class="queue-leiste" id="pe-queues"></div>
    <div class="sichten" role="tablist" id="pe-sichten"></div>
    <div id="pe-inhalt">${ladeAnzeige('Lade Tickets …')}</div>`;

  const { tickets, fehler } = await ladeAlle({ mindestens: 'bearbeiter', mitArchiv: archiv, neu });
  if (!aktuell()) return;
  fehler.forEach(f => meldung('Nicht geladen – ' + f, 'fehler'));
  _tickets = archiv ? tickets.filter(t => t.kennung === filter.kennung) : tickets;
  zeichneQueues(listen, tickets);
  zeichne();
}

function zeichneQueues(listen, tickets) {
  const offen = k => tickets.filter(t => t.kennung === k && istOffen(t.status)).length;
  const chip = (k, text, zahl) => `<button class="chip${filter.kennung === k ? ' aktiv' : ''}" data-aktion="pe-queue" data-kennung="${esc(k)}">${esc(text)}${zahl != null ? ` <span class="zahl">${zahl}</span>` : ''}</button>`;
  const alleOffen = tickets.filter(t => istOffen(t.status) && keinArchiv(t)).length;
  $('#pe-queues').innerHTML = chip('', 'Alle Queues', alleOffen)
    + listen.map(l => chip(l.queue.kennung, l.queue.modus === 'Archiv' ? `${l.queue.name} (Archiv)` : l.queue.name, l.queue.modus === 'Archiv' ? null : offen(l.queue.kennung))).join('');
}
const keinArchiv = t => zustand.listen.get(t.kennung)?.queue.modus !== 'Archiv';

function zeichne() {
  if (!$('#pe-inhalt')) return; // inzwischen andere Seite (verzögerte Sucheingabe)
  const sicht = SICHTEN.find(s => s.id === filter.sicht) || SICHTEN[0];
  const basis = filter.kennung ? _tickets.filter(t => t.kennung === filter.kennung) : _tickets.filter(keinArchiv);
  const f = { ...sicht.f, suche: filter.suche, prio: filter.prio };
  const zahlen = Object.fromEntries(SICHTEN.map(s => [s.id, filtereTickets(basis, { ...s.f, suche: filter.suche }, meineMail()).length]));
  $('#pe-sichten').innerHTML = SICHTEN.map(s =>
    `<button role="tab" aria-selected="${s.id === sicht.id}" class="sicht${s.id === sicht.id ? ' aktiv' : ''}${s.id === 'ueberfaellig' && zahlen[s.id] ? ' warnung' : ''}" data-aktion="pe-sicht" data-sicht="${s.id}">${esc(s.text)} <span class="zahl">${zahlen[s.id]}</span></button>`).join('');

  const treffer = sortiereTickets(filtereTickets(basis, f, meineMail()), filter.sort);
  const ziel = $('#pe-inhalt');
  if (!treffer.length) {
    ziel.innerHTML = leer(filter.suche ? 'Keine Tickets zu dieser Suche.' : sicht.id === 'offen' ? 'Keine offenen Tickets – alles erledigt.' : 'Keine Tickets in dieser Ansicht.', sicht.id === 'offen' ? '✅' : '📭');
    return;
  }
  const jetzt = new Date();
  const zeilen = treffer.slice(0, anzahl).map(t => `
    <tr data-aktion="oeffne" data-nr="${esc(t.nummer)}" tabindex="0" class="${istUeberfaellig(t, jetzt) ? 'ueberfaellig' : ''}">
      <td class="nr"><a href="#/t/${esc(t.nummer)}">${esc(t.nummer)}</a></td>
      <td class="titel"><div>${esc(t.titel || '(ohne Betreff)')}</div><div class="leise klein">${esc(t.melder?.name || t.melderMail || '')}</div></td>
      <td>${statusBadge(t.status)}</td>
      <td>${prioBadge(t.prio)}</td>
      <td class="personen-zelle">${personen(t.bearbeiter)}</td>
      <td class="zeit" title="${esc(datumZeit(t.gemeldetAm))}">${esc(relativ(t.gemeldetAm, jetzt))}</td>
      <td class="anh">${t.anhaenge ? '📎' : ''}</td>
    </tr>`).join('');
  ziel.innerHTML = `
    <div class="tabelle-rahmen"><table class="tickets">
      <thead><tr><th>Nr.</th><th>Titel / Melder</th><th>Status</th><th>Prio</th><th>Bearbeiter</th><th>Gemeldet</th><th><span class="sr">Anhänge</span></th></tr></thead>
      <tbody>${zeilen}</tbody>
    </table></div>
    <div class="fuss leise">${treffer.length} Tickets${treffer.length > anzahl ? ` · ${anzahl} angezeigt <button class="knopf klein" data-aktion="pe-mehr">Weitere anzeigen</button>` : ''}</div>`;
}

aktion('oeffne', el => { location.hash = '#/t/' + el.dataset.nr; });
aktion('pe-queue', async el => {
  const vorher = filter.kennung;
  filter.kennung = el.dataset.kennung; merke(); anzahl = 200;
  const archivWechsel = [vorher, filter.kennung].some(k => k && zustand.listen.get(k)?.queue.modus === 'Archiv');
  if (archivWechsel) return zeigePosteingang($('#hauptinhalt'), () => true);
  zeichneQueues(meineListen('bearbeiter'), _tickets);
  zeichne();
});
aktion('pe-sicht', el => { filter.sicht = el.dataset.sicht; merke(); anzahl = 200; zeichne(); });
aktion('pe-suche', el => { filter.suche = el.value; merke(); zeichne(); });
aktion('pe-sort', el => { filter.sort = el.value; merke(); zeichne(); });
aktion('pe-mehr', () => { anzahl += 300; zeichne(); });
aktion('pe-neu-laden', () => zeigePosteingang($('#hauptinhalt'), () => true, true));

// ── Meine Anfragen ─────────────────────────────────────────────────────────

async function zeigeMeine(main, aktuell, neu = false) {
  main.innerHTML = `
    <div class="seitenkopf">
      <h1>Meine Anfragen</h1>
      <div class="werkzeuge">
        <button class="knopf" data-aktion="meine-neu-laden">↻ Aktualisieren</button>
        <a class="knopf primaer" href="#/neu">＋ Neues Ticket</a>
      </div>
    </div>
    <p class="leise einleitung">Hier stehen die Tickets, die Sie gemeldet haben – egal ob per Mail an <strong>${esc(KONFIG.ticketPostfach)}</strong> oder hier in der App. Andere sehen Ihre Tickets nicht, nur das zuständige IT-Team.</p>
    <div id="meine-inhalt">${ladeAnzeige('Lade Ihre Tickets …')}</div>`;
  const { tickets, fehler } = await ladeAlle({ mindestens: 'melder', neu });
  if (!aktuell()) return;
  fehler.forEach(f => meldung('Nicht geladen – ' + f, 'fehler'));
  const meine = sortiereTickets(tickets.filter(t => istMeineAnfrage(t, meineMail())));
  const ziel = $('#meine-inhalt');
  if (!meine.length) {
    ziel.innerHTML = leer('Sie haben noch keine Tickets gemeldet.', '🎫')
      + `<p class="mitte"><a class="knopf primaer" href="#/neu">Erstes Ticket melden</a></p>`;
    return;
  }
  const offen = meine.filter(t => istOffen(t.status));
  const zu = meine.filter(t => !istOffen(t.status));
  const karte = t => `
    <a class="ticket-karte" href="#/t/${esc(t.nummer)}">
      <div class="karte-kopf"><span class="nr">${esc(t.nummer)}</span>${statusBadge(t.status)}</div>
      <div class="karte-titel">${esc(t.titel || '(ohne Betreff)')}</div>
      <div class="karte-fuss leise">Gemeldet ${esc(relativ(t.gemeldetAm))} · ${t.bearbeiter.length ? 'bei ' + esc(t.bearbeiter.map(b => b.name).join(', ')) : 'noch nicht zugewiesen'}</div>
    </a>`;
  const kz = kennzahlen(meine);
  ziel.innerHTML = `
    <h2 class="abschnitt">Offen <span class="zahl">${kz.offen}</span></h2>
    ${offen.length ? `<div class="karten">${offen.map(karte).join('')}</div>` : '<p class="leise">Keine offenen Tickets.</p>'}
    ${zu.length ? `<details class="abgeschlossen"><summary><h2 class="abschnitt">Abgeschlossen <span class="zahl">${zu.length}</span></h2></summary><div class="karten">${zu.map(karte).join('')}</div></details>` : ''}`;
}

aktion('meine-neu-laden', () => zeigeMeine($('#hauptinhalt'), () => true, true));
