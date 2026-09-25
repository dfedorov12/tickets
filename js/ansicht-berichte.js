/**
 * Berichte (Bearbeiter/Admins) – über die Queues, in denen man bearbeitet.
 * Kennzahlen als Kacheln, Eingang/Erledigt je Kalenderwoche als Säulen,
 * offene Tickets je Queue als Balken, dazu Tabellen (auch als Tabellenansicht der Diagramme).
 * Farben: Kategorie-Slots 1 (Blau) und 2 (Orange) der Referenzpalette, geprüft auf Weiß.
 */
import { meineListen, ladeAlle } from './daten.js';
import { kennzahlen, verlaufNachWoche, zaehleNach, istOffen, istUeberfaellig } from './modell.js';
import { esc, dauer } from './text.js';
import { $, aktion, ladeAnzeige, leer } from './ui.js';

let auswahl = '';
let _tickets = [];

export async function zeige(main, route, aktuell) {
  const listen = meineListen('bearbeiter').filter(l => l.queue.modus !== 'Archiv');
  if (!listen.length) { main.innerHTML = leer('Berichte gibt es für Bearbeiter einer Queue.'); return; }
  main.innerHTML = `
    <div class="seitenkopf">
      <h1>Berichte</h1>
      <div class="werkzeuge">
        <select data-aendern="b-queue" aria-label="Queue">
          <option value="">Alle meine Queues</option>
          ${listen.map(l => `<option value="${esc(l.queue.kennung)}"${auswahl === l.queue.kennung ? ' selected' : ''}>${esc(l.queue.name)}</option>`).join('')}
        </select>
      </div>
    </div>
    <div id="b-inhalt">${ladeAnzeige('Lade Tickets …')}</div>`;
  const { tickets } = await ladeAlle({ mindestens: 'bearbeiter' });
  if (!aktuell()) return;
  _tickets = tickets;
  zeichne();
}

function kachel(label, wert, zusatz = '', art = '') {
  return `<div class="kachel ${art}"><div class="kachel-label">${esc(label)}</div><div class="kachel-wert">${esc(wert)}</div>${zusatz ? `<div class="kachel-zusatz">${zusatz}</div>` : ''}</div>`;
}

function zeichne() {
  const t = auswahl ? _tickets.filter(x => x.kennung === auswahl) : _tickets;
  const jetzt = new Date();
  const kz = kennzahlen(t, jetzt);
  const verlauf = verlaufNachWoche(t, 12, jetzt);
  const offen = t.filter(x => istOffen(x.status));
  const jeQueue = zaehleNach(offen, x => x.kennung);
  const jePrio = ['Kritisch', 'Hoch', 'Normal', 'Niedrig'].map(p => ({ wert: p, anzahl: offen.filter(x => x.prio === p).length }));
  const jeBearbeiter = zaehleNach(offen.flatMap(x => x.bearbeiter.length ? x.bearbeiter.map(b => ({ ...x, _b: b.name })) : [{ ...x, _b: '— niemand —' }]), x => x._b);
  const ueberJeBearbeiter = name => offen.filter(x => istUeberfaellig(x, jetzt) && (x.bearbeiter.length ? x.bearbeiter.some(b => b.name === name) : name === '— niemand —')).length;

  $('#b-inhalt').innerHTML = `
    <div class="kacheln">
      ${kachel('Offen', kz.offen, `${kz.neu} neu · ${kz.wartend} wartend`, 'held')}
      ${kachel('Ohne Bearbeiter', kz.unzugewiesen, kz.unzugewiesen ? '<span aria-hidden="true">⚠</span> zuweisen' : '', kz.unzugewiesen ? 'warnung' : '')}
      ${kachel('Überfällig', kz.ueberfaellig, kz.ueberfaellig ? '<span aria-hidden="true">⛔</span> über Bearbeitungsziel' : '<span aria-hidden="true">✓</span> alles im Ziel', kz.ueberfaellig ? 'kritisch' : 'gut')}
      ${kachel('Eingang 30 Tage', kz.eingang30)}
      ${kachel('Erledigt 30 Tage', kz.erledigt30)}
      ${kachel('Lösungszeit (Median)', dauer(kz.medianLoesungStunden), 'erledigte der letzten 30 Tage')}
    </div>
    <section class="karte diagramm">
      <div class="karte-kopfzeile"><h2>Eingang und Erledigt je Kalenderwoche</h2>
        <div class="legende"><span class="schluessel s1"></span>Eingang <span class="schluessel s2"></span>Erledigt
        <button class="knopf-link" data-aktion="b-tabelle" data-ziel="b-verlauf">Als Tabelle</button></div></div>
      <div id="b-verlauf">${saeulen(verlauf)}</div>
      <div id="b-verlauf-tabelle" hidden>${tabelle(['KW', 'Eingang', 'Erledigt'], verlauf.map(v => [`KW ${v.kw}`, v.eingang, v.erledigt]))}</div>
    </section>
    <div class="zwei-spalten">
      <section class="karte diagramm"><h2>Offen je Queue</h2>${balken(jeQueue)}</section>
      <section class="karte diagramm"><h2>Offen je Priorität</h2>${balken(jePrio)}</section>
    </div>
    <section class="karte"><h2>Offen je Bearbeiter</h2>
      ${tabelle(['Bearbeiter', 'Offen', 'Überfällig'], jeBearbeiter.map(b => [b.wert, b.anzahl, ueberJeBearbeiter(b.wert)]))}
    </section>
    <p class="leise klein">„Erledigt" und die Lösungszeit beruhen auf der letzten Änderung geschlossener Tickets (eine eigene Spalte „Erledigt am" gibt es nicht). Bearbeitungsziele: Kritisch 4 Std., Hoch 1 Tag, Normal 3 Tage, Niedrig 5 Tage (Kalenderzeit).</p>`;
}

function tabelle(kopf, zeilen) {
  if (!zeilen.length) return '<p class="leise">Keine Daten.</p>';
  return `<div class="tabelle-rahmen"><table class="daten"><thead><tr>${kopf.map((k, i) => `<th${i ? ' class="zahl-spalte"' : ''}>${esc(k)}</th>`).join('')}</tr></thead>
    <tbody>${zeilen.map(z => `<tr>${z.map((w, i) => `<td${i ? ' class="zahl-spalte"' : ''}>${esc(w)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
}

/** Gruppierte Säulen (2 Reihen), SVG. Säulen ≤ 24 px, 4 px runde Kappe, Basislinie eckig. */
function saeulen(daten) {
  const max = Math.max(1, ...daten.flatMap(d => [d.eingang, d.erledigt]));
  const schritt = sauberesMaximum(max);
  // Breite ≈ Darstellungsbreite, damit Schrift und Säulen nicht mitskalieren.
  const B = 1100, H = 240, links = 34, unten = 26, oben = 10;
  const breite = (B - links) / daten.length;
  const saeule = Math.min(20, (breite - 10) / 2);
  const y = v => oben + (H - oben - unten) * (1 - v / schritt);
  const pfad = (x, w, v) => {
    const top = y(v), basis = y(0);
    if (v <= 0) return '';
    const r = Math.min(4, basis - top, w / 2);
    return `M${x},${basis}V${top + r}Q${x},${top} ${x + r},${top}H${x + w - r}Q${x + w},${top} ${x + w},${top + r}V${basis}Z`;
  };
  const ticks = [0, schritt / 2, schritt];
  let svg = `<svg viewBox="0 0 ${B} ${H}" class="svg-diagramm" role="img" aria-label="Eingang und Erledigt je Kalenderwoche, letzte 12 Wochen">`;
  svg += ticks.map(t => `<line x1="${links}" x2="${B}" y1="${y(t)}" y2="${y(t)}" class="${t ? 'gitter' : 'basis'}"/><text x="${links - 6}" y="${y(t) + 4}" class="achse" text-anchor="end">${t}</text>`).join('');
  daten.forEach((d, i) => {
    const x0 = links + i * breite + (breite - 2 * saeule - 2) / 2;
    svg += `<g class="saeulen-gruppe" tabindex="0" data-tipp="KW ${d.kw}: ${d.eingang} Eingang, ${d.erledigt} erledigt">`
      + `<rect x="${links + i * breite}" y="${oben}" width="${breite}" height="${H - oben - unten}" class="trefferflaeche"/>`
      + `<path d="${pfad(x0, saeule, d.eingang)}" class="s1"/>`
      + `<path d="${pfad(x0 + saeule + 2, saeule, d.erledigt)}" class="s2"/>`
      + `<text x="${links + i * breite + breite / 2}" y="${H - 8}" class="achse" text-anchor="middle">${d.kw}</text></g>`;
  });
  return svg + '</svg><div class="tipp" hidden></div>';
}

function sauberesMaximum(v) {
  const stufen = [2, 4, 6, 10, 20, 40, 60, 100, 200, 400, 600, 1000, 2000, 5000];
  return stufen.find(s => s >= v) || Math.ceil(v / 1000) * 1000;
}

/** Waagerechte Balken, eine Reihe, Wert an der Spitze. */
function balken(daten) {
  if (!daten.length || daten.every(d => !d.anzahl)) return '<p class="leise">Keine offenen Tickets.</p>';
  const max = Math.max(1, ...daten.map(d => d.anzahl));
  return `<div class="balken-liste">${daten.map(d => `
    <div class="balken-zeile" title="${esc(d.wert)}: ${d.anzahl}">
      <span class="balken-name">${esc(d.wert)}</span>
      <span class="balken-spur"><span class="balken s1" style="width:${(d.anzahl / max) * 100}%"></span></span>
      <span class="balken-wert">${d.anzahl}</span>
    </div>`).join('')}</div>`;
}

aktion('b-queue', el => { auswahl = el.value; zeichne(); });
aktion('b-tabelle', el => {
  const diag = $('#' + el.dataset.ziel), tab = $('#' + el.dataset.ziel + '-tabelle');
  const zeigTabelle = tab.hidden;
  tab.hidden = !zeigTabelle; diag.hidden = zeigTabelle;
  el.textContent = zeigTabelle ? 'Als Diagramm' : 'Als Tabelle';
});

// Hover-/Fokus-Tooltip für die Säulen
function tipp(ev) {
  const g = ev.target.closest?.('.saeulen-gruppe');
  const box = g?.closest('.diagramm')?.querySelector('.tipp');
  document.querySelectorAll('.diagramm .tipp').forEach(t => { if (t !== box) t.hidden = true; });
  if (!g || !box) return;
  box.textContent = g.dataset.tipp;
  box.hidden = false;
  const r = g.getBoundingClientRect(), p = box.parentElement.getBoundingClientRect();
  box.style.left = `${Math.max(0, r.left - p.left + r.width / 2 - 80)}px`;
  box.style.top = `${r.top - p.top - 8}px`;
}
document.addEventListener('mouseover', tipp);
document.addEventListener('focusin', tipp);
