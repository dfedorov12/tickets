/**
 * Verwaltung (nur Websitebesitzer): Queues · Rechte & Einrichtung · Migration · Eingang
 */
import { KONFIG, FELDER, NOTIZ_ENDUNG } from './config.js';
import { zustand, ladeQueues } from './daten.js';
import { spAlle, guid } from './api.js';
import {
  queueAusFeldern, pruefeQueues, standardNamen, queueFuerAbsender, KENNUNG_MUSTER, MODI, domainsAusText, mailsAusText,
  istOffen, ticketNummer,
} from './modell.js';
import {
  konfigListeAnlegen, queueSpeichern, queueLoeschen, stufePruefen, stufeSicherstellen, queuePruefen, queueEinrichten,
  gruppeLesen, gruppeSicherstellen, mitgliedHinzufuegen, mitgliedEntfernen, auswahlAngleichen, sollKontext,
} from './einrichtung.js';
import { kopiereTicket, inPapierkorb } from './kopie.js';
import { esc } from './text.js';
import { $, aktion, dialog, meldung, beschaeftigt, bestaetigen, ladeAnzeige, leer } from './ui.js';
import { personenwahl, leseAuswahl } from './personenwahl.js';

const BEREICHE = [
  { id: 'queues', text: 'Queues & Routing' },
  { id: 'rechte', text: 'Rechte & Einrichtung' },
  { id: 'migration', text: 'Migration' },
  { id: 'eingang', text: 'Mail-Eingang (Flow)' },
];

export async function zeige(main, route, aktuell) {
  main.innerHTML = `
    <div class="seitenkopf"><h1>Verwaltung</h1></div>
    <nav class="unternav" aria-label="Verwaltung">${BEREICHE.map(b => `<a href="#/verwaltung/${b.id}" class="${route.bereich === b.id ? 'aktiv' : ''}">${esc(b.text)}</a>`).join('')}</nav>
    <div id="v-inhalt">${ladeAnzeige()}</div>`;
  const ziel = $('#v-inhalt');
  if (zustand.konfigFehlt) { zeigeStart(ziel); return; }
  if (route.bereich === 'rechte') return zeigeRechte(ziel, aktuell);
  if (route.bereich === 'migration') return zeigeMigration(ziel, aktuell);
  if (route.bereich === 'eingang') return zeigeEingang(ziel);
  return zeigeQueues(ziel);
}

const neuZeigen = () => zeige($('#hauptinhalt'), { seite: 'verwaltung', bereich: (location.hash.split('/')[2] || 'queues') }, () => true);

// ── Start ─────────────────────────────────────────────────────────────────

function zeigeStart(ziel) {
  ziel.innerHTML = `<div class="karte">
    <h2>Ticketsystem einrichten</h2>
    <p>Auf der Site <strong>${esc(zustand.site.titel)}</strong> fehlt noch die Konfigurationsliste <code>${esc(KONFIG.konfigListe)}</code>. Sie enthält eine Zeile je Queue (Werk/Team) und wird vom Mail-Flow gelesen.</p>
    <ol class="schritte">
      <li>Konfigurationsliste anlegen</li>
      <li>Queues anlegen (Vorschlag aus dem bisherigen Flow)</li>
      <li>Rechte &amp; Einrichtung: je Queue „Einrichten" – legt Liste, Notizliste, Gruppe und Berechtigungen an</li>
      <li>Mail-Eingang: neuen Flow importieren, alten ausschalten</li>
    </ol>
    <button class="knopf primaer" data-aktion="v-konfig-anlegen">Konfigurationsliste anlegen</button>
  </div>`;
}

aktion('v-konfig-anlegen', el => beschaeftigt(el, 'Lege an …', async () => {
  await konfigListeAnlegen();
  await ladeQueues();
  meldung('Konfigurationsliste angelegt', 'erfolg');
  location.hash = '#/verwaltung/queues';
  neuZeigen();
}));

// ── Queues ────────────────────────────────────────────────────────────────

const HINWEIS_GIENANTH = 'Sehr geehrte Damen und Herren,\n\nbitte verwenden Sie für IT-Anfragen die E-Mail-Adresse it-support@dihag-gienanth.com.\n\nWir bitten um Ihr Verständnis und stehen Ihnen bei weiteren Fragen gerne zur Verfügung.\n\nMit freundlichen Grüßen\nIhr IT-Team';

/** Startaufstellung = Verhalten des bisherigen Flows (Werk nach Absender-Domain). Bearbeiter bitte in der App eintragen. */
function vorschlag() {
  const w = (kennung, domain, extra = {}) => ({ kennung, name: `Werk ${kennung}`, domains: domain ? [domain] : [], werk: kennung, ...standardNamen(kennung), modus: 'Ticket', aktiv: true, ...extra });
  return [
    w('DIHAG', 'dihag.com', { name: 'DIHAG' }),
    w('SCH', 'schmie-guss.de'),
    w('SHB', 'shb-guss.de'),
    w('WGC', 'walze-coswig.de'),
    w('EWA', 'ewa-guss.de'),
    w('LEG', 'lintorfereg.de'),
    w('ALLG', '', { name: 'Allgemein (unbekannte Absender)', werk: 'Kein', standard: true }),
    { kennung: 'GIE', name: 'Gienanth (Hinweis)', domains: ['gienanth.com'], modus: 'Hinweis', hinweis: HINWEIS_GIENANTH, aktiv: true, liste: '', gruppe: '' },
    { kennung: KONFIG.archivKennung, name: 'Archiv (bisherige Liste)', liste: KONFIG.basisListe, modus: 'Archiv', gruppe: '*', aktiv: true, domains: [] },
  ].map((q, i) => ({ ...queueAusFeldern({}), ...q, reihenfolge: (i + 1) * 10 }));
}

function zeigeQueues(ziel) {
  const qs = zustand.queues;
  const befunde = pruefeQueues(qs);
  ziel.innerHTML = `
    ${befunde.length ? `<div class="karte befunde">${befunde.map(b => `<div class="befund ${b.schwere}"><strong>${esc(b.kennung)}</strong> ${esc(b.text)}</div>`).join('')}</div>` : ''}
    <div class="karte">
      <div class="karte-kopfzeile"><h2>Queues</h2>
        <div class="knopfzeile">${qs.length ? '' : '<button class="knopf" data-aktion="v-vorschlag">Startaufstellung wie bisheriger Flow</button>'}<button class="knopf primaer" data-aktion="v-queue-neu">＋ Neue Queue</button></div></div>
      ${qs.length ? `<div class="tabelle-rahmen"><table class="daten">
        <thead><tr><th>Kennung</th><th>Name</th><th>Modus</th><th>Domains</th><th>Werk</th><th>Bearbeiter-Gruppe</th><th>Zuständig bei Eingang</th><th>Liste</th><th></th></tr></thead>
        <tbody>${qs.map(q => `<tr class="${q.aktiv ? '' : 'inaktiv'}">
          <td><strong>${esc(q.kennung)}</strong>${q.standard ? ' <span class="badge st-blau">Standard</span>' : ''}${q.aktiv ? '' : ' <span class="badge st-grau">aus</span>'}</td>
          <td>${esc(q.name)}</td>
          <td>${esc(q.modus)}</td>
          <td class="klein">${esc(q.domains.join(', ')) || '<span class="leise">–</span>'}</td>
          <td>${esc(q.werk)}</td>
          <td class="klein">${esc(q.gruppe === '*' ? 'alle Bearbeiter-Gruppen' : q.gruppe) || '<span class="leise">–</span>'}</td>
          <td class="klein">${esc(q.bearbeiter.join(', ')) || '<span class="leise">–</span>'}</td>
          <td class="klein">${q.modus === 'Hinweis' ? '<span class="leise">keine</span>' : q.listId ? `✓ ${esc(q.liste)}` : `<span class="rot">✗ ${esc(q.liste)} – einrichten</span>`}</td>
          <td><button class="knopf klein" data-aktion="v-queue-bearbeiten" data-kennung="${esc(q.kennung)}">Bearbeiten</button></td>
        </tr>`).join('')}</tbody></table></div>` : leer('Noch keine Queues. Die Startaufstellung übernimmt die Werke aus dem bisherigen Flow.', '🗂')}
    </div>
    <div class="karte">
      <h2>Routing testen</h2>
      <p class="leise">Welche Queue bekäme eine Mail von dieser Adresse? (Gleiche Regel wie im Flow: exakte Domain, sonst Standard-Queue.)</p>
      <input type="email" class="suche" data-eingabe="v-routing" placeholder="max.muster@schmie-guss.de" aria-label="Absender testen"/>
      <div id="v-routing-ergebnis" class="routing-ergebnis"></div>
    </div>`;
}

aktion('v-routing', el => {
  const q = queueFuerAbsender(zustand.queues, el.value);
  $('#v-routing-ergebnis').innerHTML = !el.value.includes('@') ? '' : q
    ? `→ <strong>${esc(q.kennung)}</strong> ${esc(q.name)} · ${q.modus === 'Hinweis' ? 'Hinweis-Mail, kein Ticket' : `Liste ${esc(q.liste)}${q.bearbeiter.length ? ', zugewiesen an ' + esc(q.bearbeiter.join(', ')) : ''}`}`
    : '<span class="rot">→ keine Queue (keine Standard-Queue) – der Flow meldet die Mail an den Admin</span>';
});

aktion('v-vorschlag', el => beschaeftigt(el, 'Lege an …', async () => {
  for (const q of vorschlag()) await queueSpeichern(q);
  await ladeQueues();
  meldung('Startaufstellung angelegt – bitte je Queue die Zuständigen eintragen und dann einrichten.', 'erfolg');
  neuZeigen();
}));

aktion('v-queue-neu', () => queueDialog(null));
aktion('v-queue-bearbeiten', el => queueDialog(zustand.queues.find(q => q.kennung === el.dataset.kennung)));

async function queueDialog(alt) {
  const q = alt || { ...queueAusFeldern({}), aktiv: true };
  const gesperrt = !!(alt && alt.listId);
  const r = await dialog({
    titel: alt ? `Queue ${alt.kennung}` : 'Neue Queue',
    breit: true,
    inhalt: `<div class="formular-raster">
      <label>Kennung (Ticket-Präfix)<input name="kennung" value="${esc(q.kennung)}" ${gesperrt ? 'readonly title="Liste existiert – Kennung nicht mehr änderbar"' : 'required'} maxlength="10" pattern="[A-Za-z][A-Za-z0-9]{1,9}" placeholder="SCH"/></label>
      <label>Name<input name="name" value="${esc(q.name)}" required placeholder="Werk Schmiedeguss"/></label>
      <label>Modus<select name="modus">${MODI.map(m => `<option${q.modus === m ? ' selected' : ''}>${m}</option>`).join('')}</select></label>
      <label>Werk (Wert der Spalte „Werk")<input name="werk" value="${esc(q.werk)}" placeholder="SCH"/></label>
      <label>Liste<input name="liste" value="${esc(q.liste)}" ${gesperrt ? 'readonly' : ''} placeholder="Tickets-SCH (leer = Vorschlag)"/></label>
      <label>Bearbeiter-Gruppe<input name="gruppe" value="${esc(q.gruppe)}" placeholder="Tickets SCH – Bearbeiter (Archiv: * = alle)"/></label>
      <label class="breit">Absender-Domains (eine pro Zeile)<textarea name="domains" rows="3" placeholder="schmie-guss.de">${esc(q.domains.join('\n'))}</textarea></label>
      <div class="breit"><span>Zuständig bei Eingang (werden dem Ticket zugewiesen)</span>${personenwahl('bearbeiter', { vorbelegt: q.bearbeiter.map(m => ({ mail: m, name: m })) })}</div>
      <label class="breit">Hinweistext (nur Modus „Hinweis": Antwort statt Ticket)<textarea name="hinweis" rows="4">${esc(q.hinweis)}</textarea></label>
      <label class="check"><input type="checkbox" name="standard"${q.standard ? ' checked' : ''}/> Standard-Queue für unbekannte Domains</label>
      <label class="check"><input type="checkbox" name="benachrichtigen"${q.benachrichtigen ? ' checked' : ''}/> Zuständige bei neuem Ticket per Mail informieren</label>
      <label class="check"><input type="checkbox" name="aktiv"${q.aktiv ? ' checked' : ''}/> Aktiv</label>
      <label>Reihenfolge<input type="number" name="reihenfolge" value="${esc(q.reihenfolge || '')}"/></label>
    </div>`,
    knoepfe: [
      ...(alt ? [{ wert: 'loeschen', text: 'Löschen', gefahr: true }] : []),
      { wert: 'abbrechen', text: 'Abbrechen' },
      { wert: 'ok', text: 'Speichern', primaer: true },
    ],
  });
  if (r.wert === 'loeschen') {
    if (await bestaetigen('Queue löschen?', `Die Konfigurationszeile ${alt.kennung} wird gelöscht. Liste, Tickets und Gruppe bleiben erhalten.`, { ja: 'Löschen', gefahr: true })) {
      await queueLoeschen(alt); await ladeQueues(); neuZeigen();
    }
    return;
  }
  if (r.wert !== 'ok') return;
  const d = r.daten;
  const kennung = String(d.kennung || '').trim().toUpperCase();
  const namen = standardNamen(kennung);
  const neu = {
    ...q,
    kennung,
    name: String(d.name || '').trim(),
    modus: d.modus,
    werk: String(d.werk || '').trim(),
    liste: d.modus === 'Hinweis' ? '' : (String(d.liste || '').trim() || namen.liste),
    gruppe: d.modus === 'Ticket' ? (String(d.gruppe || '').trim() || namen.gruppe) : String(d.gruppe || '').trim(),
    domains: domainsAusText(d.domains),
    bearbeiter: mailsAusText(leseAuswahl(d.bearbeiter).map(p => p.mail).join(';')),
    hinweis: String(d.hinweis || ''),
    standard: d.standard === 'on',
    benachrichtigen: d.benachrichtigen === 'on',
    aktiv: d.aktiv === 'on',
    reihenfolge: Number(d.reihenfolge) || 0,
  };
  const andere = zustand.queues.filter(x => x !== alt);
  const fehler = pruefeQueues([...andere, neu]).filter(b => b.schwere === 'fehler' && (b.kennung === neu.kennung || b.kennung === '–'));
  if (!KENNUNG_MUSTER.test(kennung) || fehler.length) {
    meldung(fehler.map(f => f.text).join(' · ') || 'Kennung ungültig', 'fehler');
    return queueDialog({ ...neu, itemId: q.itemId, listId: q.listId });
  }
  await queueSpeichern(neu);
  await ladeQueues();
  meldung(`Queue ${kennung} gespeichert`, 'erfolg');
  neuZeigen();
}

// ── Rechte & Einrichtung ──────────────────────────────────────────────────

const _pruefungen = new Map();

async function zeigeRechte(ziel, aktuell) {
  const stufe = await stufePruefen().catch(e => ({ fehler: e.message }));
  if (!aktuell()) return;
  const qs = zustand.queues.filter(q => q.modus !== 'Hinweis');
  ziel.innerHTML = `
    <div class="karte">
      <h2>Grundlagen</h2>
      <div class="raster-3">
        <div><span class="leise klein">Admins (Vollzugriff überall)</span><div><strong>${esc(zustand.site.ownerGruppe)}</strong></div></div>
        <div><span class="leise klein">Flow-Konto (Vollzugriff auf Ticketlisten)</span><div><strong>${esc(KONFIG.ticketPostfach)}</strong></div></div>
        <div><span class="leise klein">Melder (Lesen, nur eigene Tickets)</span><div><strong>${esc(KONFIG.melderAnzeige)}</strong></div></div>
      </div>
      <p>Berechtigungsstufe <strong>${esc(KONFIG.stufeBearbeitung)}</strong>: ${stufe.fehler ? `<span class="rot">${esc(stufe.fehler)}</span>` : stufe.vorhanden && stufe.gleich ? '✓ vorhanden' : stufe.vorhanden ? '⚠ abweichend' : '✗ fehlt'}
        ${!stufe.fehler && !(stufe.vorhanden && stufe.gleich) ? ' <button class="knopf klein" data-aktion="v-stufe">Anlegen/angleichen</button>' : ''}</p>
      <p class="leise klein">Ticketlisten: eigene Berechtigungen (keine Vererbung), „nur selbst erstellte Elemente lesen/bearbeiten", nicht in der SharePoint-Suche, Versionierung an. Bearbeiter sehen dank ihrer Stufe alle Tickets ihrer Queue, Melder nur die eigenen – durchgesetzt von SharePoint, nicht über Ansichten.</p>
      <div class="knopfzeile"><button class="knopf" data-aktion="v-alle-pruefen">Alle prüfen</button></div>
    </div>
    ${qs.length ? qs.map(q => `<div class="karte queue-pruefung" id="v-q-${esc(q.kennung)}">${queueKarte(q, _pruefungen.get(q.kennung))}</div>`).join('') : leer('Noch keine Queues mit Liste.')}`;
}

const haken = (ok, text) => `<span class="${ok ? 'gruen' : 'rot'}">${ok ? '✓' : '✗'}</span> ${text}`;

function rechteText(a) {
  if (!a) return '<span class="leise">–</span>';
  if (!a.fehlt.length && !a.zuviel.length) return haken(true, 'entsprechen dem Soll');
  return `<span class="rot">⚠ Abweichung</span><ul class="klein">`
    + a.fehlt.map(s => `<li>fehlt: <strong>${esc(s.anzeige)}</strong> → ${esc(s.rolle.anzeige)} <span class="leise">(${esc(s.grund)})</span></li>`).join('')
    + a.zuviel.map(z => `<li>zu viel: <strong>${esc(z.titel || z.login)}</strong> → ${esc(z.rolle.name)}</li>`).join('') + '</ul>';
}

function queueKarte(q, p) {
  const kopf = `<div class="karte-kopfzeile"><h2>${esc(q.kennung)} · ${esc(q.name)} <span class="leise klein">${esc(q.modus)}</span></h2>
    <div class="knopfzeile">
      <button class="knopf klein" data-aktion="v-pruefen" data-kennung="${esc(q.kennung)}">Prüfen</button>
      ${q.modus === 'Ticket' && q.gruppe ? `<button class="knopf klein" data-aktion="v-mitglieder" data-kennung="${esc(q.kennung)}">Mitglieder …</button>` : ''}
      ${q.listId ? `<button class="knopf klein" data-aktion="v-auswahl" data-kennung="${esc(q.kennung)}" title="Status/Priorität/Werk-Werte ergänzen">Auswahlwerte</button>` : ''}
      <button class="knopf primaer klein" data-aktion="v-einrichten" data-kennung="${esc(q.kennung)}">${q.listId ? 'Abgleichen' : 'Einrichten'}</button>
    </div></div>`;
  if (!p) return kopf + '<p class="leise klein">Noch nicht geprüft.</p><pre class="protokoll" hidden></pre>';
  const l = p.liste;
  return kopf + `<dl class="pruefliste">
      <dt>Liste</dt><dd>${l ? haken(true, `${esc(q.liste)} · ${l.ItemCount} Elemente`) : haken(false, `${esc(q.liste)} fehlt`)}</dd>
      ${q.modus === 'Ticket' ? `<dt>Notizliste</dt><dd>${haken(!!p.notiz, esc(q.liste + NOTIZ_ENDUNG))}${p.notizRechte && (p.notizRechte.fehlt.length || p.notizRechte.zuviel.length) ? ' · <span class="rot">Rechte weichen ab</span>' : ''}</dd>
      <dt>Gruppe</dt><dd>${p.gruppe ? haken(true, `${esc(p.gruppe.titel)} · ${p.gruppe.mitglieder.length} Mitglieder${p.gruppe.mitglieder.length ? ': ' + esc(p.gruppe.mitglieder.map(m => m.name).join(', ')) : ''}`) : haken(false, `${esc(q.gruppe || '–')} fehlt`)}</dd>` : ''}
      ${l ? `<dt>Einstellungen</dt><dd>${p.einstellungen.length ? `<span class="rot">⚠</span> ${p.einstellungen.map(e => `${esc(e.feld)}: ${esc(e.ist)} → ${esc(e.soll)}`).join(', ')}` : haken(true, 'nur eigene Elemente · nicht in Suche · Versionen')}</dd>
      <dt>Vererbung</dt><dd>${haken(p.eindeutig, p.eindeutig ? 'eigene Berechtigungen' : 'erbt von der Site (alle Site-Mitglieder sehen die Liste!)')}</dd>
      <dt>Rechte</dt><dd>${rechteText(p.rechte)}</dd>` : ''}
    </dl>
    ${p.fehler.length ? `<p class="rot klein">${p.fehler.map(esc).join('<br>')}</p>` : ''}
    <pre class="protokoll" hidden></pre>`;
}

async function pruefeUndZeige(kennung) {
  const q = zustand.queues.find(x => x.kennung === kennung);
  const box = $('#v-q-' + kennung);
  if (!q || !box) return;
  const p = await queuePruefen(q);
  _pruefungen.set(kennung, p);
  box.innerHTML = queueKarte(q, p);
}

aktion('v-pruefen', el => beschaeftigt(el, 'Prüfe …', () => pruefeUndZeige(el.dataset.kennung)));
aktion('v-alle-pruefen', el => beschaeftigt(el, 'Prüfe …', async () => {
  for (const q of zustand.queues.filter(x => x.modus !== 'Hinweis')) await pruefeUndZeige(q.kennung);
}));
aktion('v-stufe', el => beschaeftigt(el, '…', async () => { await stufeSicherstellen(); meldung('Berechtigungsstufe angelegt', 'erfolg'); neuZeigen(); }));

aktion('v-einrichten', async el => {
  const q = zustand.queues.find(x => x.kennung === el.dataset.kennung);
  const box = $('#v-q-' + q.kennung);
  const ok = await bestaetigen(`${q.kennung} einrichten/abgleichen?`,
    `Die Liste „${q.liste}" bekommt eigene Berechtigungen nach Soll: ${zustand.site.ownerGruppe} und ${KONFIG.ticketPostfach} Vollzugriff`
    + (q.modus === 'Ticket' ? `, „${q.gruppe}" ${KONFIG.stufeBearbeitung}, ${KONFIG.melderAnzeige} Lesen (nur eigene Tickets)` : q.gruppe ? ', Bearbeiter-Gruppen ' + KONFIG.stufeBearbeitung : '')
    + '. Alle anderen Rechte auf der Liste werden entfernt.', { ja: 'Einrichten' });
  if (!ok) return;
  const log = box.querySelector('.protokoll');
  log.hidden = false; log.textContent = '';
  const protokoll = t => { log.textContent += t + '\n'; };
  await beschaeftigt(el, 'Richte ein …', async () => {
    try {
      const r = await queueEinrichten(q, protokoll);
      if (r.listId && (r.listId.toLowerCase() !== q.listId || r.listUrl !== q.listUrl)) {
        await queueSpeichern({ ...q, listId: r.listId, listUrl: r.listUrl });
        protokoll('Konfiguration aktualisiert (Listen-ID)');
      }
      await ladeQueues();
      protokoll('✓ fertig');
      meldung(`${q.kennung} eingerichtet`, 'erfolg');
    } catch (e) { protokoll('✗ ' + e.message); throw e; }
  });
  const text = log.textContent;
  await pruefeUndZeige(q.kennung);
  const neuLog = $('#v-q-' + q.kennung)?.querySelector('.protokoll');
  if (neuLog) { neuLog.hidden = false; neuLog.textContent = text; }
});

aktion('v-auswahl', el => beschaeftigt(el, '…', async () => {
  const q = zustand.queues.find(x => x.kennung === el.dataset.kennung);
  const log = [];
  await auswahlAngleichen(q.listId, zustand.queues, t => log.push(t));
  meldung(log.length ? 'Ergänzt: ' + log.join(' · ') : 'Auswahlwerte vollständig', 'erfolg');
}));

aktion('v-mitglieder', async el => {
  const q = zustand.queues.find(x => x.kennung === el.dataset.kennung);
  const g = (await gruppeLesen(q.gruppe)) || null;
  const r = await dialog({
    titel: `Bearbeiter ${q.kennung}`,
    breit: true,
    inhalt: `<p class="leise">Gruppe <strong>${esc(q.gruppe)}</strong>${g ? '' : ' – wird beim Speichern angelegt'}. Mitglieder sehen und bearbeiten alle Tickets dieser Queue.</p>
      ${g?.mitglieder.length ? `<div class="mitglieder">${g.mitglieder.map(m => `<label class="check"><input type="checkbox" name="weg_${m.id}"/> ${esc(m.name)} <span class="leise klein">${esc(m.mail)}</span> – entfernen</label>`).join('')}</div>` : '<p class="leise">Noch keine Mitglieder.</p>'}
      <div class="block"><span>Hinzufügen</span>${personenwahl('neu', { vorschlaege: q.bearbeiter.filter(m => !g?.mitglieder.some(x => x.mail === m)).map(m => ({ mail: m, name: m })) })}</div>`,
    knoepfe: [{ wert: 'abbrechen', text: 'Abbrechen' }, { wert: 'ok', text: 'Speichern', primaer: true }],
  });
  if (r.wert !== 'ok') return;
  const gruppe = g || await gruppeSicherstellen(q.gruppe, `Bearbeiter der Ticket-Queue ${q.name}`);
  for (const p of leseAuswahl(r.daten.neu)) await mitgliedHinzufuegen(gruppe.id, p.mail);
  for (const k of Object.keys(r.daten).filter(k => k.startsWith('weg_'))) await mitgliedEntfernen(gruppe.id, k.slice(4));
  meldung('Mitglieder gespeichert', 'erfolg');
  if ($('#v-q-' + q.kennung)) await pruefeUndZeige(q.kennung);
});

// ── Migration ─────────────────────────────────────────────────────────────

let _abbruch = false;

function zeigeMigration(ziel) {
  const archiv = zustand.queues.find(q => q.modus === 'Archiv' && q.listId);
  const ziele = zustand.queues.filter(q => q.modus === 'Ticket' && q.listId && q.werk);
  if (!archiv) { ziel.innerHTML = leer('Kein eingerichtetes Archiv (Queue im Modus „Archiv" mit der bisherigen Liste) – erst unter „Queues" anlegen und einrichten.'); return; }
  ziel.innerHTML = `<div class="karte">
    <h2>Alt-Tickets in die Werk-Listen übernehmen</h2>
    <p>Kopiert Tickets aus <strong>${esc(archiv.liste)}</strong> (Kennung ${esc(archiv.kennung)}), deren Spalte „Werk" zur Queue passt – mit Anhängen und Kommentaren – in die Liste der Queue und legt das Original in den <strong>Papierkorb</strong> (wiederherstellbar). „Erstellt von" wird auf den Melder gesetzt, damit er sein Ticket in der App sieht. Die Tickets bekommen neue Nummern.</p>
    <div class="formular-raster">
      <label>Ziel-Queue<select id="m-ziel">${ziele.map(q => `<option value="${esc(q.kennung)}">${esc(q.kennung)} · ${esc(q.name)} (Werk ${esc(q.werk)})</option>`).join('')}</select></label>
      <label class="check"><input type="checkbox" id="m-offen" checked/> nur offene Tickets</label>
    </div>
    <div class="knopfzeile"><button class="knopf" data-aktion="m-vorschau">Vorschau</button></div>
    <div id="m-ergebnis"></div>
  </div>`;
}

let _kandidaten = [];

aktion('m-vorschau', el => beschaeftigt(el, 'Lade …', async () => {
  const archiv = zustand.queues.find(q => q.modus === 'Archiv' && q.listId);
  const ziel = zustand.queues.find(q => q.kennung === $('#m-ziel').value);
  const nurOffen = $('#m-offen').checked;
  const alle = await spAlle(`_api/web/lists(${guid(archiv.listId)})/items?$select=Id,Title,${FELDER.status},${FELDER.werk},Created&$orderby=Id&$top=2000`);
  _kandidaten = alle.filter(i => i[FELDER.werk] === ziel.werk && (!nurOffen || istOffen(i[FELDER.status])));
  $('#m-ergebnis').innerHTML = `<p><strong>${_kandidaten.length}</strong> von ${alle.length} Tickets passen zu Werk ${esc(ziel.werk)}.</p>
    ${_kandidaten.length ? `<div class="tabelle-rahmen klein-tabelle"><table class="daten"><thead><tr><th>Alt</th><th>Titel</th><th>Status</th></tr></thead><tbody>
      ${_kandidaten.slice(0, 50).map(i => `<tr><td>${esc(ticketNummer(archiv.kennung, i.Id))}</td><td>${esc(i.Title)}</td><td>${esc(i[FELDER.status])}</td></tr>`).join('')}
    </tbody></table></div>${_kandidaten.length > 50 ? `<p class="leise klein">… und ${_kandidaten.length - 50} weitere</p>` : ''}
    <div class="knopfzeile"><button class="knopf primaer" data-aktion="m-start">${_kandidaten.length} Tickets übernehmen</button><button class="knopf" data-aktion="m-stopp" hidden>Anhalten</button></div>
    <div class="fortschritt" hidden><div class="fortschritt-balken"></div></div><pre class="protokoll" id="m-log" hidden></pre>` : ''}`;
}));

aktion('m-stopp', () => { _abbruch = true; });

aktion('m-start', async el => {
  const archiv = zustand.queues.find(q => q.modus === 'Archiv' && q.listId);
  const ziel = zustand.queues.find(q => q.kennung === $('#m-ziel').value);
  if (!await bestaetigen('Migration starten?', `${_kandidaten.length} Tickets werden nach ${ziel.liste} kopiert und die Originale in den Papierkorb gelegt.`, { ja: 'Starten' })) return;
  _abbruch = false;
  const log = $('#m-log'), balken = $('.fortschritt'), stopp = $('[data-aktion="m-stopp"]');
  log.hidden = false; balken.hidden = false; stopp.hidden = false; el.disabled = true;
  let ok = 0, fehler = 0;
  for (const [i, it] of _kandidaten.entries()) {
    if (_abbruch) { log.textContent += '⏸ angehalten\n'; break; }
    const alt = ticketNummer(archiv.kennung, it.Id);
    try {
      const r = await kopiereTicket(
        { listId: archiv.listId, id: it.Id, listenName: archiv.liste },
        { listId: ziel.listId, listenName: ziel.liste, kennung: ziel.kennung },
        { hinweis: `Übernommen aus ${alt} (Migration aus „${archiv.liste}").` },
      );
      await inPapierkorb(archiv.listId, it.Id);
      ok++;
      log.textContent += `✓ ${alt} → ${ticketNummer(ziel.kennung, r.id)}${r.warnungen.length ? ' ⚠ ' + r.warnungen.join('; ') : ''}\n`;
    } catch (e) {
      fehler++;
      log.textContent += `✗ ${alt}: ${e.message}\n`;
      if (/Papierkorb|recycle/i.test(e.message)) { log.textContent += 'Abbruch: Original nicht gelöscht – bitte Duplikat prüfen.\n'; break; }
    }
    balken.firstElementChild.style.width = `${((i + 1) / _kandidaten.length) * 100}%`;
    log.scrollTop = log.scrollHeight;
  }
  stopp.hidden = true;
  zustand.tickets.delete(ziel.kennung); zustand.tickets.delete(archiv.kennung);
  meldung(`Migration: ${ok} übernommen, ${fehler} Fehler`, fehler ? 'fehler' : 'erfolg');
});

// ── Mail-Eingang ──────────────────────────────────────────────────────────

function zeigeEingang(ziel) {
  const qs = zustand.queues.filter(q => q.aktiv && q.modus !== 'Archiv');
  const ctx = sollKontext();
  ziel.innerHTML = `<div class="karte">
    <h2>So kommen Mails ins System</h2>
    <ol class="schritte">
      <li>Mail an <strong>${esc(KONFIG.ticketPostfach)}</strong> → der Flow <em>Helpdesk v2</em> startet (≈ 1 Min.).</li>
      <li>Steht eine Ticketnummer im Betreff (<code>[#SCH-12]</code>, auch alte „Neues Ticket: 123"), wird die Mail als <strong>Antwort</strong> an das Ticket gehängt, der Status ggf. wieder geöffnet und die Bearbeiter informiert.</li>
      <li>Sonst: Queue nach Absender-Domain (sonst Standard-Queue) aus der Liste <code>${esc(KONFIG.konfigListe)}</code>. Modus „Hinweis" → nur Antwort-Mail.</li>
      <li>Ticket anlegen, „Erstellt von" = Melder, Zuständige zuweisen, Anhänge + Original-Mail (.eml) anhängen, Eingangsbestätigung mit <code>[#Nummer]</code> senden.</li>
    </ol>
    <p><a class="knopf primaer" href="flow/Helpdesk-v2.zip" download>Flow-Paket herunterladen (Helpdesk-v2.zip)</a> <a class="knopf" href="https://github.com/dfedorov12/tickets/blob/main/docs/EINRICHTUNG.md" target="_blank" rel="noopener">Anleitung</a></p>
    <p class="leise klein">Import: make.powerautomate.com → Meine Flows → Importieren → Paket (Legacy) → Verbindungen ${esc(KONFIG.ticketPostfach)} (Outlook + SharePoint) und ${esc(KONFIG.adminPostfach)} (Outlook) wählen. Danach den alten Flow „Helpdesk" ausschalten.</p>
  </div>
  <div class="karte"><h2>Aktuelles Routing</h2>
    <div class="tabelle-rahmen"><table class="daten"><thead><tr><th>Domain</th><th>Queue</th><th>Ergebnis</th><th>Zuständig</th></tr></thead><tbody>
      ${qs.flatMap(q => (q.domains.length ? q.domains : [q.standard ? '(alle anderen)' : '(keine Domain)']).map(d => `<tr><td>${esc(d)}</td><td><strong>${esc(q.kennung)}</strong> ${esc(q.name)}</td><td>${q.modus === 'Hinweis' ? 'Hinweis-Mail' : `Ticket in ${esc(q.liste)}${q.listId ? '' : ' <span class="rot">(nicht eingerichtet)</span>'}`}</td><td class="klein">${esc(q.bearbeiter.join(', ')) || '–'}</td></tr>`)).join('')}
    </tbody></table></div>
    <p class="leise klein">Flow-Konto <strong>${esc(ctx.dienstkonto)}</strong> braucht Vollzugriff auf die Ticketlisten (wird beim Einrichten vergeben), damit es „Erstellt von" setzen und Antworten anhängen kann.</p>
  </div>`;
}
