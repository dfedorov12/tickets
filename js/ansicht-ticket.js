/**
 * Ticket-Detail
 * =============
 * Bearbeiter: Status, Priorität, Zuweisung, Antwort an den Melder (Kommentar + Mail),
 * interne Notizen, Anhänge, Weiterleiten in eine andere Queue.
 * Melder: Verlauf lesen, antworten (per Mail an das Ticketpostfach – der Flow hängt
 * die Antwort an und benachrichtigt die Bearbeiter).
 */
import { KONFIG, FELDER, STATUS, PRIORITAETEN, siteUrl } from './config.js';
import {
  zustand, ladeTicket, ladeFelder, setzeWerte, setzeBearbeiter, ladeKommentare, kommentieren,
  ladeNotizen, notieren, ladeAnhaenge, anhangHochladen, anhangLoeschen, meineListen, liste as listeVon,
} from './daten.js';
import { sendeMail, sp, lit } from './api.js';
import {
  istOffen, istUeberfaellig, faelligAm, passendeAuswahl, normPrio, istMirZugewiesen, ticketNummer,
} from './modell.js';
import { mailAntwortAnMelder, mailStatusAnMelder, mailMelderAntwort, mailZuweisung } from './mails.js';
import { kopiereTicket } from './kopie.js';
import { meineMail, meinName } from './auth.js';
import { esc, datumZeit, relativ, groesse } from './text.js';
import { sicheresHtml, istHtml, textFragment } from './html.js';
import { $, aktion, dialog, meldung, beschaeftigt, statusBadge, prioBadge, personen, avatar, ladeAnzeige } from './ui.js';
import { personenwahl, leseAuswahl } from './personenwahl.js';

let akt = null; // { ticket, liste, rolle }

const istBearbeiter = () => akt && (akt.rolle === 'bearbeiter' || akt.rolle === 'admin');

export async function zeige(main, route, aktuell) {
  main.innerHTML = ladeAnzeige('Lade Ticket …');
  const { ticket, liste } = await ladeTicket(route.nummer);
  if (!aktuell()) return;
  akt = { ticket, liste, rolle: liste.rolle };
  zeichne(main);
  ladeVerlauf();
  ladeAnhangListe();
  if (istBearbeiter()) ladeNotizListe();
}

function auswahlOptionen(feld, werte, aktuell, norm) {
  const liste = akt.liste.auswahl[feld]?.length ? akt.liste.auswahl[feld] : werte;
  const alle = liste.includes(aktuell) || !aktuell ? liste : [aktuell, ...liste];
  return alle.map(w => `<option value="${esc(w)}"${(norm ? norm(w) === norm(aktuell) : w === aktuell) ? ' selected' : ''}>${esc(w)}</option>`).join('');
}

function zeichne(main = $('#hauptinhalt')) {
  const t = akt.ticket;
  const q = akt.liste.queue;
  const b = istBearbeiter();
  const zurueck = b ? '#/posteingang' : '#/meine';
  const faellig = faelligAm(t);
  const ueber = istUeberfaellig(t);

  main.innerHTML = `
    <div class="ticket-kopf">
      <a href="${zurueck}" class="zurueck">← ${b ? 'Posteingang' : 'Meine Anfragen'}</a>
      <div class="nr-zeile"><span class="nr gross">${esc(t.nummer)}</span><span class="leise">${esc(q.name)}${q.modus === 'Archiv' ? ' (Archiv)' : ''}</span>${statusBadge(t.status)}${prioBadge(t.prio)}${ueber && b ? '<span class="badge st-rot">überfällig</span>' : ''}</div>
      <h1>${esc(t.titel || '(ohne Betreff)')}</h1>
    </div>
    <div class="ticket-raster">
      <section class="ticket-haupt">
        <article class="karte">
          <h2>Beschreibung</h2>
          <div class="mail-inhalt" id="t-beschreibung"></div>
        </article>
        <article class="karte">
          <div class="karte-kopfzeile"><h2>Anhänge</h2>${b ? `<label class="knopf klein">Datei anhängen<input type="file" multiple hidden data-aendern="t-hochladen"/></label>` : ''}</div>
          <div id="t-anhaenge">${ladeAnzeige()}</div>
        </article>
        <article class="karte">
          <div class="reiter" role="tablist">
            <button class="reiter-knopf aktiv" role="tab" aria-selected="true" data-aktion="t-reiter" data-reiter="verlauf">Verlauf <span class="leise klein">(für Melder sichtbar)</span></button>
            ${b ? '<button class="reiter-knopf" role="tab" aria-selected="false" data-aktion="t-reiter" data-reiter="intern">🔒 Intern <span class="leise klein">(nur IT)</span></button>' : ''}
          </div>
          <div id="t-reiter-verlauf">
            <div id="t-verlauf">${ladeAnzeige()}</div>
            ${antwortFormular(b)}
          </div>
          ${b ? `<div id="t-reiter-intern" hidden>
            <div id="t-notizen">${ladeAnzeige()}</div>
            <form class="antwort intern" data-absenden="t-notiz">
              <label class="sr" for="t-notiz-text">Interne Notiz</label>
              <textarea id="t-notiz-text" name="text" rows="3" required placeholder="Interne Notiz – sieht nur das IT-Team dieser Queue …"></textarea>
              <div class="antwort-fuss"><span class="leise klein">🔒 Nicht für den Melder sichtbar.</span><button class="knopf">Notiz speichern</button></div>
            </form>
          </div>` : ''}
        </article>
      </section>
      <aside class="ticket-seite">
        <div class="karte eigenschaften">
          ${b ? `
          <label>Status<select data-aendern="t-status">${auswahlOptionen(FELDER.status, STATUS.map(s => s.wert), t.status)}</select></label>
          <label>Priorität<select data-aendern="t-prio">${auswahlOptionen(FELDER.prio, PRIORITAETEN, t.prioRoh || t.prio, normPrio)}</select></label>`
          : `<div class="feld"><span>Status</span>${statusBadge(t.status)}</div>`}
          <div class="feld"><span>Bearbeiter</span><div class="personen-block">${personen(t.bearbeiter)}</div>
            ${b ? `<div class="knopfzeile">${istMirZugewiesen(t, meineMail()) ? '' : '<button class="knopf klein" data-aktion="t-uebernehmen">Übernehmen</button>'}<button class="knopf klein" data-aktion="t-zuweisen">Zuweisen …</button></div>` : ''}
          </div>
          <div class="feld"><span>Melder</span><div>${t.melder ? `<span class="person">${avatar(t.melder.name, t.melder.mail)}<span>${esc(t.melder.name)}</span></span>` : '<span class="leise">unbekannt</span>'}${t.melderMail ? `<div class="klein"><a href="mailto:${esc(t.melderMail)}">${esc(t.melderMail)}</a></div>` : ''}</div></div>
          <div class="feld"><span>Queue</span><div>${esc(q.name)} <span class="leise">(${esc(q.kennung)})</span></div></div>
          ${t.werk ? `<div class="feld"><span>Werk</span><div>${esc(t.werk)}</div></div>` : ''}
          ${t.kategorie ? `<div class="feld"><span>Kategorie</span><div>${esc(t.kategorie)}</div></div>` : ''}
          <div class="feld"><span>Gemeldet</span><div title="${esc(datumZeit(t.gemeldetAm))}">${esc(datumZeit(t.gemeldetAm))}</div></div>
          <div class="feld"><span>Geändert</span><div title="${esc(datumZeit(t.geaendert))}">${esc(relativ(t.geaendert))}</div></div>
          ${b && istOffen(t.status) && faellig ? `<div class="feld"><span>Ziel</span><div class="${ueber ? 'rot' : ''}">${esc(datumZeit(faellig))}</div></div>` : ''}
        </div>
        ${b ? `<div class="karte aktionen">
          ${istOffen(t.status) ? '<button class="knopf gruen" data-aktion="t-erledigt">✓ Erledigt …</button>' : '<button class="knopf" data-aktion="t-wieder-oeffnen">Wieder öffnen</button>'}
          <button class="knopf" data-aktion="t-weiterleiten">Andere Queue …</button>
          <a class="knopf" target="_blank" rel="noopener" href="${esc(`${siteUrl()}/_layouts/15/listform.aspx?PageType=4&ListId=%7B${q.listId}%7D&ID=${t.id}`)}">In SharePoint ↗</a>
        </div>` : ''}
      </aside>
    </div>`;

  const ziel = $('#t-beschreibung');
  const text = t.beschreibung || '';
  if (!text.trim()) ziel.innerHTML = '<p class="leise">Keine Beschreibung.</p>';
  else ziel.appendChild(istHtml(text) ? sicheresHtml(text) : textFragment(text));
}

function antwortFormular(b) {
  if (b) {
    const hatMail = !!akt.ticket.melderMail;
    return `<form class="antwort" data-absenden="t-antwort">
      <label class="sr" for="t-antwort-text">Antwort</label>
      <textarea id="t-antwort-text" name="text" rows="4" required placeholder="Antwort an den Melder / Kommentar …"></textarea>
      <div class="antwort-fuss">
        <label class="check"><input type="checkbox" name="mail"${hatMail ? ' checked' : ' disabled'}/> Melder per Mail benachrichtigen${hatMail ? '' : ' (keine Adresse)'}</label>
        <button class="knopf primaer">Senden</button>
      </div>
    </form>`;
  }
  return `<form class="antwort" data-absenden="t-antwort">
    <label class="sr" for="t-antwort-text">Ihre Antwort</label>
    <textarea id="t-antwort-text" name="text" rows="4" required placeholder="Ihre Antwort oder Ergänzung an das IT-Team …"></textarea>
    <div class="antwort-fuss"><span class="leise klein">Wird per Mail an ${esc(KONFIG.ticketPostfach)} gesendet und erscheint in 1–2 Minuten im Verlauf.</span><button class="knopf primaer">Antworten</button></div>
  </form>`;
}

// ── Verlauf, Notizen, Anhänge ─────────────────────────────────────────────

function eintrag(e, intern = false) {
  const div = document.createElement('div');
  div.className = 'eintrag' + (intern ? ' intern' : '') + (e.mail === meineMail() ? ' eigen' : '');
  div.innerHTML = `<div class="eintrag-kopf">${avatar(e.name, e.mail)}<strong>${esc(e.name)}</strong><span class="leise klein" title="${esc(datumZeit(e.datum))}">${esc(relativ(e.datum))}</span></div><div class="eintrag-text"></div>`;
  div.querySelector('.eintrag-text').appendChild(textFragment(e.text));
  return div;
}

async function ladeVerlauf() {
  const ziel = $('#t-verlauf');
  if (!ziel) return;
  const nr = akt.ticket.nummer;
  try {
    const kommentare = await ladeKommentare(nr);
    if (akt?.ticket.nummer !== nr) return;
    ziel.innerHTML = kommentare.length ? '' : '<p class="leise">Noch keine Nachrichten.</p>';
    kommentare.forEach(k => ziel.appendChild(eintrag(k)));
  } catch (e) { ziel.innerHTML = `<p class="rot klein">Verlauf nicht verfügbar: ${esc(e.message)}</p>`; }
}

async function ladeNotizListe() {
  const ziel = $('#t-notizen');
  if (!ziel) return;
  const nr = akt.ticket.nummer;
  try {
    const notizen = await ladeNotizen(nr);
    if (akt?.ticket.nummer !== nr) return;
    if (notizen === null) { ziel.innerHTML = '<p class="leise">Für diese Queue ist noch keine Notizliste eingerichtet (Verwaltung → Rechte).</p>'; return; }
    ziel.innerHTML = notizen.length ? '' : '<p class="leise">Keine internen Notizen.</p>';
    notizen.forEach(n => ziel.appendChild(eintrag(n, true)));
  } catch (e) { ziel.innerHTML = `<p class="rot klein">Notizen nicht verfügbar: ${esc(e.message)}</p>`; }
}

async function ladeAnhangListe() {
  const ziel = $('#t-anhaenge');
  if (!ziel) return;
  const nr = akt.ticket.nummer;
  try {
    const liste = await ladeAnhaenge(nr);
    if (akt?.ticket.nummer !== nr) return;
    ziel.innerHTML = liste.length
      ? `<ul class="anhaenge">${liste.map(a => `<li><a href="${esc(a.url)}" target="_blank" rel="noopener">📎 ${esc(a.name)}</a>${istBearbeiter() ? `<button class="knopf-link rot" data-aktion="t-anhang-weg" data-name="${esc(a.name)}" aria-label="${esc(a.name)} löschen">entfernen</button>` : ''}</li>`).join('')}</ul>`
      : '<p class="leise">Keine Anhänge.</p>';
  } catch (e) { ziel.innerHTML = `<p class="rot klein">${esc(e.message)}</p>`; }
}

// ── Aktionen ──────────────────────────────────────────────────────────────

function neuZeichnen() {
  zeichne();
  ladeVerlauf();
  ladeAnhangListe();
  ladeNotizListe();
}

aktion('t-reiter', el => {
  const r = el.dataset.reiter;
  document.querySelectorAll('.reiter-knopf').forEach(k => { const an = k.dataset.reiter === r; k.classList.toggle('aktiv', an); k.setAttribute('aria-selected', String(an)); });
  $('#t-reiter-verlauf').hidden = r !== 'verlauf';
  const intern = $('#t-reiter-intern');
  if (intern) intern.hidden = r !== 'intern';
});

async function statusSetzen(status, { text = '', mail = false } = {}) {
  const t = akt.ticket;
  const wert = passendeAuswahl(akt.liste.auswahl[FELDER.status], status);
  await setzeWerte(t.nummer, { [FELDER.status]: wert }, { status: wert });
  t.status = wert;
  if (text.trim()) await kommentieren(t.nummer, text.trim());
  if (mail && t.melderMail) {
    const m = mailStatusAnMelder({ nummer: t.nummer, titel: t.titel, status: wert, text });
    await sendeMail({ an: t.melderMail, betreff: m.betreff, html: m.html, antwortAn: KONFIG.ticketPostfach });
  }
}

async function abschliessen(status) {
  const t = akt.ticket;
  const r = await dialog({
    titel: `${t.nummer} – ${status}`,
    inhalt: `<label class="block">Lösung / Nachricht an den Melder (optional)<textarea name="text" rows="4"></textarea></label>
      <label class="check"><input type="checkbox" name="mail"${t.melderMail ? ' checked' : ' disabled'}/> Melder per Mail informieren</label>`,
    knoepfe: [{ wert: 'abbrechen', text: 'Abbrechen' }, { wert: 'ok', text: status === 'Erledigt' ? 'Als erledigt markieren' : 'Speichern', primaer: true }],
  });
  if (r.wert !== 'ok') return false;
  await statusSetzen(status, { text: r.daten.text || '', mail: r.daten.mail === 'on' });
  meldung(`${t.nummer}: ${status}`, 'erfolg');
  return true;
}

aktion('t-status', async el => {
  const neu = el.value;
  if (!istOffen(neu) && istOffen(akt.ticket.status)) {
    if (!(await abschliessen(neu))) { el.value = akt.ticket.status; return; }
  } else {
    await statusSetzen(neu);
    meldung(`Status: ${neu}`, 'erfolg');
  }
  neuZeichnen();
});

aktion('t-prio', async el => {
  await setzeWerte(akt.ticket.nummer, { [FELDER.prio]: el.value }, { prio: normPrio(el.value), prioRoh: el.value });
  akt.ticket.prio = normPrio(el.value); akt.ticket.prioRoh = el.value;
  meldung('Priorität gespeichert', 'erfolg');
  neuZeichnen();
});

aktion('t-erledigt', async () => {
  if (await abschliessen('Erledigt')) { neuZeichnen(); }
});

aktion('t-wieder-oeffnen', async () => {
  await statusSetzen('In Bearbeitung');
  neuZeichnen();
});

aktion('t-uebernehmen', async el => beschaeftigt(el, 'Übernehme …', async () => {
  const t = akt.ticket;
  const neu = [...t.bearbeiter.filter(p => p.mail), { mail: meineMail(), name: meinName() }];
  await setzeBearbeiter(t.nummer, neu);
  t.bearbeiter = neu;
  if (['Neu', 'Offen'].includes(t.status)) await statusSetzen('In Bearbeitung');
  meldung(`${t.nummer} übernommen`, 'erfolg');
  neuZeichnen();
}));

async function gruppenMitglieder(gruppe) {
  if (!gruppe) return [];
  try {
    const r = await sp(`_api/web/sitegroups/getbyname(${lit(gruppe)})/users?$select=Title,Email`);
    return (r?.value || []).filter(u => u.Email).map(u => ({ name: u.Title, mail: u.Email.toLowerCase() }));
  } catch { return []; }
}

aktion('t-zuweisen', async () => {
  const t = akt.ticket;
  const q = akt.liste.queue;
  const mitglieder = await gruppenMitglieder(q.gruppe);
  const vorschlaege = [...mitglieder, ...q.bearbeiter.map(m => ({ mail: m, name: m }))]
    .filter((p, i, a) => a.findIndex(x => x.mail === p.mail) === i && !t.bearbeiter.some(b => b.mail === p.mail));
  const r = await dialog({
    titel: `${t.nummer} zuweisen`,
    inhalt: personenwahl('personen', { vorbelegt: t.bearbeiter.filter(p => p.mail).map(p => ({ mail: p.mail, name: p.name })), vorschlaege })
      + '<label class="check"><input type="checkbox" name="mail" checked/> Neu Zugewiesene per Mail informieren</label>',
    knoepfe: [{ wert: 'abbrechen', text: 'Abbrechen' }, { wert: 'ok', text: 'Speichern', primaer: true }],
  });
  if (r.wert !== 'ok') return;
  const neu = leseAuswahl(r.daten.personen);
  const hinzu = neu.filter(p => !t.bearbeiter.some(b => b.mail === p.mail) && p.mail !== meineMail());
  await setzeBearbeiter(t.nummer, neu);
  t.bearbeiter = neu;
  if (r.daten.mail === 'on' && hinzu.length) {
    const m = mailZuweisung({ nummer: t.nummer, titel: t.titel, von: meinName() });
    await sendeMail({ an: hinzu.map(p => p.mail), betreff: m.betreff, html: m.html }).catch(e => meldung('Mail: ' + e.message, 'fehler'));
  }
  meldung('Zuweisung gespeichert', 'erfolg');
  neuZeichnen();
});

aktion('t-antwort', async form => {
  const t = akt.ticket;
  const text = String(new FormData(form).get('text') || '').trim();
  if (!text) return;
  const knopf = form.querySelector('button');
  await beschaeftigt(knopf, 'Sende …', async () => {
    if (istBearbeiter()) {
      const mail = form.querySelector('[name=mail]')?.checked && t.melderMail;
      await kommentieren(t.nummer, mail ? `✉ ${text}` : text);
      if (mail) {
        const m = mailAntwortAnMelder({ nummer: t.nummer, titel: t.titel, text, absender: meinName() });
        await sendeMail({ an: t.melderMail, betreff: m.betreff, html: m.html, antwortAn: KONFIG.ticketPostfach });
      }
      if (t.status === 'Neu') await statusSetzen('In Bearbeitung');
      meldung(mail ? 'Antwort gesendet' : 'Kommentar gespeichert', 'erfolg');
      neuZeichnen();
    } else {
      const m = mailMelderAntwort({ nummer: t.nummer, titel: t.titel, text });
      await sendeMail({ an: KONFIG.ticketPostfach, betreff: m.betreff, html: m.html });
      form.reset();
      const vorschau = eintrag({ name: meinName(), mail: meineMail(), text: text + '\n\n(wird übermittelt …)', datum: new Date().toISOString() });
      vorschau.classList.add('vorlaeufig');
      $('#t-verlauf').appendChild(vorschau);
      meldung('Antwort gesendet – sie erscheint in 1–2 Minuten im Verlauf.', 'erfolg');
    }
  });
});

aktion('t-notiz', async form => {
  const text = String(new FormData(form).get('text') || '').trim();
  if (!text) return;
  await beschaeftigt(form.querySelector('button'), 'Speichere …', async () => {
    await notieren(akt.ticket.nummer, text);
    form.reset();
    await ladeNotizListe();
  });
});

aktion('t-hochladen', async el => {
  const dateien = [...(el.files || [])];
  for (const d of dateien) {
    if (d.size > 50 * 1024 * 1024) { meldung(`${d.name}: größer als 50 MB`, 'fehler'); continue; }
    await anhangHochladen(akt.ticket.nummer, d);
    meldung(`${d.name} angehängt`, 'erfolg');
  }
  el.value = '';
  ladeAnhangListe();
});

aktion('t-anhang-weg', async el => {
  const r = await dialog({ titel: 'Anhang entfernen?', inhalt: `<p>${esc(el.dataset.name)} wird aus dem Ticket entfernt.</p>`, knoepfe: [{ wert: 'nein', text: 'Abbrechen' }, { wert: 'ja', text: 'Entfernen', gefahr: true }] });
  if (r.wert !== 'ja') return;
  await anhangLoeschen(akt.ticket.nummer, el.dataset.name);
  ladeAnhangListe();
});

aktion('t-weiterleiten', async () => {
  const t = akt.ticket;
  const quelle = akt.liste.queue;
  const ziele = meineListen('bearbeiter').filter(l => l.queue.modus === 'Ticket' && l.queue.kennung !== quelle.kennung);
  if (!ziele.length) {
    await dialog({ titel: 'Andere Queue', inhalt: '<p>Du bist in keiner anderen Queue Bearbeiter. Bitte einen Admin bitten, das Ticket zu verschieben – oder die Bearbeiter der Ziel-Queue per Mail informieren.</p>' });
    return;
  }
  const r = await dialog({
    titel: `${t.nummer} in andere Queue`,
    inhalt: `<p>Das Ticket wird mit Verlauf, Notizen und Anhängen in die Ziel-Queue kopiert und bekommt dort eine neue Nummer. Hier bleibt es als „Weitergeleitet" mit Verweis stehen.</p>
      <label class="block">Ziel-Queue<select name="ziel">${ziele.map(l => `<option value="${esc(l.queue.kennung)}">${esc(l.queue.name)} (${esc(l.queue.kennung)})</option>`).join('')}</select></label>
      <label class="check"><input type="checkbox" name="mail"${t.melderMail ? ' checked' : ' disabled'}/> Melder über die neue Nummer informieren</label>`,
    knoepfe: [{ wert: 'abbrechen', text: 'Abbrechen' }, { wert: 'ok', text: 'Weiterleiten', primaer: true }],
  });
  if (r.wert !== 'ok') return;
  const ziel = listeVon(r.daten.ziel);
  await ladeFelder(ziel.queue.kennung);
  meldung('Kopiere Ticket …', 'info');
  const { id, warnungen } = await kopiereTicket(
    { listId: quelle.listId, id: t.id, listenName: quelle.liste },
    { listId: ziel.queue.listId, listenName: ziel.queue.liste, kennung: ziel.queue.kennung },
    { werk: ziel.queue.werk, status: passendeAuswahl(ziel.auswahl[FELDER.status], 'Neu'), hinweis: `Weitergeleitet aus ${t.nummer} von ${meinName()}.` },
  );
  const neueNr = ticketNummer(ziel.queue.kennung, id);
  const weiter = (akt.liste.auswahl[FELDER.status] || []).includes('Weitergeleitet') ? 'Weitergeleitet' : passendeAuswahl(akt.liste.auswahl[FELDER.status], 'Abgebrochen');
  await setzeWerte(t.nummer, { [FELDER.status]: weiter }, { status: weiter });
  await kommentieren(t.nummer, `→ Weitergeleitet an ${neueNr} (${ziel.queue.name}) von ${meinName()}.`);
  if (r.daten.mail === 'on' && t.melderMail) {
    const m = mailStatusAnMelder({ nummer: neueNr, titel: t.titel, status: 'Neu', text: `Ihr Ticket ${t.nummer} wird jetzt von ${ziel.queue.name} bearbeitet. Neue Ticketnummer: ${neueNr}.` });
    await sendeMail({ an: t.melderMail, betreff: m.betreff, html: m.html, antwortAn: KONFIG.ticketPostfach }).catch(e => meldung('Mail: ' + e.message, 'fehler'));
  }
  zustand.tickets.delete(ziel.queue.kennung);
  warnungen.forEach(w => meldung(w, 'fehler'));
  meldung(`Weitergeleitet: ${neueNr}`, 'erfolg');
  location.hash = '#/t/' + neueNr;
});

