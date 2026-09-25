/**
 * Mailtexte des Ticketsystems – ohne DOM, damit App und Nachtlauf dieselben nutzen.
 * Jede Funktion liefert { betreff, html }. Alle Fremdwerte laufen durch esc().
 */
import { esc, textZuHtml, datumZeit } from './text.js';
import { betreffMitToken, ticketLink } from './modell.js';
import { KONFIG } from './config.js';

const RAHMEN = inhalt => `<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#1a2644;line-height:1.5">${inhalt}`
  + `<p style="margin-top:24px;color:#6b7280;font-size:12px">DIHAG IT-Service · Antworten auf diese Mail landen automatisch im Ticket.</p></div>`;

const knopf = (href, text) => `<p><a href="${esc(href)}" style="display:inline-block;padding:9px 18px;background:#17509e;color:#fff;border-radius:6px;text-decoration:none;font-weight:600">${esc(text)}</a></p>`;

/** Bearbeiter → Melder: Antwort/Kommentar. Antworten gehen per Reply-To an das Ticketpostfach. */
export function mailAntwortAnMelder({ nummer, titel, text, absender, appUrl = KONFIG.appUrl }) {
  return {
    betreff: betreffMitToken(nummer, titel),
    html: RAHMEN(`<p>Guten Tag,</p><p>zu Ihrem Ticket <strong>${esc(nummer)}</strong> („${esc(titel)}") gibt es eine Nachricht von ${esc(absender)}:</p>`
      + `<blockquote style="margin:12px 0;padding:10px 14px;border-left:3px solid #17509e;background:#f4f7fb">${textZuHtml(text)}</blockquote>`
      + `<p>Sie können einfach auf diese Mail antworten.</p>` + knopf(ticketLink(appUrl, nummer), 'Ticket ansehen')),
  };
}

/** Statusänderung an den Melder (z. B. Erledigt). */
export function mailStatusAnMelder({ nummer, titel, status, text = '', appUrl = KONFIG.appUrl }) {
  const satz = status === 'Erledigt'
    ? 'wurde als <strong>erledigt</strong> markiert. Falls das Problem weiter besteht, antworten Sie einfach auf diese Mail – das Ticket wird dann wieder geöffnet.'
    : `hat jetzt den Status <strong>${esc(status)}</strong>.`;
  return {
    betreff: betreffMitToken(nummer, titel),
    html: RAHMEN(`<p>Guten Tag,</p><p>Ihr Ticket <strong>${esc(nummer)}</strong> („${esc(titel)}") ${satz}</p>`
      + (text ? `<blockquote style="margin:12px 0;padding:10px 14px;border-left:3px solid #17509e;background:#f4f7fb">${textZuHtml(text)}</blockquote>` : '')
      + knopf(ticketLink(appUrl, nummer), 'Ticket ansehen')),
  };
}

/** Melder → Ticketpostfach: Antwort auf ein bestehendes Ticket (der Flow hängt sie als Kommentar an). */
export function mailMelderAntwort({ nummer, titel, text }) {
  return { betreff: betreffMitToken(nummer, 'Re: ' + titel), html: `<div>${textZuHtml(text)}</div>` };
}

/** Melder → Ticketpostfach: neues Ticket über das Formular der App. */
export function mailNeuesTicket({ titel, text, kategorie = '', dringend = false }) {
  const kopf = kategorie ? `<p><strong>Kategorie:</strong> ${esc(kategorie)}</p>` : '';
  return { betreff: String(titel || '').trim(), html: `${kopf}<div>${textZuHtml(text)}</div>`, wichtigkeit: dringend ? 'high' : 'normal' };
}

/** Bearbeiter an Kollegen: Hinweis auf ein Ticket (Erwähnung/Zuweisung). */
export function mailZuweisung({ nummer, titel, von, appUrl = KONFIG.appUrl }) {
  return {
    betreff: `Ticket ${nummer} wurde Ihnen zugewiesen: ${titel}`,
    html: RAHMEN(`<p>${esc(von)} hat Ihnen das Ticket <strong>${esc(nummer)}</strong> („${esc(titel)}") zugewiesen.</p>` + knopf(ticketLink(appUrl, nummer), 'Ticket öffnen')),
  };
}

/** Tagesübersicht je Queue für die Bearbeiter (Nachtlauf). */
export function mailTagesuebersicht({ queue, kennzahlen, tickets, appUrl = KONFIG.appUrl }) {
  const zeilen = tickets.slice(0, 40).map(t => `<tr>`
    + `<td style="padding:4px 8px"><a href="${esc(ticketLink(appUrl, t.nummer))}">${esc(t.nummer)}</a></td>`
    + `<td style="padding:4px 8px">${esc(t.titel)}</td>`
    + `<td style="padding:4px 8px">${esc(t.status)}</td>`
    + `<td style="padding:4px 8px">${esc(t.prio)}</td>`
    + `<td style="padding:4px 8px">${t.bearbeiter.length ? esc(t.bearbeiter.map(b => b.name).join(', ')) : '<em>niemand</em>'}</td>`
    + `<td style="padding:4px 8px">${esc(datumZeit(t.gemeldetAm))}</td></tr>`).join('');
  return {
    betreff: `Tickets ${queue.kennung}: ${kennzahlen.offen} offen, ${kennzahlen.ueberfaellig} überfällig, ${kennzahlen.unzugewiesen} ohne Bearbeiter`,
    html: RAHMEN(`<h2 style="font-size:18px;margin:0 0 8px">Tagesübersicht ${esc(queue.name)}</h2>`
      + `<p>${kennzahlen.offen} offen · ${kennzahlen.neu} neu · ${kennzahlen.unzugewiesen} ohne Bearbeiter · <strong>${kennzahlen.ueberfaellig} überfällig</strong></p>`
      + (zeilen ? `<table style="border-collapse:collapse;font-size:13px"><tr style="background:#f0f2f5"><th align="left" style="padding:4px 8px">Nr.</th><th align="left" style="padding:4px 8px">Titel</th><th align="left" style="padding:4px 8px">Status</th><th align="left" style="padding:4px 8px">Prio</th><th align="left" style="padding:4px 8px">Bearbeiter</th><th align="left" style="padding:4px 8px">Gemeldet</th></tr>${zeilen}</table>` : '<p>Nichts Dringendes. 🎉</p>')
      + (tickets.length > 40 ? `<p>… und ${tickets.length - 40} weitere.</p>` : '')
      + knopf(appUrl + '#/posteingang', 'Posteingang öffnen')),
  };
}

/** Rechtebericht des Nachtlaufs an den Admin. */
export function mailRechtebericht({ befunde, repariert = false }) {
  const zeilen = befunde.map(b => `<li><strong>${esc(b.liste)}</strong>: ${esc(b.text)}</li>`).join('');
  return {
    betreff: befunde.length ? `Ticketsystem: ${befunde.length} Abweichung(en) bei den Berechtigungen${repariert ? ' – behoben' : ''}` : 'Ticketsystem: Berechtigungen in Ordnung',
    html: RAHMEN(befunde.length
      ? `<p>Der Nachtlauf hat Abweichungen vom Soll gefunden${repariert ? ' und sie behoben' : ''}:</p><ul>${zeilen}</ul><p>Details und Abgleich: App → Verwaltung → Rechte.</p>`
      : '<p>Alle Ticketlisten entsprechen dem Soll.</p>'),
  };
}
