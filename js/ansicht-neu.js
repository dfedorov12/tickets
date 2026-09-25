/**
 * Neues Ticket
 * ============
 * Melder: Das Formular schickt eine Mail aus dem eigenen Postfach an das Ticketpostfach.
 *   So läuft jedes Ticket über denselben Eingang (Flow): Routing nach Domain,
 *   Eingangsbestätigung mit Nummer, „Erstellt von" = Melder. Keine Schreibrechte nötig.
 * Bearbeiter: zusätzlich „Direkt anlegen" in einer eigenen Queue (z. B. nach einem Anruf).
 */
import { KONFIG, PRIORITAETEN } from './config.js';
import { meineListen, ticketAnlegen, zustand } from './daten.js';
import { sendeMail } from './api.js';
import { mailNeuesTicket } from './mails.js';
import { meineMail } from './auth.js';
import { esc, textZuHtml, groesse } from './text.js';
import { $, aktion, meldung, beschaeftigt, alsBase64 } from './ui.js';
import { personenwahl, leseAuswahl } from './personenwahl.js';

const MAX_ANHANG = 3 * 1024 * 1024; // Graph sendMail: Anhänge direkt im Aufruf bis ~3 MB gesamt

export async function zeige(main) {
  const queues = meineListen('bearbeiter').filter(l => l.queue.modus === 'Ticket');
  main.innerHTML = `
    <div class="seitenkopf"><h1>Neues Ticket</h1></div>
    ${queues.length ? `<div class="reiter" role="tablist">
      <button class="reiter-knopf aktiv" role="tab" data-aktion="neu-reiter" data-reiter="mail" aria-selected="true">Als Melder melden</button>
      <button class="reiter-knopf" role="tab" data-aktion="neu-reiter" data-reiter="direkt" aria-selected="false">Direkt in Queue anlegen</button>
    </div>` : ''}
    <form class="karte formular" id="neu-mail" data-absenden="neu-mail">
      <p class="leise">Ihr Anliegen geht an das IT-Team. Sie bekommen gleich eine Eingangsbestätigung mit der Ticketnummer und sehen das Ticket danach unter „Meine Anfragen".</p>
      <label class="block">Betreff <span class="pflicht">*</span><input name="titel" required maxlength="200" placeholder="Kurz: Was ist das Problem?"/></label>
      <label class="block">Beschreibung <span class="pflicht">*</span><textarea name="text" rows="8" required placeholder="Was ist passiert? Seit wann? Welcher Rechner/welches Programm? Fehlermeldung?"></textarea></label>
      <label class="block">Anhänge (Screenshots, bis 3 MB gesamt)<input type="file" name="dateien" multiple data-aendern="neu-dateien"/></label>
      <div id="neu-dateien" class="leise klein"></div>
      <label class="check"><input type="checkbox" name="dringend"/> Dringend – ich kann nicht arbeiten</label>
      <div class="formular-fuss"><span class="leise klein">Absender: ${esc(meineMail())}</span><button class="knopf primaer">Ticket senden</button></div>
    </form>
    ${queues.length ? `<form class="karte formular" id="neu-direkt" data-absenden="neu-direkt" hidden>
      <p class="leise">Für Anliegen, die telefonisch oder persönlich kommen. Der Melder wird als „Erstellt von" eingetragen und sieht das Ticket in der App.</p>
      <label class="block">Queue<select name="kennung">${queues.map(l => `<option value="${esc(l.queue.kennung)}">${esc(l.queue.name)} (${esc(l.queue.kennung)})</option>`).join('')}</select></label>
      <div class="block"><span>Melder</span>${personenwahl('melder', { einzeln: true, platzhalter: 'Melder suchen …' })}</div>
      <label class="block">Betreff <span class="pflicht">*</span><input name="titel" required maxlength="200"/></label>
      <label class="block">Beschreibung<textarea name="text" rows="6"></textarea></label>
      <label class="block">Priorität<select name="prio">${PRIORITAETEN.map(p => `<option${p === 'Normal' ? ' selected' : ''}>${esc(p)}</option>`).join('')}</select></label>
      <label class="check"><input type="checkbox" name="mir" checked/> Mir zuweisen</label>
      <div class="formular-fuss"><span></span><button class="knopf primaer">Ticket anlegen</button></div>
    </form>` : ''}`;
}

aktion('neu-reiter', el => {
  const r = el.dataset.reiter;
  document.querySelectorAll('.reiter-knopf').forEach(k => { const an = k.dataset.reiter === r; k.classList.toggle('aktiv', an); k.setAttribute('aria-selected', String(an)); });
  $('#neu-mail').hidden = r !== 'mail';
  $('#neu-direkt').hidden = r !== 'direkt';
});

aktion('neu-dateien', el => {
  const summe = [...el.files].reduce((s, f) => s + f.size, 0);
  $('#neu-dateien').textContent = el.files.length ? `${el.files.length} Datei(en), ${groesse(summe)}${summe > MAX_ANHANG ? ' – zu groß, bitte weniger/kleinere Dateien' : ''}` : '';
});

aktion('neu-mail', async form => {
  const d = new FormData(form);
  const dateien = [...form.querySelector('[name=dateien]').files];
  if (dateien.reduce((s, f) => s + f.size, 0) > MAX_ANHANG) { meldung('Anhänge zusammen größer als 3 MB – bitte verkleinern oder später per Antwort nachreichen.', 'fehler'); return; }
  await beschaeftigt(form.querySelector('button.primaer'), 'Sende …', async () => {
    const m = mailNeuesTicket({ titel: d.get('titel'), text: d.get('text'), dringend: d.get('dringend') === 'on' });
    const anhaenge = await Promise.all(dateien.map(async f => ({ name: f.name, typ: f.type, base64: await alsBase64(f) })));
    await sendeMail({ an: KONFIG.ticketPostfach, betreff: m.betreff, html: m.html, wichtigkeit: m.wichtigkeit, anhaenge });
  });
  form.innerHTML = `<div class="erfolg-box"><div class="leer-symbol">📨</div><h2>Danke – Ihr Ticket ist unterwegs.</h2>
    <p>Sie erhalten in 1–2 Minuten eine Eingangsbestätigung mit der Ticketnummer. Unter „Meine Anfragen" sehen Sie den Stand.</p>
    <p><a class="knopf" href="#/meine">Zu meinen Anfragen</a></p></div>`;
});

aktion('neu-direkt', async form => {
  const d = new FormData(form);
  const melder = leseAuswahl(d.get('melder'))[0];
  const titel = String(d.get('titel') || '').trim();
  if (!titel) return;
  const ergebnis = await beschaeftigt(form.querySelector('button.primaer'), 'Lege an …', () => ticketAnlegen(d.get('kennung'), {
    titel,
    beschreibung: textZuHtml(d.get('text') || ''),
    prio: d.get('prio'),
    melderMail: melder?.mail || '',
    bearbeiterMails: d.get('mir') === 'on' ? [meineMail()] : [],
  }));
  ergebnis.warnungen.forEach(w => meldung(w, 'fehler'));
  meldung(`Ticket ${ergebnis.nummer} angelegt`, 'erfolg');
  zustand.tickets.delete(d.get('kennung'));
  location.hash = '#/t/' + ergebnis.nummer;
});
