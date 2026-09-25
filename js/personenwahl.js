/**
 * Personenauswahl (Graph-Suche) für Dialoge und Formulare.
 * Der Wert steht als JSON in einem versteckten Feld – so landet er über FormData
 * im Ergebnis des Dialogs bzw. Formulars.
 */
import { esc } from './text.js';
import { sucheNutzer } from './api.js';
import { aktion, avatar } from './ui.js';

export function personenwahl(name, { vorbelegt = [], vorschlaege = [], einzeln = false, platzhalter = 'Name oder Mail suchen …' } = {}) {
  return `<div class="pw" data-name="${esc(name)}"${einzeln ? ' data-einzeln="1"' : ''}>
    <input type="hidden" name="${esc(name)}" value="${esc(JSON.stringify(vorbelegt))}"/>
    <div class="pw-auswahl">${_chips(vorbelegt)}</div>
    <input type="search" class="pw-eingabe" data-eingabe="pw-suche" placeholder="${esc(platzhalter)}" autocomplete="off" aria-label="${esc(platzhalter)}"/>
    <div class="pw-treffer" role="listbox"></div>
    ${vorschlaege.length ? `<div class="pw-vorschlaege"><span class="leise klein">Vorschläge:</span> ${vorschlaege.map(_knopf).join('')}</div>` : ''}
  </div>`;
}

export const leseAuswahl = wert => { try { return JSON.parse(wert || '[]'); } catch { return []; } };

const _knopf = p => `<button type="button" class="chip klein" data-aktion="pw-waehle" data-mail="${esc(p.mail)}" data-pname="${esc(p.name || p.mail)}">${esc(p.name || p.mail)}</button>`;
const _chips = liste => liste.map(p => `<span class="pw-chip">${avatar(p.name || p.mail, p.mail)}${esc(p.name || p.mail)}<button type="button" class="pw-weg" data-aktion="pw-entferne" data-mail="${esc(p.mail)}" aria-label="${esc((p.name || p.mail) + ' entfernen')}">×</button></span>`).join('');

function _setze(pw, liste) {
  pw.querySelector('input[type=hidden]').value = JSON.stringify(liste);
  pw.querySelector('.pw-auswahl').innerHTML = _chips(liste);
}

aktion('pw-suche', async el => {
  const pw = el.closest('.pw');
  const text = el.value;
  const ziel = pw.querySelector('.pw-treffer');
  if (text.trim().length < 2) { ziel.innerHTML = ''; return; }
  const treffer = await sucheNutzer(text);
  if (el.value !== text) return; // inzwischen weitergetippt
  ziel.innerHTML = treffer.length
    ? treffer.map(p => `<button type="button" role="option" class="pw-treffer-zeile" data-aktion="pw-waehle" data-mail="${esc(p.mail)}" data-pname="${esc(p.name)}">${avatar(p.name, p.mail)}<span><strong>${esc(p.name)}</strong><span class="leise klein"> ${esc(p.mail)}${p.titel ? ' · ' + esc(p.titel) : ''}</span></span></button>`).join('')
    : '<div class="leise klein">Niemand gefunden.</div>';
});

aktion('pw-waehle', el => {
  const pw = el.closest('.pw');
  const liste = pw.dataset.einzeln ? [] : leseAuswahl(pw.querySelector('input[type=hidden]').value);
  if (!liste.some(p => p.mail === el.dataset.mail)) liste.push({ mail: el.dataset.mail, name: el.dataset.pname });
  _setze(pw, liste);
  pw.querySelector('.pw-treffer').innerHTML = '';
  const eingabe = pw.querySelector('.pw-eingabe');
  eingabe.value = '';
  eingabe.focus();
});

aktion('pw-entferne', el => {
  const pw = el.closest('.pw');
  _setze(pw, leseAuswahl(pw.querySelector('input[type=hidden]').value).filter(p => p.mail !== el.dataset.mail));
});

// Enter im Suchfeld übernimmt den ersten Treffer – statt das Formular/den Dialog abzuschicken.
document.addEventListener('keydown', ev => {
  if (ev.key !== 'Enter' || !ev.target.classList?.contains('pw-eingabe')) return;
  ev.preventDefault();
  ev.stopPropagation();
  ev.target.closest('.pw')?.querySelector('.pw-treffer-zeile')?.click();
}, true);
