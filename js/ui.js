/**
 * Oberflächen-Bausteine: Aktionen per Delegation (keine Inline-Handler – die CSP
 * erlaubt nur Skripte aus eigenen Dateien), Meldungen, Dialoge, Abzeichen.
 */
import { esc, initialen } from './text.js';
import { statusInfo } from './modell.js';

export const $ = (sel, wurzel = document) => wurzel.querySelector(sel);
export const $$ = (sel, wurzel = document) => [...wurzel.querySelectorAll(sel)];

// ── Aktionen ─────────────────────────────────────────────────────────────
// <button data-aktion="status" data-wert="Erledigt">  →  aktion('status', (el, ev) => …)
// <select data-aendern="filter">, <input data-eingabe="suche">, <form data-absenden="…">
const _aktionen = new Map();
export function aktion(name, fn) { _aktionen.set(name, fn); }

async function _ausfuehren(name, el, ev) {
  const fn = _aktionen.get(name);
  if (!fn) { console.warn('Unbekannte Aktion', name); return; }
  try { await fn(el, ev); }
  catch (e) { console.error(e); meldung(e.message || String(e), 'fehler'); }
}

export function aktionenAktivieren() {
  document.addEventListener('click', ev => {
    const el = ev.target.closest('[data-aktion]');
    if (!el || el.disabled) return;
    // Echte Links in Zeilen (Ticketnummer) sollen selbst navigieren, nicht die Zeilen-Aktion auslösen.
    if (ev.target.closest('a[href]') && ev.target.closest('a[href]') !== el) return;
    ev.preventDefault();
    _ausfuehren(el.dataset.aktion, el, ev);
  });
  document.addEventListener('change', ev => {
    const el = ev.target.closest('[data-aendern]');
    if (el) _ausfuehren(el.dataset.aendern, el, ev);
  });
  let timer = null;
  document.addEventListener('input', ev => {
    const el = ev.target.closest('[data-eingabe]');
    if (!el) return;
    clearTimeout(timer);
    timer = setTimeout(() => _ausfuehren(el.dataset.eingabe, el, ev), 180);
  });
  document.addEventListener('submit', ev => {
    const el = ev.target.closest('form[data-absenden]');
    if (!el) return;
    ev.preventDefault();
    _ausfuehren(el.dataset.absenden, el, ev);
  });
  document.addEventListener('keydown', ev => {
    if (ev.key !== 'Enter' && ev.key !== ' ') return;
    const el = ev.target.closest('[data-aktion][role="link"], tr[data-aktion]');
    if (el) { ev.preventDefault(); _ausfuehren(el.dataset.aktion, el, ev); }
  });
}

/** Während einer Aktion den Knopf sperren und einen Hinweis zeigen. */
export async function beschaeftigt(el, text, fn) {
  const alt = el?.textContent;
  if (el) { el.disabled = true; if (text) el.textContent = text; }
  try { return await fn(); }
  finally { if (el) { el.disabled = false; el.textContent = alt; } }
}

// ── Meldungen ────────────────────────────────────────────────────────────
export function meldung(text, art = 'info') {
  const box = $('#meldungen');
  if (!box) return;
  const el = document.createElement('div');
  el.className = 'meldung ' + art;
  el.setAttribute('role', art === 'fehler' ? 'alert' : 'status');
  el.textContent = text;
  box.appendChild(el);
  setTimeout(() => { el.classList.add('weg'); setTimeout(() => el.remove(), 300); }, art === 'fehler' ? 8000 : 4000);
}

// ── Dialog ───────────────────────────────────────────────────────────────
/**
 * Modaler Dialog. `inhalt` ist fertiges, bereits maskiertes HTML.
 * Gibt eine Promise zurück, die mit dem Wert des gedrückten Knopfs (data-wert) auflöst.
 */
export function dialog({ titel, inhalt, knoepfe = [{ wert: 'ok', text: 'OK', primaer: true }], breit = false }) {
  return new Promise(resolve => {
    const d = document.createElement('dialog');
    d.className = 'dialog' + (breit ? ' breit' : '');
    d.innerHTML = `<form method="dialog">
      <h2>${esc(titel)}</h2>
      <div class="dialog-inhalt">${inhalt}</div>
      <div class="dialog-knoepfe">${knoepfe.map(k => `<button value="${esc(k.wert)}" class="knopf${k.primaer ? ' primaer' : ''}${k.gefahr ? ' gefahr' : ''}">${esc(k.text)}</button>`).join('')}</div>
    </form>`;
    document.body.appendChild(d);
    // Enter in einem Eingabefeld = Hauptknopf (sonst nähme der Browser den ersten Knopf, „Abbrechen").
    d.addEventListener('keydown', ev => {
      if (ev.key === 'Enter' && ev.target.tagName === 'INPUT') {
        ev.preventDefault();
        d.querySelector('.dialog-knoepfe .primaer, .dialog-knoepfe .gefahr')?.click();
      }
    });
    d.addEventListener('close', () => {
      const daten = Object.fromEntries(new FormData(d.querySelector('form')));
      resolve({ wert: d.returnValue || 'abbrechen', daten, dialog: d });
      d.remove();
    });
    d.showModal();
    d.querySelector('input,textarea,select')?.focus();
  });
}

export async function bestaetigen(titel, text, { ja = 'Ja', gefahr = false } = {}) {
  const r = await dialog({ titel, inhalt: `<p>${esc(text)}</p>`, knoepfe: [{ wert: 'nein', text: 'Abbrechen' }, { wert: 'ja', text: ja, primaer: !gefahr, gefahr }] });
  return r.wert === 'ja';
}

// ── Abzeichen ────────────────────────────────────────────────────────────
export const statusBadge = s => s ? `<span class="badge st-${statusInfo(s).farbe}">${esc(s)}</span>` : '';
export const prioBadge = p => p ? `<span class="prio prio-${esc(p.toLowerCase())}">${esc(p)}</span>` : '';
export const avatar = (name, titel = name) => `<span class="avatar" title="${esc(titel)}">${esc(initialen(name))}</span>`;
export const personen = liste => liste?.length
  ? liste.map(p => `<span class="person">${avatar(p.name, p.mail || p.name)}<span>${esc(p.name)}</span></span>`).join('')
  : '<span class="leise">niemand</span>';

export function leer(text, symbol = '📭') {
  return `<div class="leer"><div class="leer-symbol">${symbol}</div><p>${esc(text)}</p></div>`;
}

export function ladeAnzeige(text = 'Lade …') {
  return `<div class="laden"><div class="spinner"></div><span>${esc(text)}</span></div>`;
}

/** Datei → Base64 (für Mail-Anhänge). */
export function alsBase64(datei) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res(String(r.result).split(',')[1] || '');
    r.onerror = () => rej(r.error);
    r.readAsDataURL(datei);
  });
}
