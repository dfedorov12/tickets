/**
 * Mail-HTML sicher anzeigen
 * =========================
 * Die Beschreibung eines Tickets ist der HTML-Körper der eingegangenen Mail – also
 * fremder Inhalt. Er wird in einem inerten Dokument (DOMParser) zerlegt und nur mit
 * einer Positivliste wieder aufgebaut: keine Skripte, keine Event-Attribute, keine
 * Stile, keine Rahmen, keine nachgeladenen Bilder (Tracking-Pixel), Links nur
 * http(s)/mailto und immer in neuem Tab ohne Referrer.
 *
 * Wichtig: niemals `div.innerHTML = fremd` auf einem Element des echten Dokuments –
 * dort feuert z. B. <img onerror> schon beim Zuweisen, auch ohne Einhängen.
 */
import { sichereUrl } from './text.js';

const ERLAUBT = new Set([
  'P', 'BR', 'B', 'STRONG', 'I', 'EM', 'U', 'S', 'SMALL', 'SUB', 'SUP', 'SPAN', 'DIV', 'FONT',
  'UL', 'OL', 'LI', 'A', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'BLOCKQUOTE', 'PRE', 'CODE', 'HR',
  'TABLE', 'THEAD', 'TBODY', 'TFOOT', 'TR', 'TD', 'TH', 'CAPTION',
]);
// Inhalt samt Kindern verwerfen:
const WEG = new Set(['SCRIPT', 'STYLE', 'IFRAME', 'OBJECT', 'EMBED', 'NOSCRIPT', 'TEMPLATE', 'SVG', 'MATH', 'HEAD', 'TITLE', 'META', 'LINK', 'BASE', 'FORM', 'INPUT', 'BUTTON', 'SELECT', 'TEXTAREA', 'VIDEO', 'AUDIO', 'CANVAS']);

/** Fremdes HTML → sicheres DocumentFragment für das echte Dokument. */
export function sicheresHtml(roh) {
  const quelle = new DOMParser().parseFromString(String(roh ?? ''), 'text/html');
  const ziel = document.createDocumentFragment();
  const kopiere = (von, nach) => {
    for (const k of von.childNodes) {
      if (k.nodeType === 3) { nach.appendChild(document.createTextNode(k.nodeValue)); continue; }
      if (k.nodeType !== 1) continue;
      const tag = k.tagName.toUpperCase();
      if (WEG.has(tag)) continue;
      if (tag === 'IMG') {
        // Bilder nicht laden (Tracking); Platzhalter mit Alt-Text.
        const alt = (k.getAttribute('alt') || '').trim();
        if (alt) nach.appendChild(document.createTextNode(`[Bild: ${alt}]`));
        continue;
      }
      if (!ERLAUBT.has(tag)) { kopiere(k, nach); continue; }
      // Links nur mit sicherer Adresse – sonst bleibt nur der Text (kein toter Link).
      const href = tag === 'A' ? sichereUrl(k.getAttribute('href') || '') : '';
      const linkOk = tag === 'A' && href && href !== '#' && !href.startsWith('#');
      const neu = document.createElement(tag === 'FONT' || (tag === 'A' && !linkOk) ? 'span' : tag.toLowerCase());
      if (linkOk) {
        neu.setAttribute('href', href);
        neu.setAttribute('target', '_blank');
        neu.setAttribute('rel', 'noopener noreferrer');
      }
      if ((tag === 'TD' || tag === 'TH')) {
        for (const a of ['colspan', 'rowspan']) {
          const v = k.getAttribute(a);
          if (v && /^\d{1,3}$/.test(v)) neu.setAttribute(a, v);
        }
      }
      kopiere(k, neu);
      nach.appendChild(neu);
    }
  };
  kopiere(quelle.body || quelle.documentElement, ziel);
  return ziel;
}

/** Sieht der Text nach HTML aus? (Rich-Text-Spalte vs. Nur-Text) */
export const istHtml = s => /<[a-z][\s\S]*>/i.test(String(s ?? ''));

/** Nur-Text mit Zeilenumbrüchen und klickbaren Links als Fragment. */
export function textFragment(text) {
  const frag = document.createDocumentFragment();
  const teile = String(text ?? '').split(/(https?:\/\/[^\s<>"']+)/g);
  teile.forEach((teil, i) => {
    if (i % 2 === 1) {
      const a = document.createElement('a');
      a.href = sichereUrl(teil); a.target = '_blank'; a.rel = 'noopener noreferrer'; a.textContent = teil;
      frag.appendChild(a);
    } else {
      teil.split('\n').forEach((zeile, j) => {
        if (j) frag.appendChild(document.createElement('br'));
        frag.appendChild(document.createTextNode(zeile));
      });
    }
  });
  return frag;
}
