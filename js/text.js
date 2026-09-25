/**
 * Kleine Text-Helfer ohne DOM – für App, Nachtlauf und Tests gleichermaßen.
 */

/** Für HTML-Text und -Attribute (in doppelten Anführungszeichen) maskieren. */
export function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/**
 * Eine Adresse für href: nur http(s) und mailto, alles andere wird '#'.
 * `esc()` allein ließe `javascript:…` als gültigen Attributwert durch.
 * Steuerzeichen und Leerraum fallen vor der Prüfung weg (so liest sie auch der Browser).
 */
export function sichereUrl(u) {
  const s = String(u ?? '').trim();
  const kompakt = s.replace(/[\u0000- \u007f]/g, '');
  const m = kompakt.match(/^([a-z][a-z0-9+.-]*):/i);
  if (!m) return kompakt.startsWith('//') ? '#' : s;
  return /^(https?|mailto)$/i.test(m[1]) ? s : '#';
}

const _zweistellig = n => String(n).padStart(2, '0');

/** 25.09.26 */
export function datumKurz(v) {
  const d = v instanceof Date ? v : new Date(v);
  if (!v || isNaN(d)) return '';
  return `${_zweistellig(d.getDate())}.${_zweistellig(d.getMonth() + 1)}.${String(d.getFullYear()).slice(2)}`;
}

/** 25.09.26, 10:30 */
export function datumZeit(v) {
  const d = v instanceof Date ? v : new Date(v);
  if (!v || isNaN(d)) return '';
  return `${datumKurz(d)}, ${_zweistellig(d.getHours())}:${_zweistellig(d.getMinutes())}`;
}

/** „vor 5 Min.", „vor 3 Std.", „vor 2 Tagen" – für Listen. */
export function relativ(v, jetzt = new Date()) {
  const d = v instanceof Date ? v : new Date(v);
  if (!v || isNaN(d)) return '';
  const min = Math.round((jetzt - d) / 60000);
  if (min < 1) return 'gerade eben';
  if (min < 60) return `vor ${min} Min.`;
  const std = Math.round(min / 60);
  if (std < 24) return `vor ${std} Std.`;
  const tage = Math.round(std / 24);
  if (tage === 1) return 'gestern';
  if (tage < 30) return `vor ${tage} Tagen`;
  return datumKurz(d);
}

/** Dauer in Stunden lesbar: 5 Std. / 2,5 Tage */
export function dauer(stunden) {
  if (stunden == null || !isFinite(stunden)) return '–';
  if (stunden < 24) return `${Math.round(stunden)} Std.`;
  return `${(stunden / 24).toFixed(1).replace('.', ',').replace(/,0$/, '')} Tage`;
}

/** Initialen für Avatare: „Marco Maukisch" → MM */
export function initialen(name) {
  const teile = String(name ?? '').trim().split(/\s+/).filter(Boolean);
  if (!teile.length) return '?';
  if (teile.length === 1) return teile[0].slice(0, 2).toUpperCase();
  return (teile[0][0] + teile[teile.length - 1][0]).toUpperCase();
}

/** Nur-Text aus einer Mail/Notiz in einfaches HTML (Absätze, Links) für Mails. */
export function textZuHtml(text) {
  return esc(text)
    .replace(/(https?:\/\/[^\s<"']+)/g, '<a href="$1">$1</a>')
    .replace(/\r?\n/g, '<br>');
}

/** Dateigröße lesbar machen. */
export function groesse(bytes) {
  const b = Number(bytes) || 0;
  if (b < 1024) return b + ' B';
  if (b < 1024 * 1024) return Math.round(b / 1024) + ' KB';
  return (b / 1024 / 1024).toFixed(1).replace('.', ',') + ' MB';
}
