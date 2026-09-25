/**
 * Statische Prüfung der Browser-Module (ohne DOM):
 *  - jede importierte Bezeichnung wird vom Zielmodul auch exportiert
 *  - jede Aktion im HTML (data-aktion/-aendern/-eingabe/-absenden) ist registriert
 *  - keine Inline-Handler (onclick=…) – die CSP erlaubt nur Skripte aus Dateien
 *  - index.html lädt nur eigene Skripte; CSP ohne 'unsafe-inline' für Skripte
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { ok, ende } from './_pruef.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const JS = path.join(ROOT, 'js');
const dateien = fs.readdirSync(JS).filter(f => f.endsWith('.js'));
const quelle = Object.fromEntries(dateien.map(f => [f, fs.readFileSync(path.join(JS, f), 'utf8')]));

function exporte(src) {
  const namen = new Set();
  for (const m of src.matchAll(/export\s+(?:async\s+)?(?:function\*?|const|let|class)\s+([A-Za-z_$][\w$]*)/g)) namen.add(m[1]);
  for (const m of src.matchAll(/export\s*\{([^}]+)\}/g)) m[1].split(',').map(s => s.trim().split(/\s+as\s+/).pop()).filter(Boolean).forEach(n => namen.add(n));
  return namen;
}

for (const [datei, src] of Object.entries(quelle)) {
  for (const m of src.matchAll(/import\s*\{([^}]+)\}\s*from\s*'\.\/([\w-]+\.js)'/g)) {
    const ziel = m[2];
    ok(quelle[ziel] !== undefined, `${datei}: importiert vorhandene Datei ${ziel}`);
    if (!quelle[ziel]) continue;
    const ex = exporte(quelle[ziel]);
    for (const roh of m[1].split(',').map(s => s.trim()).filter(Boolean)) {
      const name = roh.split(/\s+as\s+/)[0];
      ok(ex.has(name), `${datei}: „${name}" wird von ${ziel} exportiert`);
    }
  }
  for (const m of src.matchAll(/import\s+\*\s+as\s+\w+\s+from\s+'\.\/([\w-]+\.js)'/g)) ok(quelle[m[1]] !== undefined, `${datei}: importiert vorhandene Datei ${m[1]}`);
}

// Aktionen
const registriert = new Set();
for (const src of Object.values(quelle)) for (const m of src.matchAll(/aktion\('([\w-]+)'/g)) registriert.add(m[1]);
const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
// Kommentare ausblenden (Beispiele in Doku-Kommentaren sind keine Aktionen)
const ohneKommentare = src => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const alles = Object.values(quelle).map(ohneKommentare).join('\n') + html;
const benutzt = new Set();
for (const m of alles.matchAll(/data-(?:aktion|aendern|eingabe|absenden)="([\w-]+)"/g)) benutzt.add(m[1]);
for (const a of benutzt) ok(registriert.has(a), `Aktion „${a}" ist registriert`);
ok(benutzt.size > 30, `mindestens 30 Aktionen gefunden (${benutzt.size})`);

// Keine Inline-Handler
ok(!/\son[a-z]+\s*=\s*["']/i.test(html), 'index.html ohne Inline-Handler');
for (const [datei, src] of Object.entries(quelle)) ok(!/<[^>]+\son(click|change|input|submit|load|error|mouse\w+|key\w+)\s*=/i.test(src), `${datei}: kein Inline-Handler im erzeugten HTML`);

// CSP & Skriptquellen
const csp = html.match(/Content-Security-Policy" content="([^"]+)"/)?.[1] || '';
const scriptSrc = csp.split(';').map(s => s.trim()).find(s => s.startsWith('script-src')) || '';
ok(scriptSrc === "script-src 'self'", `CSP script-src nur 'self' (${scriptSrc})`);
ok(/frame-src 'self' https:\/\/login\.microsoftonline\.com/.test(csp), 'CSP: Anmelde-iframe erlaubt');
for (const m of html.matchAll(/<script[^>]*src="([^"]+)"/g)) ok(!/^https?:/.test(m[1]), `Skript aus eigener Quelle: ${m[1]}`);
ok(/<style id="rahmenschutz">/.test(html) && fs.existsSync(path.join(JS, 'rahmenschutz.js')), 'Clickjacking-Schutz eingebunden');
ok(fs.existsSync(path.join(ROOT, 'vendor/msal-browser/5.23.0/msal-browser.min.js')), 'MSAL liegt im Repo');
const redirect = fs.readFileSync(path.join(ROOT, 'redirect.html'), 'utf8');
ok(/msal-redirect-bridge\.min\.js/.test(redirect) && /js\/redirect\.js/.test(redirect), 'redirect.html = MSAL-Bridge');

// Fremdes HTML nie direkt per innerHTML (Beschreibung läuft über sicheresHtml)
ok(!/innerHTML\s*[+]?=\s*[^;]*\.beschreibung/.test(quelle['ansicht-ticket.js']), 'Beschreibung nie direkt als innerHTML');
ok(/sicheresHtml\(/.test(quelle['ansicht-ticket.js']), 'Beschreibung über sicheresHtml');

ende();
