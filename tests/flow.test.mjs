/**
 * Flow „Helpdesk v2": Struktur, Verweise, Paket und – mit einem kleinen Auswerter für
 * die Workflow-Ausdrucksprache – dieselbe Logik wie js/modell.js (Ticketnummer, Routing).
 */
import fs from 'fs';
import path from 'path';
import zlib from 'zlib';
import { fileURLToPath } from 'url';
import { ok, gleich, ende } from './_pruef.mjs';
import {
  bauDefinition, bauPaket, paketDateien, zip,
  AUSDRUCK_TICKETNUMMER, AUSDRUCK_DOMAIN_TREFFER, AUSDRUCK_STANDARD, AUSDRUCK_ANTWORTTEXT,
} from '../scripts/flow-paket.mjs';
import { tokenAusBetreff, queueFuerAbsender, queueAusFeldern, queueZuFeldern } from '../js/modell.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const def = bauDefinition();

// ── Struktur ────────────────────────────────────────────────────────────────
const alle = new Map(); // name → { aktion, geschwister }
const schleifen = new Set();
function lauf(actions, pfad) {
  for (const [name, a] of Object.entries(actions || {})) {
    ok(!alle.has(name), `Aktionsname eindeutig: ${name}`);
    alle.set(name, { aktion: a, geschwister: actions, pfad });
    if (a.type === 'Foreach') schleifen.add(name);
    lauf(a.actions, pfad + '/' + name);
    lauf(a.else?.actions, pfad + '/' + name + '(sonst)');
  }
}
lauf(def.actions, '');
ok(alle.size > 50, `vollständiger Ablauf (${alle.size} Aktionen)`);

for (const [name, { aktion, geschwister }] of alle) {
  for (const [vor, status] of Object.entries(aktion.runAfter || {})) {
    ok(vor in geschwister, `${name}: runAfter „${vor}" liegt in derselben Ebene`);
    ok(status.every(s => ['Succeeded', 'Failed', 'Skipped', 'TimedOut'].includes(s)), `${name}: gültige runAfter-Status`);
  }
  if (aktion.type === 'If') ok(aktion.expression && aktion.actions && aktion.else, `${name}: If vollständig`);
}
// Jede Ebene hat genau einen Einstieg ohne runAfter-Abhängigkeit
const ebenen = new Map();
for (const [name, { aktion, geschwister }] of alle) {
  if (!ebenen.has(geschwister)) ebenen.set(geschwister, []);
  if (!Object.keys(aktion.runAfter || {}).length) ebenen.get(geschwister).push(name);
}
for (const [, starts] of ebenen) ok(starts.length === 1, `genau ein Einstieg je Ebene (${starts.join(', ')})`);

// Verweise in Ausdrücken
const text = JSON.stringify(def);
for (const m of text.matchAll(/\b(outputs|body|actions)\('([^']+)'\)/g)) ok(alle.has(m[2]), `${m[1]}('${m[2]}') verweist auf vorhandene Aktion`);
for (const m of text.matchAll(/\bitems\('([^']+)'\)/g)) ok(schleifen.has(m[1]), `items('${m[1]}') verweist auf eine Schleife`);
const variablen = new Set([...alle.values()].filter(x => x.aktion.type === 'InitializeVariable').flatMap(x => x.aktion.inputs.variables.map(v => v.name)));
for (const m of text.matchAll(/variables\('([^']+)'\)/g)) ok(variablen.has(m[1]), `Variable ${m[1]} initialisiert`);
for (const x of alle.values()) if (x.aktion.type === 'InitializeVariable') ok(x.pfad === '', 'Variablen nur auf oberster Ebene');

// Ein ganzer Ausdruck („@…") darf kein @{…} enthalten – das würde NICHT ausgewertet.
function alleStrings(o, f) { if (typeof o === 'string') f(o); else if (o && typeof o === 'object') Object.values(o).forEach(v => alleStrings(v, f)); }
alleStrings(def.actions, s => { if (/^@(?!\{)/.test(s)) ok(!s.includes('@{'), `kein @{…} in Ausdruck: ${s.slice(0, 60)}`); });

// Verbindungen
const paket = bauPaket();
const flowDatei = Object.keys(paket).find(k => k.endsWith('definition.json'));
const refs = paket[flowDatei].properties.connectionReferences;
const benutzt = new Set([...text.matchAll(/"connectionName":"([^"]+)"/g)].map(m => m[1]));
for (const b of benutzt) ok(b in refs, `Verbindung ${b} deklariert`);
const apis = paket[Object.keys(paket).find(k => k.endsWith('apisMap.json'))];
const cons = paket[Object.keys(paket).find(k => k.endsWith('connectionsMap.json'))];
for (const b of benutzt) ok(apis[b] in paket['manifest.json'].resources && cons[b] in paket['manifest.json'].resources, `Paket-Ressourcen für ${b}`);
ok(!benutzt.has('shared_office365_1'), 'kein zweites Outlook-Konto nötig');

// Paket aktuell und lesbar
const zipDatei = path.join(ROOT, 'flow', 'Helpdesk-v2.zip');
ok(fs.existsSync(zipDatei), 'flow/Helpdesk-v2.zip vorhanden');
ok(fs.readFileSync(zipDatei).equals(zip(paketDateien())), 'Paket ist aktuell (sonst: node scripts/flow-paket.mjs)');
function entpacke(buf) {
  const out = {};
  const endeOff = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  let p = buf.readUInt32LE(endeOff + 16);
  for (let i = 0; i < buf.readUInt16LE(endeOff + 10); i++) {
    const nLen = buf.readUInt16LE(p + 28), lokal = buf.readUInt32LE(p + 42), gross = buf.readUInt32LE(p + 20);
    const name = buf.slice(p + 46, p + 46 + nLen).toString();
    const start = lokal + 30 + buf.readUInt16LE(lokal + 26) + buf.readUInt16LE(lokal + 28);
    out[name] = zlib.inflateRawSync(buf.slice(start, start + gross)).toString();
    p += 46 + nLen + buf.readUInt16LE(p + 30) + buf.readUInt16LE(p + 32);
  }
  return out;
}
const entpackt = entpacke(fs.readFileSync(zipDatei));
gleich(Object.keys(entpackt).sort(), Object.keys(paketDateien()).sort(), 'ZIP enthält alle Paketdateien');
ok(JSON.parse(entpackt[flowDatei]).properties.displayName === 'Helpdesk v2', 'ZIP: Definition lesbar');

// ── Kleiner Auswerter für die Workflow-Ausdrucksprache ──────────────────────
function auswerten(ausdruck, ctx) {
  const s = ausdruck.replace(/^@/, '');
  let i = 0;
  const leer = () => { while (/\s/.test(s[i])) i++; };
  function wert() {
    leer();
    let v;
    if (s[i] === "'") {
      let out = ''; i++;
      for (;;) { if (s[i] === "'" && s[i + 1] === "'") { out += "'"; i += 2; } else if (s[i] === "'") { i++; break; } else out += s[i++]; }
      v = out;
    } else if (/[0-9-]/.test(s[i])) { const m = s.slice(i).match(/^-?\d+/)[0]; i += m.length; v = Number(m); }
    else {
      const name = s.slice(i).match(/^[A-Za-z_]\w*/)[0]; i += name.length; leer();
      if (name === 'true') v = true; else if (name === 'false') v = false; else if (name === 'null') v = null;
      else {
        if (s[i] !== '(') throw new Error('Erwartet ( nach ' + name);
        i++; const args = []; leer();
        while (s[i] !== ')') { args.push(wert()); leer(); if (s[i] === ',') i++; leer(); }
        i++;
        v = FN[name] ? FN[name](...args) : ctx[name](...args);
      }
    }
    for (;;) { leer(); if (s[i] === '?' && s[i + 1] === '[') i++; if (s[i] !== '[') break; i++; const k = wert(); leer(); i++; v = v == null ? null : v[k]; }
    return v;
  }
  const FN = {
    if: (c, a, b) => (c ? a : b), contains: (a, b) => String(a).includes(b), first: a => a[0] ?? null, last: a => a[a.length - 1] ?? null,
    split: (a, b) => String(a).split(b), toUpper: a => String(a).toUpperCase(), toLower: a => String(a).toLowerCase(), trim: a => String(a).trim(),
    concat: (...a) => a.join(''), equals: (a, b) => a === b, and: (...a) => a.every(Boolean), or: (...a) => a.some(Boolean), not: a => !a,
    empty: a => a == null || a === '' || (Array.isArray(a) && !a.length), coalesce: (...a) => a.find(x => x != null) ?? null,
    take: (a, n) => String(a).slice(0, n), decodeUriComponent: a => decodeURIComponent(a), join: (a, b) => a.join(b), length: a => a.length,
    greater: (a, b) => a > b, replace: (a, b, c) => String(a).split(b).join(c), int: a => { if (!/^\d+$/.test(String(a))) throw new Error('int'); return Number(a); },
  };
  const r = wert();
  return r;
}

// Ticketnummer: gleiche Ergebnisse wie tokenAusBetreff()
const betreffs = [
  'AW: [#SCH-12] Eingangsbestätigung: Drucker', 'WG: [#ewa-3] x', 'AW: Neues Ticket: 1234 (Drucker)', 'Neues Ticket: 99',
  'Drucker kaputt', '', 'RE: AW: [#DIHAG-7] Eingangsbestätigung: [Wichtig] Server', '[#SCH-12]',
];
for (const b of betreffs) {
  const flow = auswerten(AUSDRUCK_TICKETNUMMER, { outputs: n => (n === 'Betreff' ? b : null) });
  ok(flow === tokenAusBetreff(b), `Ticketnummer „${b}" → Flow ${JSON.stringify(flow)} = App ${JSON.stringify(tokenAusBetreff(b))}`);
}

// Routing: gleiche Queue wie queueFuerAbsender() – mit Zeilen, wie „Elemente abrufen" sie liefert
const queues = [
  { Kennung: 'SCH', Domains: 'schmie-guss.de;sch-guss.de', Modus: 'Ticket', Standard: false, Aktiv: true },
  { Kennung: 'DIHAG', Domains: 'dihag.com', Modus: 'Ticket', Standard: false, Aktiv: true },
  { Kennung: 'ALLG', Domains: '', Modus: 'Ticket', Standard: true, Aktiv: true },
  { Kennung: 'GIE', Domains: 'gienanth.com', Modus: 'Hinweis', Standard: false, Aktiv: true },
  { Kennung: 'ALT', Domains: 'alt.de', Modus: 'Archiv', Standard: false, Aktiv: true },
].map(z => queueZuFeldern(queueAusFeldern(z))).map(f => ({ ...f, Modus: { Value: f.Modus } }));
for (const absender of ['a@schmie-guss.de', 'b@sch-guss.de', 'c@dihag.com', 'd@gienanth.com', 'e@alt.de', 'f@unbekannt.de', 'g@x.dihag.com']) {
  const domain = absender.split('@').pop();
  const treffer = queues.filter(item => auswerten(AUSDRUCK_DOMAIN_TREFFER, { outputs: () => domain, item: () => item }));
  const standard = queues.filter(item => auswerten(AUSDRUCK_STANDARD, { item: () => item }));
  const flow = (treffer[0] || standard[0])?.Kennung;
  const app = queueFuerAbsender(queues.map(f => queueAusFeldern({ ...f, Modus: f.Modus.Value })), absender)?.kennung;
  ok(flow === app, `Routing ${absender}: Flow ${flow} = App ${app}`);
}

// Antworttext: zitierter Verlauf fällt weg
const lf = '\n';
const mail = 'Geht wieder, danke!' + lf + lf + 'Von: IT <ticket@dihag.com>' + lf + 'Gesendet: …' + lf + 'Ihr Ticket …';
gleich(auswerten(AUSDRUCK_ANTWORTTEXT, { body: () => mail }), 'Geht wieder, danke!', 'Antworttext ohne Zitat (Von:)');
gleich(auswerten(AUSDRUCK_ANTWORTTEXT, { body: () => 'Hallo' + lf + '________________________________' + lf + 'From: x' }), 'Hallo', 'Antworttext ohne Zitat (Trennlinie)');
gleich(auswerten(AUSDRUCK_ANTWORTTEXT, { body: () => 'x'.repeat(5000) }).length, 1800, 'Antworttext gekürzt');

// Personenfeld-Wert (Zuständige)
const zust = alle.get('Bearbeiter_eintragen_Inhalt').aktion.inputs.formValues[0].FieldValue.slice(2, -1);
gleich(auswerten(zust, { outputs: () => ({ Bearbeiter: 'a@dihag.com;b@dihag.com' }) }), "[{'Key':'i:0#.f|membership|a@dihag.com'},{'Key':'i:0#.f|membership|b@dihag.com'}]", 'Personenwert für Zuständige');

// Eingangsbestätigung trägt das Token, das der Flow später wiedererkennt
const bestaetigung = alle.get('Eingangsbestaetigung').aktion.inputs.parameters['replyParameters/Subject'];
ok(bestaetigung.startsWith("[#@{outputs('Nummer')}]"), 'Eingangsbestätigung mit [#Nummer] im Betreff');
ok(tokenAusBetreff('AW: [#SCH-5] Eingangsbestätigung: Test') === 'SCH-5', 'Antwort darauf wird erkannt');
ok(!/Neues Ticket:/.test(bestaetigung), 'neues Betreff-Format kollidiert nicht mit dem alten');

ende();
