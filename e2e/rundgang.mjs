#!/usr/bin/env node
/**
 * Browser-Rundgang gegen eine SharePoint/Graph-Attrappe (ohne Tenant, ohne Anmeldung)
 * ==================================================================================
 *   node e2e/rundgang.mjs            (Screenshots nach e2e/bilder/)
 * Braucht Playwright (global oder im Projekt) mit Chromium.
 * Prüft je Rolle (Bearbeiterin, Melder, Admin), dass die Oberfläche lädt, ohne
 * Skriptfehler arbeitet und die Kernabläufe tun, was sie sollen.
 */
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import { neuerTenant, beantworte } from './attrappe.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BILDER = path.join(ROOT, 'e2e', 'bilder');
fs.mkdirSync(BILDER, { recursive: true });

let chromium;
try { ({ chromium } = await import('playwright')); }
catch { ({ chromium } = createRequire(import.meta.url)('/opt/node22/lib/node_modules/playwright')); }

// ── statischer Server ──
const TYPEN = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.zip': 'application/zip' };
const server = http.createServer((req, res) => {
  const p = path.join(ROOT, decodeURIComponent(new URL(req.url, 'http://x').pathname.replace(/^\/tickets/, '')));
  const datei = fs.existsSync(p) && fs.statSync(p).isDirectory() ? path.join(p, 'index.html') : p;
  if (!datei.startsWith(ROOT) || !fs.existsSync(datei)) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { 'Content-Type': TYPEN[path.extname(datei)] || 'application/octet-stream' });
  fs.createReadStream(datei).pipe(res);
});
await new Promise(r => server.listen(0, r));
const BASIS = `http://localhost:${server.address().port}/tickets/`;

const MSAL = mail => `window.msal = {
  PublicClientApplication: class {
    constructor() {}
    async initialize() {}
    async handleRedirectPromise() { return null; }
    getActiveAccount() { return { username: ${JSON.stringify(mail)}, name: ${JSON.stringify(mail.split('@')[0])} }; }
    getAllAccounts() { return [this.getActiveAccount()]; }
    setActiveAccount() {}
    async acquireTokenSilent() { return { accessToken: 'attrappe' }; }
    loginRedirect() {} logoutRedirect() {} acquireTokenRedirect() {}
  },
  InteractionRequiredAuthError: class extends Error {},
};`;

let gruen = 0, rot = 0;
const ok = (c, text) => { if (c) { gruen++; console.log('  ✓', text); } else { rot++; console.log('  ✗', text); } };

const browser = await chromium.launch();

async function sitzung(mail, tenant) {
  const ctx = await browser.newContext({ viewport: { width: 1360, height: 900 }, locale: 'de-DE' });
  const page = await ctx.newPage();
  const fehler = [];
  page.on('pageerror', e => fehler.push(e.message));
  page.on('console', m => { if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) fehler.push(m.text()); });
  await page.route('**/vendor/msal-browser/5.23.0/msal-browser.min.js', r => r.fulfill({ contentType: 'text/javascript', body: MSAL(mail) }));
  await page.route('https://fonts.googleapis.com/**', r => r.fulfill({ contentType: 'text/css', body: '' }));
  const api = async r => {
    const req = r.request();
    let body;
    try { body = req.postData() ? JSON.parse(req.postData()) : undefined; } catch { body = undefined; }
    if (body && typeof body === 'object') body.__accept = req.headers().accept;
    await r.fulfill(beantworte(tenant, mail, req.method() === 'POST' && req.headers()['x-http-method'] ? req.headers()['x-http-method'] : req.method(), req.url(), body));
  };
  await page.route('https://graph.microsoft.com/**', api);
  await page.route('https://dihag.sharepoint.com/**', api);
  return { page, ctx, fehler };
}

const warte = ms => new Promise(r => setTimeout(r, ms));

// ── 1) Bearbeiterin ──
{
  console.log('\nBearbeiterin (anna.agent@dihag.com)');
  const t = neuerTenant();
  const { page, ctx, fehler } = await sitzung('anna.agent@dihag.com', t);
  await page.goto(BASIS);
  await page.waitForSelector('table.tickets');
  ok(/#\/posteingang$/.test(page.url()), 'Start = Posteingang');
  const zeilen = await page.$$eval('table.tickets tbody tr', trs => trs.map(tr => tr.querySelector('.nr').textContent.trim()));
  ok(zeilen.includes('SCH-1') && zeilen.includes('SCH-4') && !zeilen.includes('SCH-3'), `offene SCH-Tickets, kein erledigtes (${zeilen.join(', ')})`);
  ok(!zeilen.some(z => z.startsWith('SHB')), 'keine SHB-Tickets (nicht Bearbeiterin dort)');
  ok(await page.$('a.nav-punkt[href="#/verwaltung"]') === null, 'keine Verwaltung ohne Besitzerrechte');
  await page.screenshot({ path: path.join(BILDER, '1-posteingang.png') });

  await page.click('button[data-sicht="ohne"]');
  const ohne = await page.$$eval('table.tickets tbody tr .nr', x => x.map(e => e.textContent.trim()));
  ok(ohne.length === 2 && !ohne.includes('SCH-2'), `Sicht „Ohne Bearbeiter" (${ohne.join(', ')})`);
  await page.fill('input.suche', 'sap');
  await warte(400);
  const such = await page.$$eval('table.tickets tbody tr .nr', x => x.map(e => e.textContent.trim()));
  ok(such.join() === 'SCH-4', 'Suche „sap" findet SCH-4');
  await page.fill('input.suche', '');
  await page.click('button[data-sicht="offen"]');

  await page.goto(BASIS + '#/t/SCH-1');
  await page.waitForSelector('#t-beschreibung p');
  await warte(300);
  ok(await page.evaluate(() => window.__xss === undefined), 'Mail-HTML: kein Skript/onerror ausgeführt');
  const links = await page.$$eval('#t-beschreibung a', as => as.map(a => a.getAttribute('href')));
  ok(links.length === 1 && links[0] === 'https://example.com/hilfe', `Mail-HTML: javascript:-Link wird Text, normaler Link bleibt (${links.join(' | ')})`);
  ok(await page.$('#t-beschreibung img, #t-beschreibung script') === null, 'Mail-HTML: keine Bilder/Skripte');
  ok((await page.textContent('#t-verlauf')).includes('Wir schauen uns das an.'), 'Verlauf zeigt Kommentar');
  ok((await page.textContent('#t-anhaenge')).includes('foto.jpg'), 'Anhang gelistet');

  await page.click('button[data-reiter="intern"]');
  await page.waitForSelector('#t-notizen .eintrag');
  ok((await page.textContent('#t-notizen')).includes('Toner ist bestellt.'), 'Interne Notiz sichtbar');
  await page.click('button[data-reiter="verlauf"]');

  await page.fill('#t-antwort-text', 'Bitte einmal neu starten.');
  await page.click('form[data-absenden="t-antwort"] button.primaer');
  await page.waitForFunction(() => document.querySelector('#t-verlauf')?.textContent.includes('Bitte einmal neu starten.'));
  const mail = t.mails.at(-1);
  ok(mail && mail.toRecipients[0].emailAddress.address === 'max@schmie-guss.de' && /^\[#SCH-1\]/.test(mail.subject) && mail.replyTo?.[0].emailAddress.address === 'ticket@dihag.com', `Antwort: Mail an Melder mit [#SCH-1] und Reply-To Ticketpostfach (${mail?.subject})`);
  ok(t.listen[Object.keys(t.listen)[1]].items[0].Status === 'In Bearbeitung', 'Status „Neu" → „In Bearbeitung" nach Antwort');

  await page.click('button[data-aktion="t-uebernehmen"]');
  await page.waitForFunction(() => !document.querySelector('button[data-aktion="t-uebernehmen"]'));
  ok(t.listen[Object.keys(t.listen)[1]].items[0].Assignedto0.some(p => p.EMail === 'anna.agent@dihag.com'), 'Übernehmen weist mir zu');

  await page.click('button[data-aktion="t-erledigt"]');
  await page.waitForSelector('dialog[open] textarea');
  await page.fill('dialog[open] textarea', 'Treiber neu installiert.');
  await page.click('dialog[open] button[value="ok"]');
  await page.waitForFunction(() => document.querySelector('.nr-zeile')?.textContent.includes('Erledigt'));
  ok(t.listen[Object.keys(t.listen)[1]].items[0].Status === 'Erledigt', 'Erledigt gespeichert');
  ok(/erledigt/i.test(t.mails.at(-1)?.body.content || ''), 'Erledigt-Mail an Melder');
  await page.screenshot({ path: path.join(BILDER, '2-ticket-bearbeiterin.png'), fullPage: true });

  await page.goto(BASIS + '#/berichte');
  await page.waitForSelector('.kacheln');
  ok(await page.$('svg.svg-diagramm') !== null, 'Berichte: Diagramm gezeichnet');
  await page.screenshot({ path: path.join(BILDER, '3-berichte.png'), fullPage: true });

  await page.goto(BASIS + '#/neu');
  await page.waitForSelector('#neu-mail');
  ok(await page.$('button[data-reiter="direkt"]') !== null, 'Neues Ticket: Reiter „Direkt anlegen" für Bearbeiter');
  ok(fehler.length === 0, 'keine Skriptfehler' + (fehler.length ? ': ' + fehler.join(' | ') : ''));
  await ctx.close();
}

// ── 2) Melder ──
{
  console.log('\nMelder (max@schmie-guss.de)');
  const t = neuerTenant();
  const { page, ctx, fehler } = await sitzung('max@schmie-guss.de', t);
  await page.goto(BASIS);
  await page.waitForSelector('#meine-inhalt .ticket-karte');
  ok(/#\/meine$/.test(page.url()), 'Start = Meine Anfragen');
  ok(await page.$('a.nav-punkt[href="#/posteingang"]') === null, 'kein Posteingang für Melder');
  const karten = await page.$$eval('.ticket-karte .nr', x => x.map(e => e.textContent.trim()));
  ok(karten.includes('SCH-1') && karten.includes('SHB-1') && !karten.includes('SCH-3'), `nur eigene Tickets (${karten.join(', ')})`);
  await page.screenshot({ path: path.join(BILDER, '4-meine-anfragen.png'), fullPage: true });

  await page.goto(BASIS + '#/t/SCH-1');
  await page.waitForSelector('#t-beschreibung');
  ok(await page.$('select[data-aendern="t-status"]') === null, 'Melder kann Status nicht ändern');
  ok(await page.$('button[data-reiter="intern"]') === null, 'Melder sieht keinen Intern-Reiter');
  await page.fill('#t-antwort-text', 'Geht immer noch nicht.');
  await page.click('form[data-absenden="t-antwort"] button.primaer');
  await page.waitForSelector('.eintrag.vorlaeufig');
  const m = t.mails.at(-1);
  ok(m?.toRecipients[0].emailAddress.address === 'ticket@dihag.com' && /\[#SCH-1\]/.test(m.subject), `Melder-Antwort geht als Mail mit Token an das Ticketpostfach (${m?.subject})`);
  await page.screenshot({ path: path.join(BILDER, '5-ticket-melder.png'), fullPage: true });

  await page.goto(BASIS + '#/neu');
  await page.waitForSelector('#neu-mail');
  ok(await page.$('button[data-reiter="direkt"]') === null, 'kein Direkt-Anlegen für Melder');
  await page.fill('#neu-mail input[name=titel]', 'Maus defekt');
  await page.fill('#neu-mail textarea[name=text]', 'Die Maus klickt doppelt.');
  await page.click('#neu-mail button.primaer');
  await page.waitForSelector('.erfolg-box');
  ok(t.mails.at(-1)?.subject === 'Maus defekt' && t.mails.at(-1).toRecipients[0].emailAddress.address === 'ticket@dihag.com', 'Neues Ticket = Mail an Ticketpostfach');
  await page.goto(BASIS + '#/t/SCH-3');
  await page.waitForSelector('.fehlerbox');
  ok((await page.textContent('.fehlerbox')).length > 0, 'fremdes Ticket SCH-3 nicht abrufbar');
  ok(fehler.filter(f => !/SharePoint 404|gibt es nicht/.test(f)).length === 0, 'keine Skriptfehler' + (fehler.length ? ': ' + fehler.join(' | ') : ''));
  await ctx.close();
}

// ── 3) Admin ──
{
  console.log('\nAdmin (admin@dihag.com)');
  const t = neuerTenant();
  const { page, ctx, fehler } = await sitzung('admin@dihag.com', t);
  await page.goto(BASIS + '#/verwaltung/queues');
  await page.waitForSelector('.unternav');
  await page.waitForSelector('table.daten');
  ok((await page.textContent('table.daten')).includes('schmie-guss.de'), 'Queues-Tabelle');
  await page.fill('input[data-eingabe="v-routing"]', 'x@schmie-guss.de');
  await page.waitForFunction(() => document.querySelector('#v-routing-ergebnis')?.textContent.includes('SCH'));
  ok(true, 'Routing-Test: schmie-guss.de → SCH');
  await page.fill('input[data-eingabe="v-routing"]', 'x@irgendwo.de');
  await page.waitForFunction(() => document.querySelector('#v-routing-ergebnis')?.textContent.includes('SHB'));
  ok(true, 'Routing-Test: unbekannt → Standard SHB');
  await page.screenshot({ path: path.join(BILDER, '6-verwaltung-queues.png'), fullPage: true });

  await page.click('button[data-aktion="v-queue-bearbeiten"][data-kennung="SCH"]');
  await page.waitForSelector('dialog[open] input[name=kennung][readonly]');
  ok(true, 'Kennung einer eingerichteten Queue ist gesperrt');
  await page.screenshot({ path: path.join(BILDER, '7-queue-dialog.png') });
  await page.click('dialog[open] button[value="abbrechen"]');

  await page.goto(BASIS + '#/verwaltung/rechte');
  await page.waitForSelector('button[data-aktion="v-alle-pruefen"]');
  await page.click('button[data-aktion="v-alle-pruefen"]');
  await page.waitForFunction(() => document.querySelectorAll('.pruefliste').length >= 3, null, { timeout: 15000 });
  const sch = await page.textContent('#v-q-SCH');
  const shb = await page.textContent('#v-q-SHB');
  ok(/zu viel: .*Mitwirken/.test(sch) && /fehlt: .*Jeder außer externen Benutzern/.test(sch), 'SCH: überzählige Mitwirken-Rechte und fehlende Melder-Leserechte erkannt');
  ok(/erbt von der Site/.test(shb) && /ReadSecurity: 1 → 2/.test(shb), 'SHB: Vererbung und „alle Elemente lesbar" erkannt');
  await page.screenshot({ path: path.join(BILDER, '8-verwaltung-rechte.png'), fullPage: true });

  await page.goto(BASIS + '#/verwaltung/eingang');
  await page.waitForSelector('a[href="flow/Helpdesk-v2.zip"]');
  ok(true, 'Eingang-Seite mit Flow-Download');
  await page.goto(BASIS + '#/verwaltung/migration');
  await page.click('button[data-aktion="m-vorschau"]');
  await page.waitForSelector('#m-ergebnis p');
  ok((await page.textContent('#m-ergebnis')).includes('1 von 1'), 'Migration: Vorschau findet das Alt-Ticket des Werks SCH');
  ok(fehler.length === 0, 'keine Skriptfehler' + (fehler.length ? ': ' + fehler.join(' | ') : ''));
  await ctx.close();
}

await browser.close();
server.close();
console.log(`\n${rot ? '✗' : '✓'} ${gruen} grün, ${rot} rot`);
process.exit(rot ? 1 : 0);
