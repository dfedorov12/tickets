/**
 * Nachtlauf: Zertifikats-Anmeldung (JWT) und ein Probelauf gegen die SharePoint-Attrappe
 * aus e2e/attrappe.mjs – ohne Netz. Prüft auch, dass das öffentliche Log keine Adressen enthält.
 */
import crypto from 'crypto';
import { ok, gleich, ende } from './_pruef.mjs';
import { neuerTenant, beantworte } from '../e2e/attrappe.mjs';

// Schlüssel + (Schein-)Zertifikat: für x5t zählt nur der DER-Inhalt des Blocks.
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const derZert = crypto.randomBytes(300);
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' })
  + `-----BEGIN CERTIFICATE-----\n${derZert.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;

Object.assign(process.env, {
  AZURE_TENANT_ID: 'fdb70646-023a-403b-a4b9-1f474a935123', AZURE_CLIENT_ID: '11111111-2222-3333-4444-555555555555',
  AZURE_ZERTIFIKAT: pem.replace(/\n/g, '\\n'), MAIL_SENDER: 'ticket@dihag.com', DRY_RUN: 'true', AUFGABEN: 'rechte,uebersicht',
});

const { zertifikatLesen, clientAssertion, main } = await import('../scripts/nachtlauf.mjs');

const z = zertifikatLesen(process.env.AZURE_ZERTIFIKAT);
const erwartetX5t = crypto.createHash('sha1').update(derZert).digest('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
gleich(z.x5t, erwartetX5t, 'x5t = SHA-1 des Zertifikats (base64url), auch aus einzeiligem Secret mit \\n');
const jwt = clientAssertion({ tenantId: 't', clientId: 'c', ...z }, 1000);
const [k, i, sig] = jwt.split('.');
const dek = x => JSON.parse(Buffer.from(x, 'base64url').toString());
gleich([dek(k).alg, dek(k).x5t, dek(i).iss, dek(i).sub, dek(i).aud, dek(i).exp], ['RS256', erwartetX5t, 'c', 'c', 'https://login.microsoftonline.com/t/oauth2/v2.0/token', 1600], 'JWT-Kopf und -Inhalt');
ok(crypto.verify('RSA-SHA256', Buffer.from(`${k}.${i}`), publicKey, Buffer.from(sig, 'base64url')), 'JWT-Signatur gültig');
let fehler = '';
try { zertifikatLesen('nur Text'); } catch (e) { fehler = e.message; }
ok(/privaten Schlüssel UND Zertifikat/.test(fehler), 'klare Meldung bei unvollständigem Zertifikat');

// Probelauf gegen die Attrappe
const t = neuerTenant();
const aufrufe = [];
globalThis.fetch = async (url, init = {}) => {
  const u = String(url);
  aufrufe.push((init.method || 'GET') + ' ' + u.replace(/\?.*/, ''));
  if (u.startsWith('https://login.microsoftonline.com/')) {
    const p = new URLSearchParams(init.body);
    const [kk, ii, ss] = p.get('client_assertion').split('.');
    const echt = crypto.verify('RSA-SHA256', Buffer.from(`${kk}.${ii}`), publicKey, Buffer.from(ss, 'base64url'));
    return new Response(JSON.stringify(echt ? { access_token: 'app', expires_in: 3600 } : { error: 'invalid_client' }), { status: echt ? 200 : 401 });
  }
  let body; try { body = init.body ? JSON.parse(init.body) : undefined; } catch { body = undefined; }
  const methode = init.headers?.['X-HTTP-Method'] || init.method || 'GET';
  const r = beantworte(t, 'admin@dihag.com', methode, u, body);
  return new Response(r.status === 202 ? null : r.body, { status: r.status, headers: { 'Content-Type': r.contentType } });
};
const zeilen = [];
const origLog = console.log;
console.log = (...a) => zeilen.push(a.join(' '));
let code;
try { code = await main(); } finally { console.log = origLog; }
const logText = zeilen.join("\n");
if (process.env.TEST_V) origLog(logText);
gleich(code, 0, 'Probelauf endet ohne Fehler');
ok(/Tickets-SCH: \d+ Abweichung/.test(logText), 'SCH: Abweichungen erkannt (Mitwirken zu viel, Melder fehlen)');
ok(/Tickets-SHB: \d+ Abweichung/.test(logText), 'SHB: Abweichungen erkannt (erbt, alle Elemente lesbar)');
ok(/SCH: \d+ offen, \d+ überfällig/.test(logText), 'Tagesübersicht SCH berechnet');
ok(/Probelauf\) Mail an/.test(logText), 'Probelauf sendet keine Mails, meldet sie nur');
ok(!/[\w.+-]+@[\w-]+\.[\w.]+/.test(logText.replace(/https?:\/\/\S+/g, '')), 'Log enthält keine Mailadressen (öffentliches Repo)');
ok(!aufrufe.some(a => /^POST .*(roleassignments|breakroleinheritance|sendMail)/.test(a)), 'Probelauf ändert nichts und sendet nichts');
ok(aufrufe.some(a => a.startsWith('POST https://login.microsoftonline.com/')), 'App-Token per Zertifikat angefordert');

ende();
