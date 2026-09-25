#!/usr/bin/env node
/**
 * Test-Runner: führt alle tests/*.test.mjs aus, jede Suite in einem eigenen
 * Node-Prozess. Ohne Abhängigkeiten (Node ≥ 20) – auch in der GitHub Action.
 *
 *   node scripts/test.mjs          alle Suiten
 *   node scripts/test.mjs flow     nur Suiten, deren Name „flow" enthält
 *   node scripts/test.mjs -v       jede Einzelprüfung anzeigen
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const verbose = argv.includes('-v');
const filter = (argv.find(a => !a.startsWith('-')) || '').toLowerCase();

const dateien = fs.readdirSync(path.join(ROOT, 'tests'))
  .filter(f => f.endsWith('.test.mjs') && f.toLowerCase().includes(filter))
  .sort();

let suitenRot = 0, gruen = 0, rot = 0;
console.log('\n▶ Ticketsystem – Testlauf\n');
for (const f of dateien) {
  const res = spawnSync(process.execPath, [path.join(ROOT, 'tests', f)], {
    encoding: 'utf8', cwd: ROOT, env: { ...process.env, TEST_V: verbose ? '1' : '' },
  });
  const out = (res.stdout || '') + (res.stderr || '');
  const m = out.match(/(\d+) grün, (\d+) rot/);
  const bestanden = res.status === 0;
  if (m) { gruen += +m[1]; rot += +m[2]; }
  if (!bestanden) suitenRot++;
  console.log(`  ${bestanden ? '✓' : '✗'} ${f.replace('.test.mjs', '').padEnd(28)} ${m ? m[1] + ' Prüfungen' : (bestanden ? 'ok' : 'Fehler')}`);
  if (verbose || !bestanden) out.trimEnd().split('\n').filter(l => verbose || /✗|Error|error/.test(l)).slice(0, 40).forEach(l => console.log('      ' + l));
}
console.log('\n' + '─'.repeat(50));
if (!dateien.length) { console.log('⚠ Keine Suiten gefunden'); process.exit(1); }
console.log(suitenRot ? `✗ ${suitenRot} Suite(n) rot – ${gruen} grün, ${rot} rot` : `✓ Alles grün – ${dateien.length} Suiten, ${gruen} Prüfungen`);
process.exit(suitenRot ? 1 : 0);
