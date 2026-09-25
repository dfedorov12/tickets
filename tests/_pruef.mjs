/**
 * Mini-Prüfgerüst für die Testsuiten (keine Abhängigkeiten).
 * Schlusszeile „N grün, M rot" – daraus liest scripts/test.mjs die Zahlen.
 */
let gruen = 0, rot = 0;

export function ok(bedingung, text) {
  if (bedingung) { gruen++; if (process.env.TEST_V) console.log('  ✓', text); }
  else { rot++; console.log('  ✗', text); }
}

export function gleich(ist, soll, text) {
  const a = JSON.stringify(ist), b = JSON.stringify(soll);
  ok(a === b, a === b ? text : `${text}\n      ist:  ${a}\n      soll: ${b}`);
}

export function wirft(fn, text) {
  try { fn(); ok(false, text + ' (hat nicht geworfen)'); } catch { ok(true, text); }
}

export function ende() {
  console.log(`\n${rot ? '✗' : '✓'} ${gruen} grün, ${rot} rot`);
  process.exit(rot ? 1 : 0);
}
