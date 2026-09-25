/**
 * Anmeldung (Microsoft Entra ID) mit MSAL.js 5
 * ============================================
 * msal-browser 5.23.0 wird selbst ausgeliefert (vendor/msal-browser/), keine fremde
 * Skriptquelle. Die Antwort von Microsoft landet auf redirect.html („Redirect-Bridge")
 * und wird von dort an die App weitergereicht. Muster aus dem Regelwerk-Management.
 *
 * Einmalig in Entra (App-Registrierung „Tickets", SPA-Plattform) eintragen:
 *   https://dfedorov12.github.io/tickets/redirect.html
 */
import { KONFIG } from './config.js';

/* global msal */

function _basis() {
  let p = location.origin + location.pathname.replace(/index\.html?$/i, '');
  if (!p.endsWith('/')) p += '/';
  return p;
}

let _msal = null;
let _konto = null;

export const spScopes = () => [`${KONFIG.spHost}/.default`];

/**
 * Anmelden. Gibt das Konto zurück – oder null, wenn die Seite gerade zur
 * Anmeldung umgeleitet wird.
 */
export async function anmelden() {
  _msal = new msal.PublicClientApplication({
    auth: {
      clientId: KONFIG.clientId,
      authority: `https://login.microsoftonline.com/${KONFIG.tenantId}`,
      redirectUri: _basis() + 'redirect.html',
      postLogoutRedirectUri: _basis(),
    },
    // localStorage: Ein Klick auf einen Ticket-Link in Outlook öffnet einen neuen Tab –
    // dort soll die Anmeldung schon bekannt sein. MSAL verschlüsselt den Cache; der
    // Schlüssel liegt in einem Sitzungs-Cookie (nach Browser-Ende abgemeldet).
    cache: { cacheLocation: 'localStorage' },
  });
  await _msal.initialize();

  const antwort = await _msal.handleRedirectPromise();
  if (antwort?.account) _konto = antwort.account;

  // Rückkehr an die ursprüngliche Stelle (z. B. #/t/SCH-12 aus einer Mail). Nur ein
  // Pfad auf DIESER Seite – „//host" wäre für den Browser eine fremde Adresse.
  if (antwort && typeof antwort.state === 'string' && /^\/(?![\/\\])/.test(antwort.state)
      && antwort.state !== location.pathname + location.search + location.hash) {
    location.replace(antwort.state);
    return null;
  }

  if (!_konto) _konto = _msal.getActiveAccount() || _msal.getAllAccounts()[0] || null;
  if (!_konto) {
    await _msal.loginRedirect({
      scopes: KONFIG.graphScopes,
      state: location.pathname + location.search + location.hash,
    });
    return null;
  }
  _msal.setActiveAccount(_konto);
  return _konto;
}

export const konto = () => _konto;
export const meineMail = () => String(_konto?.username || '').toLowerCase();
export const meinName = () => _konto?.name || _konto?.username || '';

/** Zugriffstoken; bei nötiger Interaktion Umleitung (liefert dann nie). */
export async function token(scopes) {
  if (!_msal || !_konto) throw new Error('Nicht angemeldet');
  try {
    return (await _msal.acquireTokenSilent({ scopes, account: _konto })).accessToken;
  } catch (e) {
    if (e instanceof msal.InteractionRequiredAuthError) {
      await _msal.acquireTokenRedirect({ scopes, account: _konto, state: location.pathname + location.search + location.hash });
      return new Promise(() => {}); // Seite wird umgeleitet
    }
    throw e;
  }
}

export function abmelden() {
  _msal?.logoutRedirect({ account: _konto });
}
