"use strict";
// Rückkehrseite der Anmeldung: die Antwort von Microsoft an die App weiterreichen.
msalRedirectBridge.broadcastResponseToMainFrame().catch(fehler => {
  console.error("Anmeldung: Antwort konnte nicht weitergereicht werden", fehler);
  document.body.textContent = "Die Anmeldung konnte nicht abgeschlossen werden. Bitte das Fenster schließen und erneut versuchen.";
});
