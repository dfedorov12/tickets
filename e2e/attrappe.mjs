/**
 * Attrappe für SharePoint-REST und Graph – für den Browser-Rundgang (e2e/rundgang.mjs).
 * Ein kleiner In-Memory-Tenant: Ticket-Site mit Konfigurationsliste, zwei Queue-Listen,
 * Archiv, Gruppen, Rollen und – wichtig – „nur eigene Elemente" für Melder.
 * Kein Anspruch auf Vollständigkeit: nur, was die App tatsächlich aufruft.
 */

const G = n => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
export const LISTEN = { konfig: G(1), sch: G(2), shb: G(3), alt: G(4), schIntern: G(5) };

const VOLL = { High: '2147483647', Low: '4294967295' };
const BEARBEITUNG = { High: '432', Low: String(1 + 2 + 4 + 32 + 64 + 256 + 512 + 4096 + 65536 + 131072) };
const LESEN = { High: '176', Low: '138612833' };
const KEINE = { High: '0', Low: '0' };

export function neuerTenant() {
  const nutzer = {
    'admin@dihag.com': { Id: 1, Title: 'Ada Admin' },
    'anna.agent@dihag.com': { Id: 11, Title: 'Anna Agent' },
    'bert.bearbeiter@dihag.com': { Id: 13, Title: 'Bert Bearbeiter' },
    'max@schmie-guss.de': { Id: 12, Title: 'Max Melder' },
    'ticket@dihag.com': { Id: 20, Title: 'Ticket Postfach' },
  };
  const person = mail => ({ Id: nutzer[mail].Id, Title: nutzer[mail].Title, EMail: mail });
  const tag = n => new Date(Date.now() - n * 86400e3).toISOString();
  const felderTickets = [
    { InternalName: 'Title', Title: 'Titel', TypeAsString: 'Text', FromBaseType: true },
    { InternalName: 'Description', Title: 'Beschreibung', TypeAsString: 'Note' },
    { InternalName: 'Status', Title: 'Status', TypeAsString: 'Choice', Choices: ['Neu', 'Offen', 'In Bearbeitung', 'Warten auf Rückmeldung', 'Erledigt', 'Abgebrochen', 'Projekt'] },
    { InternalName: 'Priority', Title: 'Priorität', TypeAsString: 'Choice', Choices: ['Kritisch', 'Hoch', 'Normal', 'Niedrig'] },
    { InternalName: 'Assignedto0', Title: 'Zugewiesen an', TypeAsString: 'UserMulti' },
    { InternalName: 'Issueloggedby', Title: 'Gemeldet von', TypeAsString: 'User' },
    { InternalName: 'E_x002d_Mail_x002d_Adresse', Title: 'E-Mail-Adresse', TypeAsString: 'Text' },
    { InternalName: 'DateReported', Title: 'Gemeldet am', TypeAsString: 'DateTime' },
    { InternalName: 'Werk', Title: 'Werk', TypeAsString: 'Choice', Choices: ['DIHAG', 'SCH', 'SHB', 'Kein'] },
    { InternalName: 'Kategorie', Title: 'Kategorie', TypeAsString: 'Choice', Choices: ['Hardware', 'Software'] },
  ];
  const item = (Id, t) => ({
    Id, Title: t.titel, Description: t.html || '<div><p>Beschreibung</p></div>', Status: t.status || 'Neu', Priority: t.prio || 'Normal',
    Assignedto0: (t.bearbeiter || []).map(person), Issueloggedby: t.melder ? person(t.melder) : null,
    E_x002d_Mail_x002d_Adresse: t.melder || '', DateReported: tag(t.alter ?? 1), Created: tag(t.alter ?? 1), Modified: tag((t.alter ?? 1) / 2),
    Werk: t.werk || 'SCH', Kategorie: t.kategorie || 'Hardware', Attachments: !!t.anhang, Author: person(t.autor || t.melder || 'ticket@dihag.com'),
  });
  const konfigZeile = (Id, f) => ({ Id, ID: Id, Aktiv: true, Standard: false, Benachrichtigen: false, Reihenfolge: Id * 10, Domains: '', Bearbeiter: '', Hinweistext: '', ListenUrl: '', ...f });

  const t = {
    nutzer, person,
    mails: [],
    web: { Id: G(99), Title: 'Ticket', owner: 'Ticket Besitzer' },
    gruppen: {
      'Ticket Besitzer': { Id: 3, mitglieder: ['admin@dihag.com'] },
      'Tickets SCH – Bearbeiter': { Id: 30, mitglieder: ['anna.agent@dihag.com', 'bert.bearbeiter@dihag.com'] },
      'Tickets SHB – Bearbeiter': { Id: 31, mitglieder: [] },
    },
    rollen: [
      { Id: 1073741829, Name: 'Vollzugriff', RoleTypeKind: 5, BasePermissions: VOLL },
      { Id: 1073741827, Name: 'Mitwirken', RoleTypeKind: 3, BasePermissions: { High: '432', Low: String(1 + 2 + 4 + 8 + 32 + 64 + 128 + 512 + 4096 + 65536 + 131072) } },
      { Id: 1073741826, Name: 'Lesen', RoleTypeKind: 2, BasePermissions: LESEN },
      { Id: 1073741825, Name: 'Beschränkter Zugriff', RoleTypeKind: 1, BasePermissions: KEINE },
    ],
    listen: {
      [LISTEN.konfig]: {
        Title: 'TicketQueues', felder: [], items: [
          konfigZeile(1, { Title: 'Werk SCH', Kennung: 'SCH', ListenName: 'Tickets-SCH', ListenId: LISTEN.sch, Domains: 'schmie-guss.de', Werk: 'SCH', Bearbeiter: 'anna.agent@dihag.com', Gruppe: 'Tickets SCH – Bearbeiter', Modus: 'Ticket' }),
          konfigZeile(2, { Title: 'Werk SHB', Kennung: 'SHB', ListenName: 'Tickets-SHB', ListenId: LISTEN.shb, Domains: 'shb-guss.de', Werk: 'SHB', Gruppe: 'Tickets SHB – Bearbeiter', Modus: 'Ticket', Standard: true }),
          konfigZeile(3, { Title: 'Gienanth (Hinweis)', Kennung: 'GIE', Domains: 'gienanth.com', Modus: 'Hinweis', Hinweistext: 'Bitte it-support@… verwenden' }),
          konfigZeile(4, { Title: 'Archiv (bisherige Liste)', Kennung: 'ALT', ListenName: 'Tickets', ListenId: LISTEN.alt, Modus: 'Archiv', Gruppe: '*' }),
        ],
      },
      [LISTEN.sch]: {
        Title: 'Tickets-SCH', felder: felderTickets, ReadSecurity: 2, WriteSecurity: 2, NoCrawl: true, EnableVersioning: true, EnableAttachments: true, HasUniqueRoleAssignments: true,
        rechte: { 'Tickets SCH – Bearbeiter': 'bearbeitung', melder: 'lesen' },
        zuweisungen: [
          { gruppe: 'Ticket Besitzer', rolle: 'Vollzugriff' }, { gruppe: 'Tickets SCH – Bearbeiter', rolle: 'Mitwirken' },
          { login: 'i:0#.f|membership|ticket@dihag.com', rolle: 'Vollzugriff' },
        ],
        items: [
          item(1, { titel: 'Drucker in Halle 2 druckt nicht', melder: 'max@schmie-guss.de', alter: 3, prio: 'Hoch', anhang: true, html: '<div class="ExternalClass"><p>Hallo,</p><p>der <b>Drucker</b> geht nicht. <a href="javascript:alert(1)">klick</a> <img src="x" onerror="window.__xss=1"><script>window.__xss=2</script><a href="https://example.com/hilfe">Hilfe</a></p></div>' }),
          item(2, { titel: 'VPN-Zugang für neuen Kollegen', melder: 'max@schmie-guss.de', alter: 0.2, bearbeiter: ['anna.agent@dihag.com'], status: 'In Bearbeitung' }),
          item(3, { titel: 'Outlook stürzt ab', melder: 'bert.bearbeiter@dihag.com', alter: 10, status: 'Erledigt' }),
          item(4, { titel: 'SAP-Berechtigung Einkauf', melder: 'max@schmie-guss.de', alter: 0.5, prio: 'Kritisch' }),
        ],
        kommentare: { 1: [{ id: 1, text: 'Wir schauen uns das an.', createdDate: tag(2), author: { name: 'Anna Agent', email: 'anna.agent@dihag.com' } }] },
        anhaenge: { 1: [{ FileName: 'foto.jpg', ServerRelativeUrl: '/sites/ticket/Lists/TicketsSCH/Attachments/1/foto.jpg' }] },
      },
      [LISTEN.shb]: {
        Title: 'Tickets-SHB', felder: felderTickets, ReadSecurity: 1, WriteSecurity: 1, NoCrawl: false, EnableVersioning: true, EnableAttachments: true, HasUniqueRoleAssignments: false,
        rechte: { 'Tickets SHB – Bearbeiter': 'bearbeitung', melder: 'lesen' },
        zuweisungen: [{ gruppe: 'Ticket Besitzer', rolle: 'Vollzugriff' }, { gruppe: 'Ticket Mitglieder', rolle: 'Bearbeiten' }],
        items: [item(1, { titel: 'Monitor flackert', melder: 'max@schmie-guss.de', werk: 'SHB', alter: 1 })],
      },
      [LISTEN.alt]: {
        Title: 'Tickets', felder: felderTickets, ReadSecurity: 1, WriteSecurity: 1, NoCrawl: false, EnableVersioning: true, EnableAttachments: true, HasUniqueRoleAssignments: false,
        rechte: {}, zuweisungen: [],
        items: [item(100, { titel: 'Alt: Laptop langsam', melder: 'max@schmie-guss.de', werk: 'SCH', status: 'Offen', alter: 40 })],
      },
      [LISTEN.schIntern]: {
        Title: 'Tickets-SCH-Intern', felder: [], items: [{ Id: 1, TicketId: 1, Text: 'Toner ist bestellt.', Created: tag(1), Author: person('anna.agent@dihag.com') }],
        rechte: { 'Tickets SCH – Bearbeiter': 'bearbeitung' }, zuweisungen: [],
      },
    },
  };
  return t;
}

/** Rolle von `mail` in einer Liste → Maske. */
function maske(t, liste, mail) {
  if (t.gruppen['Ticket Besitzer'].mitglieder.includes(mail)) return VOLL;
  if (mail === 'ticket@dihag.com') return VOLL;
  for (const [g, r] of Object.entries(liste.rechte || {})) {
    if (g !== 'melder' && t.gruppen[g]?.mitglieder.includes(mail)) return r === 'bearbeitung' ? BEARBEITUNG : LESEN;
  }
  return liste.rechte?.melder ? LESEN : null;
}

const json = (body, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(body) });
const nicht = text => json({ 'odata.error': { message: { value: text } } }, 404);
const verboten = () => json({ 'odata.error': { message: { value: 'Zugriff verweigert' } } }, 403);

/**
 * Anfrage beantworten. `ich` = Mail der angemeldeten Person.
 * Gibt { status, contentType, body } für route.fulfill zurück.
 */
export function beantworte(t, ich, method, urlText, body) {
  const url = new URL(urlText);
  const pfad = decodeURIComponent(url.pathname);
  const verbose = /odata=verbose/.test(body?.__accept || '');
  const q = url.searchParams;

  // ── Graph ──
  if (url.hostname === 'graph.microsoft.com') {
    if (pfad.startsWith('/v1.0/sites/dihag.sharepoint.com:')) return json({ id: 'dihag.sharepoint.com,site,web' });
    if (pfad === '/v1.0/me/sendMail') { t.mails.push({ von: ich, ...body.message }); return { status: 202, contentType: 'text/plain', body: '' }; }
    if (pfad === '/v1.0/users') {
      const such = (q.get('$filter') || '').match(/startswith\(displayName,'([^']*)'\)/)?.[1]?.toLowerCase() || '';
      return json({ value: Object.entries(t.nutzer).filter(([m, u]) => u.Title.toLowerCase().startsWith(such) || m.startsWith(such)).map(([m, u]) => ({ displayName: u.Title, mail: m })) });
    }
    const m = pfad.match(/^\/v1\.0\/sites\/[^/]+\/lists\/([0-9a-f-]+)\/items$/);
    if (m && method === 'POST') {
      const l = t.listen[m[1]];
      const id = Math.max(0, ...l.items.map(i => i.Id)) + 1;
      l.items.push({ Id: id, ...body.fields, Created: new Date().toISOString(), Modified: new Date().toISOString(), Author: t.person(ich), Assignedto0: [], Attachments: false, TicketId: body.fields.TicketId });
      return json({ id: String(id) }, 201);
    }
    return json({ error: { message: 'Graph-Attrappe: ' + pfad } }, 501);
  }

  // ── SharePoint ──
  const api = pfad.replace(/^\/sites\/ticket\/_api\//, '');
  if (api === 'web') {
    return json({ Id: t.web.Id, Title: t.web.Title, EffectiveBasePermissions: t.gruppen['Ticket Besitzer'].mitglieder.includes(ich) ? VOLL : LESEN, AssociatedOwnerGroup: { Title: t.web.owner } });
  }
  let m;
  if ((m = api.match(/^web\/lists\/getbytitle\('(.+)'\)(\/items)?$/))) {
    const [id, l] = Object.entries(t.listen).find(([, x]) => x.Title === m[1].replace(/''/g, "'")) || [];
    if (!l) return nicht(`List '${m[1]}' does not exist at site`);
    if (m[2]) return json({ value: l.items });
    return json({ Id: id, Title: l.Title, ReadSecurity: l.ReadSecurity, WriteSecurity: l.WriteSecurity, NoCrawl: l.NoCrawl, EnableVersioning: l.EnableVersioning, EnableAttachments: l.EnableAttachments, HasUniqueRoleAssignments: l.HasUniqueRoleAssignments, ItemCount: l.items.length, RootFolder: { ServerRelativeUrl: '/sites/ticket/Lists/' + l.Title } });
  }
  if ((m = api.match(/^web\/lists\(guid'([0-9a-f-]+)'\)(.*)$/))) {
    const l = t.listen[m[1]];
    if (!l) return nicht('Liste fehlt');
    const rest = m[2];
    const mk = maske(t, l, ich);
    if (!mk) return verboten();
    const nurEigene = mk === LESEN && l.ReadSecurity === 2;
    const sichtbar = i => !nurEigene || i.Author?.EMail === ich;
    if (rest === '/EffectiveBasePermissions') return json(mk);
    if (rest === '') return json({ HasUniqueRoleAssignments: l.HasUniqueRoleAssignments, ListItemEntityTypeFullName: 'SP.Data.' + l.Title + 'ListItem', Title: l.Title });
    if (rest === '/fields') return json({ value: l.felder });
    if (rest === '/items' && method === 'GET') {
      let items = l.items.filter(sichtbar);
      const f = (q.get('$filter') || '').match(/TicketId eq (\d+)/);
      if (f) items = items.filter(i => i.TicketId === Number(f[1]));
      return json({ value: items });
    }
    if ((m = rest.match(/^\/items\((\d+)\)(.*)$/))) {
      const it = l.items.find(i => i.Id === Number(m[1]));
      if (!it || !sichtbar(it)) return nicht('Element fehlt');
      if (m[2] === '') return json(it);
      if (m[2] === '/ValidateUpdateListItem') {
        if (mk !== VOLL && mk !== BEARBEITUNG) return verboten();
        for (const fv of body.formValues) {
          if (/Assignedto0|Issueloggedby|Author/.test(fv.FieldName)) {
            const leute = JSON.parse(fv.FieldValue).map(k => k.Key.split('|').pop()).filter(x => t.nutzer[x]).map(t.person);
            it[fv.FieldName] = fv.FieldName === 'Assignedto0' ? leute : leute[0];
          } else it[fv.FieldName] = fv.FieldValue;
        }
        it.Modified = new Date().toISOString();
        return json({ value: body.formValues.map(f => ({ FieldName: f.FieldName, HasException: false })) });
      }
      if (m[2] === '/AttachmentFiles') return json({ value: l.anhaenge?.[it.Id] || [] });
    }
    if ((m = rest.match(/^\/GetItemById\((\d+)\)\/Comments$/))) {
      l.kommentare ||= {};
      if (method === 'POST') {
        if (mk === LESEN) return verboten();
        (l.kommentare[m[1]] ||= []).push({ id: Date.now(), text: body.text, createdDate: new Date().toISOString(), author: { name: t.nutzer[ich].Title, email: ich } });
        return json({}, 201);
      }
      return json({ value: [...(l.kommentare[m[1]] || [])].reverse() });
    }
    if (rest === '/roleassignments') {
      const rolle = n => t.rollen.find(r => r.Name === n) || { Id: 999, Name: n, RoleTypeKind: 6 };
      return json({ value: (l.zuweisungen || []).map((z, i) => ({
        PrincipalId: z.gruppe ? (t.gruppen[z.gruppe]?.Id || 90 + i) : 20,
        Member: z.gruppe ? { Id: t.gruppen[z.gruppe]?.Id || 90 + i, LoginName: z.gruppe, Title: z.gruppe, PrincipalType: 8 } : { Id: 20, LoginName: z.login, Title: z.login, PrincipalType: 1 },
        RoleDefinitionBindings: [rolle(z.rolle)],
      })) });
    }
  }
  if ((m = api.match(/^web\/sitegroups\/getbyname\('(.+)'\)(\/users)?$/))) {
    const g = t.gruppen[m[1]];
    if (!g) return nicht('Gruppe fehlt');
    if (m[2]) return json({ value: g.mitglieder.map(x => ({ Id: t.nutzer[x].Id, Title: t.nutzer[x].Title, Email: x, LoginName: 'i:0#.f|membership|' + x })) });
    return json({ Id: g.Id, Title: m[1] });
  }
  if ((m = api.match(/^web\/sitegroups\((\d+)\)\/users$/))) {
    const g = Object.values(t.gruppen).find(x => x.Id === Number(m[1]));
    return json({ value: g.mitglieder.map(x => ({ Id: t.nutzer[x].Id, Title: t.nutzer[x].Title, Email: x, LoginName: 'i:0#.f|membership|' + x })) });
  }
  if ((m = api.match(/^web\/roledefinitions\/getbytype\((\d+)\)$/))) return json(t.rollen.find(r => r.RoleTypeKind === Number(m[1])));
  if ((m = api.match(/^web\/roledefinitions\/getbyname\('(.+)'\)$/))) {
    const r = t.rollen.find(x => x.Name.toLowerCase() === m[1].toLowerCase());
    return r ? json(r) : nicht('Rolle fehlt');
  }
  return json({ 'odata.error': { message: { value: 'SP-Attrappe kennt ' + method + ' ' + api + ' nicht' } } }, 501);
}
