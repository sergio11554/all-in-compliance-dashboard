# Microsoft Intune: Pilotanbindung

## Stand

Implementiert: lesender Microsoft-Graph-Connector, verschluesselte Importvorschau,
explizite Uebernahme in das Asset-Register, stundenweiser Hintergrundabgleich nach
Freigabe, Quelleninformationen im Asset-Detail und Audit-/Live-Update-Anbindung.
Die App-Konfiguration ist direkt in Asset Management und Integrationen verfuegbar.
Die Testvorschau im Browser verwendet ausschliesslich fiktive Geraete und speichert
keine Assets. Sie belegt keine erfolgreiche Microsoft-Verbindung.

Ein echter Kundenabruf ist erst nach Microsoft-Einrichtung und Pilotabnahme moeglich.
Der bestehende Katalog anderer Integrationen bleibt eine Planung, keine Live-Anbindung.

## Voraussetzungen und Einrichtung

1. Aktive Intune-Lizenz im Kundenmandanten und ein berechtigter Microsoft-Administrator.
2. Eine kundeneigene Single-Tenant-App in Microsoft Entra registrieren.
3. Unter Microsoft Graph die **Application permission**
   `DeviceManagementManagedDevices.Read.All` hinzufuegen und Admin Consent erteilen.
   Keine Schreibberechtigung und keine zusaetzlichen Benutzer-/Verzeichnisrechte vergeben.
4. Directory/Tenant-ID, Application/Client-ID und den **Wert** eines zeitlich begrenzten
   Client-Secrets bereitstellen. Nicht die Secret-ID verwenden. Nicht in Chat, Git,
   Browser-Storage oder Kommandozeilenargumente kopieren.
5. Als SFM-Administrator im richtigen Kundenraum anmelden ("Mein Konto").
   Im Asset Management "Verbindung oeffnen" und "Microsoft-Zugang einrichten" waehlen.
   Die Microsoft-Links oeffnen die echten Verwaltungsportale, keine SFM-SSO-Anmeldung.
   App-Registrierung und Freigabe erfolgen weiterhin durch den Microsoft-Administrator.
6. Tenant-ID, Client-ID und Client-Secret in die Konfigurationsmaske eintragen.
   "Speichern und Verbindung testen" legt den Zugang verschluesselt in der separaten
   Tabelle `intune_credentials` ab und startet eine lesende Vorschau. Der Secret-Wert
   wird nicht wieder ausgegeben, nicht ins Workspace-JSON und nicht ins Audit-Log kopiert.
   HTTPS ist fuer die Einrichtung erforderlich; lokale Loopback-Entwicklung ist erlaubt.
7. Den aktualisierten Backend-Code starten. `ISMS_JOB_WORKER_ENABLED=1` ist fuer den Test
   erforderlich. Ohne Worker kann nur die Konfiguration gespeichert werden.
8. Erst nach erfolgreichem Microsoft-Abruf die Vorschau pruefen und ins Register uebernehmen.
   "Zugang gespeichert" bedeutet ausdruecklich noch nicht "Microsoft-Zugriff geprueft".
9. Nach erfolgreicher Uebernahme bei Bedarf "Stuendlich synchronisieren" aktivieren.

Alternativ bleibt die Betreiberkonfiguration ueber `python3 scripts/configure_intune.py`
verfuegbar. Der Standardpfad ist `$ISMS_DATA_DIR/intune-config.json`, ohne Variable
`data/intune-config.json`; optional `ISMS_INTUNE_CONFIG_FILE` setzen. Dateimodus 0600,
Eigentuemer der Backend-Servicebenutzer, nicht ins Docker-Image oder Git kopieren.
Ein Eintrag in dieser Datei hat Vorrang und kann nicht durch die Webmaske ersetzt werden.
Die SFM-Kundenraum-ID bezeichnet das lokale Kundenprojekt, nicht den Microsoft-Mandanten.

Der Serverschluessel (`ISMS_FILE_KEY` oder private `file_key.bin`) muss dauerhaft und
separat gesichert werden; ohne ihn sind gespeicherte App-Zugaenge nicht lesbar.
Zugang ersetzen oder entfernen pausiert die Automatik und verwirft alte Vorschauen.
Bestehende Assets werden nicht geloescht. Entfernen widerruft nicht den Microsoft-Consent;
App-Secrets und Freigaben bei Bedarf zusaetzlich in Microsoft Entra widerrufen.

Frontend ueber HTTP/HTTPS verwenden, nicht ueber `file://`. Fuer Kundenbetrieb sind
HTTPS, sicherer Betrieb und eine separate Staging-Abnahme erforderlich.

## Daten und Verhalten

- Nur Geraete-ID, Name, Betriebssystem/-version, Seriennummer, Hersteller, Modell,
  Verschluesselungsflag, technischer Intune-Status und letzter Geraetekontakt werden gelesen.
  Keine Benutzerlisten, E-Mails, Telefonnummern oder Recovery-/Bypass-Codes.
- OAuth Client Credentials im Backend; Access Tokens bleiben ausschliesslich im Arbeitsspeicher.
- Ausschliesslich Microsoft Global Cloud: festes Login-Ziel und festes Graph-Geraete-API-Ziel.
  Weiterleitungen sowie fremde oder unpassende Folgeseiten werden abgelehnt.
- Alle Seiten werden gelesen, bevor etwas uebernommen wird. Kein Teilimport bei Fehlern.
  Pilotlimit: 5000 Geraete, 100 Seiten, etwa drei Minuten Abrufzeit plus letzte Anfrage.
- Importvorschau ist 10 Minuten gueltig, mandantengebunden und verschluesselt gespeichert.
  Aendert sich die Workspace-Revision, muss erneut eine Vorschau abgerufen werden.
- ID aus SFM-Kundenraum, Microsoft-Mandant und Geraete-ID verhindert doppelte Imports.
  Bereits manuell angelegte gleiche Geraete werden NICHT heuristisch zusammengefuehrt.
- Neue Assets erhalten einen initialen Namen/Typ, aber keinen erfundenen Owner,
  keine Kritikalitaet, keine Freigabe und keinen behaupteten Auditnachweis.
  Spaetere Abgleiche aktualisieren nur `asset.intune`, nicht manuelle Bewertungen oder Namen.
- Fehlende Geraete werden an der Quelle als nicht mehr gemeldet markiert; keine Loeschung
  und kein automatisches Archivieren. Leere Listen bei Automatik erfordern manuelle Pruefung.
- Intune `compliant` ist ein technisches Quellsignal, keine ISO-/NIS-2-Konformitaetsaussage.
- Fehlgeschlagene Abrufe behalten den letzten erfolgreichen Datenstand. Transiente Fehler
  werden bis zu drei Mal versucht, mit Wartezeit und Beachtung von Retry-After.
- Automatik wird pro Kundenraum von einem aktiven Administrator freigegeben. Rechte,
  Kundenraumstatus und Konfigurationsbindung werden im Worker erneut geprueft.
  Eine andere App/Microsoft-Tenant-Zuordnung benoetigt erneute Freigabe.

## API

- `GET /api/integrations/intune`: mandantengebundener Status, letzte Uebernahme, Vorschau.
- `POST /api/integrations/intune/configure`: `tenantId`, `clientId`, `clientSecret` und
  `expectedVersion` aus dem Status (leer bei Ersteinrichtung). Speichert nur den Zugang.
- `POST /api/integrations/intune/disconnect`: `expectedVersion` erforderlich;
  entfernt ausschliesslich den in der Plattform gespeicherten Zugang.
- `POST /api/integrations/intune/preview` mit `{}`: Hintergrundabruf, keine Asset-Aenderung.
- `POST /api/integrations/intune/apply` mit `{"previewId":"..."}`: gepruefte Vorschau uebernehmen.
- `POST /api/integrations/intune/schedule` mit `{"enabled":true}` oder `false`: Automatik.

Session, vorhandener CSRF-Schutz und Administratorrechte sind fuer Mutationen erforderlich.
Die Status-API gibt weder Secret noch Access Token aus. Vorschau-/Sync-Jobs koennen nicht
ueber den generischen Job-Erstellungsendpunkt am Freigabeablauf vorbei angelegt werden.

## Noch offene Pilotabnahme

Ein echter Intune-Mandant und Admin Consent fehlen in dieser Entwicklungsumgebung.
Vor Freigabe pruefen: erster Import, wiederholter Import ohne Duplikate, Geraeteaenderung,
fehlendes Geraet, abgelaufenes Secret, entzogener Consent, API-Ausfall, Rate Limits,
Kundenraumwechsel und parallele manuelle Bearbeitung. Produktionsbetrieb mit PostgreSQL
und mehreren Workern separat abnehmen. Zertifikats-/Workload-Identity-Anmeldung statt
Client-Secret, automatische Secret-Rotation und manuelle Zuordnung bereits vorhandener
Assets sind nachfolgende Erweiterungen, noch nicht implementiert.
Ein "Mit Microsoft verbinden"-Ein-Klick-Onboarding mit einer zentralen Multi-Tenant-App
ist nicht implementiert. Diese Variante wuerde eine eigene registrierte Betreiber-App,
Consent-/Callback-Konfiguration und weitere Mandanten-Abnahmen voraussetzen.

## Offizielle Grundlagen

- [Intune managedDevices und Leseberechtigung](https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0)
- [OAuth Client Credentials](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
- [Microsoft Graph Rate Limits](https://learn.microsoft.com/en-us/graph/throttling)
- [App in Microsoft Entra registrieren](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app)
