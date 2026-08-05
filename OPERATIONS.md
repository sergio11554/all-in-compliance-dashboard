# ISMS Catalyst Operations

Hinweis: Produktname im Kundenkontext ist **SFM Compliance**. `isms-catalyst` bleibt teilweise als technischer interner Servicename erhalten.

## Produktivmodus

Die App soll fuer Kundenbetrieb ueber den Backend-Server laufen:

```bash
./run_backend.sh
```

Danach im Browser oeffnen:

```text
http://127.0.0.1:5173/index.html
```

Für lokale Entwicklung oder Vorführungen gibt es zusätzlich ein kleines
Kontrollskript mit PID-, Log- und Healthcheck-Behandlung:

```bash
./scripts/dev_server.sh start
./scripts/dev_server.sh status
./scripts/dev_server.sh restart
./scripts/dev_server.sh logs
./scripts/dev_server.sh stop
```

Das Skript ist nur für lokale Vorführung/Entwicklung gedacht. Für Kundenbetrieb
Docker Compose, systemd oder eine vergleichbare Prozessüberwachung mit
Auto-Restart verwenden.

Auf macOS startet das Skript den lokalen Vorführserver über `launchctl`, damit
der Prozess nicht beendet wird, sobald das Terminalkommando fertig ist. Logs und
PID liegen weiterhin unter `data/backend.log`, `data/backend-error.log` und
`data/backend.pid`.

Direktes `file://`-Oeffnen ist nur fuer statische Ansicht geeignet. Authentifizierung, Rollen, MFA, Backups, Audit-Log und verschluesselte Dateiablage benoetigen den Backend-Modus.

## Secrets

Vor produktiver Nutzung `.env.example` nach `.env` kopieren und mindestens setzen:

- `ISMS_ADMIN_PASSWORD`
- `ISMS_FILE_KEY`
- `ISMS_STORAGE_BACKEND` (`local` oder `s3`)
- `ISMS_S3_ENDPOINT`, `ISMS_S3_BUCKET`, `ISMS_S3_REGION`
- `ISMS_S3_ACCESS_KEY`, `ISMS_S3_SECRET_KEY` oder eine serverseitige IAM-Rolle
- `ISMS_OIDC_PROVIDERS_JSON`: optionale OIDC-Provider mit fester Kundenraum- und Domainzuordnung
- `ISMS_OIDC_STATE_SECONDS`: kurze Gültigkeit eines begonnenen SSO-Logins
- `ISMS_MALWARE_SCAN_MODE=clamav`: ClamAV fuer Upload-Pruefungen verwenden
- `ISMS_MALWARE_SCAN_REQUIRED=1`: Upload bei nicht erreichbarem Scanner blockieren
- `ISMS_CLAMAV_HOST`, `ISMS_CLAMAV_PORT`: interne Verbindung zum Scanner
- `ISMS_PUBLIC_URL`
- `ISMS_COOKIE_SECURE=1`
- `ISMS_HSTS=1`

Die Datei `.env`, `data/file_key.bin`, `data/isms.db`, `data/uploads`, der konfigurierte S3-Bucket und `data/backups` sind vertraulich zu behandeln.

## Produktiv-Konfiguration

- `ISMS_SESSION_SECONDS`: Session-Laufzeit, produktiv konservativ setzen
- `ISMS_MFA_ENFORCEMENT=write`: privilegierte Schreibzugriffe erst nach eigener MFA-Aktivierung zulassen
- `ISMS_MFA_REQUIRED_ROLES=admin,consultant,manager`: Rollen festlegen, fuer die der Schreibschutz gilt; Platform Admins sind bei aktivem Modus immer erfasst
- `ISMS_PASSWORD_MIN_LENGTH`, `ISMS_PASSWORD_MAX_LENGTH`: zentrale Laengenregeln fuer lokale Passwoerter
- `ISMS_PASSWORD_HISTORY_COUNT`: Anzahl vorheriger Passwort-Hashes, die eine Wiederverwendung verhindern
- `ISMS_MAX_JSON_BYTES`: maximales Workspace-State-JSON
- `ISMS_MAX_UPLOAD_BYTES`: maximales Upload-Volumen pro Request
- `ISMS_MAX_TENANT_EXPORT_BYTES`: maximale unkomprimierte Größe eines kontrollierten Mandantenexports
- `ISMS_WORKSPACE_SNAPSHOT_LIMIT`: Anzahl interner State-Snapshots pro Mandant
- `ISMS_EVENT_STREAM_SECONDS`, `ISMS_EVENT_HEARTBEAT_SECONDS`: Laufzeit und Heartbeat des mandantengeschützten Live-Streams
- `ISMS_EVENT_RETENTION_DAYS`: technische Aufbewahrung bereits verteilter Live-Ereignisse; Standard sieben Tage
- `ISMS_OPERATIONS_MONITOR_ENABLED`: automatische technische Alarmprüfung aktivieren oder deaktivieren
- `ISMS_OPERATIONS_MONITOR_SECONDS`: Intervall der technischen Alarmprüfung, mindestens 30 Sekunden
- `ISMS_JOB_WORKER_ENABLED`: Hintergrundverarbeitung fuer laengere technische Aufgaben aktivieren
- `ISMS_JOB_WORKER_SECONDS`: Queue-Pruefintervall fuer Hintergrundjobs
- `ISMS_JOB_MAX_ATTEMPTS`: maximale automatische Versuche pro Hintergrundjob
- `ISMS_NOTIFICATION_DELIVERY_ENABLED`: kontrollierte externe Benachrichtigungszustellung ausdrücklich aktivieren; Standard ist deaktiviert
- `ISMS_NOTIFICATION_DELIVERY_SECONDS`: Prüfintervall der persistenten Zustellqueue
- `ISMS_NOTIFICATION_MAX_ATTEMPTS`: maximale automatische Zustellversuche vor dem Status `fehlgeschlagen`
- `ISMS_NOTIFICATION_WEBHOOK_URL` und `ISMS_NOTIFICATION_WEBHOOK_SECRET`: festes Webhook-Ziel und Secret für die HMAC-SHA-256-Signatur
- `ISMS_NOTIFICATION_SMTP_*`: optionales SMTP-Ziel; Empfänger wird ausschließlich serverseitig festgelegt
- `ISMS_INVITATION_EMAIL_ENABLED=1`: einmalige Aktivierungslinks direkt an eingeladene Adressen senden; setzt getestetes SMTP und eine korrekte `ISMS_PUBLIC_URL` voraus
- `ISMS_STATIC_BASE`: Frontend-Pfad, wenn Backend und Frontend getrennt liegen
- `ISMS_DATA_DIR`: Datenpfad ausserhalb des App-Verzeichnisses
- `DATABASE_URL`: PostgreSQL-Verbindung für den Kundenbetrieb; ohne Wert bleibt der lokale SQLite-Modus aktiv
- `ISMS_CLAMAV_TIMEOUT_SECONDS`: maximales Zeitfenster fuer Scanner-Anfragen
- `ISMS_CLAMAV_CHUNK_BYTES`: Blockgroesse des ClamAV-INSTREAM-Protokolls

## Docker Deployment

Release-Paket erstellen:

```bash
./scripts/prepare_release.sh
```

Im Release-Verzeichnis:

```bash
cp .env.example .env
chmod 600 .env
python3 scripts/production_preflight.py --env-file .env
docker compose --profile malware up -d --build
docker compose ps
python3 scripts/production_preflight.py --env-file .env --url https://isms.example.com
```

Der Preflight blockiert erkennbare Demo-Secrets, HTTP-/Cookie-Fehlkonfiguration,
SQLite statt PostgreSQL und einen nicht verpflichtenden Malware-Scan. Lokale
Dateiablage und fehlendes OIDC werden als Warnung ausgewiesen. Das Ergebnis ist
ausschließlich technisch und stellt keine ISO-, NIS-2- oder Audit-Freigabe dar.

Wichtige Unterlagen:

- `deployment/DEPLOYMENT-QUICKSTART.md`
- `deployment/GO-LIVE-CHECKLIST.md`
- `deployment/BACKUP-RESTORE-RUNBOOK.md`

## Rollen

- `admin`: Benutzer, Security Center, Backups, Retention und alle Schreibrechte
- `consultant`: Beraterrolle mit fachlichen Schreibrechten und Zugriff auf interne Generatorfunktionen
- `manager`: fachliche Schreibrechte im Workspace
- `auditor`: lesender Audit-Zugriff
- `viewer`: lesender Zugriff

## Betrieb

- HTTPS ueber Reverse Proxy aktivieren, Vorlage: `deployment/nginx-isms-catalyst.conf`
- Dienstbetrieb vorbereiten, Vorlage: `deployment/isms-catalyst.service`
- PostgreSQL ist über `DATABASE_URL` angebunden; Referenzstruktur: `deployment/postgres-schema.sql`
- Produktions-Deployment-Ablauf: `deployment/README-PRODUCTION.md`
- Regelmaessige Backups im Security Center erzeugen und Download geschuetzt ablegen
- Workspace-Importe, Saves, Snapshots und Restores werden strukturell validiert; Fehler oder Hinweise im Backup-&-Recovery-Center prüfen, bevor ein Stand an Kunden oder Auditvorbereitung übergeben wird
- System-Backups enthalten Manifest und SHA-256-Pruefsummen fuer Datenbank-Dump und verschluesselte Dateiobjekte
- Produktiven Restore-Ablauf regelmaessig isoliert pruefen: `./scripts/staging_stack.sh up && ./scripts/restore_drill.sh`
- Ein erfolgreicher Drill vergleicht State, Datei-Metadaten, Downloads und Audit-Hash-Kette und erzeugt `restore_drill_verified`; das ist eine technische Betriebspruefung, keine fachliche Freigabe
- Mandantenexporte vor Übergabe oder endgültiger Bereinigung erstellen und geschützt ablegen
- `ISMS_MFA_ENFORCEMENT=write` aktivieren und MFA fuer Admin-, Berater- und Manager-Konten einrichten. Lesen, Kontoaktionen und MFA-Setup bleiben vor der Aktivierung möglich; Speichern, Freigeben und administrative Aktionen werden serverseitig blockiert.
- Lokale Initialpasswoerter werden nur zur sicheren Uebergabe verwendet. Neu angelegte Konten muessen sie beim ersten Login ersetzen; bis dahin bleibt der Kunden-Workspace serverseitig schreibgeschuetzt.
- Betriebsmonitor regelmaessig prüfen; der Server erkennt technische Alarmübergänge automatisch, führt aber keine Wartungsaktion automatisch aus
- Hintergrundjobs unter `/#jobs` pruefen: Betriebspruefungen und Backups koennen als Queue-Aufgaben gestartet, erneut versucht oder abgebrochen werden
- Ein erfolgreicher Hintergrundjob ist nur ein technischer Abschluss; er bedeutet keine fachliche Freigabe, keine ISO-Konformitaet und keine Auditbereitschaft
- Betriebsmonitor prüft zusätzlich die kontrollierte Benachrichtigungszustellung: deaktiviert/aktiv, Kanal-Konfiguration, offene Queue, Fehler, hängende Zustellversuche und Laufzeitfehler
- Sichere Standardmaßnahmen für abgelaufene Sessions und Einladungen nur als Platform Admin ausführen
- Einladungszustände im Bereich `/#team` prüfen. Bei Neuausstellung wird das Token rotiert; der alte Link ist sofort ungültig. Zustellfehler geben keine internen SMTP-Details an Kunden aus.
- Persönliche Benachrichtigungszustände werden pro Benutzer und aktivem Kundenraum gespeichert; Lesen, Ausblenden, Wiederherstellen und Eskalieren werden auditiert
- Live-Aktualisierungen laufen über `/api/events` pro angemeldetem Kundenraum. Das 45-Sekunden-Revisionspolling bleibt als Rückfall aktiv; fremde Änderungen überschreiben keine lokal offenen Eingaben.
- Statische JavaScript-/CSS-Dateien verwenden ETag und kurze Revalidierung. Workspace-, Session-, Review- und Nachweis-APIs bleiben `no-store`.
- Dringende Benachrichtigungen nur bewusst als gemeinsame Aufgabe eskalieren; dadurch entsteht keine automatische fachliche Freigabe
- Externe Benachrichtigungszustellung bleibt standardmäßig deaktiviert und ist nur für Rollen mit Review-Recht verfügbar
- Webhooks werden mit `X-SFM-Signature: sha256=<hex>` signiert; Ziel-URL, Secret und SMTP-Zugangsdaten werden nie über die API ausgegeben
- Zustellqueue, Wiederholungen, Fehler und erfolgreiche Zustellungen werden mandantenbezogen gespeichert und auditiert; Zustellung ändert keine fachliche Freigabe
- Offene Zustellfehler im Betriebsmonitor prüfen und bewusst im Benachrichtigungscenter erneut einplanen, statt automatische Freigaben oder Löschungen daraus abzuleiten
- Malware-Scan im Kundenbetrieb verpflichtend aktivieren und Scanner-Erreichbarkeit im Security-Bereich ueberwachen
- Funde nur in `/#quarantine` behandeln; Quarantaenedateien sind von normalen Listen, Downloads und Exporten ausgeschlossen
- Freigabe aus der Quarantaene nur durch sauberen Rescan; es gibt keine manuelle Ausnahmefreigabe
- ClamAV-Signaturaktualisierung und Scanner-Ausfallalarm in den regulaeren Betriebscheck aufnehmen
- Retention im Security Center regelmaessig ausfuehren
- UX-, Datenschutz-, Betriebs- und Hardening-Unterlagen im Frontend-Ordner unter `docs/` pflegen

## Mandanten

Mandanten trennen Kundenraeume logisch voneinander:

- Benutzer gehoeren zu genau einem Mandanten
- Workspace-State wird pro Mandant gespeichert
- Datei-Metadaten und Uploads werden pro Mandant zugeordnet
- Audit-Logs sind mandantenspezifisch sichtbar
- Persönliche Benachrichtigungszustände sind zusätzlich pro Benutzer getrennt
- Plattform-Admins verwalten Mandanten, globale Backups und Retention
- Kunden-Admins verwalten Benutzer und Inhalte nur innerhalb ihres Mandanten
