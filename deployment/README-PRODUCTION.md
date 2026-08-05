# SFM Compliance - Production Deployment

Diese Datei beschreibt den technischen Zielbetrieb. Sie ersetzt keine Rechts-, Datenschutz- oder Hosting-Freigabe.

## 0. Empfohlener Weg: Release-Paket

```bash
./scripts/prepare_release.sh
```

Das erzeugt unter `release/` ein Paket mit Backend, Frontend, Dockerfile, Compose-Datei und Deployment-Unterlagen.

Im entpackten Release:

```bash
cp .env.example .env
chmod 600 .env
python3 scripts/production_preflight.py --env-file .env
docker compose up -d --build
curl -fsS http://127.0.0.1:5173/api/health
python3 scripts/production_preflight.py --env-file .env --url https://isms.example.com
```

Auf ARM-basierten Entwicklungsrechnern verwendet Compose für das gepinnte
ClamAV-Image `SFM_CLAMAV_PLATFORM=linux/amd64`. Produktive x86-Server verwenden
dieselbe Plattform ohne Emulation.

## 1. Server vorbereiten

- Systembenutzer `sfm-compliance` anlegen.
- Backend nach `/opt/sfm-compliance/backend` legen.
- Frontend nach `/opt/sfm-compliance/frontend` legen.
- Datenpfad `/var/lib/sfm-compliance` mit restriktiven Rechten anlegen.
- Environment-Datei `/etc/sfm-compliance.env` aus `.env.example` ableiten.

## 2. Pflicht-Konfiguration

```text
ISMS_HOST=127.0.0.1
ISMS_PORT=5173
ISMS_PUBLIC_URL=https://isms.example.com
ISMS_COOKIE_SECURE=1
ISMS_COOKIE_SAMESITE=Lax
ISMS_HSTS=1
ISMS_DATA_DIR=/var/lib/sfm-compliance
ISMS_STATIC_BASE=/opt/sfm-compliance/frontend
ISMS_ADMIN_PASSWORD=<long-random-secret>
ISMS_FILE_KEY=<long-random-secret>
ISMS_LOGIN_ACCOUNT_MAX_ATTEMPTS=8
ISMS_LOGIN_IP_MAX_ATTEMPTS=30
ISMS_LOGIN_ATTEMPT_WINDOW_SECONDS=900
ISMS_LOGIN_LOCK_SECONDS=900
ISMS_PASSWORD_MIN_LENGTH=12
ISMS_PASSWORD_MAX_LENGTH=256
ISMS_PASSWORD_HISTORY_COUNT=5
ISMS_ACCOUNT_RECOVERY_ENABLED=1
ISMS_ACCOUNT_RECOVERY_TOKEN_SECONDS=3600
ISMS_NOTIFICATION_SMTP_HOST=<smtp-host>
ISMS_NOTIFICATION_SMTP_FROM=<security-sender-address>
ISMS_INVITATION_EMAIL_ENABLED=1
POSTGRES_PASSWORD=<long-random-secret>
DATABASE_URL=postgresql://sfm:<url-encoded-password>@postgres:5432/sfm_compliance
```

Das Kennwort in `DATABASE_URL` muss URL-kodiert sein. Alternativ nur
URL-sichere Zeichen verwenden, zum Beispiel einen mit `openssl rand -hex 32`
erzeugten Wert. `POSTGRES_PASSWORD` enthaelt dagegen das unveraenderte Kennwort.

Mit `ISMS_INVITATION_EMAIL_ENABLED=1` sendet die Plattform einmalige
Aktivierungslinks direkt an die eingeladene Adresse. `ISMS_PUBLIC_URL` muss
dabei auf die öffentlich erreichbare HTTPS-Adresse zeigen. Ein erneuter Versand
rotiert das Token und macht den vorherigen Link sofort unbrauchbar. Bleibt die
Option deaktiviert, zeigt der Adminbereich den Link genau für die kontrollierte
manuelle Übergabe an.

## Isoliertes lokales Staging

Der wiederholbare Staging-Stack verwendet eigene Docker-Volumes, PostgreSQL,
MinIO und ClamAV. Die laufende lokale Demo auf Port 5173 wird nicht veraendert.

```bash
./scripts/staging_stack.sh up
./scripts/staging_stack.sh smoke
./scripts/staging_stack.sh status
./scripts/staging_stack.sh down
```

Die Staging-Anwendung ist unter `http://127.0.0.1:5190` erreichbar. Geheimnisse
werden einmalig in `data/staging.env` mit Dateirechten `0600` erzeugt und nicht
in Git aufgenommen. `reset` entfernt ausschliesslich den Staging-Stack, dessen
Volumes und diese lokale Staging-Konfiguration.

## 3. Reverse Proxy

- Nginx-Konfiguration aus `nginx-isms-catalyst.conf` kopieren.
- Domain und Zertifikatspfad anpassen.
- `client_max_body_size` passend zu `ISMS_MAX_UPLOAD_BYTES` setzen.
- HTTP auf HTTPS umleiten.

## 4. Systemdienst

- `sfm-compliance.service` nach `/etc/systemd/system/` kopieren.
- Pfade und User pruefen.
- Dienst aktivieren und starten.

```bash
systemctl daemon-reload
systemctl enable --now sfm-compliance
systemctl status sfm-compliance
```

## 5. Go-live Smoke Test

- `python3 scripts/production_preflight.py --env-file .env --url https://isms.example.com` meldet keine technischen Blocker.
- `GET /api/health` liefert `ok: true`.
- `GET /api/health` meldet im Kundenbetrieb `database: postgres`.
- Angemeldete Browser zeigen `Live verbunden`; eine Änderung in einer zweiten Sitzung erscheint ohne Seitenreload.
- Der Reverse Proxy deaktiviert Buffering für `/api/events` oder respektiert `X-Accel-Buffering: no`.
- Login mit Admin funktioniert.
- Wiederholte Fehlanmeldungen sperren das betroffene Konto auch über einen App-Neustart hinweg; ein Admin kann die Kontosperre nachvollziehbar aufheben.
- Neu angelegte lokale Konten muessen ihr Initialpasswort vor der ersten Aenderung an Kundendaten ersetzen.
- Die Passwort-Historie verhindert die Wiederverwendung des aktuellen und der letzten konfigurierten Passwoerter.
- Die Passwort-Wiederherstellung antwortet unabhängig von existierenden Konten gleich, versendet nur zeitlich begrenzte Einmal-Links und widerruft nach erfolgreichem Reset alle bestehenden Sitzungen.
- `ISMS_MFA_ENFORCEMENT=write` und `ISMS_MFA_REQUIRED_ROLES=admin,consultant,manager` setzen.
- Mit einem privilegierten Testkonto pruefen: Lesen funktioniert, Schreiben wird vor MFA blockiert, MFA-Setup bleibt erreichbar und Schreiben funktioniert erst nach Aktivierung.
- Upload einer Testdatei funktioniert.
- Backup erzeugen und herunterladen.
- Restore-Prozess mit `./scripts/restore_drill.sh` in der isolierten Staging-Umgebung pruefen.
- Das Ergebnis muss State, Datei-Metadaten, Downloads und Audit-Hash-Kette vergleichen und als `restore_drill_verified` protokolliert sein.
- Security Center zeigt keine kritischen offenen Punkte.

Der Preflight prüft ausschließlich die technische Konfiguration und aktive
Infrastruktur. Ein erfolgreiches Ergebnis ist keine fachliche, rechtliche oder
Audit-Freigabe.

## 6. Betriebsroutine

- Woechentlich: Benutzer, MFA, Backups und Security Center pruefen.
- Monatlich: Retention-Lauf und Audit-Log-Stichprobe.
- Quartalsweise sowie nach Aenderungen an Datenbank, Storage, Verschluesselung oder Backup-Format: automatisierter Restore-Drill und Hardening-Review.

## 7. Weitere Runbooks

- `DEPLOYMENT-QUICKSTART.md`
- `GO-LIVE-CHECKLIST.md`
- `BACKUP-RESTORE-RUNBOOK.md`
