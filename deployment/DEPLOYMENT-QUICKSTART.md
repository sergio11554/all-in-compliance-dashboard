# SFM Compliance - Deployment Quickstart

Diese Anleitung ist eine technische Betriebsunterlage. Sie ersetzt keine Hosting-, Datenschutz- oder Rechtsfreigabe.

## Variante A: Docker Compose

1. Release-Paket erstellen:

```bash
./scripts/prepare_release.sh
```

2. Archiv auf den Zielserver kopieren und entpacken.

3. Environment vorbereiten:

```bash
cp .env.example .env
chmod 600 .env
```

Mindestens setzen:

```text
ISMS_PUBLIC_URL=https://deine-domain.example
ISMS_COOKIE_SECURE=1
ISMS_HSTS=1
ISMS_ADMIN_PASSWORD=<langes-zufaelliges-passwort>
ISMS_FILE_KEY=<langes-zufaelliges-datei-secret>
POSTGRES_PASSWORD=<langes-zufaelliges-datenbankpasswort>
DATABASE_URL=postgresql://sfm:<passwort>@postgres:5432/sfm_compliance
ISMS_STORAGE_BACKEND=s3
ISMS_S3_ENDPOINT=https://s3.example.com
ISMS_S3_BUCKET=sfm-compliance-evidence
ISMS_S3_REGION=eu-central-1
ISMS_S3_ACCESS_KEY=<storage-access-key>
ISMS_S3_SECRET_KEY=<storage-secret-key>
ISMS_MALWARE_SCAN_MODE=clamav
ISMS_MALWARE_SCAN_REQUIRED=1
ISMS_CLAMAV_HOST=clamav
ISMS_CLAMAV_PORT=3310
```

4. Starten:

```bash
docker compose --profile malware up -d --build
docker compose ps
```

5. Healthcheck:

```bash
curl -fsS http://127.0.0.1:5173/api/health
```

Der Healthcheck muss im Compose-Betrieb `"database": "postgres"` melden. Ohne
`DATABASE_URL` verwendet das Backend ausschließlich für den lokalen Einzelbetrieb SQLite.

Die Dateiablage bleibt ohne `ISMS_STORAGE_BACKEND=s3` lokal in `data/uploads`. Fuer einen
skalierbaren Produktivbetrieb kann ein S3-kompatibler Objektspeicher verwendet werden. Die
Anwendung verschluesselt den Dateiinhalt weiterhin vor dem Upload; Datenbank und Objektspeicher
enthalten nur verschluesselte Blobs und getrennte Metadaten.

## Verpflichtender Malware-Scan

Im Kundenbetrieb sollten Uploads nur angenommen werden, wenn der konfigurierte Scanner erreichbar
ist. Dafuer in `.env` setzen:

```text
ISMS_MALWARE_SCAN_MODE=clamav
ISMS_MALWARE_SCAN_REQUIRED=1
ISMS_CLAMAV_HOST=clamav
ISMS_CLAMAV_PORT=3310
ISMS_CLAMAV_TIMEOUT_SECONDS=15
```

ClamAV wird im Compose-Profil `malware` gestartet:

```bash
docker compose --profile malware up -d --build
docker compose logs -f clamav
```

Der erste Start kann bis zur geladenen Signaturdatenbank dauern. Vor dem Uploadtest muss
`/api/health` den Modus `"malwareScanning": "clamav"` melden. Der Security-Bereich zeigt
zusaetzlich, ob der Scanner erreichbar ist.

Ein erkannter Fund oder ein technischer Scanfehler bei verpflichtendem Scan wird verschluesselt
in die Datei-Quarantaene verschoben. Quarantaenedateien erscheinen nicht in normalen
Nachweislisten, Downloads oder Mandantenexporten. Admins koennen sie unter
`/#quarantine` erneut pruefen oder endgueltig loeschen. Eine Datei wird nur nach einem sauberen
Rescan freigegeben; es gibt keine manuelle Umgehung des Scanners.

## Optionaler lokaler S3-Test mit MinIO

In `.env` setzen:

```text
ISMS_STORAGE_BACKEND=s3
ISMS_S3_ENDPOINT=http://minio:9000
ISMS_S3_BUCKET=sfm-compliance-evidence
ISMS_S3_ACCESS_KEY=sfm-storage-admin
ISMS_S3_SECRET_KEY=<langes-zufaelliges-storage-passwort>
ISMS_S3_AUTO_CREATE_BUCKET=1
MINIO_ROOT_USER=sfm-storage-admin
MINIO_ROOT_PASSWORD=<dasselbe-lange-zufaellige-storage-passwort>
```

Dann starten und den verschluesselten Upload-/Download-Rundlauf pruefen:

```bash
docker compose --profile s3 up -d --build
docker compose exec sfm-compliance python /app/scripts/storage_smoke.py
```

`ISMS_S3_AUTO_CREATE_BUCKET=1` ist fuer lokale Tests gedacht. Im Produktivbetrieb sollte der
Bucket vorab mit eigener Zugriffs-, Versionierungs-, Retention- und Backup-Konfiguration angelegt
werden.

## Optionales Enterprise-SSO

OIDC-Provider werden ausschließlich in der geschützten Deployment-Konfiguration hinterlegt. Ein
Provider ist immer fest einem Kundenraum zugeordnet. Beispiel:

```text
ISMS_OIDC_PROVIDERS_JSON=[{"id":"customer-sso","name":"Mit Unternehmenskonto anmelden","issuer":"https://identity.example.com/tenant/v2.0","clientId":"client-id","clientSecret":"client-secret","tenantSlug":"customer-slug","allowedDomains":["customer.example"],"algorithms":["RS256"]}]
```

Beim Identity Provider muss exakt folgende Redirect-URI eingetragen werden:

```text
https://deine-domain.example/api/auth/sso/callback
```

Die Plattform verwendet Authorization Code Flow mit PKCE, `state`, `nonce`, Signatur-, Issuer-
und Audience-Prüfung. Eine bestätigte externe Identität erhält nur Zugang, wenn bereits eine
passende Einladung oder ein bestehendes Benutzerkonto mit derselben E-Mail-Adresse im fest
zugeordneten Kundenraum existiert. Eine automatische offene Selbstregistrierung findet nicht statt.

## MFA-Schreibschutz fuer privilegierte Rollen

Im Kundenbetrieb den serverseitigen Schreibschutz aktivieren:

```text
ISMS_MFA_ENFORCEMENT=write
ISMS_MFA_REQUIRED_ROLES=admin,consultant,manager
```

Platform Admins sind bei aktivem Modus immer erfasst. Ein betroffenes Konto kann sich weiterhin
anmelden, lesen, Sitzungen verwalten und MFA unter `/#account` einrichten. Speichern, Freigeben,
Backups und andere privilegierte Änderungen werden bis zur MFA-Aktivierung mit HTTP 403 und dem
Code `mfa_enrollment_required` abgewiesen. Eine OIDC-Anmeldung ersetzt diese Plattform-MFA in
diesem Modus nicht automatisch; eine spätere IdP-Vertrauensregel muss separat geprüft werden.

## Bestehende SQLite-Daten übernehmen

Die Anwendung während der Migration nicht starten. Zuerst PostgreSQL hochfahren und ein
gesichertes Abbild der bisherigen `isms.db` verwenden:

```bash
docker compose up -d postgres
docker compose build sfm-compliance
docker compose run --rm \
  -v /geschuetzter/pfad/isms.db:/migration/isms.db:ro \
  sfm-compliance \
  python /app/scripts/migrate_sqlite_to_postgres.py \
  --source /migration/isms.db \
  --confirm MIGRATE_TO_POSTGRES
```

Das Ziel muss leer sein. Die Migration läuft in einer Transaktion und vergleicht anschließend
die Datensatzanzahl jeder Tabelle.

Wenn gleichzeitig von lokaler Dateiablage auf S3 gewechselt wird, die verschluesselten Blobs
kontrolliert kopieren. Der Quellbestand wird nicht geloescht:

```bash
docker compose run --rm \
  -v /geschuetzter/pfad/uploads:/migration/uploads:ro \
  sfm-compliance \
  python /app/scripts/migrate_file_storage.py \
  --source /migration/uploads \
  --confirm MIGRATE_FILE_STORAGE
```

Danach `storage_smoke.py` sowie mindestens einen vorhandenen Nachweis-Download testen. Der
Dateischluessel muss unveraendert und getrennt gesichert bereitstehen.

## Variante B: Systemd

Nutze `deployment/sfm-compliance.service` oder die bestehende `deployment/isms-catalyst.service` als Vorlage.

## Go-live Mindestcheck

- App laeuft nicht mehr ueber `file://`.
- Admin-Passwort und Datei-Secret sind gesetzt.
- HTTPS/Reverse Proxy ist aktiv.
- Admin-Login funktioniert.
- MFA fuer Admins ist vorbereitet.
- Testdatei-Upload funktioniert.
- Verpflichtender Malware-Scan und Datei-Quarantaene wurden getestet.
- Backup wurde erzeugt und separat gesichert.
- Restore wurde in einer Testumgebung geprueft.
- Rollen getestet: admin, consultant, manager, auditor, viewer.
