# SFM Compliance - Backup- und Restore-Runbook

Diese Unterlage beschreibt den technischen Betrieb. Ein erfolgreiches Backup oder ein Restore-Drill ist keine automatische fachliche, rechtliche oder Audit-Freigabe.

## Backup-Arten

### Workspace-Snapshots

- Mandantenbezogene Version des Workspace-State.
- Wird vor State-Ueberschreibungen erzeugt.
- Kann durch berechtigte Rollen im Produktivbetrieb-Bereich wiederhergestellt werden.
- Ersetzt kein System-Backup von Datenbank und Dateiablage.

### Verschluesselte System-Backups

- Unterstuetzen PostgreSQL und SQLite.
- Enthalten den Datenbank-Dump sowie alle verschluesselten Upload-Objekte aus S3 oder lokaler Dateiablage.
- Enthalten `backup-manifest.json` mit Formatversion, Groessen und SHA-256-Pruefsummen.
- Werden als `.ismsbak` unter dem konfigurierten Backup-Pfad abgelegt.
- Benoetigen fuer die Wiederherstellung denselben `ISMS_FILE_KEY` oder dieselbe Schluesseldatei.

Backup und Dateischluessel muessen getrennt voneinander aufbewahrt werden. Ohne den passenden Schluessel ist das Backup nicht wiederherstellbar.

## System-Backup erstellen

Ueber das Admin Center:

1. Als Platform-Admin anmelden.
2. `Produktivbetrieb` oeffnen.
3. `Backup erstellen` ausfuehren.
4. Backup herunterladen und ausserhalb des Anwendungsservers geschuetzt ablegen.

Per Skript:

```bash
SFM_BASE_URL='https://compliance.example.com' \
SFM_ADMIN_PASSWORD='<admin-passwort>' \
./scripts/backup_now.sh
```

## Backup nur verifizieren

Die Integritaetspruefung entschluesselt das Backup temporaer, validiert das Manifest sowie alle Pruefsummen und veraendert kein Zielsystem:

```bash
ISMS_FILE_KEY='<datei-secret>' \
python3 scripts/restore_system_backup.py \
  /sicherer/pfad/isms-backup-YYYYMMDD-HHMMSS.ismsbak \
  --verify-only
```

## Automatisierter Restore-Drill in Staging

Der Drill erstellt ein aktuelles Backup, stellt es in einer eigenen PostgreSQL-Datenbank und unter einem eigenen S3-Praefix wieder her, startet eine isolierte Pruefinstanz und vergleicht:

- Workspace-State,
- Datei-Metadaten,
- SHA-256 der heruntergeladenen Dateien,
- Audit-Hash-Kette,
- Datenbank- und Speicher-Backend.

Nach Erfolg werden nur die isolierte Pruefinstanz, die Drill-Datenbank und der Drill-S3-Praefix entfernt. Demo und regulaeres Staging bleiben bestehen.

```bash
./scripts/staging_stack.sh up
./scripts/restore_drill.sh
```

Ein erfolgreicher Drill wird serverseitig als `restore_drill_verified` im Audit Trail protokolliert. Das Ereignis dokumentiert ausschliesslich die technische Wiederherstellbarkeit.

## Manuelle Wiederherstellung eines System-Backups

Nur in einer frischen, kontrollierten Zielumgebung ausfuehren. Der Befehl ist destruktiv fuer die angegebene Zieldatenbank und bei `--replace-storage` fuer den konfigurierten Ziel-Speicherbereich.

```bash
export ISMS_FILE_KEY='<datei-secret>'
export DATABASE_URL='postgresql://user:pass@postgres:5432/sfm_restore'
export ISMS_STORAGE_BACKEND='s3'
export ISMS_S3_BUCKET='sfm-compliance'
export ISMS_S3_PREFIX='restore-YYYYMMDD'
python3 scripts/restore_system_backup.py \
  /sicherer/pfad/isms-backup-YYYYMMDD-HHMMSS.ismsbak \
  --database-url "$DATABASE_URL" \
  --replace-storage \
  --confirm RESTORE
```

Danach zwingend pruefen:

1. `/api/health` meldet erwartete Datenbank und Dateiablage.
2. Anmeldung funktioniert.
3. Workspace-State und Revision entsprechen der Quelle.
4. Datei-Metadaten und Downloads stimmen ueberein.
5. Audit-Hash-Kette ist gueltig.
6. Zielsystem enthaelt keine unbeabsichtigten Altobjekte.

## Workspace-Snapshot wiederherstellen

1. Als berechtigte Rolle anmelden.
2. `Produktivbetrieb` oeffnen.
3. Snapshot und Pruefsummenstatus kontrollieren.
4. Wiederherstellung bestaetigen.
5. Workspace-State, Revision und Audit Trail pruefen.

## Betriebsintervall

- Vor jedem Kunden-Go-live: automatisierten Restore-Drill erfolgreich abschliessen.
- Nach Aenderungen an Datenbank, Storage, Verschluesselung oder Backup-Format: Drill erneut ausfuehren.
- Im Regelbetrieb: mindestens quartalsweise; ein kuerzeres Intervall ist anhand Schutzbedarf und Wiederanlaufziel festzulegen.

## Kritische Grenzen

- Ein erzeugtes, aber nie wiederhergestelltes Backup ist kein belastbarer Wiederherstellungsnachweis.
- Backup und Schluessel duerfen nicht gemeinsam abgelegt werden.
- Backups koennen vertrauliche oder personenbezogene Kundendaten enthalten.
- Der aktuelle Backup-Container wird vor der Verschluesselung im Arbeitsspeicher erzeugt; fuer sehr grosse Datenbestaende ist vor Produktivbetrieb ein Streaming-/Snapshot-Verfahren des Hosting-Anbieters vorzusehen.
- Der Drill bestaetigt technische Integritaet und Vergleichbarkeit, nicht ISO-Konformitaet, NIS-2-Erfuellung oder Auditbereitschaft.
