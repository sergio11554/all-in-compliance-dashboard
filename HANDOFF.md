# SFM Compliance - Projektübergabe

Stand: 5. August 2026

## Projektziel

SFM Compliance führt Kunden durch die strukturierte Vorbereitung von ISMS-, ISO-27001- und NIS-2-Vorhaben. Die Anwendung sammelt Daten und Nachweise, macht formale Lücken sichtbar und bündelt Einreichungen für die Beraterprüfung.

Die fachliche Bewertung, Freigabe und Aussage zur Auditbereitschaft bleiben ausschließlich bei Berater oder Administrator. Die Anwendung darf automatisch nur formale Vollständigkeit oder Prüfbereitschaft anzeigen.

## Aktueller Entwicklungsstand

Es liegt ein umfangreicher lokaler Produktprototyp mit persistenter Backend-Anbindung, rollenbasierten Arbeitsbereichen, Mandantentrennung, Registern, Review-Prozess, Nachweisverwaltung und technischen Betriebsfunktionen vor. Frontend und Backend sind gemeinsam über Port 5173 ausführbar. Für den produktiven Zielbetrieb bestehen Docker-, PostgreSQL-, S3-, ClamAV-, Nginx- und systemd-Vorlagen.

Das Projekt war vor dieser Übergabe noch nicht als Git-Repository initialisiert und hatte kein Remote. Lokale Betriebsdaten und Zugangsdaten befinden sich im Verzeichnis `data/`; sie werden durch `.gitignore` vollständig von der Übergabe ausgeschlossen.

## Umgesetzte Funktionen

### Start und Steuerung

- Dashboard als Tool-Hub mit nächsten Schritten, Status und formalen Lücken
- Geschäftsführungs-Cockpit für Top-Risiken, Entscheidungen, Fristen und Compliance-Spuren
- Benachrichtigungscenter mit persönlichen Zuständen, Eskalation und optionaler externer Zustellung
- Geführter Kundenmodus mit einfacher Sprache und Schrittfolge
- Chronologischer Projektstrukturplan mit Ownern, Status, Nachweisen und Vorlagenverweisen

### Prüfung und Übergabe

- Review Center für Einreichungen, Beraterprüfung, Nacharbeit, Ablehnung und Freigabe
- Trennung zwischen internem Beraterkommentar und Kundenkommentar
- Automatische Kundenaufgaben bei angeforderter Nacharbeit
- Auditpaket-Gate mit Blockern und expliziter Beraterfreigabe
- Dokumentation, Nachweise, Versionierung und Audit Trail
- Task Management für Verantwortlichkeiten, Fristen und Ergebnisse

### Compliance und Register

- ISO-27001-Arbeitsbereich mit Clauses und Annex-A-Bezug
- NIS-2-Navigator als getrennte Sicht mit offenen Punkten und Nachweisen
- SoA-Matrix mit 93 Controls und editierbaren Entscheidungen
- Auditmatrix, Arbeitsvorlagen und Policy-Management
- Asset-, Risiko-, Lieferanten-, Rechts-, Incident- und Vertragsregister
- Management Review, internes Audit und Maßnahmen-/Feststellungsnachverfolgung

### Benutzer und Betrieb

- Mandantenbezogene Benutzer, Rollen und Einladungen
- Rollen `admin`, `consultant`, `manager`, `auditor` und `viewer`
- Lokale Authentifizierung, Session-Management, Passwortregeln und Passwort-Historie
- MFA-Schutz für privilegierte Schreibzugriffe
- Account Recovery und optionales OIDC-SSO
- Verschlüsselte lokale oder S3-kompatible Dateiablage
- Optional verpflichtender ClamAV-Scan mit Quarantäne ohne manuelle Scanner-Umgehung
- Backups, kontrollierte Restores, Restore-Drills und Retention
- Hintergrundjobs, Betriebsmonitor und technische Alarmzustände
- Mandantengeschützter Live-Stream per Server-Sent Events mit Polling-Rückfall
- Signierte Webhooks bzw. SMTP für kontrollierte Benachrichtigungszustellung

## Architektur

### Frontend

`frontend-current/` enthält eine statische Browser-Anwendung. `app.js` orchestriert die Ansichten und Interaktionen; fachliche Hilfslogik ist bereits in Module wie `risk-engine.js`, `review-workflow.js`, `soa-engine.js`, `task-engine.js`, `audit-package-gate.js`, `workspace-validator.js` und `access-control.js` ausgelagert.

### Backend

`backend_app.py` stellt HTTP-API, Sitzungen, Rollenprüfungen, Mandantenkontext, Auditierung, Uploads, Live-Ereignisse und Betriebsendpunkte bereit. `database.py` kapselt SQLite und PostgreSQL. `storage.py` kapselt verschlüsselte lokale und S3-kompatible Dateiablage. `oidc_auth.py` und `malware_scan.py` enthalten SSO- bzw. ClamAV-spezifische Logik.

### Persistenz und Datenfluss

- Lokale Entwicklung: SQLite und verschlüsselte Dateien unter `data/`
- Zielbetrieb: PostgreSQL plus S3-kompatibler Objektspeicher
- Browseränderungen werden per API mandantenbezogen gespeichert
- Live-Ereignisse informieren andere Sitzungen über Revisionen
- Review- und Auditentscheidungen werden mit Benutzer- und Zeitbezug protokolliert

### Qualität und Deployment

- `scripts/test.sh`: vollständige lokale Qualitätssuite
- `.github/workflows/quality.yml`: CI für Tests, PostgreSQL, S3 und Release-Vertrag
- `Dockerfile` und `docker-compose.yml`: containerisierter Betrieb
- `scripts/production_preflight.py`: technische Go-live-Prüfung
- `scripts/backup_now.sh`, `restore_drill.sh` und verwandte Skripte: Backup-/Restore-Ablauf

## Wichtige Ordner

```text
frontend-current/       Frontend und Benutzersichten
frontend-current/docs/  Produkt-, Betriebs- und Präsentationsunterlagen
tests/                  Python-, JavaScript- und Browser-Tests
scripts/                Betrieb, Migration, Release und Qualitätsprüfungen
deployment/             Zielbetriebs- und Infrastrukturvorlagen
data/                   Lokale vertrauliche Laufzeitdaten, nicht in Git
release/                Generierte Release-Pakete, nicht in Git
```

## Vertrauliche und ausgeschlossene Dateien

Folgende lokale Inhalte dürfen nicht in Git gelangen:

- `.env` und alle echten Environment-Dateien
- `data/staging.env`
- `data/dev_admin_password.txt`
- `data/file_key.bin`
- SQLite-Datenbanken, Uploads, Backups, Logs und PID-Dateien
- Release-Artefakte und Abhängigkeiten
- erzeugte DOCX-, PDF- und Bildausgaben der versionierten Berichtsgeneratoren
- private Schlüssel, Zertifikatscontainer und lokale Editor-Dateien

`.env.example` enthält ausschließlich Platzhalter und dokumentierte Standardwerte. Normtexte, interne Handbücher und Kundendokumente sind nicht Bestandteil des Repositorys.

## Bekannte Probleme und Grenzen

- Der aktuelle lokale Datenbestand ist Demo-/Entwicklungszustand und wird bewusst nicht übergeben.
- Ein sauberer Klon startet daher ohne Kunden-, Nachweis- oder Registerdaten.
- Vor Produktivbetrieb müssen PostgreSQL, Objektspeicher, ClamAV, HTTPS, sichere Cookies, MFA und Backups in der Zielumgebung verifiziert werden.
- OIDC-SSO und externe Benachrichtigungszustellung sind optional und benötigen kundenspezifische Konfiguration.
- `backend_app.py` und `frontend-current/app.js` sind weiterhin sehr groß; weitere Modularisierung ist für langfristige Wartbarkeit sinnvoll.
- Die vorhandenen Browsertests prüfen Kernabläufe, ersetzen aber keine vollständige manuelle UX-, Accessibility- und Geräteabnahme.
- Rechtliche, Datenschutz-, Hosting- und fachliche Normfreigaben sind nicht durch technische Tests abgedeckt.
- Die lokal verwendeten fachlichen Quelldokumente sind nicht im Repository enthalten und müssen separat verwaltet werden.

## Offene Aufgaben

1. Privates GitHub-Repository anlegen, Remote bewusst konfigurieren und den vorbereiteten Commit prüfen.
2. Ziel-Staging mit PostgreSQL, S3-kompatiblem Speicher, ClamAV und HTTPS aufbauen.
3. Produktions-Preflight, Restore-Drill und mandantenübergreifende Isolationstests in Staging durchführen.
4. Rollenbasierte End-to-End-Abnahme für Kunde, Berater, Admin und Auditor dokumentieren.
5. Accessibility, responsive Darstellung und visuelle Regression auf den wichtigsten Ansichten automatisieren.
6. Große Frontend- und Backend-Dateien schrittweise nach klaren Domänenmodulen aufteilen.
7. Datenschutz-, AVV-, Hosting-, Lösch- und Rechtsfreigaben außerhalb des Codes abschließen.

## Empfohlene nächste Entwicklungsaufgabe

Als nächster zusammenhängender Schritt sollte eine reproduzierbare Staging-Abnahme aufgebaut werden: PostgreSQL, S3, ClamAV und HTTPS starten, anschließend einen vollständigen Mandantenablauf von Einladung über Datenerfassung und Nachweis-Upload bis Beraterprüfung, Auditpaket-Gate, Backup und Restore automatisiert testen. Das reduziert das größte verbleibende Risiko zwischen lokalem Prototyp und belastbarem Kundenbetrieb.

## Übergabeschritte für GitHub

Nach Prüfung des vorbereiteten Staging-Bereichs:

```bash
git diff --cached --stat
git diff --cached -- . ':!package-lock.json'
git commit -m "Prepare SFM Compliance project handoff"
git remote add origin <private-repository-url>
git push -u origin main
```

Push und Remote-Konfiguration sind bewusst nicht Bestandteil dieser Vorbereitung und benötigen eine separate Freigabe.
