# SFM Compliance

SFM Compliance ist eine mandantenfähige Arbeitsplattform zur Vorbereitung und Steuerung von ISMS-, ISO-27001- und NIS-2-Projekten. Kunden erfassen Informationen, Aufgaben und Nachweise strukturiert; Berater und Administratoren übernehmen die fachliche Prüfung, Rückgabe und Freigabe.

Die Plattform ersetzt keine fachliche, rechtliche oder Audit-Bewertung. Automatische Prüfungen zeigen formale Vollständigkeit und Prüfbereitschaft, aber keine ISO-Konformität, NIS-2-Erfüllung oder Auditbereitschaft.

## Wichtigste Funktionen

- Kuratiertes Dashboard und Management-Cockpit mit Risiken, Fristen, Entscheidungen und Compliance-Spuren
- Geführter Kundenmodus und chronologischer Projektstrukturplan
- Review Center für Einreichungen, Nacharbeit, Freigaben und Audit-Blocker
- Auditpaket-Gate mit klarer Trennung zwischen formaler Vorbereitung und Beraterfreigabe
- Dokumentation, verschlüsselte Nachweisablage, Versionierung und Audit Trail
- Register für Assets, Risiken, Lieferanten, Policies, Rechtsanforderungen, Incidents und Verträge
- ISO-27001-Arbeitsbereich, SoA-Matrix, Auditmatrix und NIS-2-Navigator
- Aufgaben, Benachrichtigungen, Team-Einladungen und rollenbasierte Arbeitsbereiche
- Mandantentrennung, Sessions, MFA, Passwortregeln, Account Recovery und optionales OIDC-SSO
- Lokale oder S3-kompatible Dateiablage, optionaler ClamAV-Scan und Quarantäne
- Backups, Restore-Drills, Retention, Hintergrundjobs, Betriebsmonitoring und Live-Aktualisierung per Server-Sent Events

## Technik

- Frontend: HTML, CSS und modulares Vanilla JavaScript
- Backend: Python-HTTP-Anwendung
- Datenbank: SQLite für lokale Entwicklung, PostgreSQL für den Zielbetrieb
- Dateiablage: verschlüsselte lokale Ablage oder S3-kompatibler Objektspeicher
- Qualität: Python-Unittests, JavaScript-Modultests und Playwright-End-to-End-Tests
- Deployment: Dockerfile, Docker Compose, Nginx- und systemd-Vorlagen

## Voraussetzungen

- Python 3.12 oder neuer
- Node.js 22 oder neuer
- Docker mit Compose-Plugin für den containerisierten Zielbetrieb
- Optional: PostgreSQL, S3-kompatibler Speicher und ClamAV

## Installation für lokale Entwicklung

```bash
git clone <repository-url>
cd isms-catalyst-backend

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
npm ci

cp .env.example .env
```

Vor dem Start müssen in `.env` mindestens eigene Werte für `ISMS_ADMIN_PASSWORD` und `ISMS_FILE_KEY` gesetzt werden. Für lokales HTTP außerdem `ISMS_PUBLIC_URL=http://127.0.0.1:5173`, `ISMS_COOKIE_SECURE=0` und `ISMS_HSTS=0` verwenden. Echte Zugangsdaten gehören nie in Git.

## Start

```bash
./run_backend.sh
```

Danach öffnen:

```text
http://127.0.0.1:5173/
```

Healthcheck:

```bash
curl -fsS http://127.0.0.1:5173/api/health
```

## Tests

Vollständige lokale Qualitätssuite:

```bash
npm test
```

Die Suite umfasst Backend-Integrationstests, JavaScript-Modultests, Browser-End-to-End-Tests, JavaScript-Syntaxprüfung, CSS-Strukturprüfung und Python-Kompilierung.

Es gibt keinen separaten Frontend-Build: Das Frontend wird als statische Anwendung ausgeliefert. Die Deployment-Konfiguration lässt sich so prüfen:

```bash
docker compose --env-file .env.example config --quiet
docker build -t sfm-compliance:local .
```

## Produktionsvorbereitung

```bash
./scripts/prepare_release.sh
python3 scripts/production_preflight.py --env-file .env
docker compose --profile malware up -d --build
```

Weitere Betriebsunterlagen:

- `OPERATIONS.md`
- `deployment/README-PRODUCTION.md`
- `deployment/GO-LIVE-CHECKLIST.md`
- `deployment/BACKUP-RESTORE-RUNBOOK.md`

## Projektstruktur

```text
frontend-current/     Browser-Anwendung und fachliche Frontend-Module
tests/                Python-, JavaScript- und Browser-Tests
scripts/              Tests, Release, Migration, Backup und Restore
deployment/           Produktions- und Reverse-Proxy-Vorlagen
backend_app.py         HTTP-API, Authentifizierung und Anwendungsdienste
database.py            SQLite-/PostgreSQL-Abstraktion und Schema
storage.py             Verschlüsselte lokale bzw. S3-Dateiablage
oidc_auth.py           Optionales Enterprise-SSO
malware_scan.py        ClamAV-Anbindung und Scan-Ergebnisse
```

Lokale Laufzeitdaten liegen unter `data/` und werden nicht versioniert. Release-Pakete unter `release/`, Abhängigkeiten unter `node_modules/` sowie erzeugte DOCX-, PDF- und Bildausgaben der Berichtsgeneratoren sind ebenfalls ausgeschlossen. Die Python-Generatoren und Markdown-Quellen unter `frontend-current/docs/` bleiben versioniert.

## Fachliche Quellen

Normtexte, interne Handbücher und Kundendokumente werden aus Lizenz-, Datenschutz- und Vertraulichkeitsgründen nicht in diesem Repository abgelegt. Sie müssen im jeweiligen Kunden- oder Beraterkontext separat und zugriffsgeschützt bereitgestellt werden.

## Übergabe

Der aktuelle Entwicklungsstand, Architekturhinweise, bekannte Grenzen und die empfohlene nächste Aufgabe stehen in `HANDOFF.md`.
