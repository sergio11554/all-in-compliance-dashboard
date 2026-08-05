# ISMS Catalyst - Betriebshandbuch

## Betriebsmodell

MUSS:
- Produktivbetrieb ueber Backend-Server.
- HTTPS ueber Reverse Proxy.
- Datenverzeichnis ausserhalb des Frontend-Ordners.
- Regelmaessige Backups und Restore-Tests.
- Rollen- und MFA-Verwaltung dokumentiert.

## Regelbetrieb

Taeglich:
- Erreichbarkeit pruefen.
- Kritische Fehlermeldungen pruefen.

Woechentlich:
- Offene Security-Center-Warnungen pruefen.
- Neue Benutzer und Rollen pruefen.
- Letztes Backup pruefen.

Monatlich:
- Benutzerreview.
- Backup-Download und Restore-Probe stichprobenartig.
- Speicherplatz pruefen.
- Retention-Lauf dokumentieren.

Quartalsweise:
- Vollstaendiger Restore-Test.
- Security-Hardening-Checkliste erneut durchgehen.
- Datenschutz-/Rechtsvorlagen auf Aktualitaet pruefen lassen.

## Incident-Betrieb

MUSS:
- Zeitpunkt, Melder, Auswirkung, betroffene Kunden und Sofortmassnahmen dokumentieren.
- Admin-Audit-Log sichern.
- Relevante Backups vor Veraenderungen sichern.
- Kundenkommunikation ueber definierte Verantwortliche laufen lassen.

SOLLTE:
- Nach Abschluss Lessons Learned und Korrekturmassnahmen im Review Center erfassen.

## Backup und Restore

MUSS:
- Backup im Security Center erzeugen.
- Backup verschluesselt/geschuetzt ablegen.
- Restore-Test dokumentieren.
- Zugriff auf Backups auf Admins beschraenken.

## Rollen

- Admin: Plattform, Benutzer, Backups, Retention.
- Manager: fachliche Bearbeitung.
- Auditor: lesender Audit-Zugriff.
- Viewer: lesender Zugriff.

## Betriebsfreigabe

- Verantwortlicher Betrieb:
- Verantwortlicher Datenschutz:
- Verantwortlicher Security:
- Backup-Ort:
- Restore-Test am:
- Naechster Review:
