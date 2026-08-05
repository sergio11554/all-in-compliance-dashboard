# ISMS Catalyst - Security-Hardening-Checkliste

Ziel: Vor Kundennutzung muss die Plattform technisch gehaertet, nachvollziehbar betrieben und wiederherstellbar sein.

## Zugriff und Authentifizierung

MUSS:
- Individuelles langes Admin-Passwort setzen.
- Default-Zugang ersetzen oder Passwort rotieren.
- MFA fuer Admins aktivieren.
- Rollenrechte nach dem Need-to-know-Prinzip vergeben.
- Session-Cookies sicher konfigurieren.

SOLLTE:
- Separate Konten pro Person, keine geteilten Benutzer.
- Regelmaessige Benutzerreview.

## Transport und Browser-Schutz

MUSS:
- HTTPS aktivieren.
- `ISMS_COOKIE_SECURE=1` setzen.
- `ISMS_HSTS=1` oder HTTPS-`ISMS_PUBLIC_URL` setzen.
- Reverse Proxy mit Security Headers verwenden.

SOLLTE:
- Nur notwendige Ports freigeben.
- Zugriff auf Backend nur ueber Reverse Proxy.

## Daten und Uploads

MUSS:
- `ISMS_FILE_KEY` setzen und geheim halten.
- Upload-Dateitypen beschraenken.
- Upload- und JSON-Groessenlimits setzen.
- Backup-Dateien geschuetzt ablegen.

SOLLTE:
- Kundendaten nicht im App-Code-Verzeichnis speichern.
- `ISMS_DATA_DIR` auf einen geschuetzten Datenpfad legen.

## Betrieb

MUSS:
- Backups erstellen und Restore testen.
- Audit-Log pruefbar halten.
- Retention-Regel ausfuehren und dokumentieren.
- Systemdienst mit eingeschraenktem Benutzer betreiben.

SOLLTE:
- Monatlicher Security Review.
- Quartalsweise Restore-Probe.

## Abnahme vor Go-live

MUSS:
- Backend-Status ohne kritische Warnungen.
- Admin-MFA aktiv.
- Backup und Restore nachgewiesen.
- UX-Abnahme bestanden.
- Datenschutz-/Rechtsfreigabe dokumentiert.

Grenze:
- Diese Checkliste ist technische Produktivhaertung der Plattform. ISO- und NIS-2-Fachanforderungen bleiben separat in den lokalen Dokumenten und App-Modulen nachzuweisen.
