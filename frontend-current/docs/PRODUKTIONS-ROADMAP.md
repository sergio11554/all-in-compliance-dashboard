# ISMS Catalyst - Produktions-Roadmap

Ziel: Aus dem lokalen Prototyp wird eine kundenfaehige Plattform mit klarer Betriebs-, Sicherheits- und Abnahmelogik.

## Phase 1 - Produktivmodus stabilisieren

MUSS:
- App immer ueber den Backend-Server betreiben, nicht ueber `file://`.
- `ISMS_ADMIN_PASSWORD` und `ISMS_FILE_KEY` individuell setzen.
- `ISMS_PUBLIC_URL`, `ISMS_COOKIE_SECURE`, `ISMS_HSTS` und Upload-/Session-Limits konfigurieren.
- HTTPS per Reverse Proxy aktivieren.
- Security Center im Backend-Modus laden und kritische Warnungen bearbeiten.

SOLLTE:
- Eigenes Admin-Konto anlegen und Default-Zugang deaktivieren oder Passwort sofort ersetzen.
- MFA fuer Admin- und Manager-Konten aktivieren.
- Backups erzeugen und Restore praktisch testen.

PRAXISNAHE UMSETZUNGSHILFE:
- Zuerst einen internen Musterkunden anlegen.
- Ein echtes Kundenprojekt einmal vollstaendig durchspielen: Setup, Scope, Risiko, SoA, Evidence, Review, Export.
- Erst danach echte Kundendaten aufnehmen.

## Phase 2 - Kundenonboarding

MUSS:
- Kunde, Scope-Ziel, ISMS Owner, Management Sponsor und Rollen festlegen.
- Rollenrechte pruefen: Admin, Manager, Auditor, Viewer.
- Uploads nur ueber den Backend-Modus erlauben.
- Datenexport und Backup-Verantwortung klaeren.

SOLLTE:
- Kundenstart-Report aus dem Dashboard erstellen.
- Projektplan ISO 27001 und NIS-2 im Setup mit Verantwortlichen und Terminen fuellen.
- Evidence Request Center fuer Kunden-Uploads verwenden.

PRAXISNAHE UMSETZUNGSHILFE:
- Pro Kunde ein klarer Starttermin, ein woechentlicher Review-Slot und ein Verantwortlicher.
- Nicht alle Templates sofort verlangen. Erst Scope, Risk, SoA, wichtigste Policies und kritische Nachweise.

## Phase 3 - UX- und Fachabnahme

MUSS:
- Alle Kernmodule einmal mit realistischen Daten testen.
- Export/Import testen.
- Datei-Upload, Download, Audit-Log und Backup testen.
- Browser auf Desktop und kleiner Breite pruefen.

SOLLTE:
- Mindestens ein externer Testnutzer mit Viewer- oder Auditor-Rolle prueft Navigation und Verstaendlichkeit.
- Texte pruefen: keine Aussage darf ISO und NIS-2 vermischen, ohne Quelle zu trennen.

PRAXISNAHE UMSETZUNGSHILFE:
- Abnahme als 60-Minuten-Szenario: Kunde startet, laedt Dokumente hoch, legt Risiko an, erzeugt Report.

## Phase 4 - Recht, Datenschutz und Vertragsrahmen

MUSS:
- Datenschutzhinweise, Auftragsverarbeitung, Verantwortlichkeiten, Loeschkonzept und Supportprozess fachlich freigeben.
- Impressum/Anbieterkennzeichnung und Vertragsunterlagen extern oder intern rechtlich pruefen lassen.

SOLLTE:
- Datenarten und Speicherorte dokumentieren.
- Aufbewahrung und Loeschfristen je Kundendatentyp festlegen.

Grenze:
- Konkrete Rechtstexte sind in den vorliegenden Dokumenten nicht enthalten.

## Phase 5 - Betrieb und Monitoring

MUSS:
- Betriebshandbuch anwenden.
- Backup-Routine und Restore-Routine dokumentieren.
- Admin-Aktivitaeten auditierbar halten.
- Security-Hardening-Checkliste vor jedem Go-live abzeichnen.

SOLLTE:
- Monatlicher Betriebsreview: Benutzer, MFA, Backups, offene Security-Warnungen, Speicherplatz, Logs.
- Quartalsweise Restore-Probe.

## Go-live-Entscheidung

Go-live erst freigeben, wenn:
- Backend-Modus aktiv ist.
- HTTPS und sichere Cookies aktiv sind.
- Admin-Passwort und Datei-Schluessel gesetzt sind.
- Rollen/MFA getestet sind.
- Backup und Restore getestet sind.
- UX-Abnahme ohne kritische Fehler bestanden ist.
- Rechts-/Datenschutzfreigabe dokumentiert ist.
