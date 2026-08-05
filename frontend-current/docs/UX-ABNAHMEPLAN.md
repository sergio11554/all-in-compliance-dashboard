# ISMS Catalyst - UX-Abnahmeplan

Ziel: Die Plattform soll fuer Kunden ohne Erklaervideo nutzbar sein. Der Test bewertet Navigation, Lesbarkeit, Datenfluss und Exportfaehigkeit.

## Testrollen

- Admin: richtet Kunde, Rollen, MFA, Backups und Retention ein.
- Manager: pflegt Scope, Risiken, SoA, Evidence und Tasks.
- Auditor: liest Nachweise, Reports und Audit Mode.
- Viewer: prueft Lesbarkeit ohne Schreibrechte.

## Kern-Szenario

MUSS:
1. Kunde oeffnet die Plattform im Backend-Modus.
2. Kunde fuellt Setup Wizard aus.
3. Kunde erstellt Scope-Entwurf aus Template.
4. Kunde erfasst ein Asset und ein Risiko.
5. Kunde verknuepft einen Nachweis im Evidence Center.
6. Kunde prueft SoA und Gap Assessment.
7. Kunde erzeugt Management Snapshot oder Audit Pack.
8. Admin prueft Audit-Log und erstellt Backup.

SOLLTE:
- Alle wichtigen Buttons sind ohne Suchen sichtbar.
- Tabellen bleiben auf kleiner Breite bedienbar.
- Lange Texte in Formularen brechen sauber um.
- Fehlende Pflichtinformationen werden ueber Checklisten sichtbar.

## Akzeptanzkriterien

Bestanden:
- Keine JavaScript-Fehler in der Konsole.
- Alle Hauptviews rendern.
- Navigation springt nicht ungewollt.
- Formulare speichern und aktualisieren Vorschau/Tabellen.
- Exporte enthalten die erwarteten lokalen Plattformdaten.
- Backend-Funktionen zeigen bei fehlender Anmeldung klare Meldungen.

Nicht bestanden:
- Weisse Seite oder leere View.
- Upload ohne nachvollziehbare Rueckmeldung.
- Unklare Vermischung von ISO- und NIS-2-Aussagen.
- Buttons ohne Funktion im Kernprozess.
- Ueberlappender Text oder abgeschnittene Eingabefelder.

## Testmatrix

| Bereich | Test | Erwartung |
| --- | --- | --- |
| Dashboard | Startansicht oeffnen | Cockpit, Snapshot und Aktionen sichtbar |
| Setup | Kundendaten erfassen | Starter-Pack wird erzeugt |
| Projektplan | Aufgabe anlegen | Aufgabe erscheint in Aufgabenliste |
| Templates | Vorlage ausfuellen | Live-Vorschau und Entwurf funktionieren |
| Risks | Risiko anlegen | Score und Behandlung sichtbar |
| Evidence | Nachweis erfassen | Mapping wird angezeigt |
| Reports | Markdown exportieren | Datei wird erzeugt |
| Security | Status laden | Backend-Sicherheitsstatus sichtbar |
| Produktion | Checkliste oeffnen | Go-live-Luecken sind klar erkennbar |

## Dokumentation der Abnahme

- Datum:
- Tester:
- Rolle:
- Browser:
- Ergebnis:
- Kritische Fehler:
- Offene Verbesserungen:
- Freigabe durch:
