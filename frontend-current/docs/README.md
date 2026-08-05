# ISMS Catalyst - Produktionsunterlagen

Diese Unterlagen ergaenzen den Prototyp um Produktivbetrieb, Abnahme und Betrieb. Sie sind bewusst praktisch gehalten.

Wichtig: ISO-27001- und NIS-2-Fachaussagen duerfen nur aus den lokal vorliegenden Dokumenten abgeleitet werden. Diese Produktionsunterlagen beschreiben technische Plattformreife, Betriebsorganisation und Abnahmevorgehen. Konkrete Rechtstexte, Datenschutzhinweise oder Vertragsklauseln sind in den vorliegenden Dokumenten nicht enthalten und muessen fachlich/juristisch freigegeben werden.

## Unterlagen

- `PRODUKTIONS-ROADMAP.md`: Reihenfolge bis zum Kundenbetrieb
- `UX-ABNAHMEPLAN.md`: Tests aus Kundensicht
- `RECHT-DATENSCHUTZ-VORLAGEN.md`: Platzhalter und Pruefliste fuer Recht/Datenschutz
- `SECURITY-HARDENING-CHECKLISTE.md`: technische Haertung vor Go-live
- `BETRIEBSHANDBUCH.md`: Betrieb, Backup, Rollen, Incident- und Wartungsroutinen

## Minimaler Go-live-Status

- Backend-Modus statt `file://`
- HTTPS ueber Reverse Proxy
- Individuelles Admin-Passwort
- Dateiablage-Schluessel gesetzt
- Rollen und MFA vorbereitet
- Backup- und Restore-Test bestanden
- Datenschutz-/Rechtsfreigabe dokumentiert
- UX-Abnahme mit mindestens einem realistischen Kundenfall bestanden
