# SFM Compliance - Go-live Checkliste

## Technische Mindestpunkte

- [ ] Deployment laeuft ueber Backend-Server, nicht ueber `file://`.
- [ ] `ISMS_PUBLIC_URL` ist korrekt gesetzt.
- [ ] HTTPS ist aktiv.
- [ ] `ISMS_COOKIE_SECURE=1` ist aktiv.
- [ ] `ISMS_HSTS=1` ist aktiv.
- [ ] `ISMS_ADMIN_PASSWORD` ist individuell und stark.
- [ ] `ISMS_FILE_KEY` ist individuell und getrennt gesichert.
- [ ] Datenpfad ist nicht im Webroot.
- [ ] Produktive Dateiablage ist bewusst als `local` oder `s3` konfiguriert.
- [ ] Bei S3: Bucket-Zugriff, Versionierung, Retention und Recovery wurden getestet.
- [ ] Upload-Limit ist passend gesetzt.
- [ ] `ISMS_MALWARE_SCAN_MODE=clamav` und `ISMS_MALWARE_SCAN_REQUIRED=1` sind im Kundenbetrieb aktiv.
- [ ] Scanner-Erreichbarkeit wird im Security-Bereich ohne Warnung angezeigt.
- [ ] Healthcheck `/api/health` ist erfolgreich.

## Rollen und Mandanten

- [ ] `ISMS_MFA_ENFORCEMENT=write` ist aktiv.
- [ ] `ISMS_MFA_REQUIRED_ROLES` enthält mindestens `admin`, `consultant` und `manager`.
- [ ] Privilegiertes Konto ohne MFA kann lesen, aber nicht speichern, freigeben oder administrieren.
- [ ] MFA-Setup und -Aktivierung bleiben trotz Schreibsperre erreichbar.
- [ ] Privilegierter Schreibzugriff funktioniert nach MFA-Aktivierung.
- [ ] Neu angelegtes lokales Konto kann sich mit dem Initialpasswort anmelden, aber vor dem Passwortwechsel keine Kundendaten veraendern.
- [ ] Selbst gesetztes Passwort hebt die Erstwechsel-Sperre auf und beendet alle anderen Sitzungen.
- [ ] Aktuelles und vorherige Passwoerter werden entsprechend `ISMS_PASSWORD_HISTORY_COUNT` abgelehnt.
- [ ] Platform Admin getestet.
- [ ] Kundenadmin getestet.
- [ ] Consultant getestet.
- [ ] Manager getestet.
- [ ] Auditor/Viewer read-only getestet.
- [ ] Mandantentrennung mit zwei Testmandanten geprueft.
- [ ] Beratergenerator ist fuer Kundenrollen nicht sichtbar.
- [ ] Produktivbetrieb-Adminbereich ist fuer Kundenrollen nicht sichtbar.
- [ ] Persönliche Benachrichtigungszustände sind mit zwei Benutzern desselben Kundenraums getrennt getestet.
- [ ] Falls SSO aktiv ist: Redirect-URI, Signaturprüfung, erlaubte Domains und Zuordnung zum richtigen Kundenraum wurden getestet.
- [ ] SSO-Selbstregistrierung ohne Einladung oder vorhandene Benutzerzuordnung ist nicht möglich.
- [ ] Einladungsversand ist bewusst als manueller Link oder mit `ISMS_INVITATION_EMAIL_ENABLED=1` und getestetem SMTP konfiguriert.
- [ ] Ein erneut versendeter Einladungslink macht den vorherigen Link ungültig.
- [ ] Abgelaufene, widerrufene und bereits angenommene Einladungen können nicht erneut verwendet werden.
- [ ] Einladungsannahme erstellt den Benutzer im richtigen Kundenraum und erlaubt keine kundenseitige fachliche Freigabe.
- [ ] Audit Trail enthält Erstellung, Zustellung bzw. manuelle Übergabe, Neuausstellung, Widerruf und Annahme der Einladung.

## Daten und Nachweise

- [ ] Workspace-Speicherung im Backend funktioniert.
- [ ] Ungültiger Workspace-Import/State-Save wird abgelehnt und zeigt eine verständliche Validierungsmeldung.
- [ ] Datei-Upload funktioniert.
- [ ] Datei-Download funktioniert.
- [ ] Datei-Hash wird angezeigt.
- [ ] Saubere Testdatei wird gescannt, gespeichert und normal aufgelistet.
- [ ] EICAR-Testdatei wird blockiert und nur in der Datei-Quarantaene angezeigt.
- [ ] Quarantaenedatei kann nicht heruntergeladen oder in einen Mandantenexport aufgenommen werden.
- [ ] Ein sauberer Rescan gibt eine Datei frei; ein Fund oder Scanfehler umgeht die Quarantaene nicht.
- [ ] Endgueltiges Loeschen aus der Quarantaene wurde mit Audit-Trail-Eintrag getestet.
- [ ] Asset kann mit Nachweis verknuepft werden.
- [ ] Audit-Log protokolliert Login, Upload, State-Save und Backup.
- [ ] Lesen, Ausblenden, Wiederherstellen und Eskalieren von Benachrichtigungen werden im Audit Trail protokolliert.
- [ ] Eine Benachrichtigungseskalation erzeugt nur eine Aufgabe und keine automatische fachliche Freigabe.
- [ ] Externe Benachrichtigungszustellung ist entweder bewusst deaktiviert oder mit festem serverseitigem Ziel konfiguriert.
- [ ] Kundenrollen können keine externe Zustellung einplanen.
- [ ] Webhook-Signatur wurde am Empfänger geprüft; Secrets und vollständige Ziel-URL erscheinen nicht in UI, API oder Audit Trail.
- [ ] Zustellqueue, Wiederholungslogik, Fehlerstatus und manuelles Retry wurden getestet.
- [ ] Externe Zustellung verändert weder Review-Status noch fachliche Freigabe.

## Betrieb

- [ ] Backup wurde erstellt.
- [ ] Backup wurde heruntergeladen und geschuetzt abgelegt.
- [ ] Workspace-Snapshot wurde wiederhergestellt.
- [ ] Snapshot-Liste zeigt Prüfsumme, Restorable-Status und Workspace-Validierung ohne offene Strukturwarnung.
- [ ] `./scripts/restore_drill.sh` wurde gegen die isolierte Staging-Umgebung erfolgreich ausgefuehrt.
- [ ] Der Drill bestaetigt Workspace-State, Datei-Metadaten, Downloads und Audit-Hash-Kette.
- [ ] `restore_drill_verified` ist im technischen Audit Trail protokolliert; dies ist keine fachliche Auditfreigabe.
- [ ] Retention-Lauf wurde getestet.
- [ ] Automatischer Betriebsmonitor ist aktiviert und das Prüfintervall ist passend gesetzt.
- [ ] Alarmübergänge `neu`, `wieder aufgetreten` und `automatisch behoben` wurden im Audit Trail geprüft.
- [ ] Sichere Wartungsaktionen wurden getestet; es werden keine aktiven Sessions oder Einladungsdatensätze automatisch gelöscht.
- [ ] Zustellqueue-Kontrollpunkt im Betriebsmonitor zeigt den erwarteten Status: deaktiviert oder korrekt konfiguriert ohne offene Fehler.
- [ ] Zustellhistorie ist im Mandantenexport enthalten und wird bei kontrollierter Mandantenbereinigung entfernt.
- [ ] ClamAV-Signaturen werden regelmaessig aktualisiert und Scanner-Ausfaelle sind im Betriebsmonitor sichtbar.
- [ ] Betriebsverantwortliche sind benannt.

## Recht und Datenschutz

- [ ] Datenschutztexte extern/fachlich freigegeben.
- [ ] AVV/Hosting-Vertrag ist geklaert.
- [ ] Supportzugriff ist geregelt.
- [ ] Loesch- und Exportprozesse sind beschrieben.
- [ ] Rechtliche Aussagen wurden nicht aus dieser technischen Checkliste abgeleitet.
