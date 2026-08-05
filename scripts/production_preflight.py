#!/usr/bin/env python3
"""Technical go-live preflight for SFM Compliance.

The check intentionally evaluates only deployment configuration and runtime
services. It does not assess ISO 27001, NIS-2, legal, or audit readiness.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse


PLACEHOLDER_MARKERS = (
    "change-me",
    "replace-with",
    "example.com",
    "example-secret",
    "do-not-use",
)


@dataclass(frozen=True)
class Check:
    code: str
    level: str
    title: str
    detail: str
    remediation: str = ""


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def merged_config(env_file: Path, environ: dict[str, str] | None = None) -> dict[str, str]:
    values = parse_env_file(env_file)
    for key, value in (environ or dict(os.environ)).items():
        if key.startswith("ISMS_") or key.startswith("SFM_") or key in {
            "DATABASE_URL",
            "POSTGRES_PASSWORD",
        }:
            values[key] = value
    return values


def is_true(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def config_int(config: dict[str, str], key: str, default: int) -> int:
    try:
        return int(str(config.get(key, default)).strip())
    except (TypeError, ValueError):
        return -1


def secret_problem(value: str | None, minimum: int = 20) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return "fehlt"
    if any(marker in candidate.lower() for marker in PLACEHOLDER_MARKERS):
        return "enthält einen Beispiel- oder Platzhalterwert"
    if len(candidate) < minimum:
        return f"ist kürzer als {minimum} Zeichen"
    return ""


def evaluate_config(config: dict[str, str], env_file: Path) -> list[Check]:
    checks: list[Check] = []

    def add(code: str, ok: bool, title: str, detail: str, remediation: str = "", warning: bool = False):
        checks.append(Check(code, "pass" if ok else ("warning" if warning else "blocker"), title, detail, remediation))

    add(
        "env.exists",
        env_file.is_file(),
        "Deployment-Konfiguration vorhanden",
        f"Konfigurationsdatei: {env_file}",
        "Aus .env.example eine geschützte .env erstellen.",
    )
    if env_file.is_file() and os.name == "posix":
        mode = stat.S_IMODE(env_file.stat().st_mode)
        add(
            "env.permissions",
            mode & 0o077 == 0,
            "Konfigurationsdatei restriktiv geschützt",
            f"Dateirechte: {mode:04o}",
            "chmod 600 .env ausführen.",
        )

    public_url = config.get("ISMS_PUBLIC_URL", "")
    parsed_url = urlparse(public_url)
    add(
        "https.public_url",
        parsed_url.scheme == "https" and bool(parsed_url.netloc),
        "Öffentliche URL verwendet HTTPS",
        "Eine gültige HTTPS-URL ist gesetzt." if parsed_url.scheme == "https" and parsed_url.netloc else "Keine gültige HTTPS-URL gesetzt.",
        "ISMS_PUBLIC_URL auf die produktive https://-Adresse setzen.",
    )
    cookie_secure = is_true(config.get("ISMS_COOKIE_SECURE"))
    add("https.cookie", cookie_secure, "Secure-Cookie aktiv", "Session-Cookies werden nur über HTTPS übertragen." if cookie_secure else "Secure-Attribut ist deaktiviert.", "ISMS_COOKIE_SECURE=1 setzen.")
    hsts = is_true(config.get("ISMS_HSTS"))
    add("https.hsts", hsts, "HSTS aktiv", "HTTPS wird browserseitig erzwungen." if hsts else "HSTS ist deaktiviert.", "ISMS_HSTS=1 setzen.")
    add(
        "oidc.insecure",
        not is_true(config.get("ISMS_OIDC_ALLOW_INSECURE")),
        "Unsichere OIDC-Verbindungen deaktiviert",
        "OIDC verlangt sichere Provider-Verbindungen.",
        "ISMS_OIDC_ALLOW_INSECURE=0 setzen.",
    )

    for key, label in (
        ("ISMS_ADMIN_PASSWORD", "Initiales Admin-Passwort"),
        ("ISMS_FILE_KEY", "Dateiverschlüsselungs-Secret"),
        ("POSTGRES_PASSWORD", "PostgreSQL-Passwort"),
    ):
        problem = secret_problem(config.get(key))
        add(
            f"secret.{key.lower()}",
            not problem,
            f"{label} produktiv gesetzt",
            "Secret ist gesetzt und kein erkennbarer Platzhalter." if not problem else f"Secret {problem}.",
            f"{key} durch ein langes, zufälliges Secret aus dem Secret-Manager ersetzen.",
        )

    database_url = config.get("DATABASE_URL", "")
    database_ok = database_url.startswith(("postgresql://", "postgres://")) and not secret_problem(database_url, 1)
    add(
        "database.postgres",
        database_ok,
        "PostgreSQL als Kundendatenbank konfiguriert",
        "DATABASE_URL verweist auf PostgreSQL." if database_ok else "PostgreSQL-Verbindung fehlt oder enthält einen Platzhalter.",
        "Eine produktive PostgreSQL-DATABASE_URL setzen.",
    )

    storage_backend = config.get("ISMS_STORAGE_BACKEND", "local").strip().lower()
    add(
        "storage.backend",
        storage_backend == "s3",
        "Gemeinsame Objektablage konfiguriert",
        f"Ablage-Backend: {storage_backend or 'nicht gesetzt'}.",
        "Für skalierbaren Kundenbetrieb ISMS_STORAGE_BACKEND=s3 verwenden.",
        warning=True,
    )
    if storage_backend == "s3":
        bucket = config.get("ISMS_S3_BUCKET", "").strip()
        add("storage.bucket", bool(bucket), "S3-Bucket gesetzt", "Bucket-Name ist konfiguriert." if bucket else "Bucket-Name fehlt.", "ISMS_S3_BUCKET setzen.")
        for key, label in (("ISMS_S3_ACCESS_KEY", "S3 Access Key"), ("ISMS_S3_SECRET_KEY", "S3 Secret Key")):
            value = config.get(key, "").strip()
            placeholder = bool(value) and bool(secret_problem(value, 1))
            add(
                f"storage.{key.lower()}",
                not placeholder,
                f"{label} enthält keinen Platzhalter",
                "Explizites Secret ist plausibel gesetzt." if value and not placeholder else ("Serverseitige IAM-Rolle wird vorausgesetzt." if not value else "Platzhalterwert erkannt."),
                f"{key} sicher setzen oder eine serverseitige IAM-Rolle verwenden.",
            )

    malware_mode = config.get("ISMS_MALWARE_SCAN_MODE", "disabled").strip().lower()
    add("malware.mode", malware_mode == "clamav", "Malware-Scanner aktiviert", f"Scan-Modus: {malware_mode or 'nicht gesetzt'}.", "ISMS_MALWARE_SCAN_MODE=clamav setzen.")
    malware_required = is_true(config.get("ISMS_MALWARE_SCAN_REQUIRED"))
    add("malware.required", malware_required, "Upload blockiert bei Scanner-Ausfall", "Fail-closed Upload-Prüfung ist aktiv." if malware_required else "Uploads bleiben bei Scanner-Ausfall möglich.", "ISMS_MALWARE_SCAN_REQUIRED=1 setzen.")

    add("worker.jobs", is_true(config.get("ISMS_JOB_WORKER_ENABLED", "1")), "Hintergrundjobs aktiviert", "Job-Worker verarbeitet technische Aufgaben.", "ISMS_JOB_WORKER_ENABLED=1 setzen.")
    add("monitor.operations", is_true(config.get("ISMS_OPERATIONS_MONITOR_ENABLED", "1")), "Betriebsmonitor aktiviert", "Technische Alarmprüfungen laufen regelmäßig.", "ISMS_OPERATIONS_MONITOR_ENABLED=1 setzen.")
    add(
        "sso.oidc",
        bool(config.get("ISMS_OIDC_PROVIDERS_JSON", "").strip()),
        "Enterprise-SSO konfiguriert",
        "Mindestens ein OIDC-Provider ist gesetzt." if config.get("ISMS_OIDC_PROVIDERS_JSON", "").strip() else "Kein OIDC-Provider gesetzt; lokale Anmeldung bleibt möglich.",
        "Für Unternehmenskunden einen mandantengebundenen OIDC-Provider konfigurieren.",
        warning=True,
    )
    mfa_enforcement = config.get("ISMS_MFA_ENFORCEMENT", "off").strip().lower()
    add(
        "mfa.enforcement",
        mfa_enforcement == "write",
        "MFA-Schreibschutz für privilegierte Rollen aktiv",
        f"Konfigurierter Modus: {mfa_enforcement or 'nicht gesetzt'}.",
        "ISMS_MFA_ENFORCEMENT=write setzen.",
    )
    configured_mfa_roles = {
        role.strip().lower()
        for role in config.get("ISMS_MFA_REQUIRED_ROLES", "").split(",")
        if role.strip()
    }
    expected_mfa_roles = {"admin", "consultant", "manager"}
    missing_mfa_roles = sorted(expected_mfa_roles.difference(configured_mfa_roles))
    add(
        "mfa.roles",
        not missing_mfa_roles,
        "Privilegierte Standardrollen verlangen MFA",
        "Admin, Berater und Management sind erfasst." if not missing_mfa_roles else f"Fehlende Rollen: {', '.join(missing_mfa_roles)}.",
        "ISMS_MFA_REQUIRED_ROLES=admin,consultant,manager setzen.",
    )
    password_min = config_int(config, "ISMS_PASSWORD_MIN_LENGTH", 12)
    password_max = config_int(config, "ISMS_PASSWORD_MAX_LENGTH", 256)
    password_history = config_int(config, "ISMS_PASSWORD_HISTORY_COUNT", 5)
    add(
        "password.length",
        12 <= password_min <= password_max <= 1024,
        "Zentrale Passwortlaenge ist belastbar konfiguriert",
        f"Konfiguriert: mindestens {password_min}, maximal {password_max} Zeichen.",
        "ISMS_PASSWORD_MIN_LENGTH auf mindestens 12 und ISMS_PASSWORD_MAX_LENGTH auf einen groesseren, plausiblen Wert setzen.",
    )
    add(
        "password.history",
        password_history >= 5,
        "Passwort-Historie verhindert unmittelbare Wiederverwendung",
        f"Konfigurierte Historie: {password_history} vorherige Passwoerter.",
        "ISMS_PASSWORD_HISTORY_COUNT auf mindestens 5 setzen.",
    )
    recovery_enabled = is_true(config.get("ISMS_ACCOUNT_RECOVERY_ENABLED"))
    add(
        "recovery.enabled",
        recovery_enabled,
        "Sichere Kontowiederherstellung aktiviert",
        "Einmalige, zeitlich begrenzte Recovery-Links sind aktiviert." if recovery_enabled else "Kontowiederherstellung ist deaktiviert.",
        "ISMS_ACCOUNT_RECOVERY_ENABLED=1 setzen.",
    )
    smtp_host = config.get("ISMS_NOTIFICATION_SMTP_HOST", "").strip()
    smtp_from = config.get("ISMS_NOTIFICATION_SMTP_FROM", "").strip()
    recovery_delivery_ok = bool(smtp_host and smtp_from)
    add(
        "recovery.delivery",
        recovery_delivery_ok,
        "Recovery-Mailzustellung konfiguriert",
        "SMTP-Host und Absender sind gesetzt." if recovery_delivery_ok else "SMTP-Host oder Absender für Recovery-Links fehlt.",
        "ISMS_NOTIFICATION_SMTP_HOST und ISMS_NOTIFICATION_SMTP_FROM sicher konfigurieren.",
    )
    invitation_delivery_enabled = is_true(config.get("ISMS_INVITATION_EMAIL_ENABLED"))
    if invitation_delivery_enabled:
        add(
            "invitation.delivery",
            recovery_delivery_ok,
            "Einladungs-Mailzustellung konfiguriert",
            "Direkter Einladungsversand ist aktiviert und SMTP-Host sowie Absender sind gesetzt."
            if recovery_delivery_ok else "Direkter Einladungsversand ist aktiviert, aber SMTP-Host oder Absender fehlt.",
            "ISMS_NOTIFICATION_SMTP_HOST und ISMS_NOTIFICATION_SMTP_FROM setzen oder ISMS_INVITATION_EMAIL_ENABLED=0 verwenden.",
        )
    else:
        add(
            "invitation.delivery",
            False,
            "Einladungen werden manuell übergeben",
            "Direkter E-Mail-Versand ist deaktiviert; Admins erhalten einen einmalig sichtbaren Aktivierungslink.",
            "Für direkten Versand SMTP testen und anschließend ISMS_INVITATION_EMAIL_ENABLED=1 setzen.",
            warning=True,
        )
    return checks


def evaluate_runtime(base_url: str, config: dict[str, str]) -> list[Check]:
    checks: list[Check] = []
    url = f"{base_url.rstrip('/')}/api/health"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            payload = json.load(response)
    except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError) as exc:
        return [Check("runtime.health", "blocker", "Laufzeit-Healthcheck erreichbar", f"Healthcheck fehlgeschlagen: {exc}", "Dienst, Reverse Proxy und Netzwerk prüfen.")]

    checks.append(Check("runtime.health", "pass" if payload.get("ok") else "blocker", "Laufzeit-Healthcheck erfolgreich", "Backend antwortet mit ok=true." if payload.get("ok") else "Backend meldet ok=false.", "Backend-Logs und Abhängigkeiten prüfen."))
    expectations = (
        ("database", "postgres", "PostgreSQL ist zur Laufzeit aktiv"),
        ("malwareScanning", "clamav", "ClamAV ist zur Laufzeit ausgewählt"),
    )
    for field, expected, title in expectations:
        actual = str(payload.get(field, ""))
        checks.append(Check(f"runtime.{field}", "pass" if actual == expected else "blocker", title, f"Gemeldet: {actual or 'unbekannt'}.", f"Dienst mit {field}={expected} starten."))
    if config.get("ISMS_STORAGE_BACKEND", "local").lower() == "s3":
        actual = str(payload.get("storage", ""))
        checks.append(Check("runtime.storage", "pass" if actual == "s3" else "blocker", "S3 ist zur Laufzeit aktiv", f"Gemeldet: {actual or 'unbekannt'}.", "S3-Konfiguration und App-Neustart prüfen."))
    if config.get("ISMS_OIDC_PROVIDERS_JSON", "").strip():
        checks.append(Check("runtime.sso", "pass" if payload.get("sso") else "blocker", "SSO ist zur Laufzeit aktiv", f"Gemeldet: {bool(payload.get('sso'))}.", "OIDC-Konfiguration und Provider-Metadaten prüfen."))
    return checks


def evaluate_compose(compose_file: Path, env_file: Path) -> list[Check]:
    if not compose_file.is_file():
        return [Check("compose.file", "blocker", "Compose-Datei vorhanden", f"Nicht gefunden: {compose_file}", "Korrekten Pfad mit --compose-file angeben.")]
    command = ["docker", "compose", "--env-file", str(env_file), "-f", str(compose_file), "config", "--quiet"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [Check("compose.syntax", "warning", "Compose-Konfiguration prüfbar", f"Docker Compose konnte nicht ausgeführt werden: {exc}", "Docker Compose installieren und den Check erneut ausführen.")]
    detail = "Compose-Konfiguration ist syntaktisch gültig." if result.returncode == 0 else (result.stderr.strip() or "Compose-Konfiguration ist ungültig.")
    return [Check("compose.syntax", "pass" if result.returncode == 0 else "blocker", "Compose-Konfiguration gültig", detail, "docker compose config ausführen und gemeldete Fehler korrigieren.")]


def report(checks: list[Check], json_output: bool = False) -> None:
    counts = {level: sum(1 for item in checks if item.level == level) for level in ("pass", "warning", "blocker")}
    if json_output:
        print(json.dumps({"technicalReady": counts["blocker"] == 0, "counts": counts, "checks": [asdict(item) for item in checks]}, ensure_ascii=False, indent=2))
        return
    labels = {"pass": "OK", "warning": "WARNUNG", "blocker": "BLOCKER"}
    print("SFM Compliance - technischer Produktions-Preflight")
    print("Keine fachliche, rechtliche oder Audit-Freigabe.\n")
    for item in checks:
        print(f"[{labels[item.level]}] {item.title}: {item.detail}")
        if item.level != "pass" and item.remediation:
            print(f"  Maßnahme: {item.remediation}")
    print(f"\nErgebnis: {counts['pass']} OK, {counts['warning']} Warnung(en), {counts['blocker']} Blocker")
    print("Technisch startklar." if counts["blocker"] == 0 else "Noch nicht technisch startklar.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Technischer Produktions-Preflight für SFM Compliance")
    parser.add_argument("--env-file", default=".env", help="Deployment-Konfiguration (Standard: .env)")
    parser.add_argument("--compose-file", default="docker-compose.yml", help="Compose-Datei")
    parser.add_argument("--url", help="Optional: laufende Instanz zusätzlich prüfen")
    parser.add_argument("--json", action="store_true", help="Maschinenlesbare JSON-Ausgabe")
    parser.add_argument("--skip-compose", action="store_true", help="Compose-Syntaxprüfung überspringen")
    args = parser.parse_args(argv)

    env_file = Path(args.env_file).expanduser().resolve()
    config = merged_config(env_file)
    checks = evaluate_config(config, env_file)
    if not args.skip_compose:
        checks.extend(evaluate_compose(Path(args.compose_file).expanduser().resolve(), env_file))
    if args.url:
        checks.extend(evaluate_runtime(args.url, config))
    else:
        checks.append(Check("runtime.skipped", "warning", "Laufende Instanz geprüft", "Kein --url angegeben; Erreichbarkeit und aktive Dienste wurden nicht geprüft.", "Mit --url https://isms.example.com erneut ausführen."))
    report(checks, json_output=args.json)
    return 1 if any(item.level == "blocker" for item in checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())
