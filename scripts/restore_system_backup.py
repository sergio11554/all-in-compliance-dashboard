#!/usr/bin/env python3
"""Verify and restore an encrypted SFM Compliance system backup.

The tool is intentionally offline and explicit: verification is read-only, while
database and object-storage replacement require ``--confirm RESTORE``.
"""

import argparse
import hashlib
import hmac
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import zipfile
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from storage import StorageError, storage_from_env


MAX_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
MAX_ARCHIVE_FILES = 100_000


def file_key(file_key_path=None):
    configured = os.environ.get("ISMS_FILE_KEY")
    if configured:
        return hashlib.sha256(configured.encode("utf-8")).digest()
    if file_key_path:
        key = Path(file_key_path).read_bytes()
        if len(key) != 32:
            raise RuntimeError("file key must contain exactly 32 bytes")
        return key
    raise RuntimeError("ISMS_FILE_KEY or --file-key-file is required")


def stream(key, nonce, length):
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
        counter += 1
    return bytes(output[:length])


def decrypt_backup(path, key):
    payload = Path(path).read_bytes()
    if len(payload) < 16 + 32:
        raise RuntimeError("backup payload is truncated")
    nonce, authenticated = payload[:16], payload[16:]
    cipher, tag = authenticated[:-32], authenticated[-32:]
    expected = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise RuntimeError("backup integrity check failed or file key is incorrect")
    key_stream = stream(key, nonce, len(cipher))
    return bytes(left ^ right for left, right in zip(cipher, key_stream))


def safe_archive_members(archive):
    members = archive.infolist()
    if len(members) > MAX_ARCHIVE_FILES:
        raise RuntimeError("backup archive contains too many entries")
    total = 0
    for member in members:
        path = PurePosixPath(member.filename)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise RuntimeError(f"unsafe archive path: {member.filename}")
        if ((member.external_attr >> 16) & 0o170000) == 0o120000:
            raise RuntimeError(f"symbolic links are not allowed in backups: {member.filename}")
        total += int(member.file_size or 0)
        if total > MAX_ARCHIVE_BYTES:
            raise RuntimeError("decompressed backup exceeds the safety limit")
    return members


def extract_verified_backup(plain_zip, destination, allow_legacy=False):
    with zipfile.ZipFile(io.BytesIO(plain_zip), "r") as archive:
        members = safe_archive_members(archive)
        for member in members:
            target = destination.joinpath(*PurePosixPath(member.filename).parts)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member, "r") as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)

    manifest_path = destination / "backup-manifest.json"
    if not manifest_path.exists():
        if not allow_legacy:
            raise RuntimeError("backup manifest is missing; use --allow-legacy only for a trusted older backup")
        return {
            "formatVersion": 0,
            "application": "SFM Compliance",
            "database": {},
            "storage": {"directory": "uploads"},
            "files": [],
            "legacy": True,
        }

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("formatVersion") != 1 or manifest.get("application") != "SFM Compliance":
        raise RuntimeError("unsupported backup manifest")
    for item in manifest.get("files") or []:
        relative = PurePosixPath(str(item.get("path") or ""))
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise RuntimeError("backup manifest contains an unsafe path")
        path = destination.joinpath(*relative.parts)
        if not path.is_file():
            raise RuntimeError(f"backup file is missing: {relative.as_posix()}")
        payload = path.read_bytes()
        if len(payload) != int(item.get("bytes") or -1):
            raise RuntimeError(f"backup size mismatch: {relative.as_posix()}")
        if hashlib.sha256(payload).hexdigest() != item.get("sha256"):
            raise RuntimeError(f"backup checksum mismatch: {relative.as_posix()}")
    return manifest


def postgres_process(database_url, arguments, input_text=None):
    parsed = urllib.parse.urlparse(database_url)
    if parsed.scheme not in {"postgres", "postgresql"}:
        raise RuntimeError("target database URL must use PostgreSQL")
    executable = shutil.which("psql")
    if not executable:
        raise RuntimeError("PostgreSQL restore requires psql")
    environment = os.environ.copy()
    if parsed.password:
        environment["PGPASSWORD"] = urllib.parse.unquote(parsed.password)
    command = [
        executable,
        "--no-psqlrc",
        "--set",
        "ON_ERROR_STOP=1",
        "--host",
        parsed.hostname or "localhost",
        "--port",
        str(parsed.port or 5432),
        "--username",
        urllib.parse.unquote(parsed.username or ""),
        "--dbname",
        urllib.parse.unquote((parsed.path or "/").lstrip("/")),
        *arguments,
    ]
    try:
        return subprocess.run(
            command,
            env=environment,
            input=input_text,
            text=input_text is not None,
            check=True,
            capture_output=True,
            timeout=600,
        )
    except subprocess.CalledProcessError as error:
        stderr = error.stderr.decode("utf-8", "replace") if isinstance(error.stderr, bytes) else str(error.stderr or "")
        detail = " ".join(stderr.strip().splitlines()[-8:])
        raise RuntimeError(f"PostgreSQL restore command failed: {detail or 'psql returned an error'}") from error


def restore_database(extracted, manifest, database_url, sqlite_path=None):
    database_name = str((manifest.get("database") or {}).get("file") or "")
    candidates = [database_name] if database_name else ["database.sql", "isms.db"]
    backup_path = next((extracted / name for name in candidates if name and (extracted / name).is_file()), None)
    if not backup_path:
        raise RuntimeError("backup does not contain a supported database payload")
    if backup_path.suffix == ".sql":
        if not database_url:
            raise RuntimeError("--database-url or DATABASE_URL is required for this PostgreSQL backup")
        sql_text = backup_path.read_text(encoding="utf-8")
        compatibility_prefixes = ("SET transaction_timeout =",)
        sql_lines = sql_text.splitlines(keepends=True)
        compatible_lines = [
            line for line in sql_lines
            if not line.lstrip().startswith(compatibility_prefixes)
        ]
        compatibility_adjustments = len(sql_lines) - len(compatible_lines)
        compatible_path = extracted / "database-compatible.sql"
        compatible_path.write_text("".join(compatible_lines), encoding="utf-8")
        postgres_process(database_url, [], "DROP SCHEMA public CASCADE; CREATE SCHEMA public;\n")
        postgres_process(database_url, ["--single-transaction", "--file", str(compatible_path)])
        return {
            "dialect": "postgres",
            "file": backup_path.name,
            "compatibilityAdjustments": compatibility_adjustments,
        }
    if not sqlite_path:
        raise RuntimeError("--sqlite-path is required for this SQLite backup")
    target = Path(sqlite_path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.restore.tmp")
    shutil.copy2(backup_path, temporary)
    os.replace(temporary, target)
    return {"dialect": "sqlite", "file": backup_path.name}


def restore_objects(extracted, manifest, local_storage_dir=None, replace=False):
    storage_directory = str((manifest.get("storage") or {}).get("directory") or "uploads")
    source = extracted / storage_directory
    source.mkdir(parents=True, exist_ok=True)
    objects = sorted(path for path in source.iterdir() if path.is_file())
    if os.environ.get("ISMS_STORAGE_BACKEND", "local").strip().lower() == "local" and not local_storage_dir:
        raise RuntimeError("--local-storage-dir is required for local object storage")
    storage = storage_from_env(local_storage_dir or source.parent / "restored-uploads")
    existing = storage.list_names()
    if existing and not replace:
        raise RuntimeError("target object storage is not empty; use --replace-storage for an intentional replacement")
    if replace:
        for name in existing:
            storage.delete(name)
    for path in objects:
        storage.put(path.name, path.read_bytes())
    return {"backend": storage.backend, "objects": len(objects), "replacedObjects": len(existing) if replace else 0}


def parse_args():
    parser = argparse.ArgumentParser(description="Verify or restore an encrypted SFM Compliance system backup.")
    parser.add_argument("backup", help="Path to the .ismsbak file")
    parser.add_argument("--verify-only", action="store_true", help="Decrypt and verify without changing a target")
    parser.add_argument("--allow-legacy", action="store_true", help="Allow a trusted older backup without manifest")
    parser.add_argument("--confirm", default="", help="Must be RESTORE before targets are replaced")
    parser.add_argument("--file-key-file", help="32-byte file key when ISMS_FILE_KEY is not set")
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL", ""))
    parser.add_argument("--sqlite-path")
    parser.add_argument("--local-storage-dir")
    parser.add_argument("--replace-storage", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    backup = Path(args.backup).resolve()
    if backup.suffix != ".ismsbak" or not backup.is_file():
        raise SystemExit("a readable .ismsbak file is required")
    try:
        plain_zip = decrypt_backup(backup, file_key(args.file_key_file))
        with tempfile.TemporaryDirectory(prefix="sfm-restore-") as temporary:
            extracted = Path(temporary)
            manifest = extract_verified_backup(plain_zip, extracted, allow_legacy=args.allow_legacy)
            verification = {
                "ok": True,
                "backup": backup.name,
                "formatVersion": manifest.get("formatVersion"),
                "database": (manifest.get("database") or {}).get("dialect") or "legacy",
                "objects": int((manifest.get("storage") or {}).get("objects") or 0),
                "verifiedFiles": len(manifest.get("files") or []),
            }
            if args.verify_only:
                print(json.dumps(verification, sort_keys=True))
                return
            if args.confirm != "RESTORE":
                raise RuntimeError("restore requires --confirm RESTORE")
            database_result = restore_database(
                extracted,
                manifest,
                args.database_url,
                sqlite_path=args.sqlite_path,
            )
            storage_result = restore_objects(
                extracted,
                manifest,
                local_storage_dir=args.local_storage_dir,
                replace=args.replace_storage,
            )
            print(json.dumps({
                **verification,
                "restored": True,
                "databaseResult": database_result,
                "storageResult": storage_result,
            }, sort_keys=True))
    except (OSError, ValueError, RuntimeError, StorageError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        raise SystemExit(f"restore failed: {error}") from error


if __name__ == "__main__":
    main()
