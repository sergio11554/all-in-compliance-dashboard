#!/usr/bin/env python3
import argparse
import hashlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from storage import LocalObjectStorage, StorageError, storage_from_env


CONFIRMATION = "MIGRATE_FILE_STORAGE"


def digest(payload):
    return hashlib.sha256(payload).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Copy encrypted SFM upload blobs from local storage to configured S3 storage.")
    parser.add_argument("--source", required=True, help="Path to the existing encrypted uploads directory")
    parser.add_argument("--confirm", required=True, help=f"Must be {CONFIRMATION}")
    parser.add_argument("--overwrite", action="store_true", help="Replace target objects whose content differs")
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"Refusing migration: --confirm must be {CONFIRMATION}")

    source_path = Path(args.source).resolve()
    if not source_path.is_dir():
        raise SystemExit(f"Source directory does not exist: {source_path}")
    source = LocalObjectStorage(source_path)
    target = storage_from_env(source_path / ".unused-target")
    if target.backend != "s3":
        raise SystemExit("ISMS_STORAGE_BACKEND must be s3 for this migration")
    health = target.health()
    if not health["ready"]:
        raise SystemExit(health["detail"])

    names = source.list_names(suffix=".bin")
    copied = 0
    already_present = 0
    for name in names:
        payload = source.get(name)
        if target.exists(name):
            existing = target.get(name)
            if digest(existing) == digest(payload):
                already_present += 1
                continue
            if not args.overwrite:
                raise SystemExit(f"Target object differs; rerun with --overwrite only after review: {name}")
        target.put(name, payload)
        if digest(target.get(name)) != digest(payload):
            raise StorageError(f"Verification failed for {name}")
        copied += 1

    missing = [name for name in names if not target.exists(name)]
    if missing:
        raise SystemExit(f"Migration verification failed; {len(missing)} object(s) missing")
    print(f"File storage migration verified: source={len(names)}, copied={copied}, already_present={already_present}")


if __name__ == "__main__":
    main()
