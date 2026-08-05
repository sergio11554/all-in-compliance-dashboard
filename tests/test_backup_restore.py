import hashlib
import hmac
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import restore_system_backup as restore  # noqa: E402


def encrypted_backup(zip_payload, key):
    nonce = b"n" * 16
    key_stream = restore.stream(key, nonce, len(zip_payload))
    cipher = bytes(left ^ right for left, right in zip(zip_payload, key_stream))
    return nonce + cipher + hmac.new(key, nonce + cipher, hashlib.sha256).digest()


def build_zip(files, manifest_files=None):
    manifest_files = manifest_files if manifest_files is not None else files
    manifest = {
        "formatVersion": 1,
        "application": "SFM Compliance",
        "database": {"dialect": "postgres", "file": "database.sql"},
        "storage": {"directory": "uploads", "objects": sum(name.startswith("uploads/") for name in files)},
        "files": [
            {"path": name, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
            for name, payload in manifest_files.items()
        ],
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)
        archive.writestr("backup-manifest.json", json.dumps(manifest))
    return output.getvalue()


class BackupRestoreTests(unittest.TestCase):
    def test_verified_manifest_roundtrip(self):
        files = {"database.sql": b"SELECT 1;\n", "uploads/object.bin": b"encrypted-object"}
        key = b"k" * 32
        payload = encrypted_backup(build_zip(files), key)
        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary) / "test.ismsbak"
            backup.write_bytes(payload)
            plain = restore.decrypt_backup(backup, key)
            extracted = Path(temporary) / "extracted"
            extracted.mkdir()
            manifest = restore.extract_verified_backup(plain, extracted)
            self.assertEqual(manifest["storage"]["objects"], 1)
            self.assertEqual((extracted / "uploads/object.bin").read_bytes(), b"encrypted-object")

    def test_wrong_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary) / "test.ismsbak"
            backup.write_bytes(encrypted_backup(build_zip({"database.sql": b"SELECT 1;"}), b"k" * 32))
            with self.assertRaisesRegex(RuntimeError, "integrity check failed"):
                restore.decrypt_backup(backup, b"x" * 32)

    def test_manifest_checksum_mismatch_is_rejected(self):
        actual = {"database.sql": b"SELECT 2;"}
        claimed = {"database.sql": b"SELECT 1;"}
        with tempfile.TemporaryDirectory() as temporary:
            extracted = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "size mismatch|checksum mismatch"):
                restore.extract_verified_backup(build_zip(actual, manifest_files=claimed), extracted)

    def test_archive_path_traversal_is_rejected(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("../outside", b"bad")
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RuntimeError, "unsafe archive path"):
                restore.extract_verified_backup(output.getvalue(), Path(temporary), allow_legacy=True)


if __name__ == "__main__":
    unittest.main()
