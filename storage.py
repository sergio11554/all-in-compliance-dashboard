import os
import shutil
import uuid
from pathlib import Path


class StorageError(RuntimeError):
    pass


def _object_name(value):
    name = str(value or "").strip()
    if not name or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
        raise StorageError("invalid object name")
    return name


class LocalObjectStorage:
    backend = "local"

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, name):
        return self.root / _object_name(name)

    def put(self, name, payload):
        target = self._path(name)
        temporary = self.root / f".{target.name}.{uuid.uuid4().hex}.tmp"
        try:
            temporary.write_bytes(payload)
            try:
                temporary.chmod(0o600)
            except OSError:
                pass
            os.replace(temporary, target)
        finally:
            if temporary.exists():
                temporary.unlink()

    def get(self, name):
        try:
            return self._path(name).read_bytes()
        except FileNotFoundError as exc:
            raise StorageError("object not found") from exc

    def exists(self, name):
        return self._path(name).is_file()

    def delete(self, name):
        try:
            self._path(name).unlink()
            return True
        except FileNotFoundError:
            return False

    def list_names(self, suffix=None):
        names = []
        for path in self.root.iterdir():
            if not path.is_file() or path.name.startswith("."):
                continue
            if suffix and not path.name.endswith(suffix):
                continue
            names.append(path.name)
        return sorted(names)

    def total_bytes(self):
        return sum((self.root / name).stat().st_size for name in self.list_names())

    def health(self):
        probe = f".storage-health-{uuid.uuid4().hex}"
        try:
            self.put(probe, b"ok")
            valid = self.get(probe) == b"ok"
            self.delete(probe)
            return {"ready": valid, "detail": f"Lokales Verzeichnis {self.root} ist les- und beschreibbar"}
        except Exception as exc:
            try:
                self.delete(probe)
            except Exception:
                pass
            return {"ready": False, "detail": f"Lokale Dateiablage nicht verfügbar: {exc}"}

    def copy_to_directory(self, destination):
        destination = Path(destination)
        destination.mkdir(parents=True, exist_ok=True)
        for name in self.list_names():
            shutil.copy2(self._path(name), destination / name)


class S3ObjectStorage:
    backend = "s3"

    def __init__(self, bucket, prefix="uploads", client=None, auto_create=False):
        self.bucket = str(bucket or "").strip()
        if not self.bucket:
            raise StorageError("ISMS_S3_BUCKET is required for S3 storage")
        self.prefix = str(prefix or "").strip().strip("/")
        self.client = client or self._client_from_env()
        if auto_create:
            self._ensure_bucket()

    @classmethod
    def from_env(cls):
        auto_create = str(os.environ.get("ISMS_S3_AUTO_CREATE_BUCKET", "0")).strip().lower() in {
            "1", "true", "yes", "on"
        }
        return cls(
            os.environ.get("ISMS_S3_BUCKET"),
            os.environ.get("ISMS_S3_PREFIX", "uploads"),
            auto_create=auto_create,
        )

    @staticmethod
    def _client_from_env():
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:
            raise StorageError("boto3 is required for S3 storage") from exc
        kwargs = {
            "service_name": "s3",
            "region_name": os.environ.get("ISMS_S3_REGION", "eu-central-1"),
            "endpoint_url": os.environ.get("ISMS_S3_ENDPOINT") or None,
            "aws_access_key_id": os.environ.get("ISMS_S3_ACCESS_KEY") or None,
            "aws_secret_access_key": os.environ.get("ISMS_S3_SECRET_KEY") or None,
            "aws_session_token": os.environ.get("ISMS_S3_SESSION_TOKEN") or None,
            "config": Config(
                signature_version="s3v4",
                s3={"addressing_style": os.environ.get("ISMS_S3_ADDRESSING_STYLE", "path")},
                connect_timeout=5,
                read_timeout=30,
                retries={"max_attempts": 3, "mode": "standard"},
            ),
        }
        return boto3.client(**kwargs)

    def _ensure_bucket(self):
        try:
            self.client.head_bucket(Bucket=self.bucket)
            return
        except Exception:
            pass
        region = os.environ.get("ISMS_S3_REGION", "eu-central-1")
        arguments = {"Bucket": self.bucket}
        if region != "us-east-1" and not os.environ.get("ISMS_S3_ENDPOINT"):
            arguments["CreateBucketConfiguration"] = {"LocationConstraint": region}
        self.client.create_bucket(**arguments)

    def _key(self, name):
        name = _object_name(name)
        return f"{self.prefix}/{name}" if self.prefix else name

    @staticmethod
    def _not_found(exc):
        response = getattr(exc, "response", {}) or {}
        code = str((response.get("Error") or {}).get("Code") or "")
        status = (response.get("ResponseMetadata") or {}).get("HTTPStatusCode")
        return code in {"404", "NoSuchKey", "NotFound"} or status == 404

    def put(self, name, payload):
        try:
            self.client.put_object(
                Bucket=self.bucket,
                Key=self._key(name),
                Body=payload,
                ContentType="application/octet-stream",
            )
        except Exception as exc:
            raise StorageError(f"could not store object: {exc}") from exc

    def get(self, name):
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=self._key(name))
            return response["Body"].read()
        except Exception as exc:
            if self._not_found(exc):
                raise StorageError("object not found") from exc
            raise StorageError(f"could not read object: {exc}") from exc

    def exists(self, name):
        try:
            self.client.head_object(Bucket=self.bucket, Key=self._key(name))
            return True
        except Exception as exc:
            if self._not_found(exc):
                return False
            raise StorageError(f"could not inspect object: {exc}") from exc

    def delete(self, name):
        existed = self.exists(name)
        if not existed:
            return False
        try:
            self.client.delete_object(Bucket=self.bucket, Key=self._key(name))
            return True
        except Exception as exc:
            raise StorageError(f"could not delete object: {exc}") from exc

    def _objects(self):
        prefix = f"{self.prefix}/" if self.prefix else ""
        paginator = self.client.get_paginator("list_objects_v2")
        try:
            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                for item in page.get("Contents", []):
                    key = str(item.get("Key") or "")
                    name = key[len(prefix):] if prefix and key.startswith(prefix) else key
                    if name and "/" not in name:
                        yield name, int(item.get("Size") or 0)
        except Exception as exc:
            raise StorageError(f"could not list objects: {exc}") from exc

    def list_names(self, suffix=None):
        return sorted(name for name, _ in self._objects() if not suffix or name.endswith(suffix))

    def total_bytes(self):
        return sum(size for _, size in self._objects())

    def health(self):
        try:
            self.client.head_bucket(Bucket=self.bucket)
            return {"ready": True, "detail": f"S3-Bucket {self.bucket} ist erreichbar"}
        except Exception as exc:
            return {"ready": False, "detail": f"S3-Bucket nicht erreichbar: {exc}"}

    def copy_to_directory(self, destination):
        destination = Path(destination)
        destination.mkdir(parents=True, exist_ok=True)
        for name in self.list_names():
            (destination / name).write_bytes(self.get(name))


def storage_from_env(local_root):
    backend = str(os.environ.get("ISMS_STORAGE_BACKEND", "local")).strip().lower()
    if backend == "local":
        return LocalObjectStorage(local_root)
    if backend == "s3":
        return S3ObjectStorage.from_env()
    raise StorageError("ISMS_STORAGE_BACKEND must be 'local' or 's3'")
