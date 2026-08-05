import io
import tempfile
import unittest
from pathlib import Path

from storage import LocalObjectStorage, S3ObjectStorage, StorageError


class FakeNotFound(Exception):
    response = {
        "Error": {"Code": "NoSuchKey"},
        "ResponseMetadata": {"HTTPStatusCode": 404},
    }


class FakePaginator:
    def __init__(self, client):
        self.client = client

    def paginate(self, Bucket, Prefix):
        contents = [
            {"Key": key, "Size": len(value)}
            for (bucket, key), value in self.client.objects.items()
            if bucket == Bucket and key.startswith(Prefix)
        ]
        yield {"Contents": contents}


class FakeS3Client:
    def __init__(self):
        self.buckets = set()
        self.objects = {}

    def head_bucket(self, Bucket):
        if Bucket not in self.buckets:
            raise FakeNotFound()

    def create_bucket(self, Bucket, **_kwargs):
        self.buckets.add(Bucket)

    def put_object(self, Bucket, Key, Body, **_kwargs):
        if Bucket not in self.buckets:
            raise FakeNotFound()
        self.objects[(Bucket, Key)] = bytes(Body)

    def get_object(self, Bucket, Key):
        try:
            value = self.objects[(Bucket, Key)]
        except KeyError as exc:
            raise FakeNotFound() from exc
        return {"Body": io.BytesIO(value)}

    def head_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise FakeNotFound()
        return {"ContentLength": len(self.objects[(Bucket, Key)])}

    def delete_object(self, Bucket, Key):
        self.objects.pop((Bucket, Key), None)

    def get_paginator(self, name):
        if name != "list_objects_v2":
            raise AssertionError(name)
        return FakePaginator(self)


class LocalObjectStorageTests(unittest.TestCase):
    def test_roundtrip_listing_health_and_copy(self):
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as copy_dir:
            storage = LocalObjectStorage(temp_dir)
            storage.put("one.bin", b"encrypted-one")
            storage.put("two.txt", b"two")
            self.assertTrue(storage.exists("one.bin"))
            self.assertEqual(storage.get("one.bin"), b"encrypted-one")
            self.assertEqual(storage.list_names(suffix=".bin"), ["one.bin"])
            self.assertEqual(storage.total_bytes(), len(b"encrypted-one") + len(b"two"))
            self.assertTrue(storage.health()["ready"])
            storage.copy_to_directory(copy_dir)
            self.assertEqual((Path(copy_dir) / "one.bin").read_bytes(), b"encrypted-one")
            self.assertTrue(storage.delete("one.bin"))
            self.assertFalse(storage.delete("one.bin"))

    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = LocalObjectStorage(temp_dir)
            for name in ("../secret", "folder/blob.bin", "folder\\blob.bin", ""):
                with self.assertRaises(StorageError):
                    storage.put(name, b"blocked")


class S3ObjectStorageTests(unittest.TestCase):
    def test_roundtrip_listing_health_and_copy(self):
        client = FakeS3Client()
        storage = S3ObjectStorage("evidence", "tenant-objects", client=client, auto_create=True)
        storage.put("one.bin", b"encrypted-one")
        storage.put("two.txt", b"two")
        self.assertTrue(storage.exists("one.bin"))
        self.assertFalse(storage.exists("missing.bin"))
        self.assertEqual(storage.get("one.bin"), b"encrypted-one")
        self.assertEqual(storage.list_names(suffix=".bin"), ["one.bin"])
        self.assertEqual(storage.total_bytes(), len(b"encrypted-one") + len(b"two"))
        self.assertTrue(storage.health()["ready"])
        with tempfile.TemporaryDirectory() as destination:
            storage.copy_to_directory(destination)
            self.assertEqual((Path(destination) / "two.txt").read_bytes(), b"two")
        self.assertTrue(storage.delete("one.bin"))
        self.assertFalse(storage.delete("one.bin"))


if __name__ == "__main__":
    unittest.main()
