#!/usr/bin/env python3
import hashlib
import http.cookiejar
import json
import os
import secrets
import urllib.request


BASE_URL = os.environ.get("SFM_SMOKE_BASE_URL", "http://127.0.0.1:5173").rstrip("/")
PASSWORD = os.environ.get("ISMS_ADMIN_PASSWORD", "")


def request(opener, method, path, body=None, headers=None):
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=body,
        headers=headers or {},
        method=method,
    )
    with opener.open(req, timeout=20) as response:
        return response.status, response.headers, response.read()


def main():
    if not PASSWORD:
        raise SystemExit("ISMS_ADMIN_PASSWORD is required")
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    login_body = json.dumps({"username": "admin", "password": PASSWORD}).encode("utf-8")
    status, _, raw = request(
        opener,
        "POST",
        "/api/auth/login",
        login_body,
        {"Content-Type": "application/json", "Accept": "application/json"},
    )
    if status != 200:
        raise SystemExit(f"login failed: {status}")
    csrf = json.loads(raw.decode("utf-8"))["csrfToken"]

    payload = b"SFM encrypted object storage smoke test\n" + secrets.token_bytes(32)
    boundary = f"----sfm-{secrets.token_hex(12)}"
    multipart = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="files"; filename="storage-smoke.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n"
    ).encode("utf-8") + payload + f"\r\n--{boundary}--\r\n".encode("utf-8")
    status, _, raw = request(
        opener,
        "POST",
        "/api/files",
        multipart,
        {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-CSRF-Token": csrf,
            "Accept": "application/json",
        },
    )
    if status != 201:
        raise SystemExit(f"upload failed: {status} {raw[:500]!r}")
    file_info = json.loads(raw.decode("utf-8"))["files"][0]
    status, _, downloaded = request(opener, "GET", f"/api/files/{file_info['id']}/download")
    if status != 200 or downloaded != payload:
        raise SystemExit("download did not match uploaded payload")
    if file_info["sha256"] != hashlib.sha256(payload).hexdigest():
        raise SystemExit("API checksum did not match payload")

    status, _, raw = request(opener, "GET", "/api/health", headers={"Accept": "application/json"})
    health = json.loads(raw.decode("utf-8"))
    print(json.dumps({
        "ok": True,
        "storage": health.get("storage"),
        "fileId": file_info["id"],
        "bytes": len(payload),
        "roundtrip": True,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
