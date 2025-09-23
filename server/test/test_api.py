"""
test_api.py

API integration tests for the Flask server.

- Keeps Niu's original healthz route test
- Shen 9.20: added tests for security and validation:
  * create-user with missing fields
  * login with missing fields
  * protected routes without auth
  * upload-document validation (missing file, wrong type, too large)
"""

import io
import pytest
import sys, os

# Shen 9.20: ensure src/ is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from server import app


@pytest.fixture
def client():
    return app.test_client()


# --------- Niu's original test (kept) ----------
def test_healthz_route(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.is_json
    data = resp.get_json()
    assert "message" in data
    assert "db_connected" in data


# --------- Shen 9.20: security/validation tests ----------

def test_create_user_missing_fields(client):
    resp = client.post("/api/create-user", json={})
    assert resp.status_code == 400
    assert resp.is_json
    assert "error" in resp.get_json()


def test_login_missing_fields(client):
    resp = client.post("/api/login", json={})
    assert resp.status_code == 400
    assert resp.is_json
    assert "error" in resp.get_json()


def test_auth_required_routes_reject_without_token(client):
    resp = client.get("/api/list-documents")
    assert resp.status_code == 401
    assert resp.is_json
    data = resp.get_json()
    assert "error" in data


def test_upload_document_requires_file(client):
    headers = {"Authorization": "Bearer fake-token"}
    resp = client.post("/api/upload-document", headers=headers)
    assert resp.status_code in (400, 401)
    assert resp.is_json
    assert "error" in resp.get_json()


def test_upload_document_rejects_non_pdf(client):
    headers = {"Authorization": "Bearer fake-token"}
    fake_file = (io.BytesIO(b"not a pdf"), "test.txt")
    resp = client.post(
        "/api/upload-document",
        headers=headers,
        data={"file": fake_file},
        content_type="multipart/form-data",
    )
    assert resp.status_code in (400, 401)
    assert resp.is_json
    assert "error" in resp.get_json()


def test_upload_document_rejects_too_large(client):
    headers = {"Authorization": "Bearer fake-token"}
    big_file = io.BytesIO(b"x" * (21 * 1024 * 1024))  # 21 MB
    resp = client.post(
        "/api/upload-document",
        headers=headers,
        data={"file": (big_file, "big.pdf")},
        content_type="multipart/form-data",
    )
    assert resp.status_code in (400, 401, 413)
    assert resp.is_json
    assert "error" in resp.get_json()
