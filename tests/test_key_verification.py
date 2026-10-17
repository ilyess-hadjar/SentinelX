import hashlib
import hmac
import json
import secrets
import sys
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parents[1]
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import dashboard


@pytest.fixture
def signed_baseline(tmp_path, monkeypatch):
    key_dir = tmp_path / "test_local_data"
    key_dir.mkdir()
    key_path = key_dir / "baseline.key"
    manifest_path = tmp_path / "baseline_integrity.json"

    monkeypatch.setattr(dashboard, "LOCAL_DATA_DIR", key_dir)
    monkeypatch.setattr(dashboard, "BASELINE_KEY_PATH", key_path)
    monkeypatch.setattr(
        dashboard, "BASELINE_SIGNATURES_PATH", manifest_path
    )

    directory = str((tmp_path / "demo_files").resolve())
    snapshot = {
        "test.txt": hashlib.sha256(b"contenu test").hexdigest()
    }

    key = secrets.token_bytes(32)
    key_path.write_bytes(key)

    payload = dashboard._canonical_baseline(directory, snapshot)
    signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
    manifest_path.write_text(
        json.dumps({directory: signature}),
        encoding="utf-8",
    )

    return directory, snapshot, key_path


def test_baseline_verification_with_key(signed_baseline):
    directory, snapshot, _ = signed_baseline

    assert dashboard._verify_baseline(directory, snapshot)[0] == "valid"


def test_baseline_verification_without_key(signed_baseline):
    directory, snapshot, key_path = signed_baseline
    key_path.unlink()

    assert dashboard._verify_baseline(directory, snapshot)[0] == "invalid"

