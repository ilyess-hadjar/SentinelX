import hashlib
import json
import sys
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parents[1]
if str(APP) not in sys.path:
    sys.path.insert(0, str(APP))

import dashboard
from database import initialize_database, save_snapshot


@pytest.fixture
def signed_baseline(tmp_path, monkeypatch):
    database_path = tmp_path / "integrity.db"
    key_dir = tmp_path / "test_local_data"
    key_dir.mkdir()
    key_path = key_dir / "baseline.key"
    manifest_path = tmp_path / "baseline_integrity.json"

    initialize_database(database_path)

    monkeypatch.setattr(dashboard, "DATABASE_PATH", database_path)
    monkeypatch.setattr(dashboard, "LOCAL_DATA_DIR", key_dir)
    monkeypatch.setattr(dashboard, "BASELINE_KEY_PATH", key_path)
    monkeypatch.setattr(
        dashboard, "BASELINE_SIGNATURES_PATH", manifest_path
    )

    directory = str((tmp_path / "demo_files").resolve())
    snapshot = {
        "test.txt": hashlib.sha256(b"contenu test").hexdigest()
    }

    save_snapshot(snapshot, database_path, directory=directory)
    assert dashboard._sign_baseline(directory, snapshot)

    return directory, snapshot, key_path, manifest_path


def test_baseline_signature_is_valid(signed_baseline):
    directory, snapshot, _, _ = signed_baseline

    status = dashboard._verify_baseline(directory, snapshot)

    assert status[0] == "valid", f"Signature inattendue : {status}"


def test_tampered_signature_is_rejected(signed_baseline):
    directory, snapshot, _, manifest_path = signed_baseline

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[directory] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    status = dashboard._verify_baseline(directory, snapshot)

    assert status[0] == "invalid", (
        f"Une signature falsifiée a été acceptée : {status}"
    )


def test_missing_key_is_rejected(signed_baseline):
    directory, snapshot, key_path, _ = signed_baseline
    key_path.unlink()

    status = dashboard._verify_baseline(directory, snapshot)

    assert status[0] == "invalid", (
        f"La baseline a été acceptée sans clé : {status}"
    )