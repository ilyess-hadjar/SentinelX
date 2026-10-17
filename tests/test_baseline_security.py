
import json
from pathlib import Path

import dashboard


def test_baseline_signature_is_valid():
    directory = str((Path(__file__).resolve().parents[2] / "demo_files").resolve())

    snapshot = dashboard.load_snapshot(
        dashboard.DATABASE_PATH,
        directory=directory,
    )

    status = dashboard._verify_baseline(directory, snapshot)

    assert status[0] == "valid", f"Signature inattendue : {status}"


def test_tampered_signature_is_rejected(tmp_path, monkeypatch):
    directory = str((Path(__file__).resolve().parents[2] / "demo_files").resolve())

    snapshot = dashboard.load_snapshot(
        dashboard.DATABASE_PATH,
        directory=directory,
    )

    original_manifest = json.loads(
        dashboard.BASELINE_SIGNATURES_PATH.read_text(encoding="utf-8")
    )

    temporary_manifest = tmp_path / "baseline_integrity.json"
    original_manifest[directory] = "0" * 64

    temporary_manifest.write_text(
        json.dumps(original_manifest),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        dashboard,
        "BASELINE_SIGNATURES_PATH",
        temporary_manifest,
    )

    status = dashboard._verify_baseline(directory, snapshot)

    assert status[0] == "invalid", (
        f"Une signature falsifiée a été acceptée : {status}"
    )

def test_missing_key_is_rejected(tmp_path, monkeypatch):
    directory = str((Path(__file__).resolve().parents[2] / "demo_files").resolve())

    snapshot = dashboard.load_snapshot(
        dashboard.DATABASE_PATH,
        directory=directory,
    )

    temporary_key = tmp_path / "missing_baseline.key"

    monkeypatch.setattr(dashboard, "BASELINE_KEY_PATH", temporary_key)

    status = dashboard._verify_baseline(directory, snapshot)

    assert status[0] == "invalid", (
        f"La baseline a été acceptée sans clé : {status}"
    )


