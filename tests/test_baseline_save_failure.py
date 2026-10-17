import pytest
import dashboard


def test_save_and_protect_baseline_does_not_save_if_signing_fails(monkeypatch):
    saved = []

    def fake_save_snapshot(snapshot, database_path, directory=None):
        saved.append(snapshot)

    def fake_sign_baseline(directory, snapshot):
        return False

    monkeypatch.setattr(dashboard, "save_snapshot", fake_save_snapshot)
    monkeypatch.setattr(dashboard, "_sign_baseline", fake_sign_baseline)

    snapshot = {"example.txt": "fake-hash"}
    instance = type("FakeDashboard", (), {
        "selected_directory": "test-directory"
    })()

    monkeypatch.setattr(
        dashboard,
        "BASELINE_SIGNATURES_PATH",
        dashboard.Path("test_baseline_integrity.json"),
    )

    with pytest.raises(RuntimeError, match="signature"):
        dashboard.IntegrityDashboard._save_and_protect_baseline(
            instance, snapshot
        )

    assert saved == []


def test_manifest_is_restored_if_database_save_fails(monkeypatch, tmp_path):
    manifest = tmp_path / "baseline_integrity.json"
    previous_content = '{"previous": "signature"}'
    manifest.write_text(previous_content, encoding="utf-8")

    def fake_sign_baseline(directory, snapshot):
        manifest.write_text('{"new": "signature"}', encoding="utf-8")
        return True

    def fake_save_snapshot(snapshot, database_path, directory=None):
        raise OSError("Simulated database failure")

    monkeypatch.setattr(dashboard, "BASELINE_SIGNATURES_PATH", manifest)
    monkeypatch.setattr(dashboard, "_sign_baseline", fake_sign_baseline)
    monkeypatch.setattr(dashboard, "save_snapshot", fake_save_snapshot)

    instance = type("FakeDashboard", (), {
        "selected_directory": str(tmp_path / "demo")
    })()

    with pytest.raises(OSError, match="Simulated database failure"):
        dashboard.IntegrityDashboard._save_and_protect_baseline(
            instance, {"example.txt": "new-hash"}
        )

    assert manifest.read_text(encoding="utf-8") == previous_content
