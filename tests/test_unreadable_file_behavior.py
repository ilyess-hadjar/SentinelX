
import pytest
import integrity


def test_unreadable_file_does_not_produce_partial_snapshot(tmp_path, monkeypatch):
    file_path = tmp_path / "important.txt"
    file_path.write_text("contenu important", encoding="utf-8")

    baseline = integrity.scan_directory(tmp_path)
    original_hash = integrity.calculate_file_hash

    def simulate_read_error(path):
        if str(path).endswith("important.txt"):
            raise PermissionError("Erreur simulée")
        return original_hash(path)

    monkeypatch.setattr(integrity, "calculate_file_hash", simulate_read_error)

    with pytest.raises(OSError, match="Scan incomplet"):
        integrity.scan_directory(tmp_path)
