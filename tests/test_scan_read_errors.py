
import pytest
import integrity


def test_scan_stops_when_file_cannot_be_read(tmp_path, monkeypatch):
    (tmp_path / "illisible.txt").write_text("secret", encoding="utf-8")
    (tmp_path / "lisible.txt").write_text("accessible", encoding="utf-8")

    original_hash = integrity.calculate_file_hash

    def simulated_hash_error(file_path):
        if str(file_path).endswith("illisible.txt"):
            raise PermissionError("Accès refusé pour le test")
        return original_hash(file_path)

    monkeypatch.setattr(integrity, "calculate_file_hash", simulated_hash_error)

    with pytest.raises(OSError, match="Scan incomplet"):
        integrity.scan_directory(tmp_path)


def test_scan_stops_after_os_error(tmp_path, monkeypatch):
    (tmp_path / "erreur.txt").write_text("test", encoding="utf-8")
    (tmp_path / "normal.txt").write_text("normal", encoding="utf-8")

    original_hash = integrity.calculate_file_hash

    def simulated_os_error(file_path):
        if str(file_path).endswith("erreur.txt"):
            raise OSError("Erreur simulée")
        return original_hash(file_path)

    monkeypatch.setattr(integrity, "calculate_file_hash", simulated_os_error)

    with pytest.raises(OSError, match="Scan incomplet"):
        integrity.scan_directory(tmp_path)
