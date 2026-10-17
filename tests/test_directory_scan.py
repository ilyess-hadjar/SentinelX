import hashlib

from integrity import scan_directory


def test_scan_directory_calculates_sha256(tmp_path):
    test_file = tmp_path / "test.txt"
    content = b"SentinelX test"
    test_file.write_bytes(content)

    snapshot = scan_directory(tmp_path)

    assert snapshot == {
        "test.txt": hashlib.sha256(content).hexdigest()
    }


def test_scan_directory_detects_new_file_on_rescan(tmp_path):
    first_file = tmp_path / "premier.txt"
    first_file.write_text("contenu initial", encoding="utf-8")

    first_snapshot = scan_directory(tmp_path)

    second_file = tmp_path / "nouveau.txt"
    second_file.write_text("nouveau contenu", encoding="utf-8")

    second_snapshot = scan_directory(tmp_path)

    assert "nouveau.txt" in second_snapshot
    assert "nouveau.txt" not in first_snapshot


def test_scan_directory_ignores_empty_subdirectories(tmp_path):
    (tmp_path / "sous_dossier").mkdir()

    snapshot = scan_directory(tmp_path)

    assert snapshot == {}
