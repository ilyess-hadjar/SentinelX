import pytest

from integrity import scan_directory


def test_scan_directory_rejects_missing_directory(tmp_path):
    missing = tmp_path / "dossier_inexistant"

    with pytest.raises(FileNotFoundError):
        scan_directory(missing)


def test_scan_directory_rejects_file_as_directory(tmp_path):
    file_path = tmp_path / "fichier.txt"
    file_path.write_text("test", encoding="utf-8")

    with pytest.raises(NotADirectoryError):
        scan_directory(file_path)
