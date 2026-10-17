import hashlib

from integrity import scan_directory, compare_snapshots


def test_empty_file_has_correct_hash(tmp_path):
    (tmp_path / "vide.txt").write_bytes(b"")

    snapshot = scan_directory(tmp_path)

    assert snapshot["vide.txt"] == hashlib.sha256(b"").hexdigest()


def test_scan_finds_nested_files(tmp_path):
    nested = tmp_path / "niveau1" / "niveau2"
    nested.mkdir(parents=True)
    (nested / "document.txt").write_text("test", encoding="utf-8")

    snapshot = scan_directory(tmp_path)

    assert "niveau1\\niveau2\\document.txt" in snapshot or (
        "niveau1/niveau2/document.txt" in snapshot
    )


def test_identical_scans_have_no_changes(tmp_path):
    file_path = tmp_path / "stable.txt"
    file_path.write_text("contenu stable", encoding="utf-8")

    first = scan_directory(tmp_path)
    second = scan_directory(tmp_path)

    changes = compare_snapshots(first, second)

    assert changes == {"added": [], "modified": [], "deleted": []}
