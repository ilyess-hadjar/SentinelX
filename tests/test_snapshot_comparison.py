from integrity import compare_snapshots


def test_added_file_is_detected():
    old = {"test.txt": "hash_a"}
    new = {"test.txt": "hash_a", "nouveau.txt": "hash_b"}

    changes = compare_snapshots(old, new)

    assert changes["added"] == ["nouveau.txt"]
    assert changes["modified"] == []
    assert changes["deleted"] == []


def test_deleted_file_is_detected():
    old = {"test.txt": "hash_a", "ancien.txt": "hash_b"}
    new = {"test.txt": "hash_a"}

    changes = compare_snapshots(old, new)

    assert changes["added"] == []
    assert changes["modified"] == []
    assert changes["deleted"] == ["ancien.txt"]


def test_modified_file_is_detected():
    old = {"test.txt": "hash_a"}
    new = {"test.txt": "hash_different"}

    changes = compare_snapshots(old, new)

    assert changes["added"] == []
    assert changes["modified"] == ["test.txt"]
    assert changes["deleted"] == []
