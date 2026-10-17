from realtime_monitor import _ChangeHandler


class FakeEvent:
    is_directory = False

    def __init__(self, path):
        self.src_path = str(path)
        self.dest_path = str(path)


def test_deleted_event_is_forwarded():
    received = []
    handler = _ChangeHandler(
        lambda event_type, path: received.append((event_type, str(path)))
    )

    handler.on_deleted(FakeEvent("fichier_temporaire.txt"))

    assert received == [("deleted", "fichier_temporaire.txt")]
