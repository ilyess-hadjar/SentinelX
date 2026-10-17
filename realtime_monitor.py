
from pathlib import Path
from threading import Lock
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class RealtimeMonitor:
    """Observe les changements dans un dossier et ses sous-dossiers."""

    def __init__(self, directory, on_change):
        self.directory = Path(directory).resolve()
        self.on_change = on_change
        self.observer = None
        self._lock = Lock()
        self._running = False

    def start(self):
        """Démarre la surveillance du dossier."""
        with self._lock:
            if self._running:
                return

            if not self.directory.is_dir():
                raise NotADirectoryError(
                    f"Dossier introuvable : {self.directory}"
                )

            handler = _ChangeHandler(self.on_change)
            observer = Observer()
            observer.schedule(
                handler,
                str(self.directory),
                recursive=True,
            )

            observer.start()
            self.observer = observer
            self._running = True

    def stop(self):
        """Arrête proprement la surveillance."""
        with self._lock:
            observer = self.observer
            self.observer = None
            self._running = False

        if observer is not None:
            observer.stop()
            observer.join(timeout=5)

    @property
    def is_running(self):
        return self._running


class _ChangeHandler(FileSystemEventHandler):
    """Transmet les événements utiles à l'application."""

    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def on_created(self, event):
        if not event.is_directory:
            self._notify("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._notify("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._notify("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._notify("deleted", event.src_path)
            self._notify("created", event.dest_path)

    def _notify(self, event_type, path):
        try:
            self.callback(event_type, Path(path))
        except Exception as exc:
            print(f"Erreur de traitement de l'événement : {exc}")
