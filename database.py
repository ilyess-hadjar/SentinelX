
from contextlib import contextmanager
from datetime import datetime, timezone
import sqlite3
from pathlib import Path

DEFAULT_DATABASE = Path(__file__).parent / "integrity.db"


@contextmanager
def get_connection(database_path=DEFAULT_DATABASE):
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row

    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database(database_path=DEFAULT_DATABASE):
    """Crée les tables sans supprimer les anciennes données."""
    with get_connection(database_path) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS file_snapshots (
                path TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS directory_snapshots (
                directory TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                PRIMARY KEY (directory, path)
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                path TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                old_hash TEXT,
                new_hash TEXT
            )
        """)
	
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alert_states (
                directory TEXT NOT NULL,
                path TEXT NOT NULL,
                event_type TEXT NOT NULL,
                old_hash TEXT,
                new_hash TEXT,
                PRIMARY KEY (directory, path)
            )
        """)


        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(events)"
            ).fetchall()
        }

        if "directory" not in columns:
            connection.execute(
                "ALTER TABLE events ADD COLUMN directory TEXT"
            )


def save_snapshot(
    snapshot,
    database_path=DEFAULT_DATABASE,
    directory=None,
):
    """Enregistre une référence pour un dossier précis."""
    timestamp = datetime.now(timezone.utc).isoformat()

    with get_connection(database_path) as connection:
        if directory is None:
            # Compatibilité avec l'ancienne API.
            connection.execute("DELETE FROM file_snapshots")

            connection.executemany(
                """
                INSERT INTO file_snapshots (path, sha256, last_seen)
                VALUES (?, ?, ?)
                """,
                [
                    (path, sha256, timestamp)
                    for path, sha256 in snapshot.items()
                ],
            )
        else:
            root = str(Path(directory).resolve())

            connection.execute(
                "DELETE FROM directory_snapshots WHERE directory = ?",
                (root,),
            )

            connection.executemany(
                """
                INSERT INTO directory_snapshots
                    (directory, path, sha256, last_seen)
                VALUES (?, ?, ?, ?)
                """,
                [
                    (root, path, sha256, timestamp)
                    for path, sha256 in snapshot.items()
                ],
            )


def load_snapshot(database_path=DEFAULT_DATABASE, directory=None):
    """Charge la référence du dossier demandé."""
    with get_connection(database_path) as connection:
        if directory is None:
            rows = connection.execute(
                "SELECT path, sha256 FROM file_snapshots"
            ).fetchall()
        else:
            root = str(Path(directory).resolve())

            rows = connection.execute(
                """
                SELECT path, sha256
                FROM directory_snapshots
                WHERE directory = ?
                """,
                (root,),
            ).fetchall()

    return {row["path"]: row["sha256"] for row in rows}


def record_event(
    event_type,
    path,
    old_hash=None,
    new_hash=None,
    database_path=DEFAULT_DATABASE,
    directory=None,
):
    """Enregistre un événement avec le dossier concerné."""
    timestamp = datetime.now(timezone.utc).isoformat()
    root = str(Path(directory).resolve()) if directory is not None else None

    with get_connection(database_path) as connection:
        connection.execute(
            """
            INSERT INTO events
                (event_type, path, detected_at, old_hash, new_hash, directory)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event_type,
                path,
                timestamp,
                old_hash,
                new_hash,
                root,
            ),
        )


def load_events(database_path=DEFAULT_DATABASE):
    """Charge l'historique, du plus récent au plus ancien."""
    with get_connection(database_path) as connection:
        rows = connection.execute(
            "SELECT * FROM events ORDER BY id DESC"
        ).fetchall()

    return [dict(row) for row in rows]

def load_alert_states(database_path=DEFAULT_DATABASE, directory=None):
    """Charge les derniers états d'alerte enregistrés."""
    with get_connection(database_path) as connection:
        if directory is None:
            rows = connection.execute(
                """
                SELECT directory, path, event_type, old_hash, new_hash
                FROM alert_states
                """
            ).fetchall()
        else:
            root = str(Path(directory).resolve())
            rows = connection.execute(
                """
                SELECT directory, path, event_type, old_hash, new_hash
                FROM alert_states
                WHERE directory = ?
                """,
                (root,),
            ).fetchall()

    return {
        row["path"]: (
            row["event_type"].lower(),
            row["path"],
            row["old_hash"],
            row["new_hash"],
        )
        for row in rows
    }


def save_alert_state(
    directory,
    path,
    event_type,
    old_hash,
    new_hash,
    database_path=DEFAULT_DATABASE,
):
    """Enregistre durablement le dernier état alerté d'un fichier."""
    root = str(Path(directory).resolve())

    with get_connection(database_path) as connection:
        connection.execute(
            """
            INSERT INTO alert_states
                (directory, path, event_type, old_hash, new_hash)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(directory, path) DO UPDATE SET
                event_type = excluded.event_type,
                old_hash = excluded.old_hash,
                new_hash = excluded.new_hash
            """,
            (root, path, event_type.upper(), old_hash, new_hash),
        )
from pathlib import Path

def delete_alert_state(directory, path, database_path=DEFAULT_DATABASE):
    """Supprime l'état d'alerte mémorisé pour un fichier."""
    root = str(Path(directory).resolve())

    with get_connection(database_path) as connection:
        connection.execute(
            "DELETE FROM alert_states WHERE directory = ? AND path = ?",
            (root, path),
        )
