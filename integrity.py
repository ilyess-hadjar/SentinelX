
import hashlib
from pathlib import Path


def calculate_file_hash(file_path: str | Path) -> str:
    """Calcule l'empreinte SHA-256 d'un fichier."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def scan_directory(directory: str | Path) -> dict[str, str]:
    """Retourne les empreintes SHA-256 des fichiers d'un dossier."""
    root = Path(directory).resolve()

    if not root.exists():
        raise FileNotFoundError(f"Le dossier n'existe pas : {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Ce chemin n'est pas un dossier : {root}")

    snapshot = {}

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue

       
        relative_path = str(file_path.relative_to(root))

        try:
            snapshot[relative_path] = calculate_file_hash(file_path)
        except (PermissionError, OSError) as error:
            raise OSError(
                f"Scan incomplet : impossible de lire le fichier "
                f"{relative_path}: {error}"
            ) from error

    return snapshot



def compare_snapshots(
    old_snapshot: dict[str, str],
    new_snapshot: dict[str, str],
) -> dict[str, list[str]]:
    """Detecte les ajouts, modifications et suppressions."""
    old_files = set(old_snapshot)
    new_files = set(new_snapshot)

    return {
        "added": sorted(new_files - old_files),
        "modified": sorted(
            path
            for path in old_files & new_files
            if old_snapshot[path] != new_snapshot[path]
        ),
        "deleted": sorted(old_files - new_files),
    }

