
import argparse
import time
from notifications import send_notification
from pathlib import Path

from integrity import scan_directory, compare_snapshots
from database import (
    initialize_database,
    save_snapshot,
    load_snapshot,
    record_event,
    load_events,
    load_alert_states,
    save_alert_state,
    delete_alert_state,
)
from reports import export_json, export_csv


def display_changes(changes):
    labels = {
        "added": "AJOUTÃ‰",
        "modified": "MODIFIÃ‰",
        "deleted": "SUPPRIMÃ‰",
    }

    total = sum(len(paths) for paths in changes.values())

    if total == 0:
        print("\n[OK] Aucun changement dÃ©tectÃ©.")
        return

    print(f"\n[ALERTE] {total} changement(s) dÃ©tectÃ©(s) !")

    for category, paths in changes.items():
        for path in paths:
            print(f"[{labels[category]}] {path}")


def get_valid_directory(directory):
    root = Path(directory).resolve()

    if not root.exists():
        raise FileNotFoundError(f"Dossier introuvable : {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Ce chemin n'est pas un dossier : {root}")

    return root


def record_changes(changes, previous, current, database_path, root):
    labels = {
        "added": "ADDED",
        "modified": "MODIFIED",
        "deleted": "DELETED",
    }

    for category, paths in changes.items():
        for path in paths:
            record_event(
                event_type=labels[category],
                path=path,
                old_hash=previous.get(path),
                new_hash=current.get(path),
                database_path=database_path,
                directory=root,
            )


def initialize_baseline(directory, database_path):
    root = get_valid_directory(directory)
    initialize_database(database_path)

    previous = load_snapshot(database_path, directory=root)

    if previous:
        print(f"[REFUS] Une référence existe déjà pour : {root}")
        print("Utilise --accept-changes pour la remplacer volontairement.")
        return

    try:
        current = scan_directory(root)
    except OSError as exc:
        print(f"[ERREUR] Référence non créée : scan incomplet. {exc}")
        return

    print(f"\nDossier : {root}")
    print(f"{len(current)} fichier(s) seront enregistrés comme référence.")

    answer = input("Créer cette référence ? Tape OUI pour confirmer : ")

    if answer.strip() != "OUI":
        print("[ANNULÉ] Référence non créée.")
        return

    save_snapshot(current, database_path, directory=root)
    print("[OK] Référence de confiance créée.")



def monitor_directory(directory, database_path, notified_states=None):
    """Analyse un dossier et conserve les alertes entre les redémarrages."""
    root = get_valid_directory(directory)
    initialize_database(database_path)

    previous = load_snapshot(database_path, directory=root)

    if not previous:
        print(f"[ERREUR] Aucune référence pour : {root}")
        print(f'Crée-la avec : python main.py "{root}" --init-baseline')
        return

    try:
        current = scan_directory(root)
    except OSError as exc:
        print(f"[ERREUR] Analyse interrompue : scan incomplet. {exc}")
        return

    changes = compare_snapshots(previous, current)
    print(f"\nDossier surveillé : {root}")

    # Charger les alertes déjà enregistrées pour ce dossier.
    saved_states = load_alert_states(database_path, directory=root)

    # Oublier les alertes des fichiers revenus à leur état de référence.
    changed_paths = {
        path
        for paths in changes.values()
        for path in paths
    }

    for path in list(saved_states):
        if path not in changed_paths:
            delete_alert_state(
                directory=root,
                path=path,
                database_path=database_path,
            )

   

    new_changes = {
        "added": [],
        "modified": [],
        "deleted": [],
    }

    labels = {
        "added": "ADDED",
        "modified": "MODIFIED",
        "deleted": "DELETED",
    }

    for category, paths in changes.items():
        for path in paths:
            state = (
                labels[category].lower(),
                path,
                previous.get(path),
                current.get(path),
            )

            if saved_states.get(path) != state:
                new_changes[category].append(path)
                save_alert_state(
                    directory=root,
                    path=path,
                    event_type=labels[category],
                    old_hash=previous.get(path),
                    new_hash=current.get(path),
                    database_path=database_path,
                )

    display_changes(new_changes)
    total = sum(len(paths) for paths in new_changes.values())

    if total > 0:
        record_changes(new_changes, previous, current, database_path, root)

        details = [
            f"{len(paths)} {category}"
            for category, paths in new_changes.items()
            if paths
        ]

        send_notification(
            "Alerte de sécurité",
            f"{total} nouveau(x) changement(s) détecté(s) : "
            + ", ".join(details),
        )

        notification_labels = {
            "added": "Fichier ajouté",
            "modified": "Fichier modifié",
            "deleted": "Fichier supprimé",
        }

        for category, paths in new_changes.items():
            for path in paths:
                send_notification(
                    "File Integrity Monitor",
                    f"{notification_labels[category]} : {path}",
                )

    elif any(changes.values()):
        print("[OK] Aucun nouveau changement depuis la dernière alerte.")
    else:
        print("[OK] La référence de confiance est inchangée.")

def accept_changes(directory, database_path):
    root = get_valid_directory(directory)
    initialize_database(database_path)

    previous = load_snapshot(database_path, directory=root)

    if not previous:
        print("[ERREUR] Aucune rÃ©fÃ©rence pour ce dossier.")
        print(f'CrÃ©e-la avec : python main.py "{root}" --init-baseline')
        return

    try:
        current = scan_directory(root)
    except OSError as exc:
        print(f"[ERREUR] Modifications non acceptées : scan incomplet. {exc}")
        return

    changes = compare_snapshots(previous, current)

    print(f"\nDossier : {root}")
    display_changes(changes)

    if sum(len(paths) for paths in changes.values()) == 0:
        print("[OK] Rien Ã  accepter.")
        return

    answer = input(
        "\nAprÃ¨s vÃ©rification, tape ACCEPTER pour confirmer : "
    )

    if answer.strip() != "ACCEPTER":
        print("[ANNULÃ‰] La rÃ©fÃ©rence est conservÃ©e.")
        return

    record_changes(changes, previous, current, database_path, root)
    save_snapshot(current, database_path, directory=root)

    print("[OK] Nouvelle rÃ©fÃ©rence enregistrÃ©e volontairement.")


def export_reports(database_path):
    initialize_database(database_path)
    events = load_events(database_path)

    json_path = export_json(events)
    csv_path = export_csv(events)

    print(f"\n[OK] {len(events)} Ã©vÃ©nement(s) exportÃ©(s).")
    print(f"[JSON] {json_path}")
    print(f"[CSV] {csv_path}")


def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor - surveillance SHA-256"
    )

    parser.add_argument("directory", nargs="?", help="Dossier à surveiller")
    parser.add_argument(
        "--interval",
        type=int,
        default=0,
        help="Intervalle entre les analyses en secondes",
    )

    actions = parser.add_mutually_exclusive_group()
    actions.add_argument(
        "--init-baseline",
        action="store_true",
        help="CrÃ©er une rÃ©fÃ©rence initiale",
    )
    actions.add_argument(
        "--accept-changes",
        action="store_true",
        help="Accepter les changements aprÃ¨s vÃ©rification",
    )
    actions.add_argument(
        "--export",
        action="store_true",
        help="Exporter l'historique en JSON et CSV",
    )

    args = parser.parse_args()

    if args.interval < 0:
        parser.error("--interval doit Ãªtre positif ou nul")

    database_path = Path(__file__).parent / "integrity.db"

    try:
        if args.export:
            export_reports(database_path)
            return

        if not args.directory:
            parser.error("Indique un dossier Ã  surveiller.")

        if args.init_baseline:
            initialize_baseline(args.directory, database_path)
            return

        if args.accept_changes:
            accept_changes(args.directory, database_path)
            return

        notified_states = {}
        while True:
            monitor_directory(args.directory, database_path, notified_states)

            if args.interval == 0:
                break

            print(f"\nProchain contrÃ´le dans {args.interval} seconde(s)...")
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[ARRÃŠT] Surveillance interrompue.")

    except (OSError, ValueError) as error:
        print(f"\n[ERREUR] {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()



