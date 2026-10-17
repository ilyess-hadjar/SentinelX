
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

REPORTS_DIR = Path(__file__).parent / "reports"


def export_json(events: list[dict], output_dir: str | Path = REPORTS_DIR) -> Path:
    """Exporte les événements de sécurité au format JSON."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = directory / f"rapport_{timestamp}.json"

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "event_count": len(events),
        "events": events,
    }

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, ensure_ascii=False, indent=4)

    return report_path


def export_csv(events: list[dict], output_dir: str | Path = REPORTS_DIR) -> Path:
    """Exporte les événements de sécurité au format CSV."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = directory / f"rapport_{timestamp}.csv"

    fieldnames = [
        "id",
        "event_type",
        "path",
        "detected_at",
        "old_hash",
        "new_hash",
    ]

    with report_path.open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(events)

    return report_path
