"""File Integrity Monitor — dark SOC-style desktop dashboard.
_load_signature()
Place this file beside integrity.py, database.py, reports.py and notifications.py.
Run with: python dashboard.py
"""
from __future__ import annotations

import json
import sys
import queue
import time
import os
import hmac
import hashlib
import secrets
from collections import deque
import tkinter as tk
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from integrity import scan_directory, compare_snapshots, calculate_file_hash
from realtime_monitor import RealtimeMonitor
from database import initialize_database, save_snapshot, load_snapshot, record_event, load_events
from reports import export_json, export_csv
from notifications import send_notification

APP_DIR = Path(__file__).resolve().parent
DATABASE_PATH = APP_DIR / "integrity.db"
CONFIG_PATH = APP_DIR / "dashboard_config.json"
BASELINE_SIGNATURES_PATH = APP_DIR / "baseline_integrity.json"
# Clé conservée hors du dossier du projet : elle n'est pas stockée à côté de la base.
LOCAL_DATA_DIR = APP_DIR / "test_local_data"
BASELINE_KEY_PATH = LOCAL_DATA_DIR / "baseline.key"
BG = "#080D14"
PANEL = "#0E1622"
PANEL_2 = "#111D2B"
BORDER = "#243448"
TEXT = "#E7F0FA"
MUTED = "#8294A9"
CYAN = "#28D7F2"
BLUE = "#2379D4"
PURPLE = "#8B5CF6"
GREEN = "#20C997"
AMBER = "#F4B740"
RED = "#FF647C"

# Détection de suppressions massives : 5 fichiers en 10 secondes.
MASS_DELETION_THRESHOLD = 5
MASS_DELETION_WINDOW_SECONDS = 10

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


def load_config() -> dict:
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_config(data: dict) -> None:
    try:
        CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass



def _canonical_baseline(directory: str, snapshot: dict) -> bytes:
    """Sérialisation stable utilisée pour signer une baseline."""
    payload = {
        "directory": str(Path(directory).resolve()),
        "snapshot": {str(k): str(v) for k, v in sorted(snapshot.items())},
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _read_baseline_key(create: bool = False):
    """Charge la clé HMAC; ne la recrée jamais silencieusement en mode vérification."""
    try:
        if BASELINE_KEY_PATH.exists():
            key = BASELINE_KEY_PATH.read_bytes()
            return key if len(key) >= 32 else None
        if not create:
            return None
        LOCAL_DATA_DIR.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(32)
        with BASELINE_KEY_PATH.open("xb") as f:
            f.write(key)
        return key
    except OSError as exc:
        print(f"[PROTECTION BASELINE] Impossible d'accéder à la clé : {exc}")
        return None



def _load_signatures() -> dict:
    try:
        data = json.loads(BASELINE_SIGNATURES_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"__invalid_manifest__": "invalid"}
    except FileNotFoundError:
        return {"__invalid_manifest__": "missing"}
    except (OSError, json.JSONDecodeError):
        return {"__invalid_manifest__": "invalid"}




def _sign_baseline(directory: str, snapshot: dict) -> bool:
    """Signe une baseline après décision explicite de confiance de l'appelant."""
    manifest_exists = BASELINE_SIGNATURES_PATH.is_file()
    key = _read_baseline_key(create=True)
    if key is None:
        return False

    if manifest_exists:
        signatures = _load_signatures()
        if "__invalid_manifest__" in signatures:
            print("[PROTECTION BASELINE] Manifeste existant invalide : refus de le remplacer.")
            return False
    else:
        # La création d'un manifeste absent n'est permise que lorsque l'appelant
        # a explicitement choisi de créer/protéger ou de ré-enrôler la baseline.
        # _ensure_baseline_protected demande confirmation avant ce chemin.
        signatures = {}

    root = str(Path(directory).resolve())
    signatures[root] = hmac.new(
        key,
        _canonical_baseline(root, snapshot),
        hashlib.sha256,
    ).hexdigest()

    try:
        BASELINE_SIGNATURES_PATH.write_text(
            json.dumps(signatures, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return True
    except OSError as exc:
        print(f"[PROTECTION BASELINE] Impossible d'enregistrer la signature : {exc}")
        return False

def _verify_baseline(directory: str, snapshot: dict):
    """Retourne (état, raison): valid, unsigned, ou invalid."""
    root = str(Path(directory).resolve())
    # Un manifeste absent signifie « non signé » : l'enrôlement reste soumis
    # à la confirmation explicite de _ensure_baseline_protected.
    if not BASELINE_SIGNATURES_PATH.is_file():
        return "unsigned", "Le manifeste de signatures est absent ; l'historique de cette baseline ne peut pas être vérifié."

    signatures = _load_signatures()
    if "__invalid_manifest__" in signatures:
        return "invalid", "Le fichier des signatures est illisible ou invalide."
    expected = signatures.get(root)
    if not expected:
        return "unsigned", "Cette baseline n'a pas encore de signature de protection."
    key = _read_baseline_key(create=False)
    if key is None:
        return "invalid", "La clé de protection est absente ou illisible."
    actual = hmac.new(key, _canonical_baseline(root, snapshot), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(expected), actual):
        return "invalid", "La baseline ne correspond plus à sa signature cryptographique."
    return "valid", "Signature vérifiée."

def event_value(event, key, default=""):
    if isinstance(event, dict):
        return event.get(key, default)
    return getattr(event, key, default)


class IntegrityDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SentinelX | File Integrity Monitor")
        self.geometry("1440x900")
        self.minsize(1120, 760)
        self.configure(fg_color=BG)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        initialize_database(DATABASE_PATH)
        self.config_data = load_config()
        self.selected_directory = self.config_data.get("last_directory", "")
        self.current_snapshot = None
        self.current_changes = {"added": [], "modified": [], "deleted": []}
        self.monitoring = False
        self.realtime_monitor = None
        self.realtime_queue = queue.Queue()
        self.active_alerts = set()
        self.last_event_count = 0
        self.recent_deletions = deque()
        self.mass_deletion_alert_active = False
        self._build_ui()
        self.refresh_all()
        self.after(900, self._autostart_if_requested)

    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=205, corner_radius=0, fg_color="#0A111B",
                                    border_width=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        ctk.CTkFrame(self.sidebar, height=1, fg_color=BORDER).pack(fill="x", pady=(0, 22))
        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=18, pady=(20, 22))
        ctk.CTkLabel(brand, text="⬡", font=ctk.CTkFont(size=29, weight="bold"), text_color=CYAN).pack(side="left")
        brand_text = ctk.CTkFrame(brand, fg_color="transparent")
        brand_text.pack(side="left", padx=9)
        ctk.CTkLabel(brand_text, text="SENTINELX", font=ctk.CTkFont(size=17, weight="bold"), text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(brand_text, text="FILE INTEGRITY", font=ctk.CTkFont(size=9, weight="bold"), text_color=MUTED).pack(anchor="w")

        ctk.CTkLabel(self.sidebar, text="WORKSPACE", text_color="#5D7189", font=ctk.CTkFont(size=10, weight="bold")).pack(anchor="w", padx=21, pady=(2, 10))
        for label, icon in [("Command Center", "◈"), ("Event Timeline", "◷"), ("Monitored Assets", "▤"), ("Reports", "⇩")]:
            active = label == "Command Center"
            b = ctk.CTkButton(self.sidebar, text=f"{icon}   {label}", anchor="w", height=40,
                              corner_radius=8, fg_color="#12365A" if active else "transparent",
                              hover_color="#16283A", text_color=CYAN if active else "#A7B7C9",
                              font=ctk.CTkFont(size=12, weight="bold" if active else "normal"),
                              command=lambda x=label: self.navigate(x))
            b.pack(fill="x", padx=12, pady=3)

        spacer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        spacer.pack(fill="both", expand=True)
        ctk.CTkFrame(self.sidebar, height=1, fg_color=BORDER).pack(fill="x", padx=16, pady=(0, 14))
        ctk.CTkLabel(self.sidebar, text="MONITORING ENGINE", text_color="#5D7189", font=ctk.CTkFont(size=9, weight="bold")).pack(anchor="w", padx=19)
        self.engine_label = ctk.CTkLabel(self.sidebar, text="●  ENGINE READY", text_color=GREEN, font=ctk.CTkFont(size=11, weight="bold"))
        self.engine_label.pack(anchor="w", padx=19, pady=(7, 8))
        ctk.CTkLabel(self.sidebar, text="SHA-256  •  LOCAL MODE", text_color="#53677E", font=ctk.CTkFont(size=9)).pack(anchor="w", padx=19, pady=(0, 18))

        # Main scrollable workspace
        self.main = ctk.CTkScrollableFrame(self, fg_color=BG, corner_radius=0,
                                           scrollbar_button_color="#263A50",
                                           scrollbar_button_hover_color=CYAN)
        self.main.grid(row=0, column=1, sticky="nsew", padx=0, pady=0)
        for col in range(4):
            self.main.grid_columnconfigure(col, weight=1, uniform="main")

        header = ctk.CTkFrame(self.main, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=4, sticky="ew", padx=25, pady=(24, 19))
        head_left = ctk.CTkFrame(header, fg_color="transparent")
        head_left.pack(side="left", fill="x", expand=True)
        ctk.CTkLabel(head_left, text="Command Center", font=ctk.CTkFont(size=25, weight="bold"), text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(head_left, text="Real-time file integrity and change detection", font=ctk.CTkFont(size=12), text_color=MUTED).pack(anchor="w", pady=(4, 0))
        self.status_badge = ctk.CTkLabel(header, text="●  STANDBY", fg_color="#142B2A", text_color=GREEN,
                                          corner_radius=7, padx=12, pady=8, font=ctk.CTkFont(size=11, weight="bold"))
        self.status_badge.pack(side="right", padx=(10, 0))
        ctk.CTkButton(header, text="⟳  Scan now", width=115, height=36, fg_color=BLUE,
                      hover_color="#2D8AE8", font=ctk.CTkFont(size=12, weight="bold"),
                      command=self.scan_selected).pack(side="right", padx=7)

        # Folder selector
        folder = ctk.CTkFrame(self.main, fg_color=PANEL, border_color=BORDER, border_width=1, corner_radius=12)
        folder.grid(row=1, column=0, columnspan=4, sticky="ew", padx=25, pady=(0, 16))
        folder.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(folder, text="MONITORED DIRECTORY", text_color=MUTED, font=ctk.CTkFont(size=10, weight="bold")).grid(row=0, column=0, padx=(16, 12), pady=(12, 4), sticky="w")
        self.path_label = ctk.CTkLabel(folder, text=self.selected_directory or "No directory selected", text_color=TEXT, anchor="w", font=ctk.CTkFont(size=12))
        self.path_label.grid(row=1, column=0, columnspan=2, padx=16, pady=(0, 13), sticky="ew")
        ctk.CTkButton(folder, text="Choose folder", width=110, height=31, command=self.choose_directory,
                      fg_color="#1C2B3D", hover_color="#273B52").grid(row=0, column=2, rowspan=2, padx=12, pady=12)
        self.monitor_button = ctk.CTkButton(folder, text="▶  Start monitoring", width=150, height=31,
                                            command=self.toggle_monitoring, fg_color="#087F70", hover_color="#099681")
        self.monitor_button.grid(row=0, column=3, rowspan=2, padx=(0, 15), pady=12)

        # Metric cards
        self.metric_values = {}
        metrics = [
            ("FILES IN BASELINE", "files", CYAN, "▤"),
            ("ADDED FILES", "added", GREEN, "+"),
            ("MODIFIED FILES", "modified", AMBER, "↻"),
            ("DELETED FILES", "deleted", RED, "−"),
        ]
        for i, (title, key, color, icon) in enumerate(metrics):
            card = ctk.CTkFrame(self.main, fg_color=PANEL, border_color=BORDER, border_width=1, corner_radius=12)
            card.grid(row=2, column=i, sticky="ew", padx=(25 if i == 0 else 7, 7 if i < 3 else 25), pady=(0, 16))
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=15, pady=(14, 5))
            ctk.CTkLabel(top, text=title, text_color=MUTED, font=ctk.CTkFont(size=10, weight="bold")).pack(side="left")
            ctk.CTkLabel(top, text=icon, text_color=color, font=ctk.CTkFont(size=18, weight="bold")).pack(side="right")
            value = ctk.CTkLabel(card, text="0", text_color=TEXT, font=ctk.CTkFont(size=30, weight="bold"))
            value.pack(anchor="w", padx=15, pady=(0, 3))
            sub = ctk.CTkLabel(card, text="Awaiting scan", text_color=color, font=ctk.CTkFont(size=10))
            sub.pack(anchor="w", padx=15, pady=(0, 14))
            self.metric_values[key] = (value, sub)

        # Chart panels
        self.activity_panel = ctk.CTkFrame(self.main, fg_color=PANEL, border_color=BORDER, border_width=1, corner_radius=12)
        self.activity_panel.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=(25, 8), pady=(0, 16))
        self.distribution_panel = ctk.CTkFrame(self.main, fg_color=PANEL, border_color=BORDER, border_width=1, corner_radius=12)
        self.distribution_panel.grid(row=3, column=2, columnspan=2, sticky="nsew", padx=(8, 25), pady=(0, 16))
        self._panel_heading(self.activity_panel, "◈  Change activity", "EVENTS OVER THE LAST 7 DAYS")
        self._panel_heading(self.distribution_panel, "◉  Event distribution", "DETECTED CHANGES BY TYPE")
        self.activity_fig = Figure(figsize=(5.6, 2.5), dpi=100, facecolor=PANEL)
        self.activity_ax = self.activity_fig.add_subplot(111)
        self.activity_canvas = FigureCanvasTkAgg(self.activity_fig, master=self.activity_panel)
        self.activity_canvas.get_tk_widget().pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.dist_fig = Figure(figsize=(5.6, 2.5), dpi=100, facecolor=PANEL)
        self.dist_ax = self.dist_fig.add_subplot(111)
        self.dist_canvas = FigureCanvasTkAgg(self.dist_fig, master=self.distribution_panel)
        self.dist_canvas.get_tk_widget().pack(fill="both", expand=True, padx=12, pady=(0, 12))

        # Events table
        table = ctk.CTkFrame(self.main, fg_color=PANEL, border_color=BORDER, border_width=1, corner_radius=12)
        table.grid(row=4, column=0, columnspan=4, sticky="ew", padx=25, pady=(0, 24))
        table.grid_columnconfigure(0, weight=1)
        table_header = ctk.CTkFrame(table, fg_color="transparent")
        table_header.pack(fill="x", padx=16, pady=(14, 9))
        ctk.CTkLabel(table_header, text="Event timeline", text_color=TEXT, font=ctk.CTkFont(size=15, weight="bold")).pack(side="left")
        self.event_count_label = ctk.CTkLabel(table_header, text="0 events", text_color=MUTED, font=ctk.CTkFont(size=10))
        self.event_count_label.pack(side="left", padx=10)
        self.search_var = tk.StringVar()
        self.search_entry = ctk.CTkEntry(table_header, textvariable=self.search_var, placeholder_text="Search file path…", width=190, height=30)
        self.search_entry.pack(side="right", padx=(8, 0))
        self.search_entry.bind("<KeyRelease>", lambda _e: self.refresh_events())
        self.type_filter = ctk.CTkOptionMenu(table_header, values=["All events", "Added", "Modified", "Deleted"], width=125, height=30, command=lambda _v: self.refresh_events())
        self.type_filter.pack(side="right")

        self.table_head = ctk.CTkFrame(table, fg_color="#0A111A", corner_radius=6)
        self.table_head.pack(fill="x", padx=12, pady=(0, 2))
        for i, (label, width) in enumerate([("TYPE", 105), ("FILE / PATH", 1), ("TIMESTAMP", 155), ("STATUS", 105)]):
            self.table_head.grid_columnconfigure(i, weight=width if i == 1 else 0, minsize=width if i != 1 else 100)
            ctk.CTkLabel(self.table_head, text=label, text_color="#71869D", font=ctk.CTkFont(size=9, weight="bold"), anchor="w").grid(row=0, column=i, sticky="ew", padx=10, pady=10)
        self.events_frame = ctk.CTkFrame(table, fg_color="transparent")
        self.events_frame.pack(fill="x", padx=12, pady=(0, 12))
        self.footer = ctk.CTkFrame(self.main, fg_color="transparent")
        self.footer.grid(row=5, column=0, columnspan=4, sticky="ew", padx=25, pady=(0, 20))
        ctk.CTkLabel(self.footer, text="LOCAL MONITORING  •  SHA-256 CHECKSUMS", text_color="#50647B", font=ctk.CTkFont(size=9)).pack(side="left")
        ctk.CTkButton(self.footer, text="Export CSV", width=95, height=29, command=lambda: self.export_report("csv"), fg_color="#17283A", hover_color="#243B52").pack(side="right", padx=(8, 0))
        ctk.CTkButton(self.footer, text="Export JSON", width=100, height=29, command=lambda: self.export_report("json"), fg_color="#17283A", hover_color="#243B52").pack(side="right")

    def _panel_heading(self, parent, title, subtitle):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(14, 0))
        ctk.CTkLabel(row, text=title, text_color=TEXT, font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(row, text=subtitle, text_color="#61758C", font=ctk.CTkFont(size=9, weight="bold")).pack(anchor="w", pady=(4, 0))

    def navigate(self, label):
        if label == "Reports":
            self.export_report("json")
        elif label == "Event Timeline":
            self.search_entry.focus_set()
            self.events_frame.winfo_toplevel().after(50, lambda: self.main._parent_canvas.yview_moveto(1.0))
        elif label == "Monitored Assets":
            self.choose_directory()
        else:
            self.main._parent_canvas.yview_moveto(0.0)

    def choose_directory(self):
        if self.monitoring:
            self._stop_realtime_monitor()
        path = filedialog.askdirectory(title="Choose a directory to monitor", initialdir=self.selected_directory or str(APP_DIR))
        if not path:
            return
        self.selected_directory = str(Path(path).resolve())
        self.path_label.configure(text=self.selected_directory)
        self.config_data["last_directory"] = self.selected_directory
        save_config(self.config_data)
        self.current_snapshot = None
        self.current_changes = {"added": [], "modified": [], "deleted": []}
        self.active_alerts.clear()
        with self.realtime_queue.mutex:
            self.realtime_queue.queue.clear()
        self.refresh_all()

    def _ensure_baseline_protected(self, baseline, allow_enrollment=True):
        """Vérifie la signature et propose une seule fois d'enrôler une ancienne baseline."""
        state, reason = _verify_baseline(self.selected_directory, baseline)
        if state == "valid":
            return True
        if state == "unsigned" and allow_enrollment:
            trust = messagebox.askyesno(
                "Protéger la baseline",
                "Cette baseline existante n'a pas encore de signature cryptographique.\n\n"
                "Si tu la considères comme fiable, SentinelX peut la signer maintenant.\n"
                "Cette opération ne vérifie pas son historique antérieur.\n\n"
                "Faire confiance à cette baseline et activer sa protection ?",
            )
            if trust and _sign_baseline(self.selected_directory, baseline):
                self.set_status("BASELINE PROTECTED", GREEN)
                return True
            if trust:
                messagebox.showerror("Protection impossible", "La signature de la baseline n'a pas pu être enregistrée.")
            return False

        message = (
            "ALERTE DE SÉCURITÉ : intégrité de la baseline non vérifiée.\n\n"
            f"{reason}\n\n"
            "La surveillance est bloquée pour éviter de faire confiance à une référence potentiellement altérée."
        )
        self.set_status("BASELINE INTEGRITY ERROR", RED)
        print(f"[ALERTE INTÉGRITÉ BASELINE] {reason}")
        try:
            send_notification("ALERTE : baseline altérée", reason)
        except Exception as exc:
            print(f"[ERREUR NOTIFICATION BASELINE] {exc}")
        messagebox.showerror("Alerte intégrité de la baseline", message)
        return False

    
    def _save_and_protect_baseline(self, snapshot):
        manifest_path = BASELINE_SIGNATURES_PATH
        manifest_existed = manifest_path.exists()
        previous_manifest = (
            manifest_path.read_bytes() if manifest_existed else None
        )

        def restore_manifest():
            if manifest_existed:
                temporary_path = manifest_path.with_name(
                    manifest_path.name + ".restore.tmp"
                )
                temporary_path.write_bytes(previous_manifest)
                temporary_path.replace(manifest_path)
            elif manifest_path.exists():
                manifest_path.unlink()

        if not _sign_baseline(self.selected_directory, snapshot):
            try:
                restore_manifest()
            except OSError as exc:
                raise RuntimeError(
                    "La signature a échoué et la restauration du manifeste "
                    "a également échoué."
                ) from exc

            raise RuntimeError(
                "La signature de protection de la baseline n'a pas pu être créée."
            )

        try:
            save_snapshot(
                snapshot,
                DATABASE_PATH,
                directory=self.selected_directory,
            )
        except Exception:
            try:
                restore_manifest()
            except OSError as exc:
                raise RuntimeError(
                    "La sauvegarde a échoué et la restauration du manifeste "
                    "a également échoué."
                ) from exc
            raise


    def scan_selected(self):
        if not self.selected_directory or not Path(self.selected_directory).is_dir():
            messagebox.showinfo("Select a directory", "Choose a valid directory before scanning.")
            self.choose_directory()
            if not self.selected_directory or not Path(self.selected_directory).is_dir():
                return

        try:
            new_snapshot = scan_directory(self.selected_directory)
        except Exception as exc:
            messagebox.showerror("Scan failed", f"Could not scan the selected directory.\\n\\n{exc}")
            return

        baseline = load_snapshot(DATABASE_PATH, directory=self.selected_directory)
        manifest_path = Path(BASELINE_SIGNATURES_PATH)
        key_exists = Path(BASELINE_KEY_PATH).is_file()

        if not baseline:
            # Une clé existante sans manifeste indique une protection incomplète.
            # On ne doit pas proposer de recréer la référence dans ce cas.
            if key_exists and not manifest_path.is_file():
                messagebox.showerror(
                    "Security alert",
                    "The baseline manifest is missing while the protection key exists.\\n\\n"
                    "Monitoring is blocked. Restore the manifest from a trusted backup.",
                )
                self.set_status("SECURITY ALERT", RED)
                return

            # Un manifeste existe mais la référence DB est absente :
            # ne pas créer une nouvelle baseline qui masquerait l'incohérence.
            if manifest_path.is_file():
                messagebox.showerror(
                    "Security alert",
                    "A baseline manifest exists, but no baseline was found in the database.\\n\\n"
                    "Monitoring is blocked pending verification.",
                )
                self.set_status("SECURITY ALERT", RED)
                return

            if not messagebox.askyesno(
                "Create baseline",
                "No baseline exists for this directory.\\n\\n"
                "Use the current files as the trusted baseline?",
            ):
                self.current_snapshot = new_snapshot
                self.refresh_all()
                return

            try:
                self._save_and_protect_baseline(new_snapshot)
            except Exception as exc:
                messagebox.showerror("Baseline protection failed", str(exc))
                return

            self.current_snapshot = new_snapshot
            self.current_changes = {"added": [], "modified": [], "deleted": []}
            self.active_alerts.clear()
            self.set_status("BASELINE CREATED", GREEN)
            self.refresh_all()
            return

        if not self._ensure_baseline_protected(baseline):
            return

        changes = compare_snapshots(baseline, new_snapshot)
        self.current_snapshot = new_snapshot
        self.current_changes = changes
        total = sum(len(changes.get(k, [])) for k in ("added", "modified", "deleted"))

        if total:
            for kind in ("added", "modified", "deleted"):
                for item in changes.get(kind, []):
                    path = item if isinstance(item, str) else item.get("path", str(item))
                    signature = (kind, path)
                    if signature not in self.active_alerts:
                        try:
                            record_event(
                                kind,
                                path,
                                database_path=DATABASE_PATH,
                                directory=self.selected_directory,
                            )
                        except Exception as exc:
                            print(f"[ERREUR BASE DE DONNÉES] {exc}")
                        self.active_alerts.add(signature)
            self.set_status(f"{total} CHANGE(S) DETECTED", RED)
        else:
            self.active_alerts.clear()
            self.set_status("INTEGRITY NOMINAL", GREEN)

        self.refresh_all()

    def toggle_monitoring(self):
        if self.monitoring:
            self._stop_realtime_monitor()
            self.monitor_button.configure(
                text="▶  Start monitoring",
                fg_color="#087F70",
                hover_color="#099681",
            )
            self.engine_label.configure(text="●  ENGINE READY", text_color=GREEN)
            self.set_status("STANDBY", GREEN)
            return

        if not self.selected_directory or not Path(self.selected_directory).is_dir():
            messagebox.showinfo(
                "Select a directory",
                "Choose a valid directory before starting monitoring.",
            )
            self.choose_directory()
            if not self.selected_directory or not Path(self.selected_directory).is_dir():
                return

        baseline = load_snapshot(DATABASE_PATH, directory=self.selected_directory)
        manifest_path = Path(BASELINE_SIGNATURES_PATH)
        key_exists = Path(BASELINE_KEY_PATH).is_file()

        if not baseline:
            if key_exists and not manifest_path.is_file():
                messagebox.showerror(
                    "Security alert",
                    "The baseline manifest is missing while the protection key exists.\\n\\n"
                    "Monitoring is blocked. Restore the manifest from a trusted backup.",
                )
                self.set_status("SECURITY ALERT", RED)
                return

            if manifest_path.is_file():
                messagebox.showerror(
                    "Security alert",
                    "A baseline manifest exists, but no baseline was found in the database.\\n\\n"
                    "Monitoring is blocked pending verification.",
                )
                self.set_status("SECURITY ALERT", RED)
                return

            if not messagebox.askyesno(
                "Create baseline",
                "No baseline exists for this directory.\\n\\n"
                "Use the current files as the trusted baseline?",
            ):
                return

            try:
                baseline = scan_directory(self.selected_directory)
                self._save_and_protect_baseline(baseline)
                self.current_snapshot = dict(baseline)
                self.current_changes = {"added": [], "modified": [], "deleted": []}
                self.active_alerts.clear()
                self.refresh_all()
            except Exception as exc:
                messagebox.showerror("Baseline failed", str(exc))
                return

        if not self._ensure_baseline_protected(baseline):
            return

        try:
            # Seed the current view from a fresh scan before starting event-based monitoring.
            self.current_snapshot = scan_directory(self.selected_directory)
            self.current_changes = compare_snapshots(baseline, self.current_snapshot)
            self.realtime_monitor = RealtimeMonitor(
                self.selected_directory,
                self._queue_realtime_event,
            )
            self.realtime_monitor.start()
        except Exception as exc:
            self.realtime_monitor = None
            messagebox.showerror("Monitoring failed", f"Could not start monitoring.\\n\\n{exc}")
            return

        self.monitoring = True
        self.monitor_button.configure(
            text="Ⅱ  Stop monitoring",
            fg_color="#8B3044",
            hover_color="#A33B52",
        )
        self.engine_label.configure(text="●  REAL-TIME ACTIVE", text_color=CYAN)
        self.set_status("REAL-TIME MONITORING", CYAN)
        self.refresh_all()
        self._poll_realtime_queue()

    def _queue_realtime_event(self, event_type, path):
        """Watchdog callback: enqueue only; never touch Tk widgets from its thread."""
        self.realtime_queue.put((event_type, str(path)))

    def _poll_realtime_queue(self):
        """Traite les événements Watchdog sur le thread de l'interface."""
        if not self.monitoring:
            return

        pending_events = []
        while True:
            try:
                event_type, raw_path = self.realtime_queue.get_nowait()
                pending_events.append((event_type, raw_path))
            except queue.Empty:
                break

        # Traiter les événements dans leur ordre de réception.
        for event_type, raw_path in pending_events:
            try:
                self._process_realtime_path(raw_path, event_type)
            except Exception as exc:
                print(f"[ERREUR SURVEILLANCE] {event_type} {raw_path}: {exc}")

        self.after(250, self._poll_realtime_queue)

    def _process_realtime_path(self, raw_path, event_type=None):
        if not self.monitoring or not self.selected_directory:
            return

        root = Path(self.selected_directory).resolve()
        path = Path(raw_path).resolve()
        try:
            relative = str(path.relative_to(root))
        except ValueError:
            return

        baseline = load_snapshot(DATABASE_PATH, directory=self.selected_directory)
        if not baseline:
            self.set_status("BASELINE REQUIRED", AMBER)
            return
        state, reason = _verify_baseline(self.selected_directory, baseline)
        if state != "valid":
            self._stop_realtime_monitor()
            self.monitor_button.configure(text="▶  Start monitoring", fg_color="#087F70", hover_color="#099681")
            self.engine_label.configure(text="●  ENGINE READY", text_color=RED)
            self.set_status("BASELINE INTEGRITY ERROR", RED)
            print(f"[ALERTE INTÉGRITÉ BASELINE] {reason}")
            try:
                send_notification("ALERTE : baseline altérée", reason)
            except Exception as exc:
                print(f"[ERREUR NOTIFICATION BASELINE] {exc}")
            messagebox.showerror(
                "Alerte intégrité de la baseline",
                f"{reason}\n\nLa surveillance en temps réel a été arrêtée. Vérifie la base de données et les fichiers de protection.",
            )
            return

        
        if self.current_snapshot is None:
            try:
                self.current_snapshot = scan_directory(self.selected_directory)
            except OSError as exc:
                messagebox.showerror(
                    "Erreur de scan",
                    f"Impossible de poursuivre : le scan est incomplet.\n\n{exc}",
                )
                return


        # Détection d'une rafale de suppressions, indépendamment de la baseline.
        # On utilise l'horloge monotone pour éviter les problèmes de changement d'heure.
        if event_type == "deleted":
            now = time.monotonic()
            self.recent_deletions.append((now, relative))
            while (self.recent_deletions and
                   now - self.recent_deletions[0][0] > MASS_DELETION_WINDOW_SECONDS):
                self.recent_deletions.popleft()

            if len(self.recent_deletions) >= MASS_DELETION_THRESHOLD:
                if not self.mass_deletion_alert_active:
                    self.mass_deletion_alert_active = True
                    alert_text = (
                        f"{len(self.recent_deletions)} suppressions détectées en "
                        f"{MASS_DELETION_WINDOW_SECONDS} secondes. "
                        "Vérifiez immédiatement le dossier surveillé."
                    )
                    print(f"[ALERTE CRITIQUE] {alert_text}")
                    try:
                        send_notification("ALERTE CRITIQUE : suppressions massives", alert_text)
                    except Exception as exc:
                        print(f"[ERREUR NOTIFICATION ALERTE CRITIQUE] {exc}")
            else:
                self.mass_deletion_alert_active = False

        try:
            # Un événement "deleted" est prioritaire même si d'autres événements
            # du système arrivent presque simultanément pour le même chemin.
            if event_type == "deleted" or not path.is_file():
                self.current_snapshot.pop(relative, None)
            else:
                self.current_snapshot[relative] = calculate_file_hash(path)
        except (OSError, PermissionError) as exc:
            print(f"[SURVEILLANCE] Fichier momentanément inaccessible ({path}): {exc}")
            return

        # Si un fichier a été créé puis supprimé depuis la baseline, la
        # comparaison des snapshots ne verra aucune différence finale. On
        # enregistre donc explicitement cette suppression dans l'historique.
        # Pour un fichier présent dans la baseline, la boucle ci-dessous
        # l'enregistrera déjà : on évite ainsi le doublon.
        transient_deletion = event_type == "deleted" and relative not in baseline
        if transient_deletion:
            signature = ("deleted", relative)
            if signature not in self.active_alerts:
                try:
                    record_event(
                        "deleted",
                        relative,
                        old_hash=None,
                        new_hash=None,
                        database_path=DATABASE_PATH,
                        directory=self.selected_directory,
                    )
                except Exception as exc:
                    print(f"[ERREUR BASE DE DONNÉES] Impossible d'enregistrer deleted {relative}: {exc}")
                try:
                    send_notification("Fichier supprimé", f"Fichier : {relative}")
                except Exception as exc:
                    print(f"[ERREUR NOTIFICATION] {exc}")

        changes = compare_snapshots(baseline, self.current_snapshot)
        self.current_changes = changes

        current_signatures = set()
        for kind in ("added", "modified", "deleted"):
            for item in changes.get(kind, []):
                signature_path = item if isinstance(item, str) else item.get("path", str(item))
                signature = (kind, signature_path)
                current_signatures.add(signature)

                if signature not in self.active_alerts:
                    try:
                        record_event(
                            kind,
                            signature_path,
                            old_hash=baseline.get(signature_path),
                            new_hash=self.current_snapshot.get(signature_path),
                            database_path=DATABASE_PATH,
                            directory=self.selected_directory,
                        )
                    except Exception as exc:
                        print(f"[ERREUR BASE DE DONNÉES] Impossible d'enregistrer {kind} {signature_path}: {exc}")

                    titles = {
                        "added": "Fichier ajouté",
                        "modified": "Fichier modifié",
                        "deleted": "Fichier supprimé",
                    }
                    try:
                        send_notification(
                            titles.get(kind, "Changement détecté"),
                            f"Fichier : {signature_path}",
                        )
                    except Exception as exc:
                        print(f"[ERREUR NOTIFICATION] {exc}")

        self.active_alerts.intersection_update(current_signatures)
        self.active_alerts.update(current_signatures)

        total = sum(len(changes.get(k, [])) for k in ("added", "modified", "deleted"))
        self.set_status(
            f"{total} CHANGE(S) DETECTED" if total else "REAL-TIME MONITORING",
            RED if total else CYAN,
        )
        self.refresh_all()

    def _stop_realtime_monitor(self):
        self.monitoring = False
        monitor = self.realtime_monitor
        self.realtime_monitor = None
        if monitor is not None:
            try:
                monitor.stop()
            except Exception as exc:
                print(f"Error while stopping realtime monitor: {exc}")

    def set_status(self, text, color):
        bg = "#321A25" if color == RED else ("#142B2A" if color == GREEN else "#112A3A")
        self.status_badge.configure(text=f"●  {text}", text_color=color, fg_color=bg)

    def refresh_all(self):
        try:
            baseline = load_snapshot(DATABASE_PATH, directory=self.selected_directory) if self.selected_directory else None
            count = len(baseline) if isinstance(baseline, dict) else 0
            self.metric_values["files"][0].configure(text=f"{count:,}")
            self.metric_values["files"][1].configure(text="Tracked baseline" if count else "Baseline not created")
            for key, label in [("added", "Added since baseline"), ("modified", "Modified since baseline"), ("deleted", "Deleted since baseline")]:
                n = len(self.current_changes.get(key, []))
                self.metric_values[key][0].configure(text=str(n))
                self.metric_values[key][1].configure(text=label)
        except Exception:
            pass
        self.refresh_charts()
        self.refresh_events()

    def refresh_charts(self):
        try:
            events = load_events(DATABASE_PATH)
        except Exception:
            events = []
        days = [(datetime.now().date() - timedelta(days=i)) for i in range(6, -1, -1)]
        counts = {d: {"added": 0, "modified": 0, "deleted": 0} for d in days}
        for event in events:
            stamp = str(event_value(event, "timestamp", event_value(event, "detected_at", event_value(event, "created_at", ""))))
            kind = str(event_value(event, "event_type", "")).lower()
            try:
                d = datetime.fromisoformat(stamp.replace("Z", "+00:00")).date()
            except ValueError:
                continue
            if d in counts and kind in counts[d]:
                counts[d][kind] += 1
        ax = self.activity_ax
        ax.clear()
        ax.set_facecolor(PANEL)
        x = list(range(7))
        added = [counts[d]["added"] for d in days]
        modified = [counts[d]["modified"] for d in days]
        deleted = [counts[d]["deleted"] for d in days]
        ax.bar(x, added, color=GREEN, width=.58, label="Added")
        ax.bar(x, modified, bottom=added, color=AMBER, width=.58, label="Modified")
        bottoms = [added[i] + modified[i] for i in range(7)]
        ax.bar(x, deleted, bottom=bottoms, color=RED, width=.58, label="Deleted")
        ax.set_xticks(x, [d.strftime("%a") for d in days])
        ax.tick_params(colors=MUTED, labelsize=8)
        ax.grid(axis="y", color="#263548", linewidth=.6, alpha=.8)
        ax.set_axisbelow(True)
        for spine in ax.spines.values(): spine.set_visible(False)
        ax.set_ylim(bottom=0)
        ax.legend(loc="upper left", frameon=False, fontsize=8, labelcolor=MUTED, ncol=3)
        self.activity_fig.tight_layout(pad=1.5)
        self.activity_canvas.draw_idle()

        ax2 = self.dist_ax
        ax2.clear()
        ax2.set_facecolor(PANEL)
        vals = [sum(1 for e in events if str(event_value(e, "event_type", "")).lower() == k) for k in ("added", "modified", "deleted")]
        labels = ["Added", "Modified", "Deleted"]
        if sum(vals) == 0:
            ax2.text(.5, .53, "No events recorded", ha="center", va="center", color=MUTED, fontsize=11, transform=ax2.transAxes)
            ax2.axis("off")
        else:
            wedges, _ = ax2.pie(vals, startangle=90, colors=[GREEN, AMBER, RED], wedgeprops={"width": .31, "edgecolor": PANEL, "linewidth": 3})
            ax2.text(0, .06, str(sum(vals)), ha="center", va="center", color=TEXT, fontsize=21, fontweight="bold")
            ax2.text(0, -.2, "EVENTS", ha="center", va="center", color=MUTED, fontsize=8)
            ax2.legend(wedges, [f"{labels[i]}  {vals[i]}" for i in range(3)], loc="center left", bbox_to_anchor=(.85, .5), frameon=False, labelcolor=MUTED, fontsize=9)
            ax2.axis("equal")
        self.dist_fig.tight_layout(pad=1.4)
        self.dist_canvas.draw_idle()

    def refresh_events(self):
        for widget in self.events_frame.winfo_children():
            widget.destroy()
        try:
            events = list(load_events(DATABASE_PATH))
        except Exception:
            events = []
        # load_events() already returns newest events first; do not reverse the list.
        selected_type = self.type_filter.get().lower() if hasattr(self, "type_filter") else "all events"
        query = self.search_var.get().strip().lower() if hasattr(self, "search_var") else ""
        filtered = []
        for e in events:
            kind = str(event_value(e, "event_type", "unknown")).lower()
            path = str(event_value(e, "path", ""))
            directory = str(event_value(e, "directory", ""))
            if selected_type != "all events" and kind != selected_type:
                continue
            if query and query not in path.lower() and query not in directory.lower():
                continue
            filtered.append(e)
        self.event_count_label.configure(text=f"{len(filtered)} events")
        if not filtered:
            ctk.CTkLabel(self.events_frame, text="No events match your filters.", text_color=MUTED, height=54).pack(fill="x")
            return
        for e in filtered[:80]:
            kind = str(event_value(e, "event_type", "unknown")).lower()
            path = str(event_value(e, "path", "—"))
            stamp = str(event_value(e, "timestamp", event_value(e, "detected_at", event_value(e, "created_at", "—"))))
            try:
                stamp = datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d  %H:%M:%S")
            except ValueError:
                pass
            color = {"added": GREEN, "modified": AMBER, "deleted": RED}.get(kind, CYAN)
            row = ctk.CTkFrame(self.events_frame, fg_color="#0B131D" if len(self.events_frame.winfo_children()) % 2 == 0 else "transparent", corner_radius=5)
            row.pack(fill="x", pady=1)
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(row, text=kind.upper(), text_color=color, fg_color="#18252F", corner_radius=5, width=82, font=ctk.CTkFont(size=9, weight="bold")).grid(row=0, column=0, padx=8, pady=8, sticky="w")
            ctk.CTkLabel(row, text=path, text_color=TEXT, anchor="w", font=ctk.CTkFont(size=10), wraplength=560).grid(row=0, column=1, padx=10, pady=8, sticky="ew")
            ctk.CTkLabel(row, text=stamp, text_color=MUTED, font=ctk.CTkFont(size=9)).grid(row=0, column=2, padx=8, pady=8, sticky="w")
            ctk.CTkLabel(row, text="● RECORDED", text_color=color, font=ctk.CTkFont(size=8, weight="bold")).grid(row=0, column=3, padx=10, pady=8, sticky="e")

    def export_report(self, kind):
        try:
            events = load_events(DATABASE_PATH)
            path = export_csv(events) if kind == "csv" else export_json(events)
            messagebox.showinfo("Export complete", f"Report exported successfully.\n\n{path}")
        except Exception as exc:
            messagebox.showerror("Export failed", f"Could not export report.\n\n{exc}")

    def _autostart_if_requested(self):
        if "--autostart" in sys.argv and self.selected_directory and Path(self.selected_directory).is_dir():
            if load_snapshot(DATABASE_PATH, directory=self.selected_directory):
                self.toggle_monitoring()

    def on_close(self):
        self._stop_realtime_monitor()
        self.destroy()


if __name__ == "__main__":
    app = IntegrityDashboard()
    app.mainloop()
