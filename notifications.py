
from winotify import Notification


def send_notification(title: str, message: str) -> None:
    """Affiche une notification Windows."""
    try:
        notification = Notification(
            app_id="File Integrity Monitor",
            title=title,
            msg=message,
        )
        notification.show()
    except Exception as error:
        print(f"[AVERTISSEMENT] Notification impossible : {error}")
