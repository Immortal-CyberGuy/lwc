from datetime import datetime, timezone
from pathlib import Path


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def log_event(message: str, log_file: str = "results/app.log") -> None:
    path = Path(log_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = f"[{_timestamp()}] {message}\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)
