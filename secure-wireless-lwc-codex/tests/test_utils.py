from pathlib import Path

from src.utils.key_manager import generate_key, load_key, save_key
from src.utils.logger import log_event


def test_key_manager_roundtrip(tmp_path: Path):
    key = generate_key(16)
    assert len(key) == 16
    key_path = tmp_path / "key.bin"
    save_key(key, str(key_path))
    loaded = load_key(str(key_path))
    assert loaded == key


def test_logger_writes_line(tmp_path: Path):
    log_path = tmp_path / "app.log"
    log_event("hello-world", str(log_path))
    assert log_path.exists()
    content = log_path.read_text(encoding="utf-8")
    assert "hello-world" in content
